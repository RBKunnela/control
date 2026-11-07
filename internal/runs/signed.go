package runs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/pkg/contract"
)

// SignedRecordVersion is the version of a record an operator signs: a DSSE
// envelope of RecordPayloadType over a body holding every member of a
// record of major 2, the signing key's id, its algorithm, and the records/
// directory it was signed for. A reader of a signed layout's records/ takes
// any minor of major 3 and nothing else.
const SignedRecordVersion = "3.0"

// RecordPayloadType is the DSSE payload type a run record is signed under,
// operators.RunPayloadType; this package links no operator port, and a test
// holds the two equal.
const RecordPayloadType = "application/vnd.agent-run-record+json"

// MaxKeyIDBytes bounds the key id a signed record names.
const MaxKeyIDBytes = 64

// MaxRecordsPathBytes bounds the records/ path a signed record names, which
// keeps a record at its longest identity under the bound a read holds a file
// to.
const MaxRecordsPathBytes = 512

// signedAlg is the one algorithm a signed body names: an operator key's.
const signedAlg = "ed25519"

// signedKeys is every member of a signed body, each required.
var signedKeys = append([]string{"alg", "keyId", "records"}, recordKeys...)

// envelopeKeys and signatureKeys are the members of a signed record's
// envelope and of its one signature, each required, as every DSSE file of
// this module spells them.
var (
	envelopeKeys  = []string{"payloadType", "payload", "signatures"}
	signatureKeys = []string{"keyid", "sig"}
)

// Signer is an operator key a signed record is signed with: its id, and a
// function that signs a body under a payload type.
type Signer struct {
	KeyID string
	Sign  func(payloadType string, body []byte) ([]byte, error)
}

// SignedRecord is a record as a signed layout's records/ holds it, judged by
// nothing yet: the record, the key its body names, the absolute records/
// path it was signed for, and the envelope.
type SignedRecord struct {
	Record   Record
	KeyID    string
	Records  string
	Envelope policy.StatementEnvelope
}

// SignedBy is who signed a record a Judge took: the operator's subject and
// key id.
type SignedBy struct {
	Subject, KeyID string
}

// Judge is what a plane under the signed authority takes every record
// through before the record counts: its signature, and its signer's
// authority over the run's tenant and project. It answers who signed, or a
// refusal wrapping ErrUnauthenticated, ErrOtherScope, ErrUnauthorized or
// ErrAuthority.
type Judge interface {
	Judge(ctx context.Context, r SignedRecord) (SignedBy, error)
}

// signBody is a signed record's canonical body for r under keyID, for the
// records/ directory at records, refused where decodeSignedBody would not
// read it back as r.
func signBody(r Record, keyID, records string) ([]byte, error) {
	if err := checkKeyID(keyID); err != nil {
		return nil, err
	}
	if err := checkRecordsPath(records); err != nil {
		return nil, err
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	closed := ""
	if r.Closed() {
		closed = formatTime(r.ClosedAt)
	}
	body, err := canon.Canonicalize(map[string]any{
		"schema_version": SignedRecordVersion, "alg": signedAlg, "keyId": keyID,
		"run_id": r.ID, "project_id": r.Who.ProjectID, "tenant_id": r.Who.TenantID,
		"principal_type": r.Who.PrincipalType, "principal_id": r.Who.PrincipalID, "agent_id": r.Who.AgentID,
		"root": r.Root, "parent": r.Parent, "opened_at": formatTime(r.OpenedAt), "expires_at": formatTime(r.ExpiresAt),
		"closed_at": closed, "secret_sha256": r.SecretSHA256, "records": records,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMalformed, clip(err.Error()))
	}
	back, err := decodeSignedBody(body)
	if err != nil {
		return nil, err
	}
	if back.Record != canonRecord(r) || back.KeyID != keyID || back.Records != records {
		return nil, fmt.Errorf("%w: the signed body does not read back as the record", ErrMalformed)
	}
	return body, nil
}

// canonRecord is r with every time as a file holds it.
func canonRecord(r Record) Record {
	r.OpenedAt, r.ExpiresAt = canonTime(r.OpenedAt), canonTime(r.ExpiresAt)
	if r.Closed() {
		r.ClosedAt = canonTime(r.ClosedAt)
	}
	return r
}

// signRecord is the file of r signed with s for the records/ directory at
// records. Like encodeRecord it is a method of the operator's handle alone.
func (*Admin) signRecord(r Record, s Signer, records string) ([]byte, error) {
	if s.Sign == nil {
		return nil, ErrSigner
	}
	body, err := signBody(r, s.KeyID, records)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(RecordPayloadType, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigner, err)
	}
	raw, err := encode(map[string]any{
		"payloadType": RecordPayloadType,
		"payload":     base64.StdEncoding.EncodeToString(body),
		"signatures":  []map[string]string{{"keyid": s.KeyID, "sig": base64.StdEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileBytes {
		return nil, fmt.Errorf("%w: a signed record of %d bytes", ErrTooLarge, len(raw))
	}
	if _, err := decodeSignedFile(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// isEnvelope reports whether raw is one JSON object naming a payloadType,
// which no record of major 2 holds.
func isEnvelope(raw []byte) bool {
	members, err := strictjson.ReadObject(raw)
	if err != nil {
		return false
	}
	_, ok := members["payloadType"]
	return ok
}

// decodeSignedFile reads raw as a signed record: one strict DSSE envelope of
// RecordPayloadType with one signature, whose body decodeSignedBody reads
// and names the signature's key. A record that is no envelope is refused
// with ErrUnsigned. The signature is not checked here.
func decodeSignedFile(raw []byte) (SignedRecord, error) {
	if !isEnvelope(raw) {
		return SignedRecord{}, ErrUnsigned
	}
	env, err := decodeEnvelope(raw)
	if err != nil {
		return SignedRecord{}, err
	}
	switch {
	case env.PayloadType != RecordPayloadType:
		return SignedRecord{}, fmt.Errorf("%w: the payload type is not %s", ErrMalformed, RecordPayloadType)
	case len(env.Signatures) != 1:
		return SignedRecord{}, fmt.Errorf("%w: %d signatures, not one", ErrMalformed, len(env.Signatures))
	}
	sr, err := decodeSignedBody(env.Payload)
	if err != nil {
		return SignedRecord{}, err
	}
	if sr.KeyID != env.Signatures[0].KeyID {
		return SignedRecord{}, fmt.Errorf("%w: the body names another key than its signature", ErrMalformed)
	}
	sr.Envelope = env
	return sr, nil
}

// decodeEnvelope reads every member of the envelope and of its signatures
// once and none other, payload and sig standard base64 in the one spelling
// they encode back to.
func decodeEnvelope(raw []byte) (policy.StatementEnvelope, error) {
	top, err := fields(raw, envelopeKeys)
	if err != nil {
		return policy.StatementEnvelope{}, err
	}
	var env policy.StatementEnvelope
	if env.PayloadType, err = stringField(top, "payloadType"); err != nil {
		return policy.StatementEnvelope{}, err
	}
	if env.Payload, err = base64Field(top, "payload"); err != nil {
		return policy.StatementEnvelope{}, err
	}
	var sigs []json.RawMessage
	if err := json.Unmarshal(top["signatures"], &sigs); err != nil || sigs == nil {
		return policy.StatementEnvelope{}, fmt.Errorf("%w: %q is not an array", ErrMalformed, "signatures")
	}
	for _, item := range sigs {
		m, err := fields(item, signatureKeys)
		if err != nil {
			return policy.StatementEnvelope{}, fmt.Errorf("a signature: %w", err)
		}
		var s policy.StatementSignature
		if s.KeyID, err = stringField(m, "keyid"); err != nil {
			return policy.StatementEnvelope{}, err
		}
		if s.Signature, err = base64Field(m, "sig"); err != nil {
			return policy.StatementEnvelope{}, err
		}
		env.Signatures = append(env.Signatures, s)
	}
	return env, nil
}

func base64Field(f map[string]json.RawMessage, key string) ([]byte, error) {
	s, err := stringField(f, key)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("%w: %q is not standard base64", ErrMalformed, key)
	}
	return b, nil
}

// decodeSignedBody reads a signed record's body strictly: its own canonical
// JSON, every member of signedKeys and no other, schema_version of major 3,
// alg ed25519, a key id, a records/ path, and a record check holds. The
// envelope is left to the caller.
func decodeSignedBody(body []byte) (SignedRecord, error) {
	canonical, err := canon.CanonicalizeJSON(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return SignedRecord{}, fmt.Errorf("%w: the signed body is not its own canonical form", ErrMalformed)
	}
	f, err := fields(body, signedKeys)
	if err != nil {
		return SignedRecord{}, err
	}
	s, err := stringFields(f, signedKeys)
	if err != nil {
		return SignedRecord{}, err
	}
	if !strictjson.IsVersion(s["schema_version"], "3") {
		return SignedRecord{}, fmt.Errorf("%w: %q; a signed record is read at major 3", ErrSchemaVersion, clip(s["schema_version"]))
	}
	if s["alg"] != signedAlg {
		return SignedRecord{}, fmt.Errorf("%w: alg is not %s", ErrMalformed, signedAlg)
	}
	if err := checkKeyID(s["keyId"]); err != nil {
		return SignedRecord{}, err
	}
	if err := checkRecordsPath(s["records"]); err != nil {
		return SignedRecord{}, err
	}
	r, err := recordOf(s)
	if err != nil {
		return SignedRecord{}, err
	}
	return SignedRecord{Record: r, KeyID: s["keyId"], Records: s["records"]}, nil
}

// checkRecordsPath holds a records/ path to an absolute, cleaned path of at
// most MaxRecordsPathBytes with no control character, the one spelling a
// directory's own name is compared in.
func checkRecordsPath(p string) error {
	switch {
	case p == "" || len(p) > MaxRecordsPathBytes:
		return fmt.Errorf("%w: records is %d bytes, bound %d", ErrMalformed, len(p), MaxRecordsPathBytes)
	case !filepath.IsAbs(p) || filepath.Clean(p) != p:
		return fmt.Errorf("%w: records is not an absolute, cleaned path", ErrMalformed)
	case strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return fmt.Errorf("%w: records holds a control character", ErrMalformed)
	}
	return nil
}

func checkKeyID(id string) error {
	if id == "" || len(id) > MaxKeyIDBytes {
		return fmt.Errorf("%w: keyId is %d bytes, bound %d", ErrMalformed, len(id), MaxKeyIDBytes)
	}
	if err := contract.CheckIdentifier(id); err != nil {
		return fmt.Errorf("%w: keyId: %w", ErrMalformed, err)
	}
	return nil
}
