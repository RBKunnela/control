package policykey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf8"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/strictjson"
)

// MaxStatementFileBytes bounds a statement file, the envelope and all. It is
// the bound a statement read from a file meets first: ADR-0038 gives the body
// and the file one bound, and the base64 body of a file within it is well
// inside policy.MaxStatementBytes.
const MaxStatementFileBytes = policy.MaxStatementBytes

// The members of the DSSE envelope and of each of its signatures, each
// required.
const (
	memberPayloadType = "payloadType"
	memberPayload     = "payload"
	memberSignatures  = "signatures"
	memberKeyID       = "keyid"
	memberSig         = "sig"
)

// ParseStatement reads a statement file's bytes as a DSSE JSON envelope and
// returns its parts, checking no signature: policy.VerifyStatement does, and
// refuses another payload type or any number of signatures but one. The file
// is at most MaxStatementFileBytes, one strict JSON object whose members and
// whose signatures' members are exactly the envelope's, none named twice, and
// payload and sig are standard base64 in the one spelling they encode back
// to.
func ParseStatement(raw []byte) (policy.StatementEnvelope, error) {
	return parseEnvelope(raw, MaxStatementFileBytes, statementRefusals())
}

// ParseEnvelope reads raw as ParseStatement does, under limit in place of
// MaxStatementFileBytes, and refuses with the ErrEnvelope sentinels. It is
// for a DSSE file of another payload type, and checks neither the type nor
// any signature.
func ParseEnvelope(raw []byte, limit int) (policy.StatementEnvelope, error) {
	return parseEnvelope(raw, limit, envelopeRefusals())
}

// ParseEnvelope's refusals, one per statement file refusal. Each text
// differs from its counterpart's, since errors.Is compares the values. None
// quotes the file.
const (
	// ErrEnvelopeFileTooLarge is a file over the bound its reader names.
	ErrEnvelopeFileTooLarge Error = "policykey: the envelope file is over its bound"
	// ErrEnvelope is a file that is not one strict JSON object of the DSSE
	// envelope's shape.
	ErrEnvelope Error = "policykey: the file is not a DSSE envelope in strict JSON"
	// ErrEnvelopeMember is an envelope or signature member DSSE does not
	// have, or one it requires and the file lacks.
	ErrEnvelopeMember Error = "policykey: the envelope holds a member DSSE does not have, or lacks one it requires"
	// ErrEnvelopeRepeated is an envelope or signature member named twice.
	ErrEnvelopeRepeated Error = "policykey: the envelope names a member twice"
	// ErrEnvelopeBase64 is a payload or sig that is not standard base64 in
	// the one spelling it encodes back to.
	ErrEnvelopeBase64 Error = "policykey: the envelope's payload or sig is not standard base64"
)

// refusals is the sentinel a reader returns for each way a file fails.
type refusals struct {
	tooLarge, envelope, member, repeated, base64 Error
}

func statementRefusals() refusals {
	return refusals{ErrStatementFileTooLarge, ErrStatementEnvelope, ErrStatementEnvelopeMember, ErrStatementEnvelopeRepeated, ErrStatementBase64}
}

func envelopeRefusals() refusals {
	return refusals{ErrEnvelopeFileTooLarge, ErrEnvelope, ErrEnvelopeMember, ErrEnvelopeRepeated, ErrEnvelopeBase64}
}

func parseEnvelope(raw []byte, limit int, r refusals) (policy.StatementEnvelope, error) {
	if n := len(raw); n > limit {
		return policy.StatementEnvelope{}, fmt.Errorf("%w: %d bytes, limit %d", r.tooLarge, n, limit)
	}
	if !utf8.Valid(raw) {
		return policy.StatementEnvelope{}, fmt.Errorf("%w: invalid UTF-8", r.envelope)
	}
	top, err := r.members(raw, memberPayloadType, memberPayload, memberSignatures)
	if err != nil {
		return policy.StatementEnvelope{}, err
	}
	var env policy.StatementEnvelope
	if env.PayloadType, err = r.text(top[memberPayloadType]); err != nil {
		return policy.StatementEnvelope{}, err
	}
	if env.Payload, err = r.base64Value(top[memberPayload]); err != nil {
		return policy.StatementEnvelope{}, err
	}
	if env.Signatures, err = r.signatures(top[memberSignatures]); err != nil {
		return policy.StatementEnvelope{}, err
	}
	// The canonical form refuses an unpaired surrogate, which the decoder
	// reads as U+FFFD without a word.
	if _, err := canon.CanonicalizeJSON(raw); err != nil {
		return policy.StatementEnvelope{}, fmt.Errorf("%w: not strict JSON", r.envelope)
	}
	return env, nil
}

// members reads raw as one JSON object holding exactly the members named,
// each value kept as the bytes it was written as.
func (r refusals) members(raw []byte, names ...string) (strictjson.Object, error) {
	o, err := strictjson.ReadObject(raw)
	switch {
	case errors.Is(err, strictjson.ErrRepeated):
		return nil, fmt.Errorf("%w: %w", r.repeated, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", r.envelope, err)
	}
	if err := o.Only(names...); err != nil {
		return nil, fmt.Errorf("%w: %w", r.member, err)
	}
	if err := o.Require(names...); err != nil {
		return nil, fmt.Errorf("%w: %w", r.member, err)
	}
	return o, nil
}

// signatures reads the array of signatures, each an object of exactly keyid
// and sig.
func (r refusals) signatures(raw json.RawMessage) ([]policy.StatementSignature, error) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, fmt.Errorf("%w: signatures is not an array", r.envelope)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%w: signatures is not an array", r.envelope)
	}
	out := make([]policy.StatementSignature, 0, len(items))
	for _, item := range items {
		sig, err := r.members(item, memberKeyID, memberSig)
		if err != nil {
			return nil, err
		}
		keyID, err := r.text(sig[memberKeyID])
		if err != nil {
			return nil, err
		}
		signature, err := r.base64Value(sig[memberSig])
		if err != nil {
			return nil, err
		}
		out = append(out, policy.StatementSignature{KeyID: keyID, Signature: signature})
	}
	return out, nil
}

// text reads raw as a JSON string and nothing else, null included.
func (r refusals) text(raw json.RawMessage) (string, error) {
	s, ok := strictjson.String(raw)
	if !ok {
		return "", fmt.Errorf("%w: a value that is not a string", r.envelope)
	}
	return s, nil
}

// base64Value reads raw as a string of standard base64. The decoder skips
// line breaks and ignores stray padding bits, so a value is taken only when
// it encodes back to itself.
func (r refusals) base64Value(raw json.RawMessage) ([]byte, error) {
	s, err := r.text(raw)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != s {
		return nil, r.base64
	}
	return decoded, nil
}

// envelopeJSON is the file's shape, members in the order DSSE lists them.
type envelopeJSON struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []signatureJSON `json:"signatures"`
}

type signatureJSON struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// MarshalStatement is the statement file of env, ending in a newline. It
// refuses a file over MaxStatementFileBytes, or one ParseStatement would not
// read back, so nothing it returns is refused by a reader for its form.
func MarshalStatement(env policy.StatementEnvelope) ([]byte, error) {
	return marshalEnvelope(env, ParseStatement)
}

// MarshalEnvelope is MarshalStatement under limit: it refuses a file
// ParseEnvelope would not read back under the same limit.
func MarshalEnvelope(env policy.StatementEnvelope, limit int) ([]byte, error) {
	return marshalEnvelope(env, func(raw []byte) (policy.StatementEnvelope, error) { return ParseEnvelope(raw, limit) })
}

func marshalEnvelope(env policy.StatementEnvelope, readBack func([]byte) (policy.StatementEnvelope, error)) ([]byte, error) {
	out := envelopeJSON{
		PayloadType: env.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(env.Payload),
		Signatures:  make([]signatureJSON, 0, len(env.Signatures)),
	}
	for _, s := range env.Signatures {
		out.Signatures = append(out.Signatures, signatureJSON{KeyID: s.KeyID, Sig: base64.StdEncoding.EncodeToString(s.Signature)})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("policykey: encoding the envelope: %w", err)
	}
	raw := buf.Bytes()
	if _, err := readBack(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// IsStatement reports whether raw is a statement file: ParseStatement reads
// it and its payload type is the statement's. It checks no signature; it
// tells a statement from another file, a key or a bundle among them.
func IsStatement(raw []byte) bool {
	env, err := ParseStatement(raw)
	return err == nil && env.PayloadType == bundle.StatementPayloadType
}

// ReadStatement reads the statement file at path, a regular file of at most
// MaxStatementFileBytes, and parses it.
func ReadStatement(path string) (policy.StatementEnvelope, error) {
	raw, err := files.ReadRegular(filepath.Clean(path), MaxStatementFileBytes, 0)
	if err != nil {
		return policy.StatementEnvelope{}, fmt.Errorf("the statement file: %w", err)
	}
	return ParseStatement(raw)
}

// ReadStatementOf is ReadStatement of the very file judged describes, as
// files.ReadRegularOf holds it.
func ReadStatementOf(path string, judged fs.FileInfo) (policy.StatementEnvelope, error) {
	raw, err := files.ReadRegularOf(filepath.Clean(path), MaxStatementFileBytes, judged)
	if err != nil {
		return policy.StatementEnvelope{}, fmt.Errorf("the statement file: %w", err)
	}
	return ParseStatement(raw)
}

// WriteStatement writes env to path with mode 0644, a statement being public,
// through a temporary file that takes the name in one step, so a reader sees
// the old file or the new. It replaces only a path that is absent or already
// a regular file holding a freshness statement, and that entry only, and
// refuses anything else there, a key, a bundle, a directory and a link among
// them, with ErrStatementOut. An envelope of another payload type is
// policy.ErrStatementPayloadType. It waits for a lock of the file another
// process holds until ctx ends, as files.ReplaceJudgedIn does.
func WriteStatement(ctx context.Context, path string, env policy.StatementEnvelope) error {
	return writeStatement(ctx, path, env, func(held fs.FileInfo) (fs.FileInfo, error) { return held, nil })
}

// WriteStatementOver is WriteStatement that replaces only the entry judged
// describes, as a read of path found it, and with a nil judged writes only
// where nothing stands at path: one put there since, a statement among
// them, is refused with files.ErrNotJudged and left as it is, and
// files.ErrNothingWritten says when nothing was written.
func WriteStatementOver(ctx context.Context, path string, env policy.StatementEnvelope, judged fs.FileInfo) error {
	return writeStatement(ctx, path, env, func(held fs.FileInfo) (fs.FileInfo, error) {
		if (held == nil) != (judged == nil) || held != nil && !files.SameEntry(held, judged) {
			return nil, fmt.Errorf("%s: %w: %w", filepath.Base(path), files.ErrNotJudged, files.ErrNothingWritten)
		}
		return judged, nil
	})
}

// writeStatement writes env to path over the entry over returns, given the
// entry checkStatementOut judged there.
func writeStatement(ctx context.Context, path string, env policy.StatementEnvelope, over func(held fs.FileInfo) (fs.FileInfo, error)) error {
	if env.PayloadType != bundle.StatementPayloadType {
		return policy.ErrStatementPayloadType
	}
	raw, err := MarshalStatement(env)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	held, err := checkStatementOut(root, name)
	if err == nil {
		held, err = over(held)
	}
	if err == nil {
		beforeStatementReplaced()
		err = files.ReplaceJudgedIn(ctx, root, name, raw, 0o644, held)
	}
	return errors.Join(err, root.Close())
}

// beforeStatementReplaced runs, in a test, once the entry at the name was
// judged and before the statement takes its place.
var beforeStatementReplaced = func() {}

// checkStatementOut refuses a name in root that holds anything but a
// statement, and returns the entry it judged, nil where none stands. It
// judges through the handle the replace goes through, so a directory swapped
// in after the judgement receives nothing; the file judged is the one
// opened, which neither follows a link nor waits on a pipe, and the replace
// takes that entry's place only.
func checkStatementOut(root *os.Root, name string) (fs.FileInfo, error) {
	info, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s: %w", name, ErrStatementOut)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	held, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !held.Mode().IsRegular() || !os.SameFile(info, held) {
		return nil, fmt.Errorf("%s: %w: it changed while it was judged", name, ErrStatementOut)
	}
	existing, err := io.ReadAll(io.LimitReader(f, MaxStatementFileBytes+1))
	if err != nil {
		return nil, err
	}
	if !IsStatement(existing) {
		return nil, fmt.Errorf("%s: %w", name, ErrStatementOut)
	}
	return info, nil
}
