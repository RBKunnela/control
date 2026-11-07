package pause

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/guardana/control/internal/policy"
)

// The members of a signed file's DSSE envelope and of its one signature,
// each required, as every DSSE file of this module spells them. The
// envelope is parsed here rather than by the key package, which reads keys
// and is linked by no pause reader.
var (
	envelopeMembers  = []string{"payloadType", "payload", "signatures"}
	signatureMembers = []string{"keyid", "sig"}
)

type envelopeJSON struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []signatureJSON `json:"signatures"`
}

type signatureJSON struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// parseEnvelope reads raw as one strict DSSE JSON envelope: each member of
// the envelope and of every signature named once and none other, payload and
// sig standard base64 in the one spelling they encode back to. It checks no
// signature.
func parseEnvelope(raw []byte) (policy.StatementEnvelope, error) {
	top, err := members(raw, true)
	if err != nil {
		return policy.StatementEnvelope{}, err
	}
	if err := exactly(top, envelopeMembers); err != nil {
		return policy.StatementEnvelope{}, err
	}
	var env policy.StatementEnvelope
	if env.PayloadType, err = member(top, "payloadType", str); err != nil {
		return policy.StatementEnvelope{}, err
	}
	if env.Payload, err = member(top, "payload", base64Text); err != nil {
		return policy.StatementEnvelope{}, err
	}
	sigs, err := member(top, "signatures", array)
	if err != nil {
		return policy.StatementEnvelope{}, err
	}
	for i, item := range sigs {
		m, err := members(item, false)
		if err != nil {
			return policy.StatementEnvelope{}, fmt.Errorf("signatures.%d: %w", i, err)
		}
		if err := exactly(m, signatureMembers); err != nil {
			return policy.StatementEnvelope{}, fmt.Errorf("signatures.%d: %w", i, err)
		}
		var s policy.StatementSignature
		if s.KeyID, err = member(m, "keyid", str); err != nil {
			return policy.StatementEnvelope{}, fmt.Errorf("signatures.%d: %w", i, err)
		}
		if s.Signature, err = member(m, "sig", base64Text); err != nil {
			return policy.StatementEnvelope{}, fmt.Errorf("signatures.%d: %w", i, err)
		}
		env.Signatures = append(env.Signatures, s)
	}
	return env, nil
}

// exactly refuses an object missing one of names or holding another.
func exactly(m map[string]json.RawMessage, names []string) error {
	if err := only(m, names...); err != nil {
		return err
	}
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return fmt.Errorf("no member %q", name)
		}
	}
	return nil
}

// base64Text reads a JSON string of standard base64 spelled the one way it
// encodes back to.
func base64Text(raw json.RawMessage) ([]byte, error) {
	s, err := str(raw)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("not standard base64")
	}
	return b, nil
}

// marshalEnvelope is the file of env, ending in a newline, refused where
// parseEnvelope would not read it back as env.
func marshalEnvelope(env policy.StatementEnvelope) ([]byte, error) {
	out := envelopeJSON{PayloadType: env.PayloadType, Payload: base64.StdEncoding.EncodeToString(env.Payload)}
	for _, s := range env.Signatures {
		out.Signatures = append(out.Signatures, signatureJSON{KeyID: s.KeyID, Sig: base64.StdEncoding.EncodeToString(s.Signature)})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	back, err := parseEnvelope(buf.Bytes())
	if err != nil || back.PayloadType != env.PayloadType || !bytes.Equal(back.Payload, env.Payload) || len(back.Signatures) != len(env.Signatures) {
		return nil, malformed("the envelope does not read back as itself")
	}
	return buf.Bytes(), nil
}
