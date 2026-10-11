package reaction

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

const (
	// RoutePayloadType is the DSSE payload type a route is signed under. It
	// differs from every other type a key of this project signs, so a
	// signature made for one never verifies as another.
	RoutePayloadType = "application/vnd.agent-reaction-route+json"
	// LiftPayloadType is the DSSE payload type a lift is signed under.
	LiftPayloadType = "application/vnd.agent-reaction-lift+json"
	// MaxRouteFileBytes bounds a signed route file, the envelope and all. The
	// base64 of a body of MaxRouteBytes and one signature fit within it.
	MaxRouteFileBytes = 131072
)

// Envelope is a DSSE envelope's parts, the shape the freshness statement's
// file has.
type Envelope = policy.StatementEnvelope

// Signature is one signature of an Envelope.
type Signature = policy.StatementSignature

// ParseRouteFile reads a signed route file as a DSSE JSON envelope of at most
// MaxRouteFileBytes, refusing with policykey's ErrEnvelope sentinels. It
// checks neither the payload type nor the signature: VerifyRoute does.
func ParseRouteFile(raw []byte) (Envelope, error) {
	return policykey.ParseEnvelope(raw, MaxRouteFileBytes)
}

// MarshalRouteFile is the route file of env, ending in a newline, refused
// when ParseRouteFile would not read it back.
func MarshalRouteFile(env Envelope) ([]byte, error) {
	return policykey.MarshalEnvelope(env, MaxRouteFileBytes)
}

// SignRoute signs the canonical bytes of r with key under RoutePayloadType,
// with policykey's key id of the public half. It refuses a Route no reader
// made, and a key that is the route's own lift key as DistinctKeys compares.
func SignRoute(r Route, key ed25519.PrivateKey) (Envelope, error) {
	checked, err := ParseRoute(r.canonical)
	if err != nil {
		return Envelope{}, err
	}
	env, pub, err := sign(RoutePayloadType, checked.canonical, key)
	if err != nil {
		return Envelope{}, err
	}
	if policykey.SameKey(pub, checked.liftKey) {
		return Envelope{}, fmt.Errorf("%w: the route key is the route's lift key", ErrKeysEqual)
	}
	return env, nil
}

// VerifyRoute verifies env under the route key pub and reads its body. The
// checks run in this order, the first that fails returned: the payload type
// is RoutePayloadType; there is one signature; the body is at most
// MaxRouteBytes; the keyid is policykey's id of pub; the signature verifies
// over the pre-authentication encoding of the route type and the body; the
// body is a route (ParseRoute) and its own canonical form; its lift key is not
// pub as DistinctKeys compares; every rule it names may stop a run
// (CheckStopping).
func VerifyRoute(env Envelope, pub ed25519.PublicKey) (Route, error) {
	r, err := openRoute(env, pub)
	if err != nil {
		return Route{}, err
	}
	if err := CheckStopping(r); err != nil {
		return Route{}, err
	}
	return r, nil
}

// VerifyCarrySource is VerifyRoute for the route a list is carried from: its
// last check is CheckCarrySource, so it also reads a route naming a rule
// version a later one superseded. Nothing but a carry calls it.
func VerifyCarrySource(env Envelope, pub ed25519.PublicKey) (Route, error) {
	r, err := openRoute(env, pub)
	if err != nil {
		return Route{}, err
	}
	if err := CheckCarrySource(r); err != nil {
		return Route{}, err
	}
	return r, nil
}

// openRoute is VerifyRoute's checks up to the rules it names.
func openRoute(env Envelope, pub ed25519.PublicKey) (Route, error) {
	body, err := open(env, pub, envelopeRefusals{
		payloadType: RoutePayloadType, limit: MaxRouteBytes, wrongType: ErrRoutePayloadType,
		signatures: ErrRouteSignatures, tooLarge: ErrRouteTooLarge, key: ErrRouteKey, signature: ErrRouteSignature,
	})
	if err != nil {
		return Route{}, err
	}
	r, err := ParseRoute(body)
	if err != nil {
		return Route{}, err
	}
	if !bytes.Equal(body, r.canonical) {
		return Route{}, ErrRouteNotCanonical
	}
	if policykey.SameKey(pub, r.liftKey) {
		return Route{}, fmt.Errorf("%w: the route key is the route's lift key", ErrKeysEqual)
	}
	return r, nil
}

// SignLift signs the payload of l with key under LiftPayloadType, with
// policykey's key id of the public half.
func SignLift(l Lift, key ed25519.PrivateKey) (Envelope, error) {
	body, err := l.Payload()
	if err != nil {
		return Envelope{}, err
	}
	env, _, err := sign(LiftPayloadType, body, key)
	return env, err
}

// VerifyLift verifies env under the lift key pub, in VerifyRoute's order,
// and reads its body as a lift that is its own canonical form.
func VerifyLift(env Envelope, pub ed25519.PublicKey) (Lift, error) {
	body, err := open(env, pub, envelopeRefusals{
		payloadType: LiftPayloadType, limit: MaxLiftBytes, wrongType: ErrLiftPayloadType,
		signatures: ErrLiftSignatures, tooLarge: ErrLiftTooLarge, key: ErrLiftKey, signature: ErrLiftSignature,
	})
	if err != nil {
		return Lift{}, err
	}
	return readLift(body)
}

// DistinctKeys refuses, with ErrKeysEqual, any two of keys equal by bytes but
// for bit 255, and with ErrKeySize a key that is not an Ed25519 public key's
// 32 bytes. The plane holds its policy, freshness, route and lift keys to it,
// so no one key signs as two authorities.
func DistinctKeys(keys ...ed25519.PublicKey) error {
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: key %d is %d bytes", ErrKeySize, i, len(k))
		}
		for j := range i {
			if policykey.SameKey(keys[j], k) {
				return fmt.Errorf("%w: keys %d and %d", ErrKeysEqual, j, i)
			}
		}
	}
	return nil
}

func sign(payloadType string, body []byte, key ed25519.PrivateKey) (Envelope, ed25519.PublicKey, error) {
	sig, err := bundle.SignBytesAs(payloadType, body, key)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("%w: %w", ErrSigningKey, err)
	}
	// SignBytesAs took the key only once its public half was its seed's.
	pub := bytes.Clone(key[ed25519.SeedSize:])
	return Envelope{
		PayloadType: payloadType,
		Payload:     bytes.Clone(body),
		Signatures:  []Signature{{KeyID: policykey.KeyID(pub), Signature: sig}},
	}, pub, nil
}

// envelopeRefusals is what open checks a body against and how it refuses.
type envelopeRefusals struct {
	payloadType                                     string
	limit                                           int
	wrongType, signatures, tooLarge, key, signature Error
}

// open verifies env and returns the body it verified. The signature is
// checked over the fixed type, never the type the envelope names, and one
// copy of the body is verified and returned, so a write to the caller's slice
// cannot part the two.
func open(env Envelope, pub ed25519.PublicKey, r envelopeRefusals) ([]byte, error) {
	if env.PayloadType != r.payloadType {
		return nil, r.wrongType
	}
	if n := len(env.Signatures); n != 1 {
		return nil, fmt.Errorf("%w: %d", r.signatures, n)
	}
	if n := len(env.Payload); n > r.limit {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", r.tooLarge, n, r.limit)
	}
	body := bytes.Clone(env.Payload)
	pinned := bytes.Clone(pub)
	sig := env.Signatures[0]
	err := bundle.VerifyBytesAs(r.payloadType, body, sig.Signature, sig.KeyID, bundle.Keyring{policykey.KeyID(pinned): pinned})
	switch {
	case err == nil:
		return body, nil
	case errors.Is(err, bundle.ErrUnknownKey), errors.Is(err, bundle.ErrKeySize), errors.Is(err, bundle.ErrWeakKey):
		return nil, fmt.Errorf("%w: %w", r.key, err)
	default:
		return nil, fmt.Errorf("%w: %w", r.signature, err)
	}
}
