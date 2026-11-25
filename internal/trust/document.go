package trust

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/policykey"
)

// Envelope is a DSSE envelope's parts, the shape every signed file of this
// project has.
type Envelope = policy.StatementEnvelope

// Signature is one signature of an Envelope.
type Signature = policy.StatementSignature

// Document is a roster whose signature under the pinned root and whose body
// were checked. Only VerifyDocument and SignDocument make one.
type Document struct {
	id, digest          string
	serial              int64
	issuedAt, expiresAt time.Time
	keys                []Key
}

// ID is the roster id.
func (d Document) ID() string { return d.id }

// Serial is the roster's serial, which a floor keeps from going back.
func (d Document) Serial() int64 { return d.serial }

// Digest is sha256 over the roster's canonical body.
func (d Document) Digest() string { return d.digest }

// IssuedAt is when the root says the roster was signed.
func (d Document) IssuedAt() time.Time { return d.issuedAt }

// ExpiresAt is when the roster stops being trusted.
func (d Document) ExpiresAt() time.Time { return d.expiresAt }

// Keys is every key the roster names, in its order.
func (d Document) Keys() []Key { return slices.Clone(d.keys) }

// UsableAt refuses a roster issued after now with ErrFuture, and one at or
// after its expiry with ErrExpired.
func (d Document) UsableAt(now time.Time) error {
	switch {
	case now.Before(d.issuedAt):
		return fmt.Errorf("%w: issued %s", ErrFuture, policy.FormatIssuedAt(d.issuedAt))
	case !now.Before(d.expiresAt):
		return fmt.Errorf("%w: at %s", ErrExpired, policy.FormatIssuedAt(d.expiresAt))
	}
	return nil
}

// NamesNoneOf refuses, with ErrKeyReused, a roster that names one of others,
// the keys a plane pins for another authority, as the file kind refuses it.
func (d Document) NamesNoneOf(others ...ed25519.PublicKey) error {
	return distinct(d, nil, others)
}

func (d Document) key(id string) (Key, bool) {
	i := slices.IndexFunc(d.keys, func(k Key) bool { return k.id == id })
	if i < 0 || id == "" {
		return Key{}, false
	}
	return d.keys[i], true
}

// Key is one key of a verified roster: its id, the algorithm it alone
// verifies under, the role and subject it stands for and what it is granted,
// and the roster that named it.
type Key struct {
	id, subject  string
	alg          Alg
	role         Role
	pub          ed25519.PublicKey
	grants       []Grant
	rosterID     string
	rosterSerial int64
	rosterDigest string
	expiresAt    time.Time
}

// ID is the key's id.
func (k Key) ID() string { return k.id }

// Alg is the algorithm the key verifies under.
func (k Key) Alg() Alg { return k.alg }

// Role is the authority the key stands for.
func (k Key) Role() Role { return k.role }

// Subject is who the key belongs to.
func (k Key) Subject() string { return k.subject }

// Grants is what the key is granted, in the roster's order.
func (k Key) Grants() []Grant { return slices.Clone(k.grants) }

// RosterID is the id of the roster the key came from.
func (k Key) RosterID() string { return k.rosterID }

// RosterSerial is the serial of the roster the key came from.
func (k Key) RosterSerial() int64 { return k.rosterSerial }

// RosterDigest is the digest of the roster the key came from.
func (k Key) RosterDigest() string { return k.rosterDigest }

// ExpiresAt is when the roster that named the key expires.
func (k Key) ExpiresAt() time.Time { return k.expiresAt }

// SameKey reports whether k and other are one public key.
func (k Key) SameKey(other Key) bool {
	return len(k.pub) != 0 && policykey.SameKey(k.pub, other.pub)
}

// Verify checks sig over the pre-authentication encoding of payloadType and
// body under the key's own algorithm. A Key no roster named verifies nothing.
func (k Key) Verify(payloadType string, body, sig []byte) error {
	switch k.alg {
	case AlgEd25519:
		return bundle.VerifyBytesAs(payloadType, body, sig, k.id, bundle.Keyring{k.id: bytes.Clone(k.pub)})
	default:
		return fmt.Errorf("%w: a key no roster named", ErrKeyEntry)
	}
}

// CheckRoot refuses, with ErrRootKey, a root that is no usable Ed25519 key,
// and with ErrKeyReused one that is any of others, the keys the plane pins
// for policy, freshness, routes and lifts.
func CheckRoot(root ed25519.PublicKey, others ...ed25519.PublicKey) error {
	if len(root) != ed25519.PublicKeySize || bundle.WeakKey(root) {
		return fmt.Errorf("%w: not a usable Ed25519 public key", ErrRootKey)
	}
	for i, o := range others {
		if policykey.SameKey(root, o) {
			return fmt.Errorf("%w: the root is pinned key %d of another authority", ErrKeyReused, i)
		}
	}
	return nil
}

// VerifyDocument verifies env under root and reads its body. The checks run
// in this order, the first that fails returned: the payload type is
// PayloadType; there is one signature; the body is at most MaxBodyBytes; the
// keyid is policykey's id of root; the signature verifies over the
// pre-authentication encoding of the roster type and the body; the body is a
// roster and its own canonical form; no key it names is the root. It reads no
// clock: UsableAt judges the time.
func VerifyDocument(env Envelope, root ed25519.PublicKey) (Document, error) {
	if env.PayloadType != PayloadType {
		return Document{}, ErrPayloadType
	}
	if n := len(env.Signatures); n != 1 {
		return Document{}, fmt.Errorf("%w: %d", ErrSignatures, n)
	}
	if n := len(env.Payload); n > MaxBodyBytes {
		return Document{}, fmt.Errorf("%w: %d bytes, limit %d", ErrTooLarge, n, MaxBodyBytes)
	}
	if err := CheckRoot(root); err != nil {
		return Document{}, err
	}
	body := bytes.Clone(env.Payload)
	pinned := bytes.Clone(root)
	sig := env.Signatures[0]
	err := bundle.VerifyBytesAs(PayloadType, body, sig.Signature, sig.KeyID, bundle.Keyring{policykey.KeyID(pinned): pinned})
	switch {
	case err == nil:
	case errors.Is(err, bundle.ErrUnknownKey), errors.Is(err, bundle.ErrKeySize), errors.Is(err, bundle.ErrWeakKey):
		return Document{}, fmt.Errorf("%w: %w", ErrRootKey, err)
	default:
		return Document{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	d, err := readDocument(body)
	if err != nil {
		return Document{}, err
	}
	if err := distinct(d, pinned, nil); err != nil {
		return Document{}, err
	}
	return d, nil
}

// SignDocument signs a roster made of source, a roster body without issuedAt
// and expiresAt, issued at issuedAt and expiring validFor later, with the
// root key. It refuses what VerifyDocument would refuse, an issuedAt with a
// fraction of a second, and a validFor over MaxLifetime.
func SignDocument(source []byte, issuedAt time.Time, validFor time.Duration, root ed25519.PrivateKey) (Envelope, Document, error) {
	if issuedAt.Nanosecond() != 0 || validFor%time.Second != 0 {
		return Envelope{}, Document{}, fmt.Errorf("%w: a time or lifetime with a fraction of a second", ErrTimes)
	}
	members, err := strictjson.ReadObject(source)
	if err != nil {
		return Envelope{}, Document{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if _, ok := members["issuedAt"]; ok {
		return Envelope{}, Document{}, fmt.Errorf("%w: the source names issuedAt, which the signer sets", ErrMalformed)
	}
	if _, ok := members["expiresAt"]; ok {
		return Envelope{}, Document{}, fmt.Errorf("%w: the source names expiresAt, which the signer sets", ErrMalformed)
	}
	members["issuedAt"] = quoted(policy.FormatIssuedAt(issuedAt))
	members["expiresAt"] = quoted(policy.FormatIssuedAt(issuedAt.Add(validFor)))
	joined, err := joinObject(members)
	if err != nil {
		return Envelope{}, Document{}, err
	}
	body, err := canon.CanonicalizeJSON(joined)
	if err != nil {
		return Envelope{}, Document{}, fmt.Errorf("%w: not strict JSON", ErrMalformed)
	}
	if len(root) != ed25519.PrivateKeySize {
		return Envelope{}, Document{}, fmt.Errorf("%w: %w", ErrRootKey, bundle.ErrKeySize)
	}
	sig, err := bundle.SignBytesAs(PayloadType, body, root)
	if err != nil {
		return Envelope{}, Document{}, fmt.Errorf("%w: %w", ErrRootKey, err)
	}
	pub := bytes.Clone(root[ed25519.SeedSize:])
	env := Envelope{PayloadType: PayloadType, Payload: body, Signatures: []Signature{{KeyID: policykey.KeyID(pub), Signature: sig}}}
	d, err := VerifyDocument(env, pub)
	if err != nil {
		return Envelope{}, Document{}, err
	}
	return env, d, nil
}

// ParseFile reads a roster file as a DSSE JSON envelope of at most
// MaxFileBytes. It checks neither the payload type nor the signature.
func ParseFile(raw []byte) (Envelope, error) {
	return policykey.ParseEnvelope(raw, MaxFileBytes)
}

// MarshalFile is the roster file of env, ending in a newline, refused when
// ParseFile would not read it back.
func MarshalFile(env Envelope) ([]byte, error) {
	return policykey.MarshalEnvelope(env, MaxFileBytes)
}
