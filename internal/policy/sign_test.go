package policy_test

import (
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/rules"
)

// TestSignDerivesTheWrapperFromTheDocument signs both sample documents as their
// authors wrote them. Every field outside canonical comes from the document,
// canonical is the form whose digest was computed outside Go, and the
// signature is the one computed there too.
func TestSignDerivesTheWrapperFromTheDocument(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file, id, version, digest, signature string
		maxStale                             int64
	}{
		{"example.json", "payments", "2026-09-10.1", exampleDigest, exampleSignature, 300},
		{"every-field.json", "payments", "2026-09-11.1", everyFieldDigest, everyFieldSignature, 900},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			b, err := policy.Sign(sampleDocument(t, tc.file), key(1), "k1")
			if err != nil {
				t.Fatalf("Sign refused a sample document: %v", err)
			}
			if got := digestOf(b.GetCanonical()); got != tc.digest {
				t.Errorf("canonical hashes to %s, want %s", got, tc.digest)
			}
			want := &controlv1.PolicyBundle{
				Ref:             &controlv1.PolicyBundleRef{BundleId: tc.id, Version: tc.version, Digest: tc.digest},
				Canonical:       b.GetCanonical(), // held to the typed digest above
				SignatureAlg:    signatureAlg,
				Signature:       mustHex(t, tc.signature),
				KeyId:           "k1",
				MaxStaleSeconds: tc.maxStale,
			}
			if !proto.Equal(b, want) {
				t.Errorf("Sign = %v\nwant %v", b, want)
			}
		})
	}
}

// TestSignSignsTheEncodingOfTheCanonicalForm checks the example's signature
// against the typed public key over this file's own encoding, and its
// canonical bytes against the typed canonical form.
func TestSignSignsTheEncodingOfTheCanonicalForm(t *testing.T) {
	t.Parallel()
	b, err := policy.Sign([]byte(exampleRaw), key(1), "k1")
	if err != nil {
		t.Fatal(err)
	}
	if string(b.GetCanonical()) != exampleCanonical {
		t.Errorf("canonical = %s, want %s", b.GetCanonical(), exampleCanonical)
	}
	if !ed25519.Verify(mustHex(t, seed01Public), pae([]byte(exampleCanonical)), b.GetSignature()) {
		t.Error("the signature does not verify under seed 0x01's public key over the encoding of the canonical form")
	}
}

func TestSignRefuses(t *testing.T) {
	t.Parallel()
	mismatched := slices.Clone(key(1))
	copy(mismatched[ed25519.SeedSize:], publicOf(2))
	raw := []byte(exampleRaw)
	cases := []struct {
		name   string
		raw    []byte
		key    ed25519.PrivateKey
		keyID  string
		want   error
		within error
	}{
		// Load refuses an empty key_id, so a bundle signed under one could never
		// be loaded.
		{"no key id", raw, key(1), "", policy.ErrKey, bundle.ErrUnknownKey},
		{"a document the format refuses", []byte(`{"apiVersion":"agent-policy/v1alpha1"}`), key(1), "k1", policy.ErrDocument, nil},
		{"no document", nil, key(1), "k1", policy.ErrDocument, nil},
		{"a parameter its type does not declare", withParams(`{"currency":"EUR","max":"10000"}`), key(1), "k1", policy.ErrObligationParams, nil},
		{"a value its type cannot apply", withParams(`{"max":"10 000"}`), key(1), "k1", policy.ErrObligationParams, nil},
		{"a private key one byte short", raw, key(1)[:63], "k1", policy.ErrSigningKey, bundle.ErrKeySize},
		{"no private key", raw, nil, "k1", policy.ErrSigningKey, bundle.ErrKeySize},
		{"a private key whose public half is another key's", raw, mismatched, "k1", policy.ErrSigningKey, bundle.ErrKeyPair},
	}
	for _, tc := range cases {
		b, err := policy.Sign(tc.raw, tc.key, tc.keyID)
		if b != nil {
			t.Errorf("%s: a bundle beside %v", tc.name, err)
		}
		expectOnly(t, err, tc.want)
		if tc.within != nil {
			expectWithin(t, err, tc.within)
		}
		var parse *rules.Error
		if (errors.Is(tc.want, policy.ErrDocument) || errors.Is(tc.want, policy.ErrObligationParams)) && !errors.As(err, &parse) {
			t.Errorf("%s: %v does not carry the parse's own refusal", tc.name, err)
		}
	}
	if _, err := policy.Sign(raw, key(1), "k1"); err != nil {
		t.Fatalf("the accepting twin: %v", err)
	}
	for params, want := range map[string]error{
		`{"currency":"EUR","max":"10000"}`: rules.ErrObligationParam,
		`{"max":"10 000"}`:                 rules.ErrObligationValue,
	} {
		if _, err := policy.Sign(withParams(params), key(1), "k1"); !errors.Is(err, want) {
			t.Errorf("params %s: Sign = %v, want %v", params, err, want)
		}
	}
}

// withParams is the example with its obligation's params replaced.
func withParams(params string) []byte {
	return []byte(strings.Replace(exampleCanonical, `{"max":"10000"}`, params, 1))
}

// TestLoadTakesABundleSignedWithoutTheParameterCheck: the parameter check is
// Sign's, never Load's, so a bundle signed elsewhere with a parameter the
// catalogue does not declare still loads, under its own digest.
func TestLoadTakesABundleSignedWithoutTheParameterCheck(t *testing.T) {
	t.Parallel()
	doc := string(withParams(`{"currency":"EUR","max":"10000"}`))
	if _, err := policy.Sign([]byte(doc), key(1), "k1"); err == nil {
		t.Fatal("Sign accepted the parameter this test needs it to refuse")
	}
	snap := load(t, valid().withDoc(doc).build())
	if got := snap.Ref().GetDigest(); got != digestOf([]byte(doc)) {
		t.Errorf("loaded digest %s, want %s", got, digestOf([]byte(doc)))
	}
}

// TestSignSharesNothingWithItsInput hands Sign bytes that are already
// canonical, where returning them as they came would be the shortcut.
func TestSignSharesNothingWithItsInput(t *testing.T) {
	t.Parallel()
	raw := []byte(exampleCanonical)
	b, err := policy.Sign(raw, key(1), "k1")
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = ' '
	}
	if string(b.GetCanonical()) != exampleCanonical {
		t.Error("the bundle changed with the bytes Sign was handed")
	}
}

// TestSignedSamplesLoad signs under the second pinned key, so the id Sign
// writes is the one Load selects by.
func TestSignedSamplesLoad(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file     string
		serial   int64
		maxStale time.Duration
	}{
		{"example.json", 7, 5 * time.Minute},
		{"every-field.json", 12, 15 * time.Minute},
	}
	for _, tc := range cases {
		b, err := policy.Sign(sampleDocument(t, tc.file), key(2), "k2")
		if err != nil {
			t.Fatal(err)
		}
		snap := load(t, b)
		if snap.Serial() != tc.serial || snap.MaxStale() != tc.maxStale {
			t.Errorf("%s: serial %d, budget %v; want %d, %v", tc.file, snap.Serial(), snap.MaxStale(), tc.serial, tc.maxStale)
		}
	}
}
