package policy_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
)

// FuzzLoad hands Load any message a receiver could decode. Load must not
// panic, must return a snapshot or exactly one of its refusals, must leave the
// message as it was, and must accept only what a model written from ADR-0011
// accepts. The seeds are the two sample bundles and every refused change.
func FuzzLoad(f *testing.F) {
	every, err := policy.Sign(sampleDocument(f, "every-field.json"), key(2), "k2")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(marshal(f, every), loadTime().UnixNano())
	f.Add(marshal(f, valid().build()), loadTime().UnixNano())
	for _, c := range changes() {
		f.Add(marshal(f, c.edit(valid()).build()), loadTime().UnixNano())
	}
	keys := pinned()
	f.Fuzz(func(t *testing.T, wire []byte, nanos int64) {
		b := &controlv1.PolicyBundle{}
		if proto.Unmarshal(wire, b) != nil {
			return
		}
		before := marshal(t, b)
		now := time.Unix(0, nanos)
		snap, err := policy.Load(b, keys, now)
		if !bytes.Equal(marshal(t, b), before) {
			t.Fatal("Load changed the message it was handed")
		}
		if err != nil {
			expectOneCheck(t, snap, err)
			return
		}
		for _, problem := range []string{wrapperProblem(b), signatureProblem(b, keys), documentProblem(b, snap, now)} {
			if problem != "" {
				t.Fatalf("Load accepted a bundle the model refuses: %s", problem)
			}
		}
	})
}

func expectOneCheck(t *testing.T, snap *policy.Snapshot, err error) {
	t.Helper()
	if snap != nil {
		t.Fatalf("a snapshot beside %v", err)
	}
	named := 0
	for _, check := range loadChecks() {
		if errors.Is(err, check) {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("%v names %d of Load's checks, want 1", err, named)
	}
	for _, other := range []error{policy.ErrSigningKey, policy.ErrObligationParams, policy.ErrRollback, policy.ErrSerialReused} {
		if errors.Is(err, other) {
			t.Fatalf("%v names %q, which Load never returns", err, other)
		}
	}
}

// wrapperProblem is the model's check of what lies outside canonical.
func wrapperProblem(b *controlv1.PolicyBundle) string {
	for _, m := range []proto.Message{b, b.GetRef(), b.GetRef().GetCreatedAt()} {
		if r := m.ProtoReflect(); r.IsValid() && len(r.GetUnknown()) > 0 {
			return "a field this build does not know"
		}
	}
	if b.GetSignatureAlg() != signatureAlg {
		return "signature_alg " + b.GetSignatureAlg()
	}
	if b.GetRef().GetCreatedAt() != nil {
		return "a creation time"
	}
	return ""
}

func signatureProblem(b *controlv1.PolicyBundle, keys bundle.Keyring) string {
	pub, ok := keys[b.GetKeyId()]
	if !ok || b.GetKeyId() == "" {
		return "key_id " + b.GetKeyId()
	}
	if !ed25519.Verify(pub, pae(b.GetCanonical()), b.GetSignature()) {
		return "a signature that does not verify over the encoding of canonical"
	}
	return ""
}

// documentProblem holds canonical, the wrapper and the snapshot to the signed
// document.
func documentProblem(b *controlv1.PolicyBundle, snap *policy.Snapshot, now time.Time) string {
	doc, canonical, err := rules.Parse(b.GetCanonical())
	if err != nil || !bytes.Equal(canonical, b.GetCanonical()) {
		return "canonical is not a document in its own canonical form"
	}
	want := &controlv1.PolicyBundleRef{BundleId: doc.Bundle.ID, Version: doc.Bundle.Version, Digest: digestOf(canonical)}
	if !proto.Equal(b.GetRef(), want) || b.GetMaxStaleSeconds() != doc.Bundle.MaxStaleSeconds {
		return "a wrapper that differs from its document"
	}
	if !proto.Equal(snap.Ref(), want) || snap.Serial() != doc.Bundle.Serial || !snap.ConfirmedAt().Equal(now) {
		return "a snapshot that does not report what was signed"
	}
	if snap.MaxStale() != time.Duration(doc.Bundle.MaxStaleSeconds)*time.Second {
		return "a snapshot whose budget is not the document's"
	}
	return ""
}

// FuzzSign signs any bytes. Sign must refuse exactly what Parse refuses, and
// what it signs must say what the document says and load, unless Compile
// refuses the document, which Load then reports as the document check.
func FuzzSign(f *testing.F) {
	f.Add(sampleDocument(f, "example.json"))
	f.Add(sampleDocument(f, "every-field.json"))
	f.Add([]byte(exampleCanonical))
	f.Add([]byte(`{}`))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := policy.Sign(raw, key(1), "k1")
		doc, canonical, parseErr := rules.Parse(raw)
		if (err == nil) != (parseErr == nil) {
			t.Fatalf("Sign says %v where Parse says %v", err, parseErr)
		}
		if err != nil {
			if b != nil {
				t.Fatal("a bundle beside a refusal")
			}
			expectOnly(t, err, policy.ErrDocument)
			return
		}
		if problem := signedProblem(b, doc, canonical); problem != "" {
			t.Fatal(problem)
		}
		snap, err := policy.Load(b, pinned(), loadTime())
		if _, compileErr := match.Compile(doc); compileErr != nil {
			expectOnly(t, err, policy.ErrDocument)
			return
		}
		if err != nil || snap.Serial() != doc.Bundle.Serial {
			t.Fatalf("Load of what Sign made: (%v, %v)", snap, err)
		}
	})
}

func signedProblem(b *controlv1.PolicyBundle, doc *rules.Document, canonical []byte) string {
	want := &controlv1.PolicyBundle{
		Ref:             &controlv1.PolicyBundleRef{BundleId: doc.Bundle.ID, Version: doc.Bundle.Version, Digest: digestOf(canonical)},
		Canonical:       canonical,
		SignatureAlg:    signatureAlg,
		Signature:       b.GetSignature(),
		KeyId:           "k1",
		MaxStaleSeconds: doc.Bundle.MaxStaleSeconds,
	}
	if !proto.Equal(b, want) {
		return "Sign's wrapper does not say what the document says"
	}
	if !ed25519.Verify(publicOf(1), pae(canonical), b.GetSignature()) {
		return "Sign's signature does not verify over the encoding of the canonical form"
	}
	return ""
}
