//go:build unix

package pause

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// golden017 is a signed pause file the v0.17.0 writer made, with the
// generator beside it.
var golden017 = filepath.Join("testdata", "upgrade-0.17", "pause.json")

// dave017 is the public key the 0.17 file is signed with.
func dave017() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
}

// header017 and entries017 are what the generator wrote, spelled out here.
var (
	header017  = Header{KeyID: policykey.KeyID(dave017()), Tenant: "acme", Project: "orders", File: "/srv/plane/pause/pause.json", Serial: 3}
	at017      = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	entries017 = []Entry{
		{ID: "maintenance", Scope: Scope{Kind: ScopeGlobal}, CreatedAt: at017, Reason: "upstream maintenance"},
		{ID: "refunds", Scope: Scope{Kind: ScopeAction, Provider: "payments", Action: "tool", Name: "issue_refund"},
			CreatedAt: at017.Add(time.Minute), Reason: "refund review"},
	}
)

// read017 is the 0.17 file as the upgrade reads it, held to what the
// generator wrote and to its signature.
func read017(t *testing.T) ([]byte, Signed) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(golden017))
	if err != nil {
		t.Fatal(err)
	}
	from, err := decodeAny(raw)
	if err != nil {
		t.Fatalf("the upgrade does not read the 0.17 file: %v", err)
	}
	if from.Body.Header != header017 || !slices.EqualFunc(from.Body.Entries, entries017, sameEntry) {
		t.Fatalf("the 0.17 file reads as %+v with %+v; want %+v with %+v", from.Body.Header, from.Body.Entries, header017, entries017)
	}
	sig := from.Envelope.Signatures[0]
	if err := bundle.VerifyBytesAs(PayloadType, from.Envelope.Payload, sig.Signature, sig.KeyID, bundle.Keyring{header017.KeyID: dave017()}); err != nil {
		t.Fatalf("the 0.17 file's signature: %v", err)
	}
	return raw, from
}

// TestAPauseFileOf017IsRefusedByAPlaneAndSignsAgainAsWritten reads bytes the
// v0.17.0 writer signed: a plane refuses them naming pause sign, and the
// upgrade reads every entry and the signature as written and signs the
// entries again as a version 4 body unchanged.
func TestAPauseFileOf017IsRefusedByAPlaneAndSignsAgainAsWritten(t *testing.T) {
	raw, from := read017(t)
	if _, err := decodeFile(raw); !errors.Is(err, ErrVersion) || !strings.Contains(err.Error(), "pause sign") {
		t.Fatalf("a plane reads the 0.17 file as %v; want ErrVersion naming pause sign", err)
	}
	next := header017
	next.PlaneID, next.Serial = "plane-a", header017.Serial+1
	body, err := MarshalSigned(next, from.Body.Document)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSigned(body)
	if err != nil || back.Header != next || !slices.EqualFunc(back.Entries, entries017, sameEntry) {
		t.Fatalf("signed again as version 4: %+v, %v; want %+v with the same entries", back.Header, err, next)
	}
}

// TestPauseSignRefusesA017FileAtAnotherPath: the 0.17 file names the path it
// was signed for, so at any other path pause sign refuses it and writes
// nothing.
func TestPauseSignRefusesA017FileAtAnotherPath(t *testing.T) {
	raw, _ := read017(t)
	p := filepath.Join(t.TempDir(), "pause.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resign(t.Context(), p, "plane-a", signer("alice")); !errors.Is(err, ErrOtherFile) {
		t.Fatalf("pause sign of the 0.17 file at %s: %v; want ErrOtherFile", p, err)
	}
	if now, err := os.ReadFile(filepath.Clean(p)); err != nil || !bytes.Equal(now, raw) {
		t.Fatalf("a refused pause sign changed the file: %v", err)
	}
}
