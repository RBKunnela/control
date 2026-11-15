// Writes the signed pause file of version 3 the upgrade tests read. Run inside
// an export of v0.17.0: copy this file into internal/pause there and run
// `PAUSE_GOLDEN=<file> go test -run TestWritePauseGolden -count=1 ./internal/pause`.
package pause

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

func TestWritePauseGolden(t *testing.T) {
	out := os.Getenv("PAUSE_GOLDEN")
	if out == "" {
		t.Skip("PAUSE_GOLDEN names the file to write")
	}
	dave := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	keyID := policykey.KeyID(dave.Public().(ed25519.PublicKey))
	h := Header{KeyID: keyID, Tenant: "acme", Project: "orders", File: "/srv/plane/pause/pause.json", Serial: 3}
	at := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	d := Document{Entries: []Entry{
		{ID: "maintenance", Scope: Scope{Kind: ScopeGlobal}, CreatedAt: at, Reason: "upstream maintenance"},
		{ID: "refunds", Scope: Scope{Kind: ScopeAction, Provider: "payments", Action: "tool", Name: "issue_refund"}, CreatedAt: at.Add(time.Minute), Reason: "refund review"},
	}}
	s := Signer{KeyID: keyID, Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, dave)
	}}
	raw, err := signFile(h, d, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFile(raw); err != nil {
		t.Fatalf("0.17 does not read what it wrote: %v", err)
	}
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
