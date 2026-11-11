//go:build unix

package main

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/trust"
)

// trustFound runs doctor's trust check over tr placed apart and returns what
// it found, failing the test unless the verdict is ok.
func trustFound(t *testing.T, tr tree) string {
	t.Helper()
	placedApart(t)
	verdict, key, found := (&examination{cfg: tr.load(t)}).trust(t.Context())
	if verdict != verdictOK || key != doctorTrust {
		t.Fatalf("doctor's trust check = %s %s, %q; want ok", verdict, key, found)
	}
	return found
}

// TestDoctorNamesEveryFileTheSignedStartChecked: the trust line names the
// roster beside the configuration file and the root key, and the route, the
// stop list and the run records only where the configuration sets them.
func TestDoctorNamesEveryFileTheSignedStartChecked(t *testing.T) {
	bare := trustFound(t, signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a"))
	if want := "; the configuration file, trust.root_public_key and trust.roster are not the plane's to change, and the environment sets no key"; !strings.HasSuffix(bare, want) {
		t.Errorf("the trust line over a tree with no pause, route or runs = %q; want it to end %q", bare, want)
	}
	for _, unset := range []string{"pause.file", "reaction.route", "reaction.stops", "runs.dir"} {
		if strings.Contains(bare, unset) {
			t.Errorf("the trust line names %s, which the configuration leaves unset: %q", unset, bare)
		}
	}
	full := trustFound(t, signedStopsTree(t))
	if want := "; the configuration file, trust.root_public_key, trust.roster, reaction.route, reaction.stops and runs.dir are not the plane's to change"; !strings.Contains(full, want) {
		t.Errorf("the trust line over a tree with a route, a stop list and runs = %q; want %q", full, want)
	}
}

// TestDoctorSaysAReadGrantGrantsNothingYet: a roster holding read grants,
// one beside an operate grant of the same key, gets one clause counting
// them; a roster of operate and admin grants alone gets none.
func TestDoctorSaysAReadGrantGrantsNothingYet(t *testing.T) {
	const clause = "grant nothing yet: reading is by the health socket's peer uid and by file modes (ADR-0071)"
	tr := signedPlaneTree(t, "roster-a", nil, "roster-a")
	roster := filepath.Join(tr.dir, "trust", "roster.json")

	writeLeveledRoster(t, roster)
	if found := trustFound(t, tr); strings.Contains(found, clause) || strings.Contains(found, "read grant") {
		t.Errorf("a roster of admin and operate grants: %q names a read grant", found)
	}

	writeGrantsRoster(t, roster, map[string][]string{"alice": {"operate", "read"}, "bob": {"read"}, "dave": {"admin"}})
	found := trustFound(t, tr)
	if want := "; 2 read grant(s) " + clause; !strings.HasSuffix(found, want) {
		t.Errorf("a roster with two read grants: %q; want it to end %q", found, want)
	}
}

// writeGrantsRoster writes a roster of roster-a at serial 1 in which each
// named key holds one grant per level, each over its own project of acme.
func writeGrantsRoster(t *testing.T, path string, levels map[string][]string) {
	t.Helper()
	var keys []any
	for name, of := range levels {
		k := signedTestPublic(name)
		grants := make([]any, 0, len(of))
		for i, level := range of {
			grants = append(grants, map[string]any{"tenant": "acme", "project": "p" + string(rune('a'+i)), "level": level})
		}
		keys = append(keys, map[string]any{
			"keyId": policykey.KeyID(k), "alg": "ed25519", "role": "operator", "subject": name,
			"publicKey": policykey.FormatPublic(k), "grants": grants,
		})
	}
	now := time.Now().UTC().Truncate(time.Second)
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": 1,
		"issuedAt": now.Add(-time.Hour).Format(time.RFC3339), "expiresAt": now.Add(time.Hour).Format(time.RFC3339), "keys": keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(trust.PayloadType, body, signedTestKey("root"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := trust.MarshalFile(trust.Envelope{PayloadType: trust.PayloadType, Payload: body,
		Signatures: []trust.Signature{{KeyID: policykey.KeyID(signedTestPublic("root")), Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, raw)
}
