//go:build unix

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

func signedTestKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("gateway-start/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signedTestPublic(name string) ed25519.PublicKey {
	return signedTestKey(name).Public().(ed25519.PublicKey)
}

// signedPlaneTree is a tree configured, in its file alone, for the signed
// authority over a roster of rosterFileID taking roster-a, with a floor that
// lists floorIDs and an operator for each of keys.
func signedPlaneTree(t *testing.T, rosterFileID string, operatorKeys []ed25519.PublicKey, floorIDs ...string) tree {
	t.Helper()
	tr := newTree(t)
	for _, dir := range []string{recordsDir, holdsDir, "inbox", "trust"} {
		if err := os.MkdirAll(filepath.Join(tr.dir, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range floorIDs {
		if err := policystate.InitAuthority(t.Context(), filepath.Join(tr.dir, "trust", "floors"), id); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(tr.dir, "trust", "root.pub"), []byte(policykey.FormatPublic(signedTestPublic("root"))+"\n"))
	writeSignedRoster(t, filepath.Join(tr.dir, "trust", "roster.json"), rosterFileID, operatorKeys)
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	signed := strings.Replace(string(raw), "approvals:\n  authority: memory\n", `approvals:
  authority: signed
  dir: `+recordsDir+`
  hold_journal_dir: `+holdsDir+`
  inbox_dir: inbox
trust:
  root_public_key: trust/root.pub
  roster: trust/roster.json
  roster_id: roster-a
  floor_dir: trust/floors
operators:
  authenticator:
    kind: roster
  authorizer:
    kind: roster
`, 1)
	if signed == string(raw) {
		t.Fatal("the fixture configuration names no memory authority to replace")
	}
	writeTestFile(t, tr.config, []byte(signed))
	return tr
}

func writeTestFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil { //nolint:gosec // G703: a file under the test's temp dir
		t.Fatal(err)
	}
}

func writeSignedRoster(t *testing.T, path, id string, operatorKeys []ed25519.PublicKey) {
	t.Helper()
	keys := make([]any, 0, len(operatorKeys))
	for i, k := range operatorKeys {
		keys = append(keys, map[string]any{
			"keyId": policykey.KeyID(k), "alg": "ed25519", "role": "operator", "subject": "operator-" + string(rune('a'+i)),
			"publicKey": policykey.FormatPublic(k), "grants": []any{map[string]any{"tenant": "acme", "project": "orders", "level": "operate"}},
		})
	}
	now := time.Now().UTC().Truncate(time.Second)
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": id, "serial": 1,
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

// placedApart stands in for a machine where the plane's account owns
// nothing on the paths it judges, except the paths writable names.
func placedApart(t *testing.T, writable ...string) {
	t.Helper()
	saved := notPlaneWritable
	notPlaneWritable = func(path string) error {
		for _, w := range writable {
			if strings.HasSuffix(path, w) {
				return errors.New("the plane's account may write it")
			}
		}
		return nil
	}
	t.Cleanup(func() { notPlaneWritable = saved })
}

func buildSigned(t *testing.T, tr tree) (*plane, error) {
	t.Helper()
	p, err := build(tr.load(t), slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
	if err == nil {
		t.Cleanup(func() { _ = p.close() })
	}
	return p, err
}

// TestASignedStartRefusesWhatThePlanesAccountCouldTurn: the configuration
// file or the root key file the plane's account may change, and any key the
// environment sets, refuse the start; a tree with none of them starts, its
// authority usable and its roster taken.
func TestASignedStartRefusesWhatThePlanesAccountCouldTurn(t *testing.T) {
	alice := signedTestPublic("alice")
	for name, c := range map[string]struct {
		arrange func(t *testing.T)
		names   string
	}{
		"a plane-writable configuration file, as this test's own temp dir is": {func(*testing.T) {}, "the configuration file"},
		"a plane-writable root key file":                                      {func(t *testing.T) { placedApart(t, "root.pub") }, "trust.root_public_key"},
		"a key the environment sets": {func(t *testing.T) {
			placedApart(t)
			setEnv(t, "approvals.ttl", "5m")
		}, "approvals.ttl"},
	} {
		t.Run(name, func(t *testing.T) {
			tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{alice}, "roster-a")
			c.arrange(t)
			if _, err := buildSigned(t, tr); err == nil || !strings.Contains(err.Error(), c.names) {
				t.Fatalf("build = %v, want %s refused", err, c.names)
			}
		})
	}
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{alice}, "roster-a")
	placedApart(t)
	p, err := buildSigned(t, tr)
	if err != nil {
		t.Fatalf("a tree placed apart was refused: %v", err)
	}
	if got := p.trustHealth(context.Background()); got["state"] != "usable" || got["roster_id"] != "roster-a" {
		t.Errorf("trust = %v; want roster-a usable", got)
	}
	writeTestFile(t, filepath.Join(tr.dir, "inbox", "notes.txt"), []byte("x"))
	if got := p.authorityHealth(context.Background(), nil); got["kind"] != "signed" || got["state"] != "usable" || got["limits"] != nil || got["inbox_entries"] != 1 || got["inbox_full"] != false {
		t.Errorf("approvals.authority = %v; want signed, usable, no claim limit and the inbox's one name", got)
	}
}

// TestARestartOverAFloorListingTwoIdsTakesOnlyTheConfiguredRoster: a floor
// listing roster-a and roster-b, and a roster file of roster-b, give no
// roster at all to a plane configured for roster-a, which says other_roster;
// the same floor with a roster of roster-a gives it its roster.
func TestARestartOverAFloorListingTwoIdsTakesOnlyTheConfiguredRoster(t *testing.T) {
	for file, want := range map[string]string{"roster-b": "unavailable", "roster-a": "usable"} {
		tr := signedPlaneTree(t, file, []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a", "roster-b")
		placedApart(t)
		p, err := buildSigned(t, tr)
		if err != nil {
			t.Fatal(err)
		}
		got := p.trustHealth(context.Background())
		if got["state"] != want {
			t.Errorf("a roster of %s: trust = %v; want %s", file, got, want)
		}
		if file == "roster-b" && got["last"] != string(trust.CauseOtherRoster) {
			t.Errorf("a roster of roster-b: the last cause is %v, want other_roster", got["last"])
		}
		for _, port := range []string{"authenticator", "authorizer"} {
			if state := p.operatorsHealth(context.Background())[port].(map[string]any)["state"]; state != want {
				t.Errorf("a roster of %s: operators.%s is %v, want %s", file, port, state, want)
			}
		}
	}
}

// TestEveryPinnedKeyIsOneNoRosterMayName: a roster naming the plane's policy
// key as an operator's is refused whole, because the plane hands it every key
// it pins; the same roster without that entry is taken.
func TestEveryPinnedKeyIsOneNoRosterMayName(t *testing.T) {
	policyKey := fixtureKey().Public().(ed25519.PublicKey)
	for name, keys := range map[string][]ed25519.PublicKey{
		"with the policy key":    {signedTestPublic("alice"), policyKey},
		"without the policy key": {signedTestPublic("alice")},
	} {
		tr := signedPlaneTree(t, "roster-a", keys, "roster-a")
		placedApart(t)
		p, err := buildSigned(t, tr)
		if err != nil {
			t.Fatal(err)
		}
		got := p.trustHealth(context.Background())
		refused := got["last"] == string(trust.CauseRefused) && got["state"] == "unavailable"
		if refused != (name == "with the policy key") {
			t.Errorf("%s: trust = %v", name, got)
		}
	}
}

// TestThePinnedKeyRegistryNamesEveryKeyTheConfigurationPins: every key of
// the configuration that holds a public key, the trust root's aside, is one
// the plane hands the roster as a key no roster may name, and so is a
// route's lift key. A key the configuration gains fails this until it is
// added to pinnedKeys.
func TestThePinnedKeyRegistryNamesEveryKeyTheConfigurationPins(t *testing.T) {
	registered := map[string]bool{}
	for _, k := range pinnedKeys {
		registered[k.name] = true
	}
	found := 0
	for _, f := range gatewayconfig.Fields() {
		if !strings.HasSuffix(f.Path, "public_key") || f.Path == "trust.root_public_key" {
			continue
		}
		found++
		if !registered[f.Path] {
			t.Errorf("%s pins a key and pinnedKeys does not hand it to the roster", f.Path)
		}
	}
	if found != 3 || !registered["the route's lift_public_key"] || len(pinnedKeys) != found+1 {
		t.Errorf("the configuration pins %d key(s) and the registry holds %d; want the policy, freshness and route keys and the lift key", found, len(pinnedKeys))
	}
	if operators.AuthenticatorRoster != "roster" || operators.AuthorizerRoster != "roster" {
		t.Errorf("the configuration's operator kind is no longer the operators package's")
	}
}

// TestTheRostersFirstReadIsHeldToATimeout: a floor directory whose lock
// another holder keeps would hold trust.Open's first read for as long as its
// context lasts; the start gives up within the timeout and serves with the
// roster unavailable.
func TestTheRostersFirstReadIsHeldToATimeout(t *testing.T) {
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	placedApart(t)
	f, err := os.Open(filepath.Join(tr.dir, "trust", "floors"))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	saved := trustOpenTimeout
	trustOpenTimeout = 100 * time.Millisecond
	t.Cleanup(func() { trustOpenTimeout = saved })
	done := make(chan *plane, 1)
	go func() {
		p, err := build(tr.load(t), slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
		if err != nil {
			t.Errorf("build: %v", err)
		}
		done <- p
	}()
	select {
	case p := <-done:
		if p != nil {
			t.Cleanup(func() { _ = p.close() })
		}
	case <-time.After(10 * time.Second):
		_ = f.Close()
		t.Fatal("the start waited on the floor's lock past its timeout")
	}
}
