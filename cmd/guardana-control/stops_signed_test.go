package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/trust"
)

// signedRouteDoc is stopRouteDoc as a v1alpha2 route of project orders, the
// project who's runs are opened in.
const signedRouteDoc = `{"kind":"reaction-route/v1alpha2","route_id":"refund-stops","serial":1,` +
	`"tenant_id":"acme","project_id":"orders","rules":[` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"REPEATED_DENIAL","rule_version":"2","scope":"run","expires_seconds":600},` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run"}]}`

// signedTree is a plane of tenant acme and project orders under a roster in
// which dave is admin, alice operates and bob only reads; mallory is no
// operator. Each has a key file; the route dave signed and an empty stops
// directory are beside them.
type signedTree struct {
	dir, route, stops string
	judge             []string
	keys              map[string]string
}

func signedKey(name string) ed25519.PrivateKey {
	return seeded(map[string]byte{"dave": 0x44, "alice": 0x41, "bob": 0x42, "mallory": 0x4d}[name])
}

func newSignedTree(t *testing.T) signedTree {
	t.Helper()
	dir := t.TempDir()
	tr := signedTree{dir: dir, route: filepath.Join(dir, "route.json"), stops: ownerDir(t, filepath.Join(dir, "stops")),
		keys: map[string]string{}}
	var entries []any
	for name, level := range map[string]string{"dave": "admin", "alice": "operate", "bob": "read"} {
		pub := signedKey(name).Public().(ed25519.PublicKey)
		entries = append(entries, map[string]any{
			"keyId": policykey.KeyID(pub), "alg": "ed25519", "role": "operator", "subject": name,
			"publicKey": policykey.FormatPublic(pub),
			"grants":    []any{map[string]any{"tenant": "acme", "project": "orders", "level": level}},
		})
	}
	for _, name := range []string{"dave", "alice", "bob", "mallory"} {
		keyDir := filepath.Join(dir, name)
		if err := policykey.WriteKeyPair(keyDir, signedKey(name)); err != nil {
			t.Fatal(err)
		}
		tr.keys[name] = filepath.Join(keyDir, policykey.PrivateFile)
	}
	root := seeded(0x7e)
	source, err := canon.Canonicalize(map[string]any{"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": 1, "keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := trust.SignDocument(source, time.Now().UTC().Truncate(time.Second), time.Hour, root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := trust.MarshalFile(env)
	if err != nil {
		t.Fatal(err)
	}
	roster, rootKey := filepath.Join(dir, "roster.json"), filepath.Join(dir, "root.pub")
	if err := os.WriteFile(roster, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootKey, []byte(policykey.FormatPublic(root.Public().(ed25519.PublicKey))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr.judge = []string{"--roster", roster, "--root-key", rootKey}
	tr.signRoute(t, "dave", tr.route)
	return tr
}

// signRoute has who sign signedRouteDoc into out with route sign.
func (tr signedTree) signRoute(t *testing.T, who, out string) (int, string) {
	t.Helper()
	doc := filepath.Join(tr.dir, "route-doc.json")
	if err := os.WriteFile(doc, []byte(signedRouteDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := invoke(t, "route", "sign", "--key", tr.keys[who], "--out", out, doc)
	return code, stderr
}

func (tr signedTree) run(t *testing.T, words string, args ...string) (int, string, string) {
	t.Helper()
	full := append(strings.Fields(words), "--route", tr.route)
	full = append(append(full, tr.judge...), args...)
	return invoke(t, full...)
}

// takenRoute is the tree's route as the stops commands take it, for a test
// to write a stop as react would.
func (tr signedTree) takenRoute(t *testing.T) reaction.Route {
	t.Helper()
	r, err := rosterRoute("--route", tr.route, tr.judge[1], tr.judge[3], tr.stops, nil, reaction.VerifySignedRoute)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func listBytes(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, stoplist.FileName)) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// appendRunStop appends a stop of run-1 to the tree's list.
func (tr signedTree) appendRunStop(t *testing.T) {
	t.Helper()
	r := tr.takenRoute(t)
	stop := reaction.Stop{EntryID: reaction.EntryID("f-1"), TenantID: "acme", ProjectID: "orders", Scope: reaction.ScopeRun,
		RunID: "run-1", FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: stopProcDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: time.Now().UTC().Truncate(time.Second)}
	stop.ExpiresAt = stop.CreatedAt.Add(time.Hour)
	if _, _, _, err := stopwrite.AppendFinding(context.Background(), tr.stops, r, time.Now,
		func(time.Time) (reaction.Stop, error) { return stop, nil }); err != nil {
		t.Fatal(err)
	}
}

// expectLiftsRefused lifts run-1 with each operator's key and expects each
// lift refused and the list left as it was.
func (tr signedTree) expectLiftsRefused(t *testing.T, operators ...string) {
	t.Helper()
	before := listBytes(t, tr.stops)
	for _, who := range operators {
		if code, _, stderr := tr.run(t, "stops lift", "--key", tr.keys[who], "--run", "run-1", tr.stops); code == exitOK {
			t.Fatalf("a lift %s signed: %d, %q", who, code, stderr)
		}
		if !bytes.Equal(listBytes(t, tr.stops), before) {
			t.Fatalf("a lift %s signed was written", who)
		}
	}
}

// initAtSerial3 starts the tree's list with alice's key at serial 3.
func (tr signedTree) initAtSerial3(t *testing.T) {
	t.Helper()
	code, stdout, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], "--serial", "3", tr.stops)
	if code != exitOK || !strings.Contains(stderr, "signed list header") || !strings.Contains(stderr, "serial 3") ||
		!strings.Contains(stdout, "serial: 3") {
		t.Fatalf("stops init: %d, %q, %q", code, stdout, stderr)
	}
}

func TestASignedListIsStartedListedAndLiftedThroughTheRoster(t *testing.T) {
	tr := newSignedTree(t)
	tr.initAtSerial3(t)
	tr.appendRunStop(t)
	alice := policykey.KeyID(signedKey("alice").Public().(ed25519.PublicKey))
	code, stdout, stderr := tr.run(t, "stops list", tr.stops)
	if code != exitOK || !strings.Contains(stdout, "signed by key: "+alice) || !strings.Contains(stdout, "run run-1") {
		t.Fatalf("stops list: %d, %q, %q", code, stdout, stderr)
	}

	tr.expectLiftsRefused(t, "mallory", "bob")
	code, _, stderr = tr.run(t, "stops lift", "--key", tr.keys["alice"], "--run", "run-1", tr.stops)
	if code != exitOK || !strings.Contains(stderr, "signed lift of run run-1") {
		t.Fatalf("stops lift: %d, %q", code, stderr)
	}
	if code, stdout, _ := tr.run(t, "stops list", tr.stops); code != exitOK || strings.Contains(stdout, "run run-1") ||
		!strings.Contains(stdout, "lifts: 1") {
		t.Fatalf("stops list after the lift: %d, %q", code, stdout)
	}
}

// TestASignedCommandRefusesWhatTheRosterDoesNotVouchFor: a route an
// operator without the admin grant signed, and a header signed with the
// reader's grant, are each refused before anything is signed or written.
func TestASignedCommandRefusesWhatTheRosterDoesNotVouchFor(t *testing.T) {
	tr := newSignedTree(t)
	notAdmin := tr
	notAdmin.route = filepath.Join(tr.dir, "route-alice.json")
	if code, stderr := tr.signRoute(t, "alice", notAdmin.route); code != exitOK || !strings.Contains(stderr, "signed route") {
		t.Fatalf("route sign: %d, %q", code, stderr)
	}
	if code, _, stderr := notAdmin.run(t, "stops init", "--key", tr.keys["alice"], tr.stops); code == exitOK ||
		!strings.Contains(stderr, "no operator granted") {
		t.Fatalf("stops init under a route an operator signed: %d, %q", code, stderr)
	}
	if code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["bob"], tr.stops); code == exitOK {
		t.Fatalf("stops init by a reader: %d, %q", code, stderr)
	}
	if entries, err := os.ReadDir(tr.stops); err != nil || len(entries) != 0 {
		t.Fatalf("a refused init wrote %v, %v", entries, err)
	}
}

// writeForgedHeader writes into dir a list whose header mallory, whom the
// roster does not hold, signed for the route r.
func writeForgedHeader(t *testing.T, dir string, r reaction.Route) {
	t.Helper()
	mallory := signedKey("mallory")
	malloryID := policykey.KeyID(mallory.Public().(ed25519.PublicKey))
	body, err := reaction.HeaderBody(reaction.Header{ListID: "lst-forged", RouteID: r.ID(), RouteSerial: r.Serial(), RouteDigest: r.Digest(),
		Signed: reaction.HeaderSigned{KeyID: malloryID, TenantID: "acme", ProjectID: "orders", File: r.Plane().ListFile, Serial: 1}})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := headerSigner(mallory).Sign(reaction.SignedHeaderPayloadType, body)
	if err != nil {
		t.Fatal(err)
	}
	line, err := reaction.SignedHeaderLine(reaction.Envelope{PayloadType: reaction.SignedHeaderPayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: malloryID, Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stoplist.FileName), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestASignedCommandRefusesAHeaderNoOperatorSigned: a list whose header no
// operator of the roster signed is neither listed nor lifted, and a v1alpha2
// route is not verified with a bare public key.
func TestASignedCommandRefusesAHeaderNoOperatorSigned(t *testing.T) {
	tr := newSignedTree(t)
	forged := ownerDir(t, filepath.Join(tr.dir, "forged"))
	r, err := rosterRoute("--route", tr.route, tr.judge[1], tr.judge[3], forged, nil, reaction.VerifySignedRoute)
	if err != nil {
		t.Fatal(err)
	}
	writeForgedHeader(t, forged, r)
	before := listBytes(t, forged)
	if code, _, stderr := tr.run(t, "stops list", forged); code == exitOK || !strings.Contains(stderr, "no operator granted") {
		t.Fatalf("stops list of a header mallory signed: %d, %q", code, stderr)
	}
	if code, _, _ := tr.run(t, "stops lift", "--key", tr.keys["alice"], "--run", "run-1", forged); code == exitOK ||
		!bytes.Equal(listBytes(t, forged), before) {
		t.Fatalf("stops lift on a header mallory signed: %d", code)
	}
	if code, _, _ := invoke(t, "stops", "list", "--route", tr.route, "--public-key", tr.judge[3], tr.stops); code == exitOK {
		t.Fatal("a v1alpha2 route verified with --public-key")
	}
}

// TestReactUnderASignedRouteRefusesThePlanesAccount: react needs the plane's
// approvals directory under a v1alpha2 route, and refuses to run as the
// account that owns it, before it reads a finding.
func TestReactUnderASignedRouteRefusesThePlanesAccount(t *testing.T) {
	tr := newSignedTree(t)
	if code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], tr.stops); code != exitOK {
		t.Fatalf("stops init: %d, %q", code, stderr)
	}
	approvalsDir := ownerDir(t, filepath.Join(tr.dir, "approvals"))
	plane, err := approvals.OpenPlane(approvalsDir, approvals.WithAuthority(approvals.HeldUnderSigned))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plane.Close() })
	base := []string{"react", "--findings", filepath.Join(tr.dir, "absent-findings"), "--runs", filepath.Join(tr.dir, "absent-runs"),
		"--route", tr.route}
	base = append(base, tr.judge...)
	if code, _, _ := invoke(t, append(append([]string{}, base...), "--stops", tr.stops)...); code != exitUsage {
		t.Fatalf("react with no --approvals: %d, want %d", code, exitUsage)
	}
	code, _, stderr := invoke(t, append(append([]string{}, base...), "--approvals", approvalsDir, "--stops", tr.stops)...)
	if code == exitOK || !strings.Contains(stderr, errPlaneAccount.Error()) {
		t.Fatalf("react as the plane's account: %d, %q", code, stderr)
	}
}
