//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// golden017 is a signed plane as v0.17.0 wrote it (testdata/upgrade-0.17):
// dave's v1alpha2 route and alice's 2.0 list at serial 4 with stops of run-1
// and run-2, a covered line of run-1 and alice's lift of run-2, each naming
// the plane's files at /srv/plane, and the floors that plane kept; no pause
// file. It is judged and carried here through the library, not the commands.
const golden017 = "testdata/upgrade-0.17"

// The golden's files as its documents name them, and the time it was written.
const (
	goldenRouteFile = "/srv/plane/route.json"
	goldenListFile  = "/srv/plane/stops/" + stoplist.FileName
)

var goldenNow = time.Date(2026, 11, 1, 10, 10, 0, 0, time.UTC)

// copyGolden copies the golden's directory name into dir as name-017, keeping its files
// private as a plane's are.
func copyGolden(t *testing.T, name, dir string) string {
	t.Helper()
	to := filepath.Join(dir, name+"-017")
	if err := os.Mkdir(to, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(golden017, name))
	noErr(t, err)
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(golden017, name, e.Name())) //nolint:gosec // G304: the test's own golden
		noErr(t, err)
		if err := os.WriteFile(filepath.Join(to, e.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

func goldenBytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(golden017, name)) //nolint:gosec // G304: the test's own golden
	noErr(t, err)
	return raw
}

// signRouteDoc has dave sign doc into out with route sign.
func (tr signedTree) signRouteDoc(t *testing.T, doc, out string) (int, string) {
	t.Helper()
	path := filepath.Join(tr.dir, filepath.Base(out)+".doc")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := invoke(t, "route", "sign", "--key", tr.keys["dave"], "--out", out, path)
	return code, stderr
}

// routeDocAt is the golden's route as a v1alpha3 document of plane at serial.
func routeDocAt(plane, serial string) string {
	return strings.NewReplacer(`"plane_id":"plane-a"`, `"plane_id":"`+plane+`"`, `"serial":1,`, `"serial":`+serial+`,`).Replace(signedRouteDoc)
}

// TestA017SignedPlaneIsRefusedUntilItsRouteAndListAreCarried: every command
// a plane serves from refuses the golden's route and list, naming the command
// that upgrades it; route sign refuses a v1alpha2 document. A v1alpha3 route
// at the next serial and a carry of the golden's list into a 3.0 list at the
// next serial, chained to the old head, are taken: the carried run is
// stopped, the lifted run clear, and the stop list floor moves to the new
// head. The old list put back, a header with another previous, another
// plane's route and the old route copied back are each refused.
func TestA017SignedPlaneIsRefusedUntilItsRouteAndListAreCarried(t *testing.T) {
	tr := newSignedTree(t)
	oldRoute := filepath.Join(tr.dir, "route-017.json")
	noErr(t, os.WriteFile(oldRoute, goldenBytes(t, "route.json"), 0o600))
	oldStops := copyGolden(t, "stops", tr.dir)
	oldList := listBytes(t, oldStops)
	expectCommandsRefuse017(t, tr, oldRoute, oldStops)
	from := goldenCarrySource(t, tr)

	newRoute := filepath.Join(tr.dir, "route-018.json")
	if code, stderr := tr.signRouteDoc(t, routeDocAt("plane-a", "2"), newRoute); code != exitOK {
		t.Fatalf("route sign of the v1alpha3 route at serial 2: %d, %q", code, stderr)
	}
	newStops := ownerDir(t, filepath.Join(tr.dir, "stops-018"))
	route, err := rosterRoute("--route", newRoute, tr.judge[1], tr.judge[3], newStops, "", nil, reaction.VerifySignedRoute)
	noErr(t, err)
	if route.ID() != from.ID() || route.Serial() != from.Serial()+1 || route.PlaneID() != "plane-a" {
		t.Fatalf("the new route: %s serial %d plane %s", route.ID(), route.Serial(), route.PlaneID())
	}
	routeFloor := copyGolden(t, "routefloor", tr.dir)
	if raised, err := policystate.RaiseRoute(t.Context(), routeFloor, route.ID(), route.Serial(), route.Digest()); err != nil || raised.Serial != 2 {
		t.Fatalf("the 0.17 route floor raised to the new route: %+v, %v", raised, err)
	}
	if _, err := reaction.Judge(route, reaction.Prefix{}, oldList, goldenNow, 0); !errors.Is(err, reaction.ErrListUpgrade) {
		t.Fatalf("the 0.17 list under the new route: %v, want %v", err, reaction.ErrListUpgrade)
	}
	raised := expectGoldenCarried(t, tr, oldStops, from, route, newStops)
	if code, _, stderr := invoke(t, append(append([]string{"stops", "list", "--route", newRoute}, tr.judge...), newStops)...); code != exitOK {
		t.Fatalf("stops list of the carried list: %d, %q", code, stderr)
	}
	expectCarriedPlaneHeld(t, tr, route, raised, oldList, newRoute, newStops)
}

// expectCommandsRefuse017: stops list, stops lift and react refuse the
// golden's route at oldRoute, naming route sign, and change nothing in
// oldStops; route sign refuses a v1alpha2 document, naming the kind and the
// member that replace it.
func expectCommandsRefuse017(t *testing.T, tr signedTree, oldRoute, oldStops string) {
	t.Helper()
	oldList := listBytes(t, oldStops)
	judge := append([]string{"--route", oldRoute}, tr.judge...)
	held := reactPlaneAccount
	reactPlaneAccount = func(string) error { return nil }
	t.Cleanup(func() { reactPlaneAccount = held })
	for _, c := range []struct {
		name string
		args []string
	}{
		{"stops list", append(append([]string{"stops", "list"}, judge...), oldStops)},
		{"stops lift", append(append([]string{"stops", "lift", "--key", tr.keys["alice"], "--run", "run-1"}, judge...), oldStops)},
		{"react", append([]string{"react", "--findings", filepath.Join(tr.dir, "findings"), "--runs", filepath.Join(tr.dir, "runs"),
			"--approvals", filepath.Join(tr.dir, "approvals"), "--stops", oldStops}, judge...)},
	} {
		if code, _, stderr := invoke(t, c.args...); code == exitOK || !strings.Contains(stderr, "route sign") {
			t.Errorf("%s under the 0.17 route: %d, %q; want a refusal naming route sign", c.name, code, stderr)
		}
	}
	if !bytes.Equal(listBytes(t, oldStops), oldList) {
		t.Fatal("a refused command changed the 0.17 list")
	}
	v2Doc := strings.Replace(signedRouteDoc, `"kind":"reaction-route/v1alpha3","plane_id":"plane-a",`, `"kind":"reaction-route/v1alpha2",`, 1)
	if code, stderr := tr.signRouteDoc(t, v2Doc, filepath.Join(tr.dir, "v2.json")); code == exitOK ||
		!strings.Contains(stderr, reaction.SignedRouteKindV3) || !strings.Contains(stderr, "plane_id") {
		t.Fatalf("route sign of a v1alpha2 document: %d, %q", code, stderr)
	}
}

// goldenCarrySource is the golden's route as a carry takes it, for the
// plane its documents name; the plane itself refuses it.
func goldenCarrySource(t *testing.T, tr signedTree) reaction.Route {
	t.Helper()
	doc, err := readRoster(tr.judge[1], tr.judge[3], nil)
	noErr(t, err)
	goldenPlane := reaction.Plane{ID: "plane-a", Tenant: "acme", Project: "orders", RouteFile: goldenRouteFile, ListFile: goldenListFile}
	oldVoucher, err := signedstops.NewRoster(doc, goldenPlane)
	noErr(t, err)
	env, err := reaction.ParseRouteFile(goldenBytes(t, "route.json"))
	noErr(t, err)
	if _, err := reaction.VerifySignedRoute(env, oldVoucher); !errors.Is(err, reaction.ErrRouteUpgrade) {
		t.Fatalf("the plane over the 0.17 route: %v, want %v", err, reaction.ErrRouteUpgrade)
	}
	from, err := reaction.VerifySignedCarrySource(env, oldVoucher)
	noErr(t, err)
	return from
}

// expectGoldenCarried carries the golden's list into newStops under route,
// held to the golden's stop list floor, and expects a 3.0 header at serial 5
// naming the old head, run-1 stopped and run-2 clear, and the floor raised to
// the carried head, which it returns.
func expectGoldenCarried(t *testing.T, tr signedTree, oldStops string, from, route reaction.Route, newStops string) policystate.StopsFloor {
	t.Helper()
	floorDir := copyGolden(t, "stopsfloor", tr.dir)
	stored, err := policystate.ReadStops(floorDir, "acme", "orders")
	if err != nil || stored.Serial != 4 {
		t.Fatalf("the 0.17 stop list floor: %+v, %v", stored, err)
	}
	hold := func(l reaction.List, content []byte) error { return signedstops.Hold(stored, l, content) }
	c, err := stopwrite.CarrySigned(context.Background(), oldStops, from, newStops, route, goldenNow, headerSigner(signedKey("alice")), hold)
	noErr(t, err)
	type carriedAs struct {
		serial          int64
		previous, plane string
		stops, covered  int
	}
	want := carriedAs{5, stored.Digest, "plane-a", 1, 2}
	if got := (carriedAs{c.Header.Signed.Serial, c.Header.Signed.Previous, c.Header.Signed.PlaneID, c.Stops, c.Covered}); got != want {
		t.Fatalf("carried %+v, want %+v", got, want)
	}
	carried := listBytes(t, newStops)
	l, err := reaction.Judge(route, reaction.Prefix{}, carried, goldenNow, 0)
	noErr(t, err)
	expectRun1Alone(t, l, goldenNow)
	floor, err := signedstops.NewFloor(floorDir, "acme", "orders")
	noErr(t, err)
	raised, err := floor.Take(t.Context(), l, carried)
	if err != nil || raised.Serial != 5 || raised.Digest != c.Header.Signed.Digest {
		t.Fatalf("the stop list floor over the carried list: %+v, %v; want serial 5 at %s", raised, err, c.Header.Signed.Digest)
	}
	return raised
}

// expectCarriedPlaneHeld: once the floor holds the carried head, the 0.17
// list put back, a 3.0 header naming another previous, another plane's
// v1alpha3 route of the same tenant, project and file and the 0.17 route
// copied back are each refused.
func expectCarriedPlaneHeld(t *testing.T, tr signedTree, route reaction.Route, raised policystate.StopsFloor, oldList []byte, newRoute, newStops string) {
	t.Helper()
	old, err := reaction.ParseLine(bytes.SplitN(oldList, []byte{'\n'}, 2)[0])
	noErr(t, err)
	if err := signedstops.Check(raised, old.Header.Signed); !errors.Is(err, stoplist.ErrBelowFloor) {
		t.Errorf("the 0.17 head against the raised floor: %v, want %v", err, stoplist.ErrBelowFloor)
	}

	body, err := reaction.HeaderBody(reaction.Header{ListID: "lst-forked", RouteID: route.ID(), RouteSerial: route.Serial(), RouteDigest: route.Digest(),
		Signed: reaction.HeaderSigned{KeyID: headerSigner(signedKey("alice")).KeyID, PlaneID: "plane-a", TenantID: "acme", ProjectID: "orders",
			File: route.Plane().ListFile, Serial: raised.Serial + 1, Previous: bundle.Digest([]byte("another head"))}})
	noErr(t, err)
	sig, err := headerSigner(signedKey("alice")).Sign(reaction.SignedHeaderPayloadType, body)
	noErr(t, err)
	line, err := reaction.SignedHeaderLine(reaction.Envelope{PayloadType: reaction.SignedHeaderPayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: headerSigner(signedKey("alice")).KeyID, Signature: sig}}})
	noErr(t, err)
	forked := append(line, '\n')
	l, err := reaction.Judge(route, reaction.Prefix{}, forked, goldenNow, 0)
	if err != nil {
		t.Fatalf("a header naming another previous, as the judge reads it: %v", err)
	}
	if err := signedstops.Hold(raised, l, forked); !errors.Is(err, stoplist.ErrChain) {
		t.Errorf("a header naming another previous against the floor: %v, want %v", err, stoplist.ErrChain)
	}

	doc, err := readRoster(tr.judge[1], tr.judge[3], nil)
	noErr(t, err)
	v, err := signedstops.NewRoster(doc, route.Plane())
	noErr(t, err)
	other := filepath.Join(tr.dir, "route-b.json")
	if code, stderr := tr.signRouteDoc(t, routeDocAt("plane-b", "3"), other); code != exitOK {
		t.Fatalf("route sign of plane-b's route: %d, %q", code, stderr)
	}
	if err := os.Rename(other, newRoute); err != nil {
		t.Fatal(err)
	}
	if _, err := reaction.VerifySignedRoute(routeEnvelopeAt(t, newRoute), v); !errors.Is(err, reaction.ErrOtherPlane) {
		t.Errorf("plane-b's route at plane-a's route file: %v, want %v", err, reaction.ErrOtherPlane)
	}
	if code, _, stderr := invoke(t, append(append([]string{"stops", "list", "--route", newRoute}, tr.judge...), newStops)...); code == exitOK {
		t.Errorf("stops list of plane-a's list under plane-b's route: %d, %q", code, stderr)
	}

	if err := os.WriteFile(newRoute, goldenBytes(t, "route.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reaction.VerifySignedRoute(routeEnvelopeAt(t, newRoute), v); !errors.Is(err, reaction.ErrRouteUpgrade) {
		t.Errorf("the 0.17 route copied back: %v, want %v", err, reaction.ErrRouteUpgrade)
	}
	if code, _, stderr := invoke(t, append(append([]string{"stops", "list", "--route", newRoute}, tr.judge...), newStops)...); code == exitOK ||
		!strings.Contains(stderr, "route sign") {
		t.Errorf("stops list under the 0.17 route copied back: %d, %q", code, stderr)
	}
}

func routeEnvelopeAt(t *testing.T, path string) reaction.Envelope {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	noErr(t, err)
	env, err := reaction.ParseRouteFile(raw)
	noErr(t, err)
	return env
}

// writeV2Plane writes into dir, with this build's writers, the documents a
// 0.17 operator signed for the files there: dave's v1alpha2 route at
// route.json and alice's 2.0 list in stops at serial 3 with a stop of run-1;
// it returns the list's head. What 0.17 itself wrote is golden017.
func writeV2Plane(t *testing.T, dir string) string {
	t.Helper()
	routePath, stops := filepath.Join(dir, "route.json"), ownerDir(t, filepath.Join(dir, "stops"))
	routeFile, err := signedstops.BindingOf(routePath)
	noErr(t, err)
	raw, err := json.Marshal(map[string]any{
		"kind": reaction.SignedRouteKind, "alg": "ed25519", "keyId": headerSigner(signedKey("dave")).KeyID, "route_id": "refund-stops",
		"serial": 1, "tenant_id": "acme", "project_id": "orders", "file": routeFile,
		"rules": []any{map[string]any{"procedure_id": "refund", "version": "1", "digest": stopProcDigest,
			"rule_id": "STEP_OUTSIDE_PROCEDURE", "rule_version": "1", "scope": "run", "expires_seconds": 3600}},
	})
	noErr(t, err)
	body, err := canon.CanonicalizeJSON(raw)
	noErr(t, err)
	route, err := reaction.ParseRoute(body)
	noErr(t, err)
	file, err := reaction.MarshalRouteFile(operatorEnvelope(t, "dave", reaction.SignedRoutePayloadType, body))
	noErr(t, err)
	if err := os.WriteFile(routePath, file, 0o600); err != nil {
		t.Fatal(err)
	}
	listFile, err := signedstops.BindingOf(filepath.Join(stops, stoplist.FileName))
	noErr(t, err)
	header, err := reaction.HeaderBody(reaction.Header{ListID: "lst-017", RouteID: route.ID(), RouteSerial: route.Serial(), RouteDigest: route.Digest(),
		Signed: reaction.HeaderSigned{KeyID: headerSigner(signedKey("alice")).KeyID, TenantID: "acme", ProjectID: "orders", File: listFile, Serial: 3}})
	noErr(t, err)
	headerLine, err := reaction.SignedHeaderLine(operatorEnvelope(t, "alice", reaction.SignedHeaderPayloadType, header))
	noErr(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	stop, err := reaction.Stop{EntryID: reaction.EntryID("f-1"), TenantID: "acme", ProjectID: "orders", Scope: reaction.ScopeRun,
		RunID: "run-1", FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: stopProcDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}.Marshal()
	noErr(t, err)
	if err := os.WriteFile(filepath.Join(stops, stoplist.FileName), append(append(append(headerLine, '\n'), stop...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundle.Digest(header)
}

func operatorEnvelope(t *testing.T, who, payloadType string, body []byte) reaction.Envelope {
	t.Helper()
	s := headerSigner(signedKey(who))
	sig, err := s.Sign(payloadType, body)
	noErr(t, err)
	return reaction.Envelope{PayloadType: payloadType, Payload: body, Signatures: []reaction.Signature{{KeyID: s.KeyID, Signature: sig}}}
}

// TestStopsInitCarriesA017ListIntoA30One: stops init refuses a new list under
// a v1alpha2 route, naming route sign; with --carry and --carry-route it
// carries writeV2Plane's 2.0 list into a 3.0 list of the v1alpha3 route,
// at the next serial, chained to the old head, with run-1's stop as scope run
// and subject run-1.
func TestStopsInitCarriesA017ListIntoA30One(t *testing.T) {
	tr := newSignedTree(t)
	old := filepath.Join(tr.dir, "old")
	noErr(t, os.Mkdir(old, 0o700))
	head := writeV2Plane(t, old)
	oldRoute, oldStops := filepath.Join(old, "route.json"), filepath.Join(old, "stops")
	fresh := ownerDir(t, filepath.Join(tr.dir, "fresh"))
	if code, _, stderr := invoke(t, append(append([]string{"stops", "init", "--key", tr.keys["alice"], "--route", oldRoute}, tr.judge...), fresh)...); code == exitOK ||
		!strings.Contains(stderr, "route sign") {
		t.Fatalf("stops init under a v1alpha2 route: %d, %q", code, stderr)
	}
	newRoute := filepath.Join(tr.dir, "route-018.json")
	if code, stderr := tr.signRouteDoc(t, routeDocAt("plane-a", "2"), newRoute); code != exitOK {
		t.Fatalf("route sign: %d, %q", code, stderr)
	}
	into := ownerDir(t, filepath.Join(tr.dir, "stops-018"))
	args := append([]string{"stops", "init", "--key", tr.keys["alice"], "--route", newRoute, "--carry", oldStops, "--carry-route", oldRoute}, tr.judge...)
	if code, _, stderr := invoke(t, append(args, into)...); code != exitOK || !strings.Contains(stderr, "plane-a") {
		t.Fatalf("stops init --carry from a 2.0 list: %d, %q", code, stderr)
	}
	route, err := rosterRoute("--route", newRoute, tr.judge[1], tr.judge[3], into, "", nil, reaction.VerifySignedRoute)
	noErr(t, err)
	l, err := reaction.Judge(route, reaction.Prefix{}, listBytes(t, into), time.Now(), 0)
	noErr(t, err)
	if s := l.Header().Signed; s.Serial != 4 || s.Previous != head || s.PlaneID != "plane-a" {
		t.Fatalf("the carried header: %+v, want serial 4 after %s", s, head)
	}
	expectRun1Alone(t, l, time.Now())
}

// expectRun1Alone fails unless l's one entry is run-1's stop, of scope run
// and subject run-1, active at now.
func expectRun1Alone(t *testing.T, l reaction.List, now time.Time) {
	t.Helper()
	e := l.Entries()
	if len(e) != 1 || e[0].RunID != "run-1" || e[0].Scope != reaction.ScopeRun || e[0].Subject != "run-1" || !e[0].ExpiresAt.After(now) {
		t.Fatalf("the carried entries %+v, want run-1's stop alone", e)
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
