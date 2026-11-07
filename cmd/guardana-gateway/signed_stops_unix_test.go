//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/trust"
)

// writeLeveledRoster writes a roster of roster-a in which dave is admin and
// alice operates acme/orders, and returns it as verified.
func writeLeveledRoster(t *testing.T, path string) trust.Document {
	t.Helper()
	var keys []any
	for name, level := range map[string]string{"dave": "admin", "alice": "operate"} {
		k := signedTestPublic(name)
		keys = append(keys, map[string]any{
			"keyId": policykey.KeyID(k), "alg": "ed25519", "role": "operator", "subject": name,
			"publicKey": policykey.FormatPublic(k), "grants": []any{map[string]any{"tenant": "acme", "project": "orders", "level": level}},
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
	env := trust.Envelope{PayloadType: trust.PayloadType, Payload: body,
		Signatures: []trust.Signature{{KeyID: policykey.KeyID(signedTestPublic("root")), Signature: sig}}}
	raw, err := trust.MarshalFile(env)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, raw)
	doc, err := trust.VerifyDocument(env, signedTestPublic("root"))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// signedRouteFile has who sign a v1alpha2 route of acme/orders bound to path
// and writes it there.
func signedRouteFile(t *testing.T, path, who string) {
	t.Helper()
	doc := `{"kind":"reaction-route/v1alpha2","route_id":"` + fixtureRouteID + `","serial":1,"tenant_id":"acme","project_id":"orders",` +
		`"rules":[{"procedure_id":"refund","version":"3","digest":"` + fixtureProcedure + `","rule_id":"` + fixtureRule +
		`","rule_version":"1","scope":"run","expires_seconds":3600}]}`
	file, err := signedstops.BindingOf(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := reaction.SignedRouteBody([]byte(doc), policykey.KeyID(signedTestPublic(who)), file)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedRoutePayloadType, body, signedTestKey(who))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := reaction.MarshalRouteFile(reaction.Envelope{PayloadType: reaction.SignedRoutePayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: policykey.KeyID(signedTestPublic(who)), Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, raw)
}

// initStopsState makes under dir the stops directory, a signed runs layout
// and the route and stop list floors a signed start reads.
func initStopsState(t *testing.T, dir string) {
	t.Helper()
	for _, sub := range []string{"stops", "runs"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := runs.InitSignedAdmin(t.Context(), filepath.Join(dir, "runs"))
	if err == nil {
		err = admin.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitRoute(t.Context(), filepath.Join(dir, "routefloor"), fixtureRouteID); err != nil {
		t.Fatal(err)
	}
	if err := policystate.InitStops(t.Context(), filepath.Join(dir, "stopsfloor"), "acme", "orders"); err != nil {
		t.Fatal(err)
	}
}

// rosterRouteOf verifies the route file at routePath through the roster doc
// for the plane of acme/orders whose list lives in stops.
func rosterRouteOf(t *testing.T, doc trust.Document, routePath, stops string) reaction.Route {
	t.Helper()
	plane, err := signedstops.PlaneOf("acme", "orders", routePath, stops, stoplist.FileName)
	if err != nil {
		t.Fatal(err)
	}
	v, err := signedstops.NewRoster(doc, plane)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(routePath) //nolint:gosec // G304: a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	route, err := reaction.VerifySignedRoute(env, v)
	if err != nil {
		t.Fatal(err)
	}
	return route
}

// signedStopsTree is signedPlaneTree with a route dave signed, a 2.0 stop
// list alice started at serial 1, their floors and a runs directory.
func signedStopsTree(t *testing.T) tree {
	t.Helper()
	tr := signedPlaneTree(t, "roster-a", nil, "roster-a")
	doc := writeLeveledRoster(t, filepath.Join(tr.dir, "trust", "roster.json"))
	initStopsState(t, tr.dir)
	routePath, stops := filepath.Join(tr.dir, "route.json"), filepath.Join(tr.dir, "stops")
	signedRouteFile(t, routePath, "dave")
	route := rosterRouteOf(t, doc, routePath, stops)
	alice := signedTestKey("alice")
	s := stopwrite.Signer{KeyID: policykey.KeyID(signedTestPublic("alice")), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, alice)
	}}
	if _, err := stopwrite.InitSigned(t.Context(), stops, route, time.Now(), s, 1); err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, tr.config, append(cfg, []byte("\nruns:\n  dir: runs\nreaction:\n  route: route.json\n  floor_dir: routefloor\n"+
		"  stops: stops\n  stops_floor_dir: stopsfloor\n  poll_interval: 100ms\n")...))
	return tr
}

// expectOneAccountStart builds tr on one account and expects alice's list
// taken, the floor raised to its head and /healthz to count only the serial.
func expectOneAccountStart(t *testing.T, tr tree) {
	t.Helper()
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatalf("build on one account = %v", err)
	}
	snap := p.stops.poller.Current()
	if snap.State() != reaction.Clear {
		t.Fatalf("the stop state = %s, %q: %s", snap.State(), snap.Cause(), snap.Detail())
	}
	head := snap.AcceptedList().Header().Signed.Digest
	floor, err := policystate.ReadStops(filepath.Join(tr.dir, "stopsfloor"), "acme", "orders")
	if err != nil || floor.Serial != 1 || floor.Digest != head {
		t.Fatalf("the stop list floor after the start = %+v, %v; want serial 1 and %s", floor, err, head)
	}
	whole := p.stopsAnswer(snap, time.Now())
	want := stopsSigned{Serial: 1, Subject: "alice", KeyID: policykey.KeyID(signedTestPublic("alice")),
		RouteSubject: "dave", RouteKeyID: policykey.KeyID(signedTestPublic("dave"))}
	if whole.Signed == nil || *whole.Signed != want {
		t.Fatalf("the socket's signed stops = %+v, want %+v", whole.Signed, want)
	}
	counted := healthAnswer{Stops: whole}.counted()
	if counted.Stops.Signed == nil || *counted.Stops.Signed != (stopsSigned{Serial: 1}) {
		t.Fatalf("/healthz's signed stops = %+v, want the serial alone", counted.Stops.Signed)
	}
}

// TestASignedStartTakesOnlyAStopListAndRouteItsAccountCannotRewrite: a stops
// directory or route file the plane's account may write refuses the start,
// naming the key; placed apart, a route file its own account owns is refused
// at the read; on one account, as dev runs, the plane takes alice's list
// under dave's route and raises the floor to its head, and /healthz counts
// the serial and names no operator.
func TestASignedStartTakesOnlyAStopListAndRouteItsAccountCannotRewrite(t *testing.T) {
	tr := signedStopsTree(t)
	for _, c := range []struct{ writable, key string }{{"/stops", "reaction.stops"}, {"route.json", "reaction.route"}} {
		placedApart(t, c.writable)
		if _, err := buildSigned(t, tr); err == nil || !strings.Contains(err.Error(), c.key+": under the signed authority the plane's own account may not be able to change it") {
			t.Fatalf("build over a plane-writable %s = %v", c.key, err)
		}
	}
	placedApart(t)
	if _, err := buildSigned(t, tr); !errors.Is(err, errPlaneOwnedRoute) {
		t.Fatalf("build over a route file the plane's account owns = %v", err)
	}
	expectOneAccountStart(t, tr)
}

// TestASignedStartRefusesAListBelowItsFloorAndARouteNoAdminSigned: a floor
// raised past the list's serial, and a route an operator without the admin
// grant signed, each refuse the start.
func TestASignedStartRefusesAListBelowItsFloorAndARouteNoAdminSigned(t *testing.T) {
	tr := signedStopsTree(t)
	ab := "sha256:" + strings.Repeat("ab", 32)
	if _, err := policystate.RaiseStops(context.Background(), filepath.Join(tr.dir, "stopsfloor"),
		policystate.StopsFloor{Tenant: "acme", Project: "orders", Serial: 2, Digest: ab, Length: 1, Prefix: ab}); err != nil {
		t.Fatal(err)
	}
	if _, err := buildOneAccount(t, tr); !errors.Is(err, stoplist.ErrNotServable) || !strings.Contains(err.Error(), string(stoplist.CauseBelowFloor)) {
		t.Fatalf("build over a list below its floor = %v", err)
	}
	other := signedStopsTree(t)
	signedRouteFile(t, filepath.Join(other.dir, "route.json"), "alice")
	if _, err := buildOneAccount(t, other); !errors.Is(err, reaction.ErrUnvouched) {
		t.Fatalf("build over a route alice signed = %v", err)
	}
}

// TestASignedStartRefusesAListCutBackBelowWhatItsFloorHolds: a plane takes
// the list grown by a covered line and raises the floor to it, and starts
// again over the same list; the list cut back to its header, which holds no
// line the judge refuses, refuses the next start as a broken chain.
func TestASignedStartRefusesAListCutBackBelowWhatItsFloorHolds(t *testing.T) {
	tr := signedStopsTree(t)
	list := filepath.Join(tr.dir, "stops", stoplist.FileName)
	header, err := os.ReadFile(list) //nolint:gosec // G304: a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	covered, err := reaction.Covered{FindingID: "f-1", TenantID: "acme", RunID: "run-1", ProjectID: "orders",
		CreatedAt: time.Now().UTC().Truncate(time.Second)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	grown := append(append(bytes.Clone(header), covered...), '\n')
	writeTestFile(t, list, grown)
	for _, start := range []string{"first", "second"} {
		p, err := buildChecked(tr.load(t), slog.New(slog.DiscardHandler), time.Now(), roleServe, "", func(*gatewayconfig.Config) error { return nil })
		if err != nil {
			t.Fatalf("the %s build over the grown list = %v", start, err)
		}
		if err := p.close(); err != nil {
			t.Fatal(err)
		}
	}
	floor, err := policystate.ReadStops(filepath.Join(tr.dir, "stopsfloor"), "acme", "orders")
	if err != nil || floor.Length != int64(len(grown)) {
		t.Fatalf("the floor after the grown list = %+v, %v; want %d bytes", floor, err, len(grown))
	}
	writeTestFile(t, list, header)
	if _, err := buildOneAccount(t, tr); !errors.Is(err, stoplist.ErrNotServable) || !strings.Contains(err.Error(), string(stoplist.CauseChain)) {
		t.Fatalf("build over the list cut back to its header = %v", err)
	}
}

// TestTheStopListFloorIsKeptForTheListenersTenant: with
// listener.principal.tenant_id naming the route's tenant and tenant_id
// another, the plane binds its documents and keeps its stop list floor for
// the listener's tenant, so a floor made for that tenant is taken.
func TestTheStopListFloorIsKeptForTheListenersTenant(t *testing.T) {
	tr := signedStopsTree(t)
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "tenant_id: acme\n", "tenant_id: elsewhere\n", 1)
	cfg = strings.Replace(cfg, "  principal:\n    id: agent-runner\n", "  principal:\n    id: agent-runner\n    tenant_id: acme\n", 1)
	if !strings.Contains(cfg, "tenant_id: elsewhere") || !strings.Contains(cfg, "    tenant_id: acme") {
		t.Fatal("the fixture configuration names no tenant_id or principal to replace")
	}
	writeTestFile(t, tr.config, []byte(cfg))
	if _, err := buildOneAccount(t, tr); err != nil {
		t.Fatalf("build with the listener's tenant apart from tenant_id = %v", err)
	}
	floor, err := policystate.ReadStops(filepath.Join(tr.dir, "stopsfloor"), "acme", "orders")
	if err != nil || floor.Serial != 1 {
		t.Fatalf("the listener tenant's floor after the start = %+v, %v", floor, err)
	}
}
