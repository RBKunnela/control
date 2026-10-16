package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// oldListLines is a stop list as a release whose route named REPEATED_DENIAL
// at version "1" wrote it: a repeated denial stops open for five minutes, and
// second, stopped by a repeated denial and a step outside the procedure, is
// lifted through line 4.
func oldListLines(t *testing.T, tr stopTree, route reaction.Route, created time.Time) []byte {
	t.Helper()
	h := reaction.HeaderFor(route, "lst-00000000000000000000000000000001")
	stop := func(n int, run, rule string, lasts time.Duration) reaction.Stop {
		return reaction.Stop{EntryID: reaction.EntryID(fid(n)), TenantID: "acme", RunID: run, FindingID: fid(n),
			ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: stopProcDigest,
			RuleID: rule, RuleVersion: "1", CreatedAt: created, ExpiresAt: created.Add(lasts)}
	}
	env, err := reaction.SignLift(reaction.Lift{Version: reaction.LiftVersion, ListID: h.ListID,
		RouteDigest: route.Digest(), RunID: tr.second, ThroughLine: 4}, seeded(0x4c))
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	for _, line := range []func() ([]byte, error){
		h.Marshal,
		stop(80, tr.open, denial, 5*time.Minute).Marshal,
		stop(81, tr.second, denial, 5*time.Minute).Marshal,
		stop(82, tr.second, outside, time.Hour).Marshal,
		reaction.LiftLine{RunID: tr.second, ThroughLine: 4, Envelope: env}.Marshal,
	} {
		raw, err := line()
		if err != nil {
			t.Fatal(err)
		}
		body = append(append(body, raw...), '\n')
	}
	return body
}

// verifiedAsAPlane is the signed route at path as a plane verifies it at
// start, under the fixture's route key.
func verifiedAsAPlane(t *testing.T, path string) (reaction.Route, error) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file of the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	env, err := reaction.ParseRouteFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := seeded(0x52).Public().(ed25519.PublicKey)
	return reaction.VerifyRoute(env, pub)
}

// servedAt is the list in dir as a plane at start serves it under route.
func servedAt(t *testing.T, route reaction.Route, dir string) reaction.Snapshot {
	t.Helper()
	content, err := stoplist.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := reaction.Snapshot{}.Next(route, content, time.Now(), time.Second)
	if s.State() == reaction.Unknown {
		t.Fatalf("a plane at start refuses the list: %s %s", s.Cause(), s.Detail())
	}
	return s
}

// expectStates fails unless s answers each run of tenant acme with its state.
func expectStates(t *testing.T, s reaction.Snapshot, want map[string]reaction.State) {
	t.Helper()
	for run, state := range want {
		if got, cause := s.ForCall(run, "acme", time.Now(), time.Time{}); got != state {
			t.Errorf("run %s: %s %s, want %s", run, got, cause, state)
		}
	}
}

// TestAListUnderTheOldRepeatedDenialIsCarriedToVersionTwo: a list made under
// a route naming REPEATED_DENIAL at version "1" is carried, by stops init
// --carry with the old route as --carry-route, into a list under the route
// naming version "2". The unlifted stop still stops its run, the lift still
// holds, a plane verifying the new route at start accepts the new list and
// serves it, stops list and stops lift take it, and react writes no stop of
// a finding at version "1". A plane still refuses the old route.
func TestAListUnderTheOldRepeatedDenialIsCarriedToVersionTwo(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now()
	oldRoute := filepath.Join(tr.dir, "old.signed")
	old := signRouteFile(t, oldRoute, routeDocNaming(t, 1, denial, "1"), seeded(0x52))
	oldDir := ownerDir(t, filepath.Join(tr.dir, "old"))
	created := now.UTC().Truncate(time.Second).Add(-time.Minute)
	if err := os.WriteFile(filepath.Join(oldDir, stoplist.FileName), oldListLines(t, tr, old, created), 0o600); err != nil {
		t.Fatal(err)
	}
	newRoute := filepath.Join(tr.dir, "new.signed")
	signRouteFile(t, newRoute, routeDoc(seeded(0x4c), 2), seeded(0x52))
	pub := []string{"--public-key", tr.routePub}

	carried := ownerDir(t, filepath.Join(tr.dir, "carried"))
	code, stdout, stderr := invoke(t, withFlags(pub, "stops", "init", "--route", newRoute,
		"--carry", oldDir, "--carry-route", oldRoute, carried)...)
	if code != exitOK || !strings.HasSuffix(stdout, "route_serial: 2\nroute_digest: "+routeDigestOf(t, routeDoc(seeded(0x4c), 2))+
		"\nstops: 1\ncovered: 2\n") {
		t.Fatalf("stops init --carry from the old route answered %d: %q\n%s", code, stderr, stdout)
	}
	route, err := verifiedAsAPlane(t, newRoute)
	if err != nil {
		t.Fatalf("a plane refuses the new route: %v", err)
	}
	expectStates(t, servedAt(t, route, carried), map[string]reaction.State{
		tr.open: reaction.Stopped, tr.second: reaction.Clear, tr.child: reaction.Clear})

	code, stdout, stderr = invoke(t, withFlags(pub, "stops", "list", "--route", newRoute, carried)...)
	if code != exitOK || !strings.Contains(stdout, "stop line 2 run "+tr.open+" finding "+fid(80)+" rule REPEATED_DENIAL ") {
		t.Errorf("stops list of the carried list answered %d: %q %q", code, stdout, stderr)
	}

	stale := finding(83, tr.child, denial, confirmed)
	stale.Finding.RuleVersion = "1"
	a := tr.reactArgs(tr.findingsDir(t, "stale", stale))
	a.route, a.stops = newRoute, carried
	var out, errOut strings.Builder
	if code := react(context.Background(), a, clockAt(now), &out, &errOut); code != exitOK ||
		out.String() != "stops 0, covered 0, already named 0, not stopping 1, not written 0\n" {
		t.Errorf("react of a version 1 finding over the carried list answered %d: %q %q", code, out.String(), errOut.String())
	}

	code, stdout, stderr = invoke(t, withFlags(pub, "stops", "lift", "--route", newRoute, "--key", tr.liftKey, "--run", tr.open, carried)...)
	if code != exitOK || stdout != "lift line 5 run "+tr.open+" through line 4\n" {
		t.Fatalf("stops lift of the carried stop answered %d: %q %q", code, stdout, stderr)
	}
	expectStates(t, servedAt(t, route, carried), map[string]reaction.State{tr.open: reaction.Clear})

	if _, err := verifiedAsAPlane(t, oldRoute); !errors.Is(err, reaction.ErrRouteRuleStops) {
		t.Errorf("a plane given the old route: %v, want %v", err, reaction.ErrRouteRuleStops)
	}
}
