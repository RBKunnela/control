package stopwrite_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// deadlineStopOf is stopOf under DEADLINE_EXCEEDED at version "1", lasting
// ten minutes.
func deadlineStopOf(t *testing.T, finding, run string, created time.Time) reaction.Stop {
	t.Helper()
	s := stopOf(t, finding, run, created)
	s.RuleID, s.RuleVersion, s.ExpiresAt = "DEADLINE_EXCEEDED", "1", created.Add(10*time.Minute)
	return s
}

// TestAnUpgradeLiftsNoStopOfARetiredRule: a list under a route naming
// DEADLINE_EXCEEDED at version "1", holding a stop of run-1, a stop of run-2
// and a lift of run-2, is carried into a list under the route signed again
// without it: the stop of run-1 is kept as it was and still stops run-1 on
// the plane, the lifted one is covered, and the operator's lift ends the
// kept one. No writer appends a new stop of that version.
func TestAnUpgradeLiftsNoStopOfARetiredRule(t *testing.T) {
	from, to := routeNamingAlso(t, "DEADLINE_EXCEEDED", "1"), routeOf(t, 3, false)
	h := reaction.HeaderFor(from, "lst-0123456789abcdef0123456789abcdef")
	kept := must(t)(deadlineStopOf(t, "f-1", "run-1", clock0.Add(-time.Minute)).Marshal())
	old := writeLines(t, must(t)(h.Marshal()), kept,
		must(t)(deadlineStopOf(t, "f-2", "run-2", clock0.Add(-time.Minute)).Marshal()),
		must(t)(liftOf(t, liftKey(), from, h.ListID, "run-2", 3).Marshal()))
	dir := emptyDir(t)
	got, err := stopwrite.Carry(bg, old, from, dir, to, clock0)
	if err != nil {
		t.Fatalf("Carry from the route naming the retired version: %v", err)
	}
	if got.Stops != 1 || got.Covered != 1 || got.LeftOut != 0 {
		t.Errorf("Carry = %+v; want 1 stop and 1 covered", got)
	}
	lines := strings.Split(string(content(t, dir)), "\n")
	if len(lines) != 4 || lines[1] != string(kept) || !strings.Contains(lines[2], `"finding_id":"f-2"`) {
		t.Fatalf("the carried list:\n%s", content(t, dir))
	}
	p := planeOn(t, dir, to)
	if s, _, _ := p.Current().ForSubject(reaction.Subject{Tenant: "acme", Run: "run-1"}, clock0, time.Time{}); s != reaction.Stopped {
		t.Errorf("run-1 on the carried list: %s, want %s", s, reaction.Stopped)
	}
	expectRetiredRefusedThenLifted(t, dir, to, lines[0])
}

// expectRetiredRefusedThenLifted fails unless the list in dir under route
// to, whose header line is headLine, refuses a new stop of DEADLINE_EXCEEDED
// "1" from every writer, left unchanged, and takes a lift of run-1's kept stop.
func expectRetiredRefusedThenLifted(t *testing.T, dir string, to reaction.Route, headLine string) {
	t.Helper()
	before := content(t, dir)
	stale := deadlineStopOf(t, "f-3", "run-3", clock0)
	if _, err := stopwrite.AppendStop(bg, dir, to, stale, clock0); !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrStopRetired) {
		t.Errorf("AppendStop of a stop of the retired version: %v", err)
	}
	if _, _, err := appendFinding(bg, dir, to, stale, clock0); !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrStopRetired) {
		t.Errorf("AppendFinding of a stop of the retired version: %v", err)
	}
	if !bytes.Equal(content(t, dir), before) {
		t.Fatal("a refused append changed the list")
	}
	head, err := reaction.ParseLine([]byte(headLine))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := stopwrite.AppendLift(bg, dir, to, liftOf(t, liftKey(), to, head.Header.ListID, "run-1", 2), clock0); err != nil || n != 4 {
		t.Errorf("a lift of the kept stop: line %d, %v", n, err)
	}
}

// TestACarriedStopTheNewRouteDoesNotGrantIsLiftedUnderTheOldOne: the old
// route names DEADLINE_EXCEEDED "1" for refund "2" and no other rule of it,
// so the new route grants that stop nothing. The carry refuses, naming the
// stop and the lift that ends it; the lift is appended under the old route,
// which no writer of a stop takes; the carry then writes the list, the
// lifted stop covered, and a plane starts on it.
func TestACarriedStopTheNewRouteDoesNotGrantIsLiftedUnderTheOldOne(t *testing.T) {
	pub := base64.StdEncoding.EncodeToString(liftKey().Public().(ed25519.PublicKey))
	doc := `{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":3,"tenant_id":"acme","scope":"run",` +
		`"lift_public_key":"` + pub + `","rules":[` +
		`{"procedure_id":"refund","version":"1","digest":"` + refundDigest(t) + `","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","expires_seconds":3600},` +
		`{"procedure_id":"refund","version":"2","digest":"` + refundDigest(t) + `","rule_id":"DEADLINE_EXCEEDED","rule_version":"1"}]}`
	from, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	to := routeOf(t, 4, false)
	h := reaction.HeaderFor(from, "lst-0123456789abcdef0123456789abcdef")
	s := stopOf(t, "f-1", "run-1", clock0.Add(-time.Minute))
	s.ProcedureVersion, s.RuleID, s.RuleVersion = "2", "DEADLINE_EXCEEDED", "1"
	old := writeLines(t, must(t)(h.Marshal()), must(t)(s.Marshal()))

	into := emptyDir(t)
	_, err = stopwrite.Carry(bg, old, from, into, to, clock0)
	for _, want := range []string{`run "run-1"`, `finding "f-1"`, "DEADLINE_EXCEEDED 1", "line 2 of the list carried from", "stops lift --run"} {
		if !errors.Is(err, stopwrite.ErrRefused) || err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Carry of a stop the new route grants nothing: %v; want %v naming %q", err, stopwrite.ErrRefused, want)
		}
	}
	if n, err := stopwrite.AppendLift(bg, old, from, liftOf(t, liftKey(), from, h.ListID, "run-1", 2), clock0); err != nil || n != 3 {
		t.Fatalf("a lift of the stop under the route it was written under: line %d, %v", n, err)
	}
	c, err := stopwrite.Carry(bg, old, from, into, to, clock0)
	if err != nil || c.Stops != 0 || c.Covered != 1 {
		t.Fatalf("the carry after the lift: %+v, %v", c, err)
	}
	if st, _, _ := planeOn(t, into, to).Current().ForSubject(reaction.Subject{Tenant: "acme", Run: "run-1"}, clock0, time.Time{}); st == reaction.Stopped {
		t.Errorf("run-1 on the carried list: %s", st)
	}
}

// retiredWideRoute is a v1alpha3 route of plane-a at serial, for the plane
// whose list is in dir, whose rules are rules, read as the route a list is
// carried from when carrySource is set.
func retiredWideRoute(t *testing.T, dir string, serial int, carrySource bool, rules ...string) reaction.Route {
	t.Helper()
	doc := `{"kind":"reaction-route/v1alpha3","plane_id":"plane-a","route_id":"refunds","serial":` + strconv.Itoa(serial) +
		`,"tenant_id":"acme","project_id":"shop","rules":[` + strings.Join(rules, ",") + `]}`
	body, err := reaction.SignedRouteBody([]byte(doc), operatorID(), "/plane/route.json")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedRoutePayloadType, body, operatorKey())
	if err != nil {
		t.Fatal(err)
	}
	env := reaction.Envelope{PayloadType: reaction.SignedRoutePayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: operatorID(), Signature: sig}}}
	verify := reaction.VerifySignedRoute
	if carrySource {
		verify = reaction.VerifySignedCarrySource
	}
	r, err := verify(env, planeVoucher(dir))
	if err != nil {
		t.Fatalf("verifying the route: %v", err)
	}
	return r
}

// refundRule is a v1alpha3 rule of refund version "1".
func refundRule(t *testing.T, id, version, scope, seconds string) string {
	return `{"procedure_id":"refund","version":"1","digest":"` + refundDigest(t) + `","rule_id":"` + id +
		`","rule_version":"` + version + `","scope":"` + scope + `","expires_seconds":` + seconds + `}`
}

// TestASignedCarryKeepsARetiredAgentStopOnlyWhereTheRouteStopsAnAgent: a 3.0
// list under a route letting DENIED_ACTION_RETRIED_ARGUMENTS "1" stop an
// agent for two hours holds such a stop. CarrySigned keeps it under a route
// letting REPEATED_DENIAL "2" stop an agent of the same procedure for two
// hours, and a plane stops the agent on it; under a route that stops runs
// alone it refuses the carry, naming the stop and the lift that ends it.
func TestASignedCarryKeepsARetiredAgentStopOnlyWhereTheRouteStopsAnAgent(t *testing.T) {
	from := emptyDir(t)
	fromRoute := retiredWideRoute(t, from, 5, true, refundRule(t, "STEP_OUTSIDE_PROCEDURE", "1", "run", "3600"),
		refundRule(t, "DENIED_ACTION_RETRIED_ARGUMENTS", "1", "agent", "7200"))
	header, err := stopwrite.SignedHeaderLine(fromRoute, signer(), 7)
	if err != nil {
		t.Fatal(err)
	}
	stop := reaction.Stop{
		EntryID: reaction.EntryID("f-1"), TenantID: "acme", ProjectID: "shop", Scope: reaction.ScopeAgent, Subject: "agent-1",
		RunID: "run-1", FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: refundDigest(t),
		RuleID: "DENIED_ACTION_RETRIED_ARGUMENTS", RuleVersion: "1", CreatedAt: clock0.Add(-time.Minute),
		ExpiresAt: clock0.Add(-time.Minute + 2*time.Hour),
	}
	setContent(t, from, append(append(append(header, '\n'), must(t)(stop.Marshal())...), '\n'))

	runsOnly := emptyDir(t)
	_, err = stopwrite.CarrySigned(bg, from, fromRoute, runsOnly, signedRouteIn(t, runsOnly, 6), clock0, signer(), nil)
	for _, want := range []string{`agent "agent-1"`, "DENIED_ACTION_RETRIED_ARGUMENTS 1", "stops lift --agent"} {
		if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, reaction.ErrClaimScope) || !strings.Contains(err.Error(), want) {
			t.Fatalf("CarrySigned into a route that stops runs alone: %v; want %v naming %q", err, reaction.ErrClaimScope, want)
		}
	}

	into := emptyDir(t)
	route := retiredWideRoute(t, into, 6, false, refundRule(t, "STEP_OUTSIDE_PROCEDURE", "1", "run", "3600"),
		refundRule(t, "REPEATED_DENIAL", "2", "agent", "7200"))
	c, err := stopwrite.CarrySigned(bg, from, fromRoute, into, route, clock0, signer(), nil)
	if err != nil || c.Stops != 1 {
		t.Fatalf("CarrySigned into a route stopping an agent of the procedure: %+v, %v", c, err)
	}
	entries, _ := planeOn(t, into, route).Current().ActiveEntries(clock0, time.Time{})
	if len(entries) != 1 || entries[0].Target() != (reaction.Target{Scope: reaction.ScopeAgent, Subject: "agent-1"}) {
		t.Errorf("the plane's active stops on the carried list: %+v", entries)
	}
}
