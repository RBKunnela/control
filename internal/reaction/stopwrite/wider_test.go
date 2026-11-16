package stopwrite_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// widerRouteIn is a v1alpha3 route of plane-a whose STEP_OUTSIDE_PROCEDURE
// stops a run for an hour, REPEATED_DENIAL an agent and
// DENIED_ACTION_RETRIED_ARGUMENTS a principal for two hours, taken for the
// plane whose stop list is in dir.
func widerRouteIn(t *testing.T, dir string) reaction.Route {
	t.Helper()
	rule := func(id, version, scope, seconds string) string {
		return `{"procedure_id":"refund","version":"1","digest":"` + refundDigest(t) + `","rule_id":"` + id +
			`","rule_version":"` + version + `","scope":"` + scope + `","expires_seconds":` + seconds + `}`
	}
	doc := `{"kind":"reaction-route/v1alpha3","plane_id":"plane-a","route_id":"refunds","serial":1,"tenant_id":"acme",` +
		`"project_id":"shop","rules":[` + rule("STEP_OUTSIDE_PROCEDURE", "1", "run", "3600") + "," +
		rule("REPEATED_DENIAL", "2", "agent", "7200") + "," + rule("DENIED_ACTION_RETRIED_ARGUMENTS", "1", "principal", "7200") + `]}`
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
	r, err := reaction.VerifySignedRoute(env, planeVoucher(dir))
	if err != nil {
		t.Fatalf("VerifySignedRoute: %v", err)
	}
	return r
}

// wideStopOf is a 3.0 stop of scope and subject for finding about run,
// created at created and lasting life.
func wideStopOf(t *testing.T, finding, run, scope, subject string, created time.Time, life time.Duration) reaction.Stop {
	t.Helper()
	id, version := "STEP_OUTSIDE_PROCEDURE", "1"
	switch scope {
	case reaction.ScopeAgent:
		id, version = "REPEATED_DENIAL", "2"
	case reaction.ScopePrincipal:
		id, version = "DENIED_ACTION_RETRIED_ARGUMENTS", "1"
	}
	return reaction.Stop{
		EntryID: reaction.EntryID(finding), TenantID: "acme", ProjectID: "shop", Scope: scope, Subject: subject,
		RunID: run, FindingID: finding, ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: refundDigest(t),
		RuleID: id, RuleVersion: version, CreatedAt: created, ExpiresAt: created.Add(life),
	}
}

// TestAFindingIsCoveredOnlyByAStopOfItsScopeAndSubject: a stop of a run is
// written beside a longer stop of the agent that names the same run, a stop
// of an agent beside a longer stop of its run, and a stop of a principal
// beside a stop of an agent of the same name; only an active stop of the
// same scope and subject that lasts as long covers a finding, whatever run
// that finding was about.
func TestAFindingIsCoveredOnlyByAStopOfItsScopeAndSubject(t *testing.T) {
	dir := emptyDir(t)
	r := widerRouteIn(t, dir)
	if _, err := stopwrite.InitSigned(bg, dir, r, clock0, signer(), 1); err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	for _, c := range []struct {
		name    string
		stop    reaction.Stop
		covered bool
	}{
		{"an agent stop from run-1", wideStopOf(t, "f-1", "run-1", reaction.ScopeAgent, "agent-a", clock0, 2*time.Hour), false},
		{"a run stop of run-1 under agent-a's longer stop", wideStopOf(t, "f-2", "run-1", reaction.ScopeRun, "run-1", clock0, time.Hour), false},
		{"an agent finding of run-2 within agent-a's stop", wideStopOf(t, "f-3", "run-2", reaction.ScopeAgent, "agent-a", clock0, time.Hour), true},
		{"a run finding of run-1 within its run's stop", wideStopOf(t, "f-4", "run-1", reaction.ScopeRun, "run-1", clock0, 30*time.Minute), true},
		{"an agent stop of agent-b", wideStopOf(t, "f-5", "run-3", reaction.ScopeAgent, "agent-b", clock0, time.Hour), false},
		{"a principal named like agent-a", wideStopOf(t, "f-6", "run-1", reaction.ScopePrincipal, "agent-a", clock0, time.Hour), false},
		{"a principal finding within that principal's stop", wideStopOf(t, "f-7", "run-4", reaction.ScopePrincipal, "agent-a", clock0, time.Hour), true},
	} {
		_, covered, err := appendFinding(bg, dir, r, c.stop, clock0)
		if err != nil || covered != c.covered {
			t.Errorf("%s: covered %v, %v; want covered %v", c.name, covered, err, c.covered)
		}
	}
	scopes := map[reaction.Target]int{}
	l, err := reaction.Judge(r, reaction.Prefix{}, content(t, dir), clock0, poll)
	if err != nil {
		t.Fatalf("the plane's judge refuses the list: %v", err)
	}
	for _, e := range l.Entries() {
		scopes[e.Target()]++
	}
	want := map[reaction.Target]int{
		{Scope: reaction.ScopeAgent, Subject: "agent-a"}: 1, {Scope: reaction.ScopeRun, Subject: "run-1"}: 1,
		{Scope: reaction.ScopeAgent, Subject: "agent-b"}: 1, {Scope: reaction.ScopePrincipal, Subject: "agent-a"}: 1,
	}
	if len(scopes) != len(want) {
		t.Fatalf("the plane reads stops %v, want %v", scopes, want)
	}
	for k, n := range want {
		if scopes[k] != n {
			t.Errorf("the plane reads %d stop(s) of %+v, want %d", scopes[k], k, n)
		}
	}
}

// TestAShorterAgentStopDoesNotCoverALongerOne: an agent finding whose stop
// would outlast the agent's active stop is a stop of its own.
func TestAShorterAgentStopDoesNotCoverALongerOne(t *testing.T) {
	dir := emptyDir(t)
	r := widerRouteIn(t, dir)
	if _, err := stopwrite.InitSigned(bg, dir, r, clock0, signer(), 1); err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	if _, covered, err := appendFinding(bg, dir, r, wideStopOf(t, "f-1", "run-1", reaction.ScopeAgent, "agent-a", clock0, time.Hour), clock0); err != nil || covered {
		t.Fatalf("the first agent stop: covered %v, %v", covered, err)
	}
	later := clock0.Add(10 * time.Minute)
	if _, covered, err := appendFinding(bg, dir, r, wideStopOf(t, "f-2", "run-2", reaction.ScopeAgent, "agent-a", later, time.Hour), later); err != nil || covered {
		t.Errorf("an agent stop outlasting the active one: covered %v, %v; want a stop", covered, err)
	}
}

// TestACarriedLiftOfAnAgentKeepsItsCoveredLinesScope: a carry names the
// finding of a lifted agent stop as a covered line of that agent, scope and
// subject kept, not of the run the finding was about.
func TestACarriedLiftOfAnAgentKeepsItsCoveredLinesScope(t *testing.T) {
	from := emptyDir(t)
	fromRoute := widerRouteIn(t, from)
	h, err := stopwrite.InitSigned(bg, from, fromRoute, clock0, signer(), 1)
	if err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	if _, _, err := appendFinding(bg, from, fromRoute, wideStopOf(t, "f-1", "run-1", reaction.ScopeAgent, "agent-a", clock0, time.Hour), clock0); err != nil {
		t.Fatal(err)
	}
	appendAgentLift(t, from, h, "agent-a", 2)
	into := emptyDir(t)
	c, err := stopwrite.CarrySigned(bg, from, fromRoute, into, widerRouteIn(t, into), clock0, signer(), nil)
	if err != nil || c.Stops != 0 || c.LeftOut != 0 {
		t.Fatalf("CarrySigned: %+v, %v; want the lifted stop carried as covered", c, err)
	}
	covered := coveredLines(t, into)
	if len(covered) != 1 {
		t.Fatalf("the carry wrote covered lines %+v, want one", covered)
	}
	if c := covered[0]; c.FindingID != "f-1" || c.Scope != reaction.ScopeAgent || c.Subject != "agent-a" || c.RunID != "run-1" {
		t.Errorf("the carried covered line names %+v, want finding f-1 of agent agent-a found on run-1", c)
	}
}

// appendAgentLift appends to the signed list in dir a lift of agent through
// line, signed by the operator over the list's header h.
func appendAgentLift(t *testing.T, dir string, h reaction.Header, agent string, through int64) {
	t.Helper()
	body, err := reaction.SignedLiftV3{KeyID: operatorID(), PlaneID: "plane-a", ListHead: h.Signed.Digest, Scope: reaction.ScopeAgent,
		Subject: agent, ThroughLine: through, TenantID: "acme", Project: "shop", File: listPath(dir)}.Payload()
	if err != nil {
		t.Fatal(err)
	}
	line, err := reaction.LiftLine{Scope: reaction.ScopeAgent, Subject: agent, ThroughLine: through,
		Envelope: envelopeBy(t, operatorKey(), reaction.SignedLiftPayloadType, body)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	appendRaw(t, dir, line)
}

// coveredLines is every covered line of the list in dir, in order.
func coveredLines(t *testing.T, dir string) []reaction.Covered {
	t.Helper()
	var out []reaction.Covered
	for raw := range bytes.Lines(content(t, dir)) {
		if l, err := reaction.ParseLine(bytes.TrimSuffix(raw, []byte{'\n'})); err == nil && l.Kind == reaction.KindCovered {
			out = append(out, l.Covered)
		}
	}
	return out
}
