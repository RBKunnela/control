package reaction_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// widerRouteDoc is a v1alpha3 route of plane-a with one rule of each scope:
// STEP_OUTSIDE_PROCEDURE stops a run for an hour, REPEATED_DENIAL an agent
// and, under the procedure's next version, a principal, each for two hours.
const widerRouteDoc = `{"kind":"reaction-route/v1alpha3","plane_id":"plane-a","route_id":"refunds","serial":7,"tenant_id":"acme",
 "project_id":"shop","rules":[
 {"procedure_id":"refund","version":"3","digest":"` + procDigest + `","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run","expires_seconds":3600},
 {"procedure_id":"refund","version":"3","digest":"` + procDigest + `","rule_id":"REPEATED_DENIAL","rule_version":"2","scope":"agent","expires_seconds":7200},
 {"procedure_id":"refund","version":"4","digest":"` + procDigest + `","rule_id":"REPEATED_DENIAL","rule_version":"2","scope":"principal","expires_seconds":7200}]}`

// widerRoute is widerRouteDoc signed for plane-a and taken by the fake voucher.
func widerRoute(t testing.TB) reaction.Route {
	t.Helper()
	body, err := reaction.SignedRouteBody([]byte(widerRouteDoc), keyIDOf(operatorKey()), sRouteFile)
	if err != nil {
		t.Fatalf("SignedRouteBody: %v", err)
	}
	env := envelopeOf(t, reaction.SignedRoutePayloadType, body, operatorKey(), keyIDOf(operatorKey()))
	r, err := reaction.VerifySignedRoute(env, newVoucher())
	if err != nil {
		t.Fatalf("VerifySignedRoute: %v", err)
	}
	return r
}

// ruleOf is the procedure version, the rule id and version, and the
// lifetime, of a stop of scope under widerRouteDoc.
func ruleOf(scope string) (procedure, id, version string, life time.Duration) {
	switch scope {
	case reaction.ScopeAgent:
		return "3", "REPEATED_DENIAL", "2", 2 * time.Hour
	case reaction.ScopePrincipal:
		return "4", "REPEATED_DENIAL", "2", 2 * time.Hour
	}
	return "3", "STEP_OUTSIDE_PROCEDURE", "1", time.Hour
}

// wideStop is a 3.0 stop of scope and subject for finding about run-1.
func wideStop(t testing.TB, finding, scope, subject string) []byte {
	t.Helper()
	procedure, id, version, life := ruleOf(scope)
	line, err := reaction.Stop{
		EntryID: reaction.EntryID(finding), TenantID: sTenant, ProjectID: sProject, Scope: scope, Subject: subject,
		RunID: "run-1", FindingID: finding, ProcedureID: "refund", ProcedureVersion: procedure, ProcedureDigest: procDigest,
		RuleID: id, RuleVersion: version, CreatedAt: sCreated, ExpiresAt: sCreated.Add(life),
	}.Marshal()
	if err != nil {
		t.Fatalf("Stop.Marshal: %v", err)
	}
	return line
}

// wideLift is a 3.0 lift of scope and subject through line through of the
// list whose head is head, signed by the operator.
func wideLift(t testing.TB, head, scope, subject string, through int64) []byte {
	t.Helper()
	body, err := reaction.SignedLiftV3{KeyID: keyIDOf(operatorKey()), PlaneID: sPlane, ListHead: head, Scope: scope,
		Subject: subject, ThroughLine: through, TenantID: sTenant, Project: sProject, File: sListFile}.Payload()
	if err != nil {
		t.Fatalf("SignedLiftV3.Payload: %v", err)
	}
	env := envelopeOf(t, reaction.SignedLiftPayloadType, body, operatorKey(), keyIDOf(operatorKey()))
	line, err := reaction.LiftLine{Scope: scope, Subject: subject, ThroughLine: through, Envelope: env}.Marshal()
	if err != nil {
		t.Fatalf("LiftLine.Marshal: %v", err)
	}
	return line
}

// TestOnlyTheActorRulesMayStopAnAgentOrAPrincipal: a v1alpha3 rule of scope
// agent or principal is read for REPEATED_DENIAL with a lifetime; for any
// other rule it is ErrRouteScope, and without expires_seconds
// ErrRouteLifetime. The retired versions of the two retry rules are read, as
// a carry's source names them, and CheckStopping refuses them.
func TestOnlyTheActorRulesMayStopAnAgentOrAPrincipal(t *testing.T) {
	if ruledDoc("X", "1", "agent") == ruledDoc("STEP_OUTSIDE_PROCEDURE", "1", "run") {
		t.Fatal("the route document names no rule to edit")
	}
	for _, scope := range []string{reaction.ScopeAgent, reaction.ScopePrincipal} {
		expectActorRule(t, "REPEATED_DENIAL", "2", scope)
		expectRetiredActorRule(t, "DENIED_ACTION_RETRIED_ARGUMENTS", scope)
		expectRetiredActorRule(t, "DENIED_ACTION_RETRIED_RESOURCE", scope)
		for _, rule := range [][2]string{{"STEP_OUTSIDE_PROCEDURE", "1"}, {"DEADLINE_EXCEEDED", "1"}, {"DEADLINE_EXCEEDED", "2"},
			{"RESOURCE_OUTSIDE_RUN", "1"}, {"DENIED_ACTION_RETRIED_ARGUMENTS", "2"}, {"DENIED_ACTION_RETRIED_RESOURCE", "2"}} {
			if _, err := reaction.ParseRouteDocument([]byte(ruledDoc(rule[0], rule[1], scope))); !errors.Is(err, reaction.ErrRouteScope) {
				t.Errorf("%s of scope %s: %v, want %v", rule[0], scope, err, reaction.ErrRouteScope)
			}
		}
	}
	for _, rule := range [][2]string{{"REPEATED_DENIAL", "2"}, {"STEP_OUTSIDE_PROCEDURE", "1"}} {
		unbounded := strings.Replace(ruledDoc(rule[0], rule[1], "run"), `,"expires_seconds":3600`, ``, 1)
		if _, err := reaction.ParseRouteDocument([]byte(unbounded)); err != nil {
			t.Errorf("%s of scope run with no lifetime: %v", rule[0], err)
		}
	}
	if !reaction.MayStopWider("REPEATED_DENIAL", "2") || reaction.MayStopWider("REPEATED_DENIAL", "1") ||
		reaction.MayStopWider("STEP_OUTSIDE_PROCEDURE", "1") || reaction.MayStopWider("DENIED_ACTION_RETRIED_ARGUMENTS", "1") ||
		reaction.MayStopWider("DENIED_ACTION_RETRIED_RESOURCE", "1") {
		t.Error("MayStopWider takes another rule than the current version of REPEATED_DENIAL")
	}
}

// ruledDoc is signedRouteDoc whose STEP_OUTSIDE_PROCEDURE rule of runs is
// rule id at version, of scope.
func ruledDoc(id, version, scope string) string {
	doc := strings.NewReplacer("PLANE", sPlane, "PROJECT", sProject).Replace(signedRouteDoc)
	return strings.NewReplacer(`"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run"`,
		`"rule_id":"`+id+`","rule_version":"`+version+`","scope":"`+scope+`"`).Replace(doc)
}

// expectRetiredActorRule fails unless rule id at version "1" of scope is read,
// as a carry's source names it, and CheckStopping refuses it naming the rule.
func expectRetiredActorRule(t *testing.T, id, scope string) {
	t.Helper()
	r, err := reaction.ParseRouteDocument([]byte(ruledDoc(id, "1", scope)))
	if err != nil {
		t.Errorf("%s 1 of scope %s: %v", id, scope, err)
		return
	}
	if err := reaction.CheckStopping(r); !errors.Is(err, reaction.ErrRouteRuleStops) || !strings.Contains(err.Error(), id) {
		t.Errorf("CheckStopping of %s 1 of scope %s: %v, want %v naming it", id, scope, err, reaction.ErrRouteRuleStops)
	}
}

// expectActorRule fails unless rule id at version of scope is read with its
// scope and lifetime, passes CheckStopping, and is refused with no lifetime.
func expectActorRule(t *testing.T, id, version, scope string) {
	t.Helper()
	r, err := reaction.ParseRouteDocument([]byte(ruledDoc(id, version, scope)))
	if err != nil {
		t.Errorf("%s %s of scope %s: %v", id, version, scope, err)
		return
	}
	if got := r.Rules()[0]; got.Scope != scope || got.Lifetime != time.Hour {
		t.Errorf("%s of scope %s read as scope %q, lifetime %v", id, scope, got.Scope, got.Lifetime)
	}
	if err := reaction.CheckStopping(r); err != nil {
		t.Errorf("CheckStopping of %s of scope %s: %v", id, scope, err)
	}
	unbounded := strings.Replace(ruledDoc(id, version, scope), `,"expires_seconds":3600`, ``, 1)
	if _, err := reaction.ParseRouteDocument([]byte(unbounded)); !errors.Is(err, reaction.ErrRouteLifetime) {
		t.Errorf("%s of scope %s with no lifetime: %v, want %v", id, scope, err, reaction.ErrRouteLifetime)
	}
}

// TestAWiderStopLiftAndCoveredLineAreRead: a 3.0 stop or covered line of
// scope agent or principal names its subject and the finding's run; a
// subject up to MaxSubjectBytes is read and one past it refused; a lift of
// either scope is signed and read.
func TestAWiderStopLiftAndCoveredLineAreRead(t *testing.T) {
	long := strings.Repeat("a", reaction.MaxSubjectBytes)
	for _, scope := range []string{reaction.ScopeAgent, reaction.ScopePrincipal} {
		l, err := reaction.ParseLine(wideStop(t, "f-1", scope, long))
		if err != nil || l.Stop.Scope != scope || l.Stop.Subject != long || l.Stop.RunID != "run-1" {
			t.Fatalf("a 3.0 stop of scope %s: %+v, %v", scope, l.Stop, err)
		}
		over := strings.Replace(string(wideStop(t, "f-1", scope, long)), long, long+"a", 1)
		if _, err := reaction.ParseLine([]byte(over)); !errors.Is(err, reaction.ErrLineValue) {
			t.Errorf("a %s subject past its bound: %v, want %v", scope, err, reaction.ErrLineValue)
		}
		expectWiderCovered(t, scope)
		lift, err := reaction.ParseLine(wideLift(t, "sha256:"+procDigest, scope, long, 2))
		if err != nil || lift.Lift.Scope != scope || lift.Lift.Subject != long || lift.Lift.RunID != "" {
			t.Errorf("a 3.0 lift of scope %s: %+v, %v", scope, lift.Lift, err)
		}
	}
}

// TestAWiderStopKeepsTheRunIDsBound: under an agent stop, whose subject may
// reach MaxSubjectBytes, the finding's run_id still holds to MaxRunIDBytes.
func TestAWiderStopKeepsTheRunIDsBound(t *testing.T) {
	runLong := strings.Repeat("r", reaction.MaxRunIDBytes+1)
	past := strings.Replace(string(wideStop(t, "f-1", reaction.ScopeAgent, "agent-a")), `"run_id":"run-1"`, `"run_id":"`+runLong+`"`, 1)
	if !strings.Contains(past, runLong) {
		t.Fatal("the stop line names no run_id to lengthen")
	}
	if _, err := reaction.ParseLine([]byte(past)); !errors.Is(err, reaction.ErrLineValue) {
		t.Errorf("a run id past its bound under an agent stop: %v, want %v", err, reaction.ErrLineValue)
	}
}

// expectWiderCovered fails unless a covered line of scope reads back with
// its scope and subject.
func expectWiderCovered(t *testing.T, scope string) {
	t.Helper()
	covered, err := reaction.Covered{FindingID: "f-2", TenantID: sTenant, RunID: "run-1", ProjectID: sProject,
		Scope: scope, Subject: "agent-a", CreatedAt: sCreated}.Marshal()
	if err != nil {
		t.Fatalf("a covered line of scope %s: %v", scope, err)
	}
	if l, err := reaction.ParseLine(covered); err != nil || l.Covered.Scope != scope || l.Covered.Subject != "agent-a" {
		t.Errorf("a covered line of scope %s read as %+v, %v", scope, l.Covered, err)
	}
}

// TestALiftEndsOnlyItsOwnScopeAndSubject: of an agent stop and a run stop
// made from findings about one run, a lift of the run ends the run's stop
// alone and a lift of the agent the agent's; a principal stop outlives both.
func TestALiftEndsOnlyItsOwnScopeAndSubject(t *testing.T) {
	r := widerRoute(t)
	header, head := signedHeaderLine(t, r, headerOpts{})
	lines := [][]byte{
		header,
		wideStop(t, "f-agent", reaction.ScopeAgent, "agent-a"),
		wideStop(t, "f-run", reaction.ScopeRun, "run-1"),
		wideStop(t, "f-principal", reaction.ScopePrincipal, "alice"),
		wideLift(t, head, reaction.ScopeRun, "run-1", 4),
	}
	scopes := func(l reaction.List) []string {
		var out []string
		for _, e := range l.Entries() {
			out = append(out, e.Scope+":"+e.Subject)
		}
		return out
	}
	l, err := reaction.Judge(r, reaction.Prefix{}, joinLines(lines...), sNow, 0)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if got := strings.Join(scopes(l), ","); got != "agent:agent-a,principal:alice" {
		t.Fatalf("after a lift of run-1 the list holds %s, want the agent's and the principal's stops", got)
	}
	lines = append(lines, wideLift(t, head, reaction.ScopeAgent, "agent-a", 5))
	l, err = reaction.Judge(r, reaction.Prefix{}, joinLines(lines...), sNow, 0)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if got := strings.Join(scopes(l), ","); got != "principal:alice" {
		t.Fatalf("after a lift of agent-a the list holds %s, want the principal's stop alone", got)
	}
	lines = append(lines, wideLift(t, head, reaction.ScopePrincipal, "agent-a", 6))
	l, err = reaction.Judge(r, reaction.Prefix{}, joinLines(lines...), sNow, 0)
	if err != nil || strings.Join(scopes(l), ",") != "principal:alice" {
		t.Fatalf("after a lift of principal agent-a the list holds %v, %v; want alice's stop standing", scopes(l), err)
	}
	again := append(lines[:len(lines):len(lines)], wideLift(t, head, reaction.ScopeAgent, "agent-a", 5))
	if _, err := reaction.Judge(r, reaction.Prefix{}, joinLines(again...), sNow, 0); !errors.Is(err, reaction.ErrLiftAgain) {
		t.Errorf("a second lift of agent-a through line 5: %v, want %v", err, reaction.ErrLiftAgain)
	}
}

// TestAWiderStopUnderARuleOfAnotherScopeIsRefused: a stop line whose scope
// is not its rule's is refused by the judge, so an agent stop cannot ride on
// a rule of runs.
func TestAWiderStopUnderARuleOfAnotherScopeIsRefused(t *testing.T) {
	r := widerRoute(t)
	header, _ := signedHeaderLine(t, r, headerOpts{})
	stop := strings.Replace(string(wideStop(t, "f-1", reaction.ScopeAgent, "agent-a")),
		`"rule_id":"REPEATED_DENIAL","rule_version":"2"`, `"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1"`, 1)
	if !strings.Contains(stop, "STEP_OUTSIDE_PROCEDURE") {
		t.Fatal("the stop line names no rule to edit")
	}
	if _, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header, []byte(stop)), sNow, 0); !errors.Is(err, reaction.ErrClaimScope) {
		t.Errorf("an agent stop under a rule of runs: %v, want %v", err, reaction.ErrClaimScope)
	}
}

// widerSnapshot is the list of an agent stop of agent-a and a run stop of
// run-1, read at sNow.
func widerSnapshot(t *testing.T, extra ...[]byte) reaction.Snapshot {
	t.Helper()
	r := widerRoute(t)
	header, _ := signedHeaderLine(t, r, headerOpts{})
	lines := append([][]byte{header, wideStop(t, "f-agent", reaction.ScopeAgent, "agent-a")}, extra...)
	s := reaction.Snapshot{}.Next(r, joinLines(lines...), sNow, time.Minute)
	if s.State() != reaction.Stopped {
		t.Fatalf("the list read as %s: %s", s.State(), s.Detail())
	}
	return s
}

// TestAWiderStopMatchesEveryCallOfItsSubject: an agent stop matches a call
// of its agent in its tenant whatever its run, the run it was found on, a
// run opened after it and a call with no run, and no call of another agent
// or tenant; a run stop matches its own run alone, never a call with no run;
// a call that names no agent under an active agent stop, or no tenant, is
// Unknown and never Clear.
func TestAWiderStopMatchesEveryCallOfItsSubject(t *testing.T) {
	s := widerSnapshot(t, wideStop(t, "f-run", reaction.ScopeRun, "run-1"))
	now := sNow.Add(time.Second)
	for _, c := range []struct {
		name  string
		who   reaction.Subject
		state reaction.State
		cause reaction.Cause
		match reaction.StopMatch
	}{
		{"the run it was found on", reaction.Subject{Tenant: sTenant, Run: "run-1", Agent: "agent-a", Principal: "alice"},
			reaction.Stopped, "", reaction.StopRun | reaction.StopWider},
		{"another run of the agent", reaction.Subject{Tenant: sTenant, Run: "run-2", Agent: "agent-a", Principal: "alice"},
			reaction.Stopped, "", reaction.StopWider},
		{"a call with no run", reaction.Subject{Tenant: sTenant, Agent: "agent-a", Principal: "alice"},
			reaction.Stopped, "", reaction.StopWider},
		{"another agent's run-1", reaction.Subject{Tenant: sTenant, Run: "run-1", Agent: "agent-b", Principal: "alice"},
			reaction.Stopped, "", reaction.StopRun},
		{"another agent with no run", reaction.Subject{Tenant: sTenant, Agent: "agent-b", Principal: "alice"},
			reaction.Clear, "", 0},
		{"another tenant", reaction.Subject{Tenant: "globex", Run: "run-1", Agent: "agent-a", Principal: "alice"},
			reaction.Clear, "", 0},
		{"no agent", reaction.Subject{Tenant: sTenant, Run: "run-2", Principal: "alice"},
			reaction.Unknown, reaction.CauseSubject, 0},
		{"no agent on the stopped run", reaction.Subject{Tenant: sTenant, Run: "run-1", Principal: "alice"},
			reaction.Unknown, reaction.CauseSubject, reaction.StopRun},
		{"no tenant", reaction.Subject{Run: "run-2", Agent: "agent-a", Principal: "alice"},
			reaction.Unknown, reaction.CauseSubject, 0},
	} {
		state, cause, match := s.ForSubject(c.who, now, time.Time{})
		if state != c.state || cause != c.cause || match != c.match {
			t.Errorf("%s: %s %q %b, want %s %q %b", c.name, state, cause, match, c.state, c.cause, c.match)
		}
	}
	if state, _, _ := s.ForSubject(reaction.Subject{Tenant: sTenant, Agent: "agent-a", Principal: "alice"},
		sCreated.Add(3*time.Hour), time.Time{}); state != reaction.Unknown {
		t.Errorf("a snapshot past its age read as %s", state)
	}
}

// TestAPrincipalStopMatchesItsPrincipalAlone: a principal stop matches every
// call of its principal and none of another, whatever agent; a call that
// names no principal under it is Unknown.
func TestAPrincipalStopMatchesItsPrincipalAlone(t *testing.T) {
	r := widerRoute(t)
	header, _ := signedHeaderLine(t, r, headerOpts{})
	s := reaction.Snapshot{}.Next(r, joinLines(header, wideStop(t, "f-p", reaction.ScopePrincipal, "alice")), sNow, time.Minute)
	for who, want := range map[reaction.Subject]reaction.StopMatch{
		{Tenant: sTenant, Agent: "agent-b", Principal: "alice"}:                reaction.StopWider,
		{Tenant: sTenant, Run: "run-9", Agent: "agent-a", Principal: "bob"}:    0,
		{Tenant: sTenant, Run: "run-9", Agent: "alice", Principal: "bob"}:      0,
		{Tenant: "globex", Run: "run-9", Agent: "agent-a", Principal: "alice"}: 0,
	} {
		if _, _, got := s.ForSubject(who, sNow, time.Time{}); got != want {
			t.Errorf("%+v matched %b, want %b", who, got, want)
		}
	}
	if state, cause, _ := s.ForSubject(reaction.Subject{Tenant: sTenant, Agent: "agent-a"}, sNow, time.Time{}); state != reaction.Unknown || cause != reaction.CauseSubject {
		t.Errorf("a call naming no principal: %s %q", state, cause)
	}
	if got := reaction.Matches(s, reaction.Subject{Tenant: sTenant, Principal: "alice"}, sNow, time.Time{}); got != reaction.StopWider {
		t.Errorf("Matches = %b, want the principal's stop", got)
	}
}

// TestAWiderStopEndsAtItsOwnLifetime: a stop of an agent or a principal ends
// at its creation plus its rule's lifetime even when the run its finding was
// about expires first; a run's stop ends at its run's expiry, rounded up to
// a whole second, or at its lifetime when that comes first.
func TestAWiderStopEndsAtItsOwnLifetime(t *testing.T) {
	r := widerRoute(t)
	created := sCreated
	runEnds := created.Add(10*time.Minute + 300*time.Millisecond)
	for _, rule := range r.Rules() {
		got := rule.ExpiresAt(created, runEnds)
		want := created.Add(10*time.Minute + time.Second)
		if rule.Scope != reaction.ScopeRun {
			want = created.Add(2 * time.Hour)
		}
		if !got.Equal(want) {
			t.Errorf("a stop of scope %s ends at %v, want %v", rule.Scope, got, want)
		}
		if late := rule.ExpiresAt(created, created.Add(24*time.Hour)); !late.Equal(created.Add(rule.Lifetime)) {
			t.Errorf("a stop of scope %s on a long run ends at %v, want its lifetime", rule.Scope, late)
		}
		if err := r.Permits(reaction.StopClaim{TenantID: sTenant, ProjectID: sProject, Scope: rule.Scope,
			ProcedureID: rule.ProcedureID, ProcedureVersion: rule.ProcedureVersion, ProcedureDigest: rule.ProcedureDigest,
			RuleID: rule.RuleID, RuleVersion: rule.RuleVersion, CreatedAt: created, ExpiresAt: got}); err != nil {
			t.Errorf("the route refuses the stop ExpiresAt makes for scope %s: %v", rule.Scope, err)
		}
	}
}

// TestSubjectOfTakesTheRunRecordsIdentity: the subject of each scope is the
// run record's run, agent or principal, and an empty one is refused.
func TestSubjectOfTakesTheRunRecordsIdentity(t *testing.T) {
	run := reaction.RunFacts{RunID: "run-1", AgentID: "agent-a", PrincipalID: "alice"}
	for scope, want := range map[string]string{reaction.ScopeRun: "run-1", reaction.ScopeAgent: "agent-a", reaction.ScopePrincipal: "alice"} {
		if got, err := reaction.SubjectOf(scope, run); err != nil || got != want {
			t.Errorf("SubjectOf(%s) = %q, %v; want %q", scope, got, err, want)
		}
		if got, err := reaction.SubjectOf(scope, reaction.RunFacts{}); !errors.Is(err, reaction.ErrStopSubject) || got != "" {
			t.Errorf("SubjectOf(%s) of no record = %q, %v; want %v", scope, got, err, reaction.ErrStopSubject)
		}
	}
	if _, err := reaction.SubjectOf("tree", run); !errors.Is(err, reaction.ErrStopSubject) {
		t.Errorf("SubjectOf of a scope outside the grammar: %v", err)
	}
}
