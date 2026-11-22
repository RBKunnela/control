package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/runs"
)

// widerRouteDoc is signedRouteDoc whose REPEATED_DENIAL stops the agent and
// DENIED_ACTION_RETRIED_ARGUMENTS the principal for ten minutes, and whose
// STEP_OUTSIDE_PROCEDURE stops the run.
const widerRouteDoc = `{"kind":"reaction-route/v1alpha3","plane_id":"plane-a","route_id":"refund-stops","serial":1,` +
	`"tenant_id":"acme","project_id":"orders","rules":[` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"REPEATED_DENIAL","rule_version":"2","scope":"agent","expires_seconds":600},` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"DENIED_ACTION_RETRIED_ARGUMENTS","rule_version":"1","scope":"principal","expires_seconds":600},` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run"}]}`

// newWiderTree is a signed tree whose route is widerRouteDoc, signed by
// dave, and whose list alice started.
func newWiderTree(t *testing.T) signedTree {
	t.Helper()
	tr := newSignedTree(t)
	doc := filepath.Join(tr.dir, "wider-doc.json")
	if err := os.WriteFile(doc, []byte(widerRouteDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invoke(t, "route", "sign", "--key", tr.keys["dave"], "--out", tr.route, doc); code != exitOK {
		t.Fatalf("route sign: %d, %q", code, stderr)
	}
	if code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], tr.stops); code != exitOK {
		t.Fatalf("stops init: %d, %q", code, stderr)
	}
	return tr
}

// reactOver runs one pass over records under the tree's route at now, with
// the runs ending at ends, each a run of agent-1 and user-1, and returns
// what it wrote.
func (tr signedTree) reactOver(t *testing.T, now time.Time, ends map[string]time.Time, records ...*findingv1alpha1.FindingRecord) []string {
	t.Helper()
	route := tr.takenRoute(t)
	list, _, err := judgedList(tr.stops, route, now)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, id string) (runs.Record, error) {
		end, ok := ends[id]
		if !ok {
			return runs.Record{}, runs.ErrNoRun
		}
		return runs.Record{ID: id, Who: runs.Identity{ProjectID: "orders", TenantID: "acme", PrincipalType: "user",
			PrincipalID: "user-1", AgentID: "agent-1"}, ExpiresAt: end}, nil
	}
	r := newReactor(context.Background(), route, list, lookup, tr.stops, clockAt(now))
	var wrapped []*findingv1alpha1.Record
	for _, fr := range records {
		wrapped = append(wrapped, &findingv1alpha1.Record{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: fr}})
	}
	if err := r.each(wrapped); err != nil || len(r.unwritten) != 0 {
		t.Fatalf("react: %v, not written %v", err, r.unwritten)
	}
	return r.written
}

// TestReactStopsTheAgentOfTheJudgedRunForItsOwnLifetime: a confirmed
// REPEATED_DENIAL under a rule of agents stops the agent the run's record
// names, until its creation plus the rule's lifetime though the run ends
// first; a second run's finding of that agent is covered, and a finding of
// the first run under a rule of runs is a stop of its own.
func TestReactStopsTheAgentOfTheJudgedRunForItsOwnLifetime(t *testing.T) {
	tr := newWiderTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	ends := map[string]time.Time{"run-1": now.Add(5 * time.Minute), "run-2": now.Add(time.Hour)}
	written := tr.reactOver(t, now, ends,
		finding(1, "run-1", denial, confirmed), finding(2, "run-2", denial, confirmed), finding(3, "run-1", outside, confirmed))
	want := []string{
		"stop line 2 agent agent-1 run run-1 finding " + fid(1) + " rule REPEATED_DENIAL expires_at " + policy.FormatIssuedAt(now.Add(10*time.Minute)),
		"covered line 3 agent agent-1 run run-2 finding " + fid(2),
		"stop line 4 run run-1 finding " + fid(3) + " rule STEP_OUTSIDE_PROCEDURE expires_at " + policy.FormatIssuedAt(now.Add(5*time.Minute)),
	}
	if strings.Join(written, "\n") != strings.Join(want, "\n") {
		t.Fatalf("react wrote\n%s\nwant\n%s", strings.Join(written, "\n"), strings.Join(want, "\n"))
	}
	l, err := reaction.Judge(tr.takenRoute(t), reaction.Prefix{}, listBytes(t, tr.stops), now, 0)
	if err != nil || len(l.Entries()) != 2 {
		t.Fatalf("the plane's judge: %d entries, %v", len(l.Entries()), err)
	}
	if e := l.Entries()[0]; e.Target() != (reaction.Target{Scope: reaction.ScopeAgent, Subject: "agent-1"}) || e.RunID != "run-1" {
		t.Errorf("the agent stop names %+v of run %s", e.Target(), e.RunID)
	}
}

// TestStopsLiftNamesExactlyOneSubject: stops lift refuses none or two of
// --run, --agent and --principal, and an empty one, as a usage error; a lift
// of a principal no stop names is refused and writes nothing.
func TestStopsLiftNamesExactlyOneSubject(t *testing.T) {
	tr := newWiderTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	tr.reactOver(t, now, map[string]time.Time{"run-1": now.Add(time.Hour)}, finding(1, "run-1", denial, confirmed))
	for _, args := range [][]string{
		{},
		{"--run", "run-1", "--agent", "agent-1"},
		{"--agent", "agent-1", "--principal", "user-1"},
		{"--run", "run-1", "--principal", "user-1"},
		{"--agent", ""},
	} {
		full := append(append([]string{"--key", tr.keys["alice"]}, args...), tr.stops)
		if code, _, _ := tr.run(t, "stops lift", full...); code != exitUsage {
			t.Errorf("stops lift %v: %d, want %d", args, code, exitUsage)
		}
	}
	before := listBytes(t, tr.stops)
	if code, _, stderr := tr.run(t, "stops lift", "--key", tr.keys["alice"], "--principal", "user-1", tr.stops); code == exitOK ||
		!strings.Contains(stderr, "principal user-1 has no stop") {
		t.Errorf("a lift of a principal no stop names: %d, %q", code, stderr)
	}
	if string(listBytes(t, tr.stops)) != string(before) {
		t.Error("a refused lift wrote the list")
	}
}

// TestStopsLiftOfTheRunLeavesItsAgentStopped: a lift of the run leaves the
// agent stop found on it standing, and a lift of the agent ends it.
func TestStopsLiftOfTheRunLeavesItsAgentStopped(t *testing.T) {
	tr := newWiderTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	tr.reactOver(t, now, map[string]time.Time{"run-1": now.Add(time.Hour)},
		finding(1, "run-1", denial, confirmed), finding(2, "run-1", outside, confirmed))
	code, stdout, stderr := tr.run(t, "stops lift", "--key", tr.keys["alice"], "--run", "run-1", tr.stops)
	if code != exitOK || !strings.Contains(stdout, "run run-1 through line 3") {
		t.Fatalf("stops lift --run: %d, %q, %q", code, stdout, stderr)
	}
	if code, stdout, _ := tr.run(t, "stops list", tr.stops); code != exitOK || !strings.Contains(stdout, "stop line 2 agent agent-1 run run-1") ||
		strings.Contains(stdout, "stop line 3") {
		t.Fatalf("stops list after the run's lift: %d, %q", code, stdout)
	}
	code, stdout, stderr = tr.run(t, "stops lift", "--key", tr.keys["alice"], "--agent", "agent-1", tr.stops)
	if code != exitOK || !strings.Contains(stdout, "agent agent-1 through line 4") || !strings.Contains(stderr, "signed lift of agent agent-1") {
		t.Fatalf("stops lift --agent: %d, %q, %q", code, stdout, stderr)
	}
	if code, stdout, _ := tr.run(t, "stops list", tr.stops); code != exitOK || strings.Contains(stdout, "stop line") ||
		!strings.Contains(stdout, "lifts: 2") {
		t.Fatalf("stops list after the agent's lift: %d, %q", code, stdout)
	}
}

// TestAKeyedRouteLiftsRunsAlone: under a v1alpha1 route, whose stops are of
// runs alone, stops lift refuses --agent and --principal.
func TestAKeyedRouteLiftsRunsAlone(t *testing.T) {
	tr := newStopTree(t)
	for _, flag := range []string{"--agent", "--principal"} {
		args := append(append([]string{"stops", "lift"}, tr.routeArgs()...), "--key", tr.liftKey, flag, "agent-1", tr.stops)
		if code, _, _ := invoke(t, args...); code != exitUsage {
			t.Errorf("stops lift %s under a v1alpha1 route: %d, want %d", flag, code, exitUsage)
		}
	}
}

// TestReactStopsThePrincipalOfTheJudgedRun: a confirmed
// DENIED_ACTION_RETRIED_ARGUMENTS under a rule of principals stops the
// principal the run's record names, not its agent.
func TestReactStopsThePrincipalOfTheJudgedRun(t *testing.T) {
	tr := newWiderTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	written := tr.reactOver(t, now, map[string]time.Time{"run-1": now.Add(time.Hour)},
		finding(1, "run-1", "DENIED_ACTION_RETRIED_ARGUMENTS", confirmed))
	want := "stop line 2 principal user-1 run run-1 finding " + fid(1) + " rule DENIED_ACTION_RETRIED_ARGUMENTS expires_at " +
		policy.FormatIssuedAt(now.Add(10*time.Minute))
	if len(written) != 1 || written[0] != want {
		t.Fatalf("react wrote %q, want %q", written, want)
	}
	l, err := reaction.Judge(tr.takenRoute(t), reaction.Prefix{}, listBytes(t, tr.stops), now, 0)
	if err != nil || len(l.Entries()) != 1 || l.Entries()[0].Target() != (reaction.Target{Scope: reaction.ScopePrincipal, Subject: "user-1"}) {
		t.Fatalf("the plane's judge reads %+v, %v; want one stop of principal user-1", l.Entries(), err)
	}
}

// TestALiftOfAPrincipalNeverEndsAnAgentOfTheSameName: an agent stop of
// agent-1 is not a stop a lift of principal agent-1 ends, so that lift is
// refused and writes nothing, and a lift of agent agent-1 ends it.
func TestALiftOfAPrincipalNeverEndsAnAgentOfTheSameName(t *testing.T) {
	tr := newWiderTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	tr.reactOver(t, now, map[string]time.Time{"run-1": now.Add(time.Hour)}, finding(1, "run-1", denial, confirmed))
	before := listBytes(t, tr.stops)
	if code, _, stderr := tr.run(t, "stops lift", "--key", tr.keys["alice"], "--principal", "agent-1", tr.stops); code == exitOK ||
		!strings.Contains(stderr, "principal agent-1 has no stop") {
		t.Errorf("a lift of principal agent-1 beside a stop of agent agent-1: %d, %q", code, stderr)
	}
	if string(listBytes(t, tr.stops)) != string(before) {
		t.Error("a refused lift wrote the list")
	}
	if code, stdout, stderr := tr.run(t, "stops lift", "--key", tr.keys["alice"], "--agent", "agent-1", tr.stops); code != exitOK ||
		!strings.Contains(stdout, "agent agent-1 through line 2") {
		t.Errorf("a lift of agent agent-1: %d, %q, %q", code, stdout, stderr)
	}
}

// TestAStopWhoseSubjectTheRunLacksStopsThePass: a finding under a rule of
// agents whose run's record names no agent has no subject to stop. That is
// no refusal of the list's bound or of its judge, so the pass stops there,
// with nothing written, rather than name it unwritten and go on.
func TestAStopWhoseSubjectTheRunLacksStopsThePass(t *testing.T) {
	tr := newWiderTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	route := tr.takenRoute(t)
	list, _, err := judgedList(tr.stops, route, now)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, id string) (runs.Record, error) {
		return runs.Record{ID: id, Who: runs.Identity{ProjectID: "orders", TenantID: "acme", PrincipalType: "user",
			PrincipalID: "user-1"}, ExpiresAt: now.Add(time.Hour)}, nil
	}
	r := newReactor(context.Background(), route, list, lookup, tr.stops, clockAt(now))
	var records []*findingv1alpha1.Record
	for _, fr := range []*findingv1alpha1.FindingRecord{finding(1, "run-1", denial, confirmed), finding(2, "run-1", outside, confirmed)} {
		records = append(records, &findingv1alpha1.Record{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: fr}})
	}
	before := listBytes(t, tr.stops)
	if err := r.each(records); !errors.Is(err, reaction.ErrStopSubject) {
		t.Fatalf("each = %v, want the pass stopped on the missing subject", err)
	}
	if r.stops != 0 || len(r.written) != 0 || len(r.unwritten) != 0 {
		t.Errorf("%d stops, written %q, unwritten %q; want the pass stopped at the first finding", r.stops, r.written, r.unwritten)
	}
	if !bytes.Equal(listBytes(t, tr.stops), before) {
		t.Error("a pass stopped on a missing subject changed the list")
	}
}
