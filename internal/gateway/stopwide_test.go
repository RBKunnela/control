package gateway_test

import (
	"context"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/reaction"
)

// widePlaneOver is a plane serving opened runs of root-1 to root-3 under the
// snapshot of l read at base(), whose harness admits under run-a of root-1.
func widePlaneOver(t *testing.T, l *wideList, mut ...func(*gateway.Config)) *harness {
	t.Helper()
	opts := append([]func(*gateway.Config){withRuns(newRuns("root-1", "root-2", "root-3")), withStops(newStopSource(l.readAt(base())))}, mut...)
	h := build(t, modeEnforce, snapshot(t, allowReads), opts...)
	h.run = opened("run-a", "root-1")
	return h
}

// readUnder admits a read named req under run, nil for a call with no run.
func readUnder(h *harness, run *gateway.OpenedRun, req string) gateway.Disposition {
	h.run = run
	return h.admit(requestNamed(tool(readEnvelope()), req), []byte(`{}`))
}

// expectExecuted fails unless d was executed.
func expectExecuted(t *testing.T, what string, d gateway.Disposition) {
	t.Helper()
	if d.Action != core.Execute {
		t.Errorf("%s: Action = %d, codes %v; want it run", what, d.Action, d.Decision.GetReasonCodes())
	}
}

// TestAnAgentStopBlocksEveryRunOfThePlane: two operators' runs overlap on one
// plane, which serves one agent. A stop of that agent, made from a finding
// about the first run, blocks the first run, the second, a run opened after
// the stop and a call with no run, each AGENT_OR_PRINCIPAL_STOPPED; the
// listing is the listing under no stop.
func TestAnAgentStopBlocksEveryRunOfThePlane(t *testing.T) {
	l := newWideList(t, "tenant-1")
	l.stop(reaction.ScopeAgent, "agent-1")
	h := widePlaneOver(t, l)
	for _, c := range []struct {
		name string
		run  *gateway.OpenedRun
	}{
		{"the run the finding was about", opened("run-a", "root-1")},
		{"the other operator's run", opened("run-b", "root-2")},
		{"a run opened after the stop", opened("run-c", "root-3")},
	} {
		expectPlaneBlock(t, h, readUnder(h, c.run, c.name), verdictDeny, codeSubjectStopped)
	}
	expectPlaneBlock(t, h, readUnder(h, nil, "no run"), verdictDeny, codeSubjectStopped, codeEvidenceUnavailable)
	none := build(t, modeEnforce, snapshot(t, allowReads), withRuns(newRuns("root-1")))
	for _, env := range []func() *controlv1.ActionEnvelope{readEnvelope, writeEnvelope} {
		a := admission(tool(env()), nil)
		a.Run = opened("run-a", "root-1")
		got, want := h.p.Preview(context.Background(), a), none.p.Preview(context.Background(), a)
		if got.Listing != want.Listing || !slices.Equal(got.Decision.GetReasonCodes(), want.Decision.GetReasonCodes()) {
			t.Errorf("%s previews as %v %v under an agent stop, want %v %v", env().GetAction().GetName(),
				got.Listing, got.Decision.GetReasonCodes(), want.Listing, want.Decision.GetReasonCodes())
		}
	}
}

// TestARunStopBlocksOneRunAndBothCodesStand: a stop of the first run blocks
// it RUN_STOPPED and leaves the second running; with the agent stopped too,
// the first run's call lists both codes, the run's first.
func TestARunStopBlocksOneRunAndBothCodesStand(t *testing.T) {
	l := newWideList(t, "tenant-1")
	l.stop(reaction.ScopeRun, "run-a")
	h := widePlaneOver(t, l)
	expectPlaneBlock(t, h, readUnder(h, opened("run-a", "root-1"), "run-a"), verdictDeny, codeRunStopped)
	expectExecuted(t, "the other run", readUnder(h, opened("run-b", "root-2"), "run-b"))
	l.stop(reaction.ScopeAgent, "agent-1")
	h = widePlaneOver(t, l)
	expectPlaneBlock(t, h, readUnder(h, opened("run-a", "root-1"), "both"), verdictDeny, codeRunStopped, codeSubjectStopped)
	expectPlaneBlock(t, h, readUnder(h, opened("run-b", "root-2"), "agent"), verdictDeny, codeSubjectStopped)
}

// TestARunLiftLeavesTheAgentStopStanding: a lift of the run the agent stop
// was found on ends the run's stop and not the agent's; a lift of the agent
// ends it, and every run runs again.
func TestARunLiftLeavesTheAgentStopStanding(t *testing.T) {
	l := newWideList(t, "tenant-1")
	l.stop(reaction.ScopeAgent, "agent-1")
	runStop := l.stop(reaction.ScopeRun, "run-a")
	l.lift(reaction.ScopeRun, "run-a", runStop)
	h := widePlaneOver(t, l)
	expectPlaneBlock(t, h, readUnder(h, opened("run-a", "root-1"), "run-a"), verdictDeny, codeSubjectStopped)
	expectPlaneBlock(t, h, readUnder(h, opened("run-b", "root-2"), "run-b"), verdictDeny, codeSubjectStopped)
	l.lift(reaction.ScopeAgent, "agent-1", runStop)
	h = widePlaneOver(t, l)
	expectExecuted(t, "run-a after the agent's lift", readUnder(h, opened("run-a", "root-1"), "run-a"))
	expectExecuted(t, "run-b after the agent's lift", readUnder(h, opened("run-b", "root-2"), "run-b"))
}

// TestAStopOfAnotherTenantsPrincipalBlocksNothing: a principal stop under a
// route of another tenant names the plane's principal and blocks none of
// its calls, with a run or without.
func TestAStopOfAnotherTenantsPrincipalBlocksNothing(t *testing.T) {
	l := newWideList(t, "tenant-2")
	l.stop(reaction.ScopePrincipal, "user-1")
	h := widePlaneOver(t, l)
	expectExecuted(t, "a call of run-a", readUnder(h, opened("run-a", "root-1"), "run-a"))
	if d := readUnder(h, nil, "no run"); slices.Contains(d.Decision.GetReasonCodes(), codeSubjectStopped) {
		t.Errorf("a call with no run reads %v under another tenant's stop", d.Decision.GetReasonCodes())
	}
	own := newWideList(t, "tenant-1")
	own.stop(reaction.ScopePrincipal, "user-1")
	h = widePlaneOver(t, own)
	expectPlaneBlock(t, h, readUnder(h, opened("run-b", "root-2"), "own"), verdictDeny, codeSubjectStopped)
}

// TestTheSubjectIsTheListenersNeverTheRunsOrTheEnvelopes: the plane matches
// a stop of an agent or a principal against the identity its configuration
// names, so a call whose envelope and run name agent-1 and user-1 is
// blocked by a stop of the agent-9 and admin-1 the listener serves, and runs
// under a stop of agent-1 when the listener serves agent-9.
func TestTheSubjectIsTheListenersNeverTheRunsOrTheEnvelopes(t *testing.T) {
	served := func(agent, principal string) func(*gateway.Config) {
		return func(c *gateway.Config) {
			c.Listener.AgentID, c.Listener.PrincipalID = agent, principal
		}
	}
	for _, c := range []struct{ scope, subject string }{
		{reaction.ScopeAgent, "agent-9"}, {reaction.ScopePrincipal, "admin-1"},
	} {
		l := newWideList(t, "tenant-1")
		l.stop(c.scope, c.subject)
		h := widePlaneOver(t, l, served("agent-9", "admin-1"))
		expectPlaneBlock(t, h, readUnder(h, opened("run-a", "root-1"), "listener"), verdictDeny, codeSubjectStopped)
	}
	l := newWideList(t, "tenant-1")
	l.stop(reaction.ScopeAgent, "agent-1")
	h := widePlaneOver(t, l, served("agent-9", "admin-1"))
	expectExecuted(t, "a stop of the envelope's agent on a plane serving another", readUnder(h, opened("run-a", "root-1"), "envelope"))
}

// heldUnderAWideList holds a refund of run-a under a clear 3.0 list of
// tenant-1 and approves it, and returns the list to stop the agent on.
func heldUnderAWideList(t *testing.T, store **stepStore) (*harness, *stopSource, *wideList) {
	t.Helper()
	l := newWideList(t, "tenant-1")
	src := newStopSource(l.readAt(base()))
	h := stopPlane(t, modeEnforce, []string{approveRefunds}, src, withStepStore(store))
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	return h, src, l
}

// TestAnAgentStopDuringTheApprovalLookupBlocksTheResume: an agent stop
// written while the store looks the hold up is read at the check before the
// approval is consumed, so the retry is blocked AGENT_OR_PRINCIPAL_STOPPED,
// nothing is consumed and the hold stands.
func TestAnAgentStopDuringTheApprovalLookupBlocksTheResume(t *testing.T) {
	var store *stepStore
	h, src, l := heldUnderAWideList(t, &store)
	l.stop(reaction.ScopeAgent, "agent-1")
	store.onFind = func() { src.set(l.readAt(base())) }
	expectPlaneBlock(t, h, h.admit(retry(t, "req-2"), refundArgs()), verdictDeny, codeSubjectStopped)
	if h.spent() != 0 {
		t.Errorf("the blocked retry consumed %d approval(s)", h.spent())
	}
	if h.p.Stats().Held != 1 {
		t.Errorf("Stats.Held = %d, want the hold standing", h.p.Stats().Held)
	}
}

// TestAnAgentStopReadAfterTheConsumeClosesTheHeldTrail: an agent stop
// written while the approval is consumed is read before the execution
// starts, so nothing runs and the held trail closes AGENT_OR_PRINCIPAL_STOPPED.
func TestAnAgentStopReadAfterTheConsumeClosesTheHeldTrail(t *testing.T) {
	var store *stepStore
	h, src, l := heldUnderAWideList(t, &store)
	l.stop(reaction.ScopePrincipal, "user-1")
	h.ledger.afterSpend = func() { src.set(l.readAt(base())) }
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictDeny, codeSubjectStopped, gateway.PDPType)
	if d.ExecutionID != "" {
		t.Errorf("a stopped resume was handed execution %q", d.ExecutionID)
	}
	if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 || s.Blocks[codeSubjectStopped] != 1 {
		t.Errorf("Stats = %+v; want nothing run and the block counted as AGENT_OR_PRINCIPAL_STOPPED", s)
	}
}
