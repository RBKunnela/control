package gateway_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// memRuns is a runs directory in memory: a state per root, and switches that
// make a read or a raise fail.
type memRuns struct {
	mu        sync.Mutex
	states    map[string]gateway.RunState
	failState bool
	failRaise bool
	raises    int
	onRaise   func()
}

func newRuns(roots ...string) *memRuns {
	m := &memRuns{states: map[string]gateway.RunState{}}
	for _, root := range roots {
		m.states[root] = gateway.RunState{Trusted: true, MaxRead: sensPublic}
	}
	return m
}

func (*memRuns) Resolve(context.Context, string, gateway.RunIdentity, time.Time) (gateway.OpenedRun, error) {
	return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunUnknown}
}

func (m *memRuns) State(_ context.Context, root string) (gateway.RunState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[root]
	if m.failState || !ok {
		return gateway.RunState{}, errors.New("state: unreadable")
	}
	return s, nil
}

func (m *memRuns) Raise(_ context.Context, root string, join func(gateway.RunState) gateway.RunState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[root]
	if m.failRaise || !ok {
		return errors.New("state: not raised")
	}
	if m.onRaise != nil {
		m.onRaise()
	}
	m.states[root] = join(s)
	m.raises++
	return nil
}

func (m *memRuns) state(root string) gateway.RunState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[root]
}

// withRuns serves opened runs from m through an adapter that presents them.
func withRuns(m *memRuns) func(*gateway.Config) {
	return func(c *gateway.Config) {
		caps := c.Adapter.Capabilities()
		caps.PresentsRuns = true
		c.Adapter = fakeAdapter{name: c.Adapter.Name(), caps: caps}
		c.Runs = m
	}
}

// opened is a run of user-1 and agent-1, the identity readEnvelope carries.
func opened(id, root string) *gateway.OpenedRun {
	return &gateway.OpenedRun{
		ID: id, Root: root, Expires: base().Add(time.Hour),
		Who: gateway.RunIdentity{TenantID: "tenant-1", PrincipalID: "user-1", AgentID: "agent-1"},
	}
}

func under(a gateway.Admission, r *gateway.OpenedRun) gateway.Admission {
	a.Run = r
	return a
}

var allModes = []controlv1.EnforcementMode{modeObserve, modeApprove, modeEnforce, modeLockdown}

// TestAnOpenedRunNamesTheTrailAndRaisesItsRoot: the trail carries the opened
// run's id and the root whose state was used, and what the result brings in
// is written to the root.
func TestAnOpenedRunNamesTheTrailAndRaisesItsRoot(t *testing.T) {
	runs := newRuns("root-1")
	h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(runs))
	d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), opened("run-a", "root-1")))
	if d.Action != core.Execute {
		t.Fatalf("Action = %d, %s %v; want Execute", d.Action, d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	expectTags(t, h.proposedTags(t, "r-1"), "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC", "flow.v1.root=root-1")
	for _, e := range h.trailOf("r-1") {
		if e.GetRunId() != "run-a" {
			t.Errorf("%s carries run %q, want run-a", e.GetKind(), e.GetRunId())
		}
	}
	if got := runs.state("root-1"); got.Trusted || got.MaxRead != controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED {
		t.Errorf("root-1 after an untrusted, undeclared result = %+v, want untrusted and unknown", got)
	}
	if s := h.p.Stats(); s.Runs != 0 || s.Executed != 1 {
		t.Errorf("Stats: %d local runs, %d executed; want 0 and 1", s.Runs, s.Executed)
	}
}

// TestTheRootIsRaisedBeforeTheExecutionStarts: when the raise happens, the
// trail holds no ACTION_STARTED yet.
func TestTheRootIsRaisedBeforeTheExecutionStarts(t *testing.T) {
	runs := newRuns("root-1")
	h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(runs))
	var atRaise []controlv1.EventKind
	runs.onRaise = func() { atRaise = kindsOf(h.trailOf("r-1")) }
	h.admitA(under(returning(readOf("r-1", "user-1"), 0, sensConfidential), opened("run-a", "root-1")))
	expectKinds(t, atRaise, []controlv1.EventKind{kindProposed, kindDecided})
	expectKinds(t, kindsOf(h.trailOf("r-1")), []controlv1.EventKind{kindProposed, kindDecided, kindStarted})
}

// TestARaiseThatFailsStartsNothing, in every mode: the call is blocked with
// nothing recorded as started and nothing kept open.
func TestARaiseThatFailsStartsNothing(t *testing.T) {
	for _, mode := range allModes {
		t.Run(mode.String(), func(t *testing.T) {
			runs := newRuns("root-1")
			runs.failRaise = true
			h := build(t, mode, snapshot(t, allowReads), withRuns(runs))
			d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, sensConfidential), opened("run-a", "root-1")))
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			expectKinds(t, kindsOf(h.trailOf("r-1")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
			if s := h.p.Stats(); s.Open != 0 || s.Executed != 0 || s.RunStateFailures != 1 {
				t.Errorf("Stats: %d open, %d executed, %d state failures; want 0, 0 and 1", s.Open, s.Executed, s.RunStateFailures)
			}
		})
	}
}

// TestACallTheRunsDirectoryCannotVouchForIsBlocked, in every mode: a state
// that cannot be read, a root with no state, no run at all, and a run whose
// record names another identity.
func TestACallTheRunsDirectoryCannotVouchForIsBlocked(t *testing.T) {
	cases := map[string]struct {
		run  func() *gateway.OpenedRun
		runs func() *memRuns
	}{
		"an unreadable state":  {func() *gateway.OpenedRun { return opened("run-a", "root-1") }, func() *memRuns { r := newRuns("root-1"); r.failState = true; return r }},
		"a root with no state": {func() *gateway.OpenedRun { return opened("run-a", "root-9") }, func() *memRuns { return newRuns("root-1") }},
		"no run":               {func() *gateway.OpenedRun { return nil }, func() *memRuns { return newRuns("root-1") }},
		"another tenant": {func() *gateway.OpenedRun {
			r := opened("run-a", "root-1")
			r.Who.TenantID = "tenant-2"
			return r
		}, func() *memRuns { return newRuns("root-1") }},
		"another principal type": {func() *gateway.OpenedRun {
			r := opened("run-a", "root-1")
			r.Who.PrincipalType = "service"
			return r
		}, func() *memRuns { return newRuns("root-1") }},
		"another principal": {func() *gateway.OpenedRun {
			r := opened("run-a", "root-1")
			r.Who.PrincipalID = "user-2"
			return r
		}, func() *memRuns { return newRuns("root-1") }},
		"another agent": {func() *gateway.OpenedRun {
			r := opened("run-a", "root-1")
			r.Who.AgentID = "agent-2"
			return r
		}, func() *memRuns { return newRuns("root-1") }},
		"a run with no root": {func() *gateway.OpenedRun { return opened("run-a", "") }, func() *memRuns { return newRuns("") }},
		"a run with no id":   {func() *gateway.OpenedRun { return opened("", "root-1") }, func() *memRuns { return newRuns("root-1") }},
	}
	stateFailures := map[string]uint64{"an unreadable state": 1, "a root with no state": 1}
	for name, tc := range cases {
		for _, mode := range allModes {
			t.Run(name+"/"+mode.String(), func(t *testing.T) {
				runs := tc.runs()
				h := build(t, mode, snapshot(t, allowReads), withRuns(runs))
				d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), tc.run()))
				expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
				expectTags(t, h.proposedTags(t, "r-1"), "flow.v1.state=uncomputed")
				if s := h.p.Stats(); s.Executed != 0 || s.FlowUncomputed != 1 || runs.raises != 0 || s.RunStateFailures != stateFailures[name] {
					t.Errorf("Stats: %d executed, %d uncomputed, %d raises, %d state failures; want 0, 1, 0 and %d",
						s.Executed, s.FlowUncomputed, runs.raises, s.RunStateFailures, stateFailures[name])
				}
			})
		}
	}
}

// TestTwoRunsOfOneAgentStayApart: one run takes in something untrusted and
// confidential, so its next call to an untrusted destination is denied, while
// another run of the same principal and agent is not; a child opened under
// the first reads the first's state.
func TestTwoRunsOfOneAgentStayApart(t *testing.T) {
	runs := newRuns("run-a", "run-b")
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic), withRuns(runs))
	h.admitA(under(returning(readOf("a-1", "user-1"), 0, sensConfidential), opened("run-a", "run-a")))
	expectVerdict(t, h.admitA(under(returning(readOf("a-2", "user-1"), 0, 0), opened("run-a", "run-a"))), verdictDeny)
	if d := h.admitA(under(returning(readOf("b-1", "user-1"), 0, 0), opened("run-b", "run-b"))); d.Action != core.Execute {
		t.Errorf("the other run: %s %v, want an allow", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	expectVerdict(t, h.admitA(under(returning(readOf("c-1", "user-1"), 0, 0), opened("run-c", "run-a"))), verdictDeny)
	expectTags(t, h.proposedTags(t, "c-1"), "flow.v1.untrusted=true", "flow.v1.max_read=CONFIDENTIAL", "flow.v1.root=run-a")
}

// TestAResultTheStateCoversWritesNothing: a root's state only rises, so a
// result it already covers is not written, and a result that raises it is.
func TestAResultTheStateCoversWritesNothing(t *testing.T) {
	runs := newRuns("clean")
	runs.states["tainted"] = gateway.RunState{}
	h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(runs))
	h.admitA(under(returning(readOf("t-1", "user-1"), 0, sensSecret), opened("run-t", "tainted")))
	h.admitA(under(returning(readOf("c-1", "user-1"), zoneInternal, sensPublic), opened("run-c", "clean")))
	if runs.raises != 0 {
		t.Fatalf("%d raise(s) for results the states already cover", runs.raises)
	}
	h.admitA(under(returning(readOf("c-2", "user-1"), zoneInternal, sensInternal), opened("run-c", "clean")))
	if got := runs.state("clean"); runs.raises != 1 || !got.Trusted || got.MaxRead != sensInternal {
		t.Errorf("after an INTERNAL result: %d raise(s), state %+v; want 1 and trusted INTERNAL", runs.raises, got)
	}
}

// TestARunThatExpiredBeforeHandOutStartsNothing: the run's expiry is judged
// again by the clock the call reads right before it starts.
func TestARunThatExpiredBeforeHandOutStartsNothing(t *testing.T) {
	for name, expires := range map[string]time.Time{"at the reading": base(), "before it": base().Add(-time.Nanosecond)} {
		t.Run(name, func(t *testing.T) {
			runs := newRuns("root-1")
			h := build(t, modeObserve, snapshot(t, allowReads), withRuns(runs))
			r := opened("run-a", "root-1")
			r.Expires = expires
			d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, sensSecret), r))
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			if runs.raises != 0 || slices.Contains(kindsOf(h.trailOf("r-1")), kindStarted) {
				t.Errorf("an expired run raised %d time(s) or started: %v", runs.raises, kindsOf(h.trailOf("r-1")))
			}
		})
	}
	runs := newRuns("root-1")
	h := build(t, modeObserve, snapshot(t, allowReads), withRuns(runs))
	r := opened("run-a", "root-1")
	r.Expires = base().Add(time.Nanosecond)
	if d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), r)); d.Action != core.Execute {
		t.Errorf("a run expiring after the reading: %s %v, want Execute", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
}

// TestAHoldBelongsToItsRun: a retry from another run of the same principal and
// agent is held anew, the first run still resumes its own hold, and once that
// approval is spent the same action from any run is refused as already used.
func TestAHoldBelongsToItsRun(t *testing.T) {
	runs := newRuns("run-a", "run-b")
	h := build(t, modeEnforce, snapshot(t, approveRefunds), withRuns(runs))
	admitIn := func(env *controlv1.ActionEnvelope, r *gateway.OpenedRun) gateway.Disposition {
		return h.admitA(under(admission(env, refundArgs()), r))
	}
	first := admitIn(refundEnvelope(t, refundArgs()), opened("run-a", "run-a"))
	if first.Action != core.AwaitApproval {
		t.Fatalf("the first refund: Action = %d", first.Action)
	}
	other := admitIn(retry(t, "req-2"), opened("run-b", "run-b"))
	if other.Action != core.AwaitApproval || other.Pending == nil || other.Pending.ApprovalID == first.Pending.ApprovalID {
		t.Fatalf("the retry from run-b: Action = %d, pending %+v; want a hold of its own", other.Action, other.Pending)
	}
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base().Add(time.Minute)); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.clock.set(base().Add(2 * time.Minute))
	if d := admitIn(retry(t, "req-3"), opened("run-b", "run-b")); d.Action != core.AwaitApproval || d.Pending.ApprovalID != other.Pending.ApprovalID {
		t.Fatalf("run-b after run-a's approval: Action = %d, pending %+v; want run-b's own hold", d.Action, d.Pending)
	}
	if d := admitIn(retry(t, "req-4"), opened("run-a", "run-a")); d.Action != core.Execute {
		t.Fatalf("run-a's approved retry: Action = %d, %v", d.Action, d.Decision.GetReasonCodes())
	}
	if err := h.store.Answer(other.Pending.ApprovalID, approved, "alice", "", base().Add(3*time.Minute)); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.clock.set(base().Add(4 * time.Minute))
	used := admitIn(retry(t, "req-5"), opened("run-c", "run-a"))
	expectBlock(t, used, verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)
}

// TestARunThatExpiresWhileItsStartIsAppendedIsAborted: the run is open when the
// call is handed toward execution and expires while ACTION_STARTED is written,
// so the execution is closed as never sent, not handed out.
func TestARunThatExpiresWhileItsStartIsAppendedIsAborted(t *testing.T) {
	runs := newRuns("root-1")
	h := build(t, modeObserve, snapshot(t, allowReads), withRuns(runs))
	r := opened("run-a", "root-1")
	r.Expires = base().Add(time.Second)
	h.sink.hook(kindStarted, func() { h.clock.set(base().Add(time.Second)) })
	d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), r))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("r-1")), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindFailed})
	if failed := h.trailOf("r-1")[3].GetResult(); failed.GetToolProtocolStatus() != codeEvidenceUnavailable || failed.GetExecutedActionDigest() != "" {
		t.Errorf("ACTION_FAILED carries %+v", failed)
	}
	if s := h.p.Stats(); s.Open != 0 || s.Executed != 0 {
		t.Errorf("Stats: %d open, %d executed; want 0 and 0", s.Open, s.Executed)
	}
}

// TestACallBlockedForItsRootsStateNamesItsRun: a run the listener resolved
// and whose identity is the envelope's is named on the trail of the call its
// unreadable state blocked; a run nobody vouched for is not.
func TestACallBlockedForItsRootsStateNamesItsRun(t *testing.T) {
	runs := newRuns("root-1")
	runs.failState = true
	h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(runs))
	h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), opened("run-a", "root-1")))
	other := opened("run-b", "root-1")
	other.Who.AgentID = "agent-2"
	h.admitA(under(returning(readOf("r-2", "user-1"), 0, 0), other))
	for request, want := range map[string]string{"r-1": "run-a", "r-2": ""} {
		trail := h.trailOf(request)
		expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
		for _, e := range trail {
			if e.GetRunId() != want {
				t.Errorf("%s: %s carries run %q, want %q", request, e.GetKind(), e.GetRunId(), want)
			}
		}
	}
}

// stuckRuns is a runs directory whose root lock another holder never lets
// go: a raise waits until its context ends.
type stuckRuns struct{ *memRuns }

func (stuckRuns) Raise(ctx context.Context, _ string, _ func(gateway.RunState) gateway.RunState) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestARaiseThatWaitsPastItsBoundStartsNothing: a raise waits for its root's
// lock no longer than its bound, then the call is blocked with nothing
// started, though the call's own context has no deadline.
func TestARaiseThatWaitsPastItsBoundStartsNothing(t *testing.T) {
	defer gateway.SetRunStateWait(20 * time.Millisecond)()
	stuck := stuckRuns{newRuns("root-1")}
	h := build(t, modeEnforce, snapshot(t, allowReads), func(c *gateway.Config) {
		withRuns(stuck.memRuns)(c)
		c.Runs = stuck
	})
	done := make(chan gateway.Disposition, 1)
	go func() {
		done <- h.admitA(under(returning(readOf("r-1", "user-1"), 0, sensSecret), opened("run-a", "root-1")))
	}()
	select {
	case d := <-done:
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectKinds(t, kindsOf(h.trailOf("r-1")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	case <-time.After(30 * time.Second):
		t.Fatal("the raise waited past its bound")
	}
}

// TestNoCallIsHeldUnderARunThatLapsed: a hold under an expired run is one no
// retry could reach, since the listener refuses the run's token, so the call
// is blocked and nothing is held.
func TestNoCallIsHeldUnderARunThatLapsed(t *testing.T) {
	runs := newRuns("run-a")
	h := build(t, modeEnforce, snapshot(t, approveRefunds), withRuns(runs))
	r := opened("run-a", "run-a")
	r.Expires = base()
	d := h.admitA(under(admission(refundEnvelope(t, refundArgs()), refundArgs()), r))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if slices.Contains(kindsOf(h.trailOf("req-1")), kindApprovalRequested) {
		t.Errorf("a call under a lapsed run was held: %v", kindsOf(h.trailOf("req-1")))
	}
	if s := h.p.Stats(); s.Held != 0 || s.Pending != 0 {
		t.Errorf("Stats: %d held, %d pending; want 0 and 0", s.Held, s.Pending)
	}
}
