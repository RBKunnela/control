package gateway_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
)

// stepStore runs onFind during the next Find it is armed for and hides the
// held requests from the Find calls it is told to.
type stepStore struct {
	gateway.ApprovalStore
	onFind    func()
	hideFinds atomic.Int64
}

func (s *stepStore) Find(ctx context.Context, b approval.Binding, now time.Time) ([]gateway.Held, error) {
	if run := s.onFind; run != nil {
		s.onFind = nil
		run()
	}
	if s.hideFinds.Add(-1) >= 0 {
		return nil, gateway.ErrNoApproval
	}
	return s.ApprovalStore.Find(ctx, b, now)
}

func withStepStore(store **stepStore) func(*gateway.Config) {
	return func(c *gateway.Config) {
		*store = &stepStore{ApprovalStore: c.Approvals}
		c.Approvals = *store
	}
}

// clearAt is the snapshot a plane reads at now from a file with no entry.
func clearAt(t *testing.T, now time.Time) pause.Snapshot {
	t.Helper()
	s := pause.Read(pauseFile(t), now, pauseInterval)
	if s.State() != pause.Clear {
		t.Fatalf("the empty pause file read as %s, %q", s.State(), s.Cause())
	}
	return s
}

// stepChanges are the two ways the state a call took can stop vouching for
// it while a slow step runs: a pause written, and the snapshot growing older
// than three poll intervals by the plane's clock.
var stepChanges = []struct {
	name    string
	apply   func(t *testing.T, h *harness)
	verdict controlv1.Verdict
	code    string
}{
	{"a global pause written", func(t *testing.T, h *harness) { h.pause.set(paused(t, pauseGlobal)) }, verdictDeny, codePaused},
	{"one tick past three intervals", func(_ *testing.T, h *harness) {
		h.clock.set(base().Add(3*pauseInterval + time.Nanosecond))
	}, verdictIndeterminate, codePauseStateUnavailable},
}

// TestAPauseDuringTheApprovalLookupBlocksTheResume: a state that stops
// vouching for an approved retry while the store looks its hold up blocks the
// retry on a trail of its own before anything is spent; the hold stands, and
// the next retry after the lift resumes it and runs once.
func TestAPauseDuringTheApprovalLookupBlocksTheResume(t *testing.T) {
	for _, change := range stepChanges {
		t.Run(change.name, func(t *testing.T) {
			var store *stepStore
			ledger := &fakeLedger{}
			h := build(t, modeEnforce, snapshot(t, approveRefunds), withStepStore(&store), overLedger(ledger))
			first := hold(t, h)
			if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			h.pause.set(paused(t))
			store.onFind = func() { change.apply(t, h) }
			blocked := h.admit(retry(t, "req-2"), refundArgs())
			expectPlaneBlock(t, h, blocked, change.verdict, change.code)
			if spends, _ := ledger.asked(); spends != 0 {
				t.Errorf("the blocked retry spent %d approval(s)", spends)
			}
			expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
			if h.p.Stats().Held != 1 {
				t.Errorf("Stats.Held = %d after the blocked retry, want the hold standing", h.p.Stats().Held)
			}

			h.pause.set(clearAt(t, h.clock.read()))
			run := h.admit(retry(t, "req-3"), refundArgs())
			if run.Action != core.Execute {
				t.Fatalf("the retry after the lift: Action = %d, codes %v", run.Action, run.Decision.GetReasonCodes())
			}
			capped := []byte(`{"amount":1000,"currency":"EUR","ssn":"x"}`)
			if err := h.p.Close(context.Background(), run, capped, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
				t.Fatalf("Close: %v", err)
			}
			held := h.trailOf("req-1")
			expectKinds(t, kindsOf(held), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindCompleted})
			if err := evidence.ValidateChain(held); err != nil {
				t.Errorf("ValidateChain over the held trail: %v", err)
			}
			if spends, _ := ledger.asked(); h.p.Stats().Executed != 1 || spends != 1 {
				t.Errorf("Executed = %d, spent = %d; want the held request run once", h.p.Stats().Executed, spends)
			}
		})
	}
}

// TestAPauseBetweenTwoSpendsBlocksTheSecond: with two approved held requests
// the retry equals, the first of which the plane settled, a pause written
// while the first one's approval is offered to the ledger blocks the retry
// before the second one's approval is spent.
func TestAPauseBetweenTwoSpendsBlocksTheSecond(t *testing.T) {
	var store *stepStore
	ledger := &fakeLedger{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), withStepStore(&store), overLedger(ledger))
	first := hold(t, h)
	store.hideFinds.Store(1)
	second := h.admit(retry(t, "req-2"), refundArgs())
	if second.Action != core.AwaitApproval || second.Pending == nil {
		t.Fatalf("setup: the second hold is %d, codes %v", second.Action, second.Decision.GetReasonCodes())
	}
	for _, d := range []gateway.Disposition{first, second} {
		if err := h.store.Answer(d.Pending.ApprovalID, approved, "alice", "", base().Add(time.Minute)); err != nil {
			t.Fatalf("Answer: %v", err)
		}
	}
	a := approvalOfHoldIn(t, h.store, first, 2)
	if _, err := ledger.MemoryLedger.Settle(ctx(), bindingOfHeld(t, a), a.GetRequestId(), a.GetApprovalId(), base()); err != nil {
		t.Fatal(err)
	}
	h.clock.set(base().Add(time.Minute))
	h.pause.set(clearAt(t, base().Add(time.Minute)))
	ledger.beforeSpend = func() { h.pause.set(paused(t, pauseGlobal)) }
	d := h.admit(retry(t, "req-3"), refundArgs())
	expectPlaneBlock(t, h, d, verdictDeny, codePaused)
	if spends, _ := ledger.asked(); spends != 1 {
		t.Errorf("the retry offered %d approval(s) to the ledger; want once, for the settled first hold", spends)
	}
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if s := h.p.Stats(); s.Executed != 0 || s.Held != 2 {
		t.Errorf("Executed = %d, Held = %d; want nothing run and both holds standing", s.Executed, s.Held)
	}
}

// TestAPauseDuringTheLastAppendBlocksTheStart: a state that stops vouching
// for a call while its POLICY_DECIDED is appended blocks it before an
// execution is handed out.
func TestAPauseDuringTheLastAppendBlocksTheStart(t *testing.T) {
	for _, change := range stepChanges {
		t.Run(change.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads))
			h.pause.set(paused(t))
			h.sink.hook(kindDecided, func() { change.apply(t, h) })
			d := h.admit(tool(readEnvelope()), []byte(`{}`))
			expectPlaneBlock(t, h, d, change.verdict, change.code)
			if d.ExecutionID != "" {
				t.Errorf("a blocked call was handed execution %q", d.ExecutionID)
			}
			if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 {
				t.Errorf("Executed = %d, Open = %d; want nothing run", s.Executed, s.Open)
			}
		})
	}
}

// TestAPauseDuringTheApprovalRecordBlocksTheStart: a pause written while a
// resume appends APPROVAL_DECIDED closes the held trail with the plane's
// block, the approval spent and nothing run, and its journal entry goes with
// the closed trail.
func TestAPauseDuringTheApprovalRecordBlocksTheStart(t *testing.T) {
	j := &journalDouble{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(cfg *gateway.Config) { cfg.Journal = j })
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.pause.set(paused(t))
	h.sink.hook(kindApprovalDecided, func() { h.pause.set(paused(t, pauseGlobal)) })
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictDeny, codePaused, gateway.PDPType)
	if d.ExecutionID != "" {
		t.Errorf("a blocked resume was handed execution %q", d.ExecutionID)
	}
	expectOneChain(t, h, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindBlocked})
	expectNoEntry(t, j)
	if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 || s.Held != 0 || s.Blocks[codePaused] != 1 {
		t.Errorf("Stats = %+v; want nothing run or open and the block counted as PAUSED", s)
	}
}
