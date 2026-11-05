package gateway_test

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// TestAnAgentsCancelNeverDropsTheClosingRecord: the context a closing comes
// with may already be done, an agent having cancelled the call once it was
// handed out. The call ran or was aborted all the same, so its trail is
// closed, nothing is counted as a sink failure and material calls are not
// halted.
func TestAnAgentsCancelNeverDropsTheClosingRecord(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, closeIt := range map[string]func(*harness) error{
		"closed with the bytes sent": func(h *harness) error {
			d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
			return h.p.Close(cancelled, d, []byte(`{"k":1}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS))
		},
		"closed with nothing sent": func(h *harness) error {
			d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
			return h.p.Close(cancelled, d, nil, nil)
		},
		"aborted": func(h *harness) error {
			d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
			return h.p.Abort(cancelled, d, gateway.AbortUntranslatable)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowWrites))
			_ = closeIt(h)
			events := h.events()
			if last := events[len(events)-1].GetKind(); last != kindCompleted && last != kindFailed {
				t.Fatalf("the trail ends at %s", last)
			}
			if err := evidence.ValidateChain(events); err != nil {
				t.Errorf("ValidateChain: %v", err)
			}
			if s := h.p.Stats(); s.SinkFailuresAfterEffect != 0 || s.Halted {
				t.Errorf("stats after a cancelled closing: %+v", s)
			}
		})
	}
}

// TestAnAgentsCancelNeverStrandsAnotherRequestsExpiredHold: a call reserving
// its trail closes the holds that expired on the way, which are other
// requests'; its own cancellation must not leave their trails open.
func TestAnAgentsCancelNeverStrandsAnotherRequestsExpiredHold(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds))
	hold(t, h)
	h.clock.set(base().Add(time.Hour))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	env := writeEnvelope()
	env.RequestId = "req-9"
	h.p.Admit(cancelled, admission(env, []byte(`{"k":1}`)))
	trail := h.trailOf("req-1")
	if last := trail[len(trail)-1].GetKind(); last != kindBlocked {
		t.Errorf("the expired hold's trail ends at %s", last)
	}
	if s := h.p.Stats(); s.HeldTrailsLeftOpen != 0 {
		t.Errorf("HeldTrailsLeftOpen = %d after another agent's cancelled call", s.HeldTrailsLeftOpen)
	}
}

// TestAnAgentsCancelAfterTheStartNeverDropsTheLapse: an approval that lapses
// while ACTION_STARTED is appended is aborted with a record, and the agent's
// cancellation after the start does not drop it.
func TestAnAgentsCancelAfterTheStartNeverDropsTheLapse(t *testing.T) {
	r := lapsing(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.sink.hook(kindStarted, func() { r.clock.set(base().Add(lapseTTL)) })
	r.sink.hook(kindFailed, cancel)
	r.p.Admit(ctx, admission(retry(t, "req-2"), refundArgs()))
	expectKinds(t, kindsOf(r.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindFailed})
	if s := r.p.Stats(); s.HeldTrailsLeftOpen != 0 {
		t.Errorf("HeldTrailsLeftOpen = %d after a cancel past the start", s.HeldTrailsLeftOpen)
	}
}

// expectNoSinkFailure asserts the sink failed nothing and no held trail was
// left open: an agent's cancel is not the sink's failure.
func expectNoSinkFailure(t *testing.T, h *harness) {
	t.Helper()
	if s := h.p.Stats(); s.SinkFailuresBeforeEffect != 0 || s.SinkFailuresAfterEffect != 0 || s.HeldTrailsLeftOpen != 0 || s.Halted {
		t.Errorf("Stats after an agent's cancel: %d sink failures before, %d after, %d held trails left open, halted %v; want 0, 0, 0, false",
			s.SinkFailuresBeforeEffect, s.SinkFailuresAfterEffect, s.HeldTrailsLeftOpen, s.Halted)
	}
}

// TestAnAgentsCancelNeverCutsAProposedCallsTrail: a call is proposed once the
// plane decided it, so an agent that cancels before its trail is written, or
// while its block or its start is appended, still has the whole trail
// written, and nothing is counted as the sink's failure.
func TestAnAgentsCancelNeverCutsAProposedCallsTrail(t *testing.T) {
	cases := map[string]struct {
		rules  string
		cancel controlv1.EventKind
		want   []controlv1.EventKind
	}{
		"cancelled before the admission":    {denyWrites, 0, []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}},
		"cancelled before the block record": {denyWrites, kindBlocked, []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}},
		"cancelled before the start record": {allowWrites, kindStarted, []controlv1.EventKind{kindProposed, kindDecided, kindStarted}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, tc.rules))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel == 0 {
				cancel()
			} else {
				h.sink.hook(tc.cancel, cancel)
			}
			h.p.Admit(ctx, admission(writeEnvelope(), []byte(`{"k":1}`)))
			expectKinds(t, h.kinds(), tc.want)
			if err := evidence.ValidateChain(h.events()); err != nil {
				t.Errorf("ValidateChain: %v", err)
			}
			expectNoSinkFailure(t, h)
		})
	}
}

// cancellingStore cancels the admitting agent's context as the store is asked
// to keep a hold: an agent that gives up while the store syncs.
type cancellingStore struct {
	*gateway.MemoryApprovals
	cancel func()
	onHold bool
}

func (s *cancellingStore) Hold(ctx context.Context, held gateway.Held, now time.Time) error {
	if s.onHold {
		s.cancel()
	}
	return s.MemoryApprovals.Hold(ctx, held, now)
}

// cancellingJournal cancels the admitting agent's context as an entry is
// filed, when onRecord is set.
type cancellingJournal struct {
	*gateway.MemoryHoldJournal
	cancel   func()
	onRecord bool
}

func (j *cancellingJournal) Record(ctx context.Context, entry gateway.HoldEntry) error {
	if j.onRecord {
		j.cancel()
	}
	return j.MemoryHoldJournal.Record(ctx, entry)
}

// cancelledHolds is how many agents give up on their hold in one run.
const cancelledHolds = 500

// TestAnAgentsCancelDuringTheHoldLeavesNoTrailOpen: 500 agents each give up
// while the plane files its hold, in the store or in the journal. Every hold
// is still filed whole, so each trail stands at its request for approval with
// its records kept, none is left open with its request id reserved, and the
// sink is not blamed.
func TestAnAgentsCancelDuringTheHoldLeavesNoTrailOpen(t *testing.T) {
	for _, where := range []string{"store", "journal"} {
		t.Run(where, func(t *testing.T) {
			store := &cancellingStore{MemoryApprovals: &gateway.MemoryApprovals{}, onHold: where == "store"}
			journal := &cancellingJournal{MemoryHoldJournal: &gateway.MemoryHoldJournal{}, onRecord: where == "journal"}
			h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) {
				c.Approvals, c.Journal, c.MaxHeld = store, journal, 2*cancelledHolds
			})
			pending, standing := 0, 0
			for i := range cancelledHolds {
				ctx, cancel := context.WithCancel(context.Background())
				store.cancel, journal.cancel = cancel, cancel
				args := []byte(`{"amount": ` + strconv.Itoa(i+1) + `, "currency": "EUR"}`)
				env := refundEnvelope(t, args)
				env.RequestId = "h-" + strconv.Itoa(i)
				if d := h.p.Admit(ctx, admission(env, args)); d.Action == core.AwaitApproval {
					pending++
				}
				cancel()
				if slices.Equal(kindsOf(h.trailOf(env.RequestId)), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested}) {
					standing++
				}
			}
			if pending != cancelledHolds || standing != cancelledHolds {
				t.Errorf("%d answered pending and %d trails standing at their request for approval, want %d of each", pending, standing, cancelledHolds)
			}
			expectNoSinkFailure(t, h)
			if s := h.p.Stats(); s.Held != cancelledHolds || s.JournalRefusals != 0 {
				t.Errorf("Stats: %d held, %d journal refusals; want %d and 0", s.Held, s.JournalRefusals, cancelledHolds)
			}
			if got := len(journal.Entries()); got != cancelledHolds {
				t.Errorf("the journal keeps %d entries, want %d", got, cancelledHolds)
			}
		})
	}
}

// TestAnAgentsCancelAfterTheSpendStillStartsTheCall: the approval is spent
// once the ledger has marked it, so an agent that gives up right then still
// has the answer and the start written on the held trail, its journal entry
// flipped, and the execution handed out for its adapter to close or abort.
func TestAnAgentsCancelAfterTheSpendStillStartsTheCall(t *testing.T) {
	store := &cancellingStore{MemoryApprovals: &gateway.MemoryApprovals{}}
	journal := &gateway.MemoryHoldJournal{}
	ledger := &fakeLedger{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.Approvals, c.Journal, c.Ledger = store, journal, ledger })
	first := hold(t, h)
	if err := store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ledger.afterSpend = cancel
	d := h.p.Admit(ctx, admission(retry(t, "req-2"), refundArgs()))
	if d.Action != core.Execute && d.Action != core.ExecuteWithObligations {
		t.Errorf("the resumed call: %s %v, want it handed out", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
	if entry, kept := journal.Entries()["req-1"]; !kept || entry.State != gateway.HoldResuming {
		t.Errorf("the journal entry: kept %v in state %d, want it resuming", kept, entry.State)
	}
	if err := h.p.Abort(ctx, d, gateway.AbortUntranslatable); err != nil {
		t.Errorf("Abort: %v", err)
	}
	if err := evidence.ValidateChain(h.trailOf("req-1")); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	expectNoSinkFailure(t, h)
}

// TestAnAgentsCancelBeforeTheSpendSpendsNothing: an agent that gives up on
// the retry of an approved hold before its approval is spent, at the
// admission or while the store is asked, has that call blocked on a whole
// trail of its own with nothing spent: the hold stands, nothing is counted as
// the sink's failure, and the agent's next retry runs on the approval.
func TestAnAgentsCancelBeforeTheSpendSpendsNothing(t *testing.T) {
	for _, when := range []string{"before the admission", "while the store is asked"} {
		t.Run(when, func(t *testing.T) {
			f := newFakeStore()
			h := withStore(t, f)
			holdApproved(t, h, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if when == "before the admission" {
				cancel()
			} else {
				f.found = func(*controlv1.Approval) { cancel() }
			}
			d := h.p.Admit(ctx, admission(retry(t, "req-2"), refundArgs()))
			f.found = nil
			if d.Action != core.Block || d.ExecutionID != "" {
				t.Errorf("the cancelled retry: Action = %d under execution %q, want a block with nothing handed out", d.Action, d.ExecutionID)
			}
			expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
			expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
			expectNoSinkFailure(t, h)
			if again := h.admit(retry(t, "req-3"), refundArgs()); again.Action != core.Execute && again.Action != core.ExecuteWithObligations {
				t.Errorf("the next retry: %s %v, want it run on the approval nothing spent", again.Decision.GetVerdict(), again.Decision.GetReasonCodes())
			}
		})
	}
}

// TestAnAgentsCancelBeforeTheStartHandsNothingOut: a call whose agent gave up
// before its execution was handed out is blocked on a whole trail, with
// nothing started and nothing counted as the sink's failure.
func TestAnAgentsCancelBeforeTheStartHandsNothingOut(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := h.p.Admit(ctx, admission(writeEnvelope(), []byte(`{"k":1}`)))
	if d.Action != core.Block || d.ExecutionID != "" {
		t.Errorf("the cancelled call: Action = %d under execution %q, want a block with nothing handed out", d.Action, d.ExecutionID)
	}
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	if err := evidence.ValidateChain(h.events()); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	expectNoSinkFailure(t, h)
	if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 {
		t.Errorf("Stats: %d executed, %d open; want nothing", s.Executed, s.Open)
	}
}
