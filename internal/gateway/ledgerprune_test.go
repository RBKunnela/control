package gateway_test

import (
	"errors"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// TestASweptLedgerKeepsTheMarkOfALiveRecord: an approval held at base and
// spent a minute later keeps its mark through a sweep at the last instant
// its record lives, so the next identical call is still refused as already
// used rather than held anew. The mark goes one approval lifetime after it
// was written, and not a nanosecond before.
func TestASweptLedgerKeepsTheMarkOfALiveRecord(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds))
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	spentAt := base().Add(time.Minute)
	h.clock.set(spentAt)
	run := h.admit(retry(t, "req-2"), refundArgs())
	if run.Action != core.Execute {
		t.Fatalf("the approved retry: Action = %d, codes %v", run.Action, run.Decision.GetReasonCodes())
	}
	if err := h.p.Close(ctx(), run, run.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lastLive := first.Pending.ExpiresAt.Add(-time.Nanosecond)
	if !lastLive.After(spentAt) {
		t.Fatalf("the record expires at %s, before the spend at %s, so the sweep below examines nothing", first.Pending.ExpiresAt, spentAt)
	}
	if n, err := h.p.PruneLedger(ctx(), lastLive); n != 0 || err != nil {
		t.Fatalf("a sweep while the record lives forgot %d mark(s), %v; want 0, nil", n, err)
	}
	h.clock.set(base().Add(2 * time.Minute))
	expectUsed(t, h, "req-3")

	lifetime := spentAt.Add(10 * time.Minute)
	if n, err := h.p.PruneLedger(ctx(), lifetime); n != 0 || err != nil {
		t.Errorf("a sweep one lifetime after the spend forgot %d mark(s), %v; want 0, nil", n, err)
	}
	if n, err := h.p.PruneLedger(ctx(), lifetime.Add(time.Nanosecond)); n != 1 || err != nil {
		t.Errorf("a sweep past one lifetime after the spend forgot %d mark(s), %v; want 1, nil", n, err)
	}
}

// unprunable is a ledger with no Prune of its own.
type unprunable struct{ gateway.Ledger }

// TestALedgerSweepThatCannotRunSaysSo: a ledger that cannot forget, and a
// clock that reads zero, are errors, never zero marks forgotten.
func TestALedgerSweepThatCannotRunSaysSo(t *testing.T) {
	plain := build(t, modeEnforce, snapshot(t, approveRefunds))
	if _, err := plain.p.PruneLedger(ctx(), time.Time{}); !errors.Is(err, gateway.ErrZeroTime) {
		t.Errorf("a sweep at the zero time: %v, want ErrZeroTime", err)
	}
	if _, err := plain.p.PruneLedger(ctx(), base()); err != nil {
		t.Errorf("the control, a sweep of a ledger that prunes: %v", err)
	}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(cfg *gateway.Config) {
		cfg.Ledger = unprunable{cfg.Ledger}
	})
	if _, err := h.p.PruneLedger(ctx(), base()); !errors.Is(err, gateway.ErrLedgerUnprunable) {
		t.Errorf("a sweep of a ledger that cannot forget: %v, want ErrLedgerUnprunable", err)
	}
}
