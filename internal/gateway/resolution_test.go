package gateway_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
)

var errLedger = errors.New("ledger: unavailable")

// fakeLedger is a memory ledger a test can break and watch: it counts what
// the plane asked of it, runs beforeSpend before a spend and afterSpend once
// it is written, and answers an error of its own from a call that names one.
// failAfterSpend writes the mark and then answers an error, which is a ledger
// that crashed after its write.
type fakeLedger struct {
	gateway.MemoryLedger

	mu                  sync.Mutex
	spends, settles     int
	spentBinding        approval.Binding
	beforeSpend         func()
	afterSpend          func()
	spendErr, settleErr error
	lookupErr           error
	failAfterSpend      bool
}

func (l *fakeLedger) Spend(ctx context.Context, b approval.Binding, req, appr, proof string, now time.Time) (gateway.Resolution, error) {
	l.mu.Lock()
	l.spends++
	l.spentBinding = b
	before, then, fail, after := l.beforeSpend, l.afterSpend, l.spendErr, l.failAfterSpend
	l.mu.Unlock()
	if before != nil {
		before()
	}
	if fail != nil {
		return gateway.ResolutionUnspecified, fail
	}
	res, err := l.MemoryLedger.Spend(ctx, b, req, appr, proof, now)
	if then != nil {
		then()
	}
	if after && err == nil {
		return gateway.ResolutionUnspecified, errLedger
	}
	return res, err
}

func (l *fakeLedger) Settle(ctx context.Context, b approval.Binding, req, appr string, now time.Time) (gateway.Resolution, error) {
	l.mu.Lock()
	l.settles++
	fail := l.settleErr
	l.mu.Unlock()
	if fail != nil {
		return gateway.ResolutionUnspecified, fail
	}
	return l.MemoryLedger.Settle(ctx, b, req, appr, now)
}

func (l *fakeLedger) Lookup(ctx context.Context, b approval.Binding, now time.Time) (map[string]gateway.Resolution, error) {
	l.mu.Lock()
	fail := l.lookupErr
	l.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	return l.MemoryLedger.Lookup(ctx, b, now)
}

// spentUnder is the binding the last spend named.
func (l *fakeLedger) spentUnder() approval.Binding {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.spentBinding
}

func (l *fakeLedger) asked() (spends, settles int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.spends, l.settles
}

// overStore builds a pipeline over store.
func overStore(store gateway.ApprovalStore) func(*gateway.Config) {
	return func(cfg *gateway.Config) { cfg.Approvals = store }
}

// overLedger builds a pipeline over ledger.
func overLedger(ledger gateway.Ledger) func(*gateway.Config) {
	return func(cfg *gateway.Config) { cfg.Ledger = ledger }
}

// TestARecordThisPlaneDoesNotHoldIsReadAndNeverSpent: a store keeps a record
// for a request this plane never held, which is what a plane that restarted
// finds. What the plane does with it is read off its own ledger: only a mark
// that the approval was spent refuses the call, a ledger that cannot be read
// blocks it, and everything else holds it anew. Spend is never called, so no
// answer the plane does not hold is spent, and a later reconciliation can
// still settle it.
func TestARecordThisPlaneDoesNotHoldIsReadAndNeverSpent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mark   func(*testing.T, *fakeLedger, *controlv1.Approval)
		used   bool
		broken bool
		unheld uint64
	}{
		{"no mark", nil, false, false, 1},
		{"settled", func(t *testing.T, l *fakeLedger, a *controlv1.Approval) {
			if _, err := l.MemoryLedger.Settle(ctx(), bindingOfHeld(t, a), a.GetRequestId(), a.GetApprovalId(), base()); err != nil {
				t.Fatal(err)
			}
		}, false, false, 0},
		{"spent", func(t *testing.T, l *fakeLedger, a *controlv1.Approval) {
			if _, err := l.MemoryLedger.Spend(ctx(), bindingOfHeld(t, a), a.GetRequestId(), a.GetApprovalId(), "alice", base()); err != nil {
				t.Fatal(err)
			}
		}, true, false, 0},
		{"a ledger that cannot be read", func(_ *testing.T, l *fakeLedger, _ *controlv1.Approval) { l.lookupErr = errLedger }, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := snapshot(t, approveRefunds)
			store := &gateway.MemoryApprovals{}
			ledger := &fakeLedger{}
			first := build(t, modeEnforce, snap, overStore(store), overLedger(ledger))
			held := hold(t, first)

			// The plane restarts: the store and the ledger keep what they
			// hold, and the new plane holds nothing.
			next := build(t, modeEnforce, snap, overStore(store), overLedger(ledger))
			if tc.mark != nil {
				tc.mark(t, ledger, approvalOfHold(t, store, held))
			}
			d := next.admit(retry(t, "req-2"), refundArgs())

			want := []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested}
			switch {
			case tc.used:
				expectBlock(t, d, verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)
				want = []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}
			case tc.broken:
				expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
				want = []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}
			case d.Action != core.AwaitApproval || d.Pending == nil:
				t.Fatalf("Action = %d, pending %+v; want a hold of its own", d.Action, d.Pending)
			}
			expectKinds(t, kindsOf(next.trailOf("req-2")), want)
			if s := next.p.Stats(); s.UnheldRecords != tc.unheld {
				t.Errorf("Stats().UnheldRecords = %d, want %d", s.UnheldRecords, tc.unheld)
			}
			if spends, _ := ledger.asked(); spends != 0 {
				t.Errorf("the plane spent %d approval(s) it does not hold; it may spend none", spends)
			}
		})
	}
}

// TestAnApprovedHoldRunsOnceAcrossARestartAndALostLedger: a held request
// approved and run is ALREADY_USED for its next identical call, on this plane
// and on one that restarts over the same store and ledger; over an empty
// ledger the same call is held anew and never runs, which is all a lost ledger
// can cost.
func TestAnApprovedHoldRunsOnceAcrossARestartAndALostLedger(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	store := &gateway.MemoryApprovals{}
	ledger := &gateway.MemoryLedger{}
	h := build(t, modeEnforce, snap, overStore(store), overLedger(ledger))
	first := hold(t, h)
	if err := store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if d := h.admit(retry(t, "req-2"), refundArgs()); d.Action != core.Execute {
		t.Fatalf("the approved retry: Action = %d, decision %+v", d.Action, d.Decision)
	}
	expectBlock(t, h.admit(retry(t, "req-3"), refundArgs()), verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)

	restarted := build(t, modeEnforce, snap, overStore(store), overLedger(ledger))
	expectBlock(t, restarted.admit(retry(t, "req-4"), refundArgs()), verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)

	lost := build(t, modeEnforce, snap, overStore(store), overLedger(&gateway.MemoryLedger{}))
	d := lost.admit(retry(t, "req-5"), refundArgs())
	if d.Action != core.AwaitApproval || d.Pending == nil {
		t.Fatalf("the same call over an empty ledger: Action = %d, pending %+v; want a hold of its own", d.Action, d.Pending)
	}
	expectKinds(t, kindsOf(lost.trailOf("req-5")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if s := lost.p.Stats(); s.Executed != 0 || s.UnheldRecords != 1 {
		t.Errorf("over an empty ledger Stats() = %+v; want nothing run and the record counted", s)
	}
}

// bindingOfHeld is the binding the plane held a under, computed from its two
// digests as the directory store checks it.
func bindingOfHeld(t *testing.T, a *controlv1.Approval) approval.Binding {
	t.Helper()
	b, err := canon.ApprovalBinding(a.GetActionDigest(), a.GetPolicyBundleDigest())
	if err != nil {
		t.Fatalf("binding the held approval: %v", err)
	}
	return approval.Binding(b)
}

// approvalOfHold names the hold d answered, as the store keeps it.
func approvalOfHold(t *testing.T, store *gateway.MemoryApprovals, d gateway.Disposition) *controlv1.Approval {
	t.Helper()
	return approvalOfHoldIn(t, store, d, 1)
}

// approvalOfHoldIn is approvalOfHold where the store keeps records records
// under the hold's binding.
func approvalOfHoldIn(t *testing.T, store *gateway.MemoryApprovals, d gateway.Disposition, records int) *controlv1.Approval {
	t.Helper()
	a := &controlv1.Approval{
		ApprovalId: d.Pending.ApprovalID, RequestId: d.Decision.GetRequestId(),
		ActionDigest: d.Pending.ActionDigest, PolicyBundleDigest: d.Decision.GetPolicyBundleDigest(),
	}
	found, err := store.Find(ctx(), bindingOfHeld(t, a), d.Pending.ExpiresAt.Add(-time.Nanosecond))
	if err != nil || len(found) != records {
		t.Fatalf("the store keeps %d record(s), %v; want %d", len(found), err, records)
	}
	return a
}

// TestALedgerThatFailsAfterItsWriteNeverRunsTheCallTwice: the ledger marks
// the approval spent and then fails, as a crash between the spend and
// APPROVAL_DECIDED leaves it. The call is blocked on its own trail and nothing
// runs; the next retry reads the mark and is ALREADY_USED, and a plane that
// comes back over the same journal, store and ledger closes the lost hold as
// not resumed, keeps the mark, and refuses the same retry again.
func TestALedgerThatFailsAfterItsWriteNeverRunsTheCallTwice(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	ledger := &fakeLedger{failAfterSpend: true}
	first := build(t, modeEnforce, snap, overLedger(ledger), func(cfg *gateway.Config) { cfg.Journal = j })
	pending := hold(t, first)
	if err := first.store.Answer(pending.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	expectBlock(t, first.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(first.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	ledger.mu.Lock()
	ledger.failAfterSpend = false
	ledger.mu.Unlock()
	expectBlock(t, first.admit(retry(t, "req-3"), refundArgs()), verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)

	next := build(t, modeApprove, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = first.store
		cfg.Ledger = ledger
		cfg.Sink = first.sink
		cfg.NewID = restartIDs()
	})
	next.clock.set(base().Add(time.Minute))
	if r := next.p.Reconcile(context.Background()); r.Closed != 1 {
		t.Fatalf("Reconcile = %+v; want the lost hold closed", r)
	}
	expectClosedLostHold(t, first, kindApprovalDecided, verdictDeny, codeApprovalNotResumed)
	if s := next.p.Stats(); s.UnheldRecords != 1 {
		t.Errorf("Stats().UnheldRecords = %d; a settle the spent mark refuses is counted", s.UnheldRecords)
	}
	expectBlock(t, next.admit(retry(t, "req-4"), refundArgs()), verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)
	if a, b := first.p.Stats().Executed, next.p.Stats().Executed; a != 0 || b != 0 {
		t.Errorf("%d and %d execution(s); want none on an approval whose spend was never recorded", a, b)
	}
}

// vagueLedger answers every spend with no error and no resolution, which no
// ledger may do.
type vagueLedger struct{ gateway.MemoryLedger }

func (*vagueLedger) Spend(context.Context, approval.Binding, string, string, string, time.Time) (gateway.Resolution, error) {
	return gateway.ResolutionUnspecified, nil
}

// TestASpendTheLedgerDoesNotConfirmRunsNothing: a ledger that answers a spend
// without saying the approval is consumed has not spent it, so the call is
// blocked on its own trail and the hold stands.
func TestASpendTheLedgerDoesNotConfirmRunsNothing(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds), overLedger(&vagueLedger{}))
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if s := h.p.Stats(); s.Executed != 0 || s.Held != 1 {
		t.Errorf("Stats = %+v; want nothing run and the hold standing", s)
	}
}

// TestAnExpiryIsNotClosedOverALedgerThatCannotBeRead: before the plane closes
// a held trail on an expired or rejected answer it asks the ledger whether the
// approval was spent; a ledger that cannot answer blocks the retry on its own
// trail and leaves the hold for a later one. With the ledger back the trail
// closes as expired.
func TestAnExpiryIsNotClosedOverALedgerThatCannotBeRead(t *testing.T) {
	f := newFakeStore()
	ledger := &fakeLedger{lookupErr: errLedger}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), overStore(f), overLedger(ledger))
	holdApproved(t, h, f)
	reportExpired(f)
	expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	ledger.mu.Lock()
	ledger.lookupErr = nil
	ledger.mu.Unlock()
	expectBlock(t, h.admit(retry(t, "req-3"), refundArgs()), verdictDeny, codeApprovalExpired, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
}

// TestAnApprovalSpentElsewhereIsNotClosedAsExpired: the ledger marks the held
// approval spent and the store now hands it back expired. The spent mark is
// proof of an execution, so the retry is ALREADY_USED and the held trail is
// left to the call that spent it, never closed as expired.
func TestAnApprovalSpentElsewhereIsNotClosedAsExpired(t *testing.T) {
	f := newFakeStore()
	ledger := &fakeLedger{}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), overStore(f), overLedger(ledger))
	first := hold(t, h)
	if err := f.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	a := approvalOfHold(t, f.MemoryApprovals, first)
	if _, err := ledger.MemoryLedger.Spend(ctx(), bindingOfHeld(t, a), a.GetRequestId(), a.GetApprovalId(), "alice", base()); err != nil {
		t.Fatal(err)
	}
	reportExpired(f)
	expectBlock(t, h.admit(retry(t, "req-2"), refundArgs()), verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
}

// vagueSettler answers every settle with no error and no resolution, which
// no ledger may do.
type vagueSettler struct{ gateway.MemoryLedger }

func (*vagueSettler) Settle(context.Context, approval.Binding, string, string, time.Time) (gateway.Resolution, error) {
	return gateway.ResolutionUnspecified, nil
}

// TestASettleTheLedgerDoesNotConfirmIsCounted: a reconciliation whose ledger
// answers a settle without saying the approval is not resumed has settled
// nothing, and counts the record as one it cannot prove unspent.
func TestASettleTheLedgerDoesNotConfirmIsCounted(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	first := build(t, modeEnforce, snap, func(cfg *gateway.Config) { cfg.Journal = j })
	hold(t, first)
	next := build(t, modeApprove, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = first.store
		cfg.Ledger = &vagueSettler{}
		cfg.Sink = first.sink
		cfg.NewID = restartIDs()
	})
	next.clock.set(base().Add(time.Minute))
	if r := next.p.Reconcile(context.Background()); r.Closed != 1 {
		t.Fatalf("Reconcile = %+v; want the lost hold closed", r)
	}
	if s := next.p.Stats(); s.UnheldRecords != 1 {
		t.Errorf("Stats().UnheldRecords = %d; want the unconfirmed settle counted", s.UnheldRecords)
	}
}
