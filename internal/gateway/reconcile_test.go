package gateway_test

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
)

// restartIDs names the events of the plane that comes back, apart from the
// ids the plane before it minted: two planes writing one trail under one id
// sequence would break the chain on the identifiers and not on the order.
func restartIDs() func() string {
	var n atomic.Int64
	return func() string { return "again-" + strconv.FormatInt(n.Add(1), 10) }
}

// lost holds a refund on first and returns the plane that comes back to the
// same journal, the same store and the same evidence: the plane that lost the
// hold. It reads a minute later and enforces in another mode, so what the
// closing events carry can only come from the plane that wrote them.
func lost(t *testing.T, snap *policy.Snapshot, first *harness, j gateway.HoldJournal) *harness {
	t.Helper()
	next := build(t, modeApprove, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = first.store
		cfg.Ledger = first.ledger
		cfg.Sink = first.sink
		cfg.NewID = restartIDs()
	})
	next.clock.set(base().Add(time.Minute))
	return next
}

// holdLost holds one refund on a plane built over j, and returns that plane's
// pending state and the plane that comes back to it.
func holdLost(t *testing.T, snap *policy.Snapshot, j gateway.HoldJournal) (*harness, gateway.Disposition, *harness) {
	t.Helper()
	first := build(t, modeEnforce, snap, func(cfg *gateway.Config) { cfg.Journal = j })
	pending := hold(t, first)
	return first, pending, lost(t, snap, first, j)
}

// TestTheReconciliationClosesALostHoldWithTheAnswerItFinds: an approver said
// yes while the plane was gone. The trail is closed with that answer and a
// DENY naming APPROVAL_NOT_RESUMED, because the approval was granted and the
// call was never run; the approval is settled rather than spent, so the next
// identical call is held anew instead of being told that an action ran.
func TestTheReconciliationClosesALostHoldWithTheAnswerItFinds(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	first, pending, next := holdLost(t, snap, j)
	if err := first.store.Answer(pending.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	r := next.p.Reconcile(context.Background())
	if (r != gateway.Reconciliation{Closed: 1, Complete: true}) {
		t.Errorf("Reconcile = %+v; want one trail closed and a complete pass", r)
	}
	trail := expectClosedLostHold(t, first, kindApprovalDecided, verdictDeny, codeApprovalNotResumed)
	decided := trail[3].GetApproval()
	if decided.GetState() != approved || decided.GetApproverId() != "alice" || decided.GetApprovalId() != pending.Pending.ApprovalID {
		t.Errorf("APPROVAL_DECIDED carries %+v; want the answer this plane found", decided)
	}
	expectTheRestartedPlanesMode(t, trail[4])
	if _, kept := j.state("req-1"); kept {
		t.Errorf("the entry of a closed trail is still in the journal")
	}
	if s := next.p.Stats(); s.HoldsClosed != 1 || s.Blocks[codeApprovalNotResumed] != 1 || s.ReconcileIncomplete {
		t.Errorf("Stats = %+v; want one hold closed, counted, and a measured pass", s)
	}

	// The approval was settled, not spent: the next identical call is held
	// anew, and the plane counts nothing it cannot prove.
	again := next.admit(retry(t, "req-2"), refundArgs())
	if again.Action != core.AwaitApproval {
		t.Fatalf("the call after a lost hold: Action = %d, want a hold of its own", again.Action)
	}
	if s := next.p.Stats(); s.UnheldRecords != 0 {
		t.Errorf("Stats().UnheldRecords = %d; the reconciliation settled that approval, so nothing is unprovable about it", s.UnheldRecords)
	}
}

// expectTheRestartedPlanesMode asserts a closing event and its decision carry
// the mode of the plane that wrote them, which is what says the call was
// never run rather than that some plane enforced anything.
func expectTheRestartedPlanesMode(t *testing.T, closing *controlv1.Event) {
	t.Helper()
	if got := closing.GetEnforcementMode(); got != modeApprove {
		t.Errorf("the closing event carries mode %s; want the mode of the plane that wrote it", got)
	}
	if got := closing.GetDecision().GetEnforcementMode(); got != modeApprove {
		t.Errorf("the closing decision carries mode %s; want the mode of the plane that wrote it", got)
	}
}

// TestTheReconciliationClosesARefusedHoldAsRefused: an approver said no, so
// the close says so and not that nobody answered.
func TestTheReconciliationClosesARefusedHoldAsRefused(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	first, pending, next := holdLost(t, snap, j)
	if err := first.store.Answer(pending.Pending.ApprovalID, rejected, "", "no", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if r := next.p.Reconcile(context.Background()); (r != gateway.Reconciliation{Closed: 1, Complete: true}) {
		t.Errorf("Reconcile = %+v; want one trail closed", r)
	}
	trail := expectClosedLostHold(t, first, kindApprovalDecided, verdictDeny, codeApprovalRejected)
	if state := trail[3].GetApproval().GetState(); state != rejected {
		t.Errorf("APPROVAL_DECIDED carries state %s, want REJECTED", state)
	}
}

// lostUnder holds one refund on a plane over store, lets setUp answer or
// break the store, and reconciles from the plane that comes back to the same
// journal, store, ledger and evidence with its clock at at. The pass must
// close the one trail. The ledger the two planes share is the restarted
// plane's spy.
func lostUnder(t *testing.T, store gateway.ApprovalStore, at time.Time, setUp func(pending gateway.Disposition)) (*harness, gateway.Disposition, *harness) {
	t.Helper()
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	ledger := &fakeLedger{}
	first := build(t, modeEnforce, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = store
		cfg.Ledger = ledger
	})
	pending := hold(t, first)
	setUp(pending)
	next := build(t, modeApprove, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = store
		cfg.Ledger = ledger
		cfg.Sink = first.sink
		cfg.NewID = restartIDs()
	})
	next.spy = ledger
	next.clock.set(at)
	if r := next.p.Reconcile(context.Background()); (r != gateway.Reconciliation{Closed: 1, Complete: true}) {
		t.Errorf("Reconcile = %+v; want one trail closed", r)
	}
	return first, pending, next
}

// expectOwnApprovalExpired asserts the lost hold's window was closed with the
// approval this plane minted, marked expired, and nothing a store said.
func expectOwnApprovalExpired(t *testing.T, trail []*controlv1.Event, pending gateway.Disposition) {
	t.Helper()
	expired := trail[3].GetApproval()
	if expired.GetState() != controlv1.ApprovalState_APPROVAL_STATE_EXPIRED || expired.GetApprovalId() != pending.Pending.ApprovalID ||
		expired.GetApproverId() != "" {
		t.Errorf("APPROVAL_EXPIRED carries %+v; want the approval this plane minted, expired", expired)
	}
}

// lostHoldExpiry is when the lost hold's approval expires: ten minutes after
// base, the TTL build sets.
var lostHoldExpiry = base().Add(10 * time.Minute)

// answeredThen approves the held refund in store and edits every record the
// store hands back with edit.
func answeredThen(t *testing.T, store *fakeStore, pending gateway.Disposition, edit func(*controlv1.Approval)) {
	t.Helper()
	if err := store.Answer(pending.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	store.found = edit
}

// TestTheReconciliationClosesAnUnansweredOrLapsedHoldAsExpired: nobody
// answered, the store hands back a record whose own expiry has passed, the
// store holds no record once the approval the plane minted has expired by the
// restarted plane's clock, or the store marks the record EXPIRED before its
// expiry. Each is an expiry the plane can stand behind, so the close is
// APPROVAL_EXPIRED with the plane's own approval.
func TestTheReconciliationClosesAnUnansweredOrLapsedHoldAsExpired(t *testing.T) {
	for _, tc := range []struct {
		name  string
		at    time.Time
		setUp func(t *testing.T, store *fakeStore, pending gateway.Disposition)
	}{
		{"nobody answered", base().Add(time.Minute), func(*testing.T, *fakeStore, gateway.Disposition) {}},
		{"a record the store reports past its expiry", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ExpiresAt = timestamppb.New(base()) })
		}},
		{"no record once the plane's own expiry passed", lostHoldExpiry, func(_ *testing.T, store *fakeStore, _ gateway.Disposition) {
			store.findErr = gateway.ErrNoApproval
		}},
		{"a record the store marks expired before its expiry", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) {
				a.State, a.ApproverId = controlv1.ApprovalState_APPROVAL_STATE_EXPIRED, ""
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			first, pending, next := lostUnder(t, store, tc.at, func(pending gateway.Disposition) { tc.setUp(t, store, pending) })
			trail := expectClosedLostHold(t, first, kindApprovalExpired, verdictDeny, codeApprovalExpired)
			expectOwnApprovalExpired(t, trail, pending)
			if s := next.p.Stats(); s.Blocks[codeApprovalExpired] != 1 || len(s.Blocks) != 1 {
				t.Errorf("Stats().Blocks = %v; want the close counted once as APPROVAL_EXPIRED", s.Blocks)
			}
			expectSettledOnce(t, next)
		})
	}
}

// TestTheReconciliationClosesAnAnswerItCannotReadOrTrustAsUnknown: a store
// that fails, one that has lost a record whose approval has not expired, and
// an answer the field checks refuse leave the plane unable to say what the
// approver answered. The call still never runs, and the close says
// INDETERMINATE with APPROVAL_STATE_UNKNOWN instead of claiming an expiry or
// a grant. The digest case is the adversarial one: a record edited after the
// plane minted it is never recorded as granted.
func TestTheReconciliationClosesAnAnswerItCannotReadOrTrustAsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name  string
		at    time.Time
		setUp func(t *testing.T, store *fakeStore, pending gateway.Disposition)
	}{
		{"a store that fails", base().Add(time.Minute), func(_ *testing.T, store *fakeStore, _ gateway.Disposition) {
			store.findErr = errStore
		}},
		{"a store that fails after the expiry", lostHoldExpiry, func(_ *testing.T, store *fakeStore, _ gateway.Disposition) {
			store.findErr = errStore
		}},
		{"no record a tick before the expiry", lostHoldExpiry.Add(-time.Nanosecond), func(_ *testing.T, store *fakeStore, _ gateway.Disposition) {
			store.findErr = gateway.ErrNoApproval
		}},
		{"an answer under another digest", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ActionDigest = "sha256:" + digits })
		}},
		{"an answer under another bundle", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.PolicyBundleDigest = "sha256:" + digits })
		}},
		{"an answer that outlives what the plane minted", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ExpiresAt = timestamppb.New(base().Add(time.Hour)) })
		}},
		{"an answer with no expiry", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ExpiresAt = nil })
		}},
		{"an answer for another request only", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.RequestId = "req-other" })
		}},
		{"an approval with no approver", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ApproverId = "" })
		}},
		{"a state no answer has", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.State = controlv1.ApprovalState(99) })
		}},
		{"an answer of another major", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.SchemaVersion = "9.0" })
		}},
		{"an answer decided after the reading", base().Add(time.Minute), func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.DecidedAt = timestamppb.New(base().Add(time.Minute + time.Nanosecond)) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			first, pending, next := lostUnder(t, store, tc.at, func(pending gateway.Disposition) { tc.setUp(t, store, pending) })
			if spends, _ := next.spy.asked(); spends != 0 {
				t.Errorf("the reconciliation spent %d approval(s); an answer to a lost hold is never spent", spends)
			}
			trail := expectClosedLostHold(t, first, kindApprovalExpired, verdictIndeterminate, codeApprovalStateUnknown)
			expectOwnApprovalExpired(t, trail, pending)
			if s := next.p.Stats(); s.Blocks[codeApprovalStateUnknown] != 1 || len(s.Blocks) != 1 || s.HoldsClosed != 1 || s.Executed != 0 {
				t.Errorf("Stats = %+v; want nothing run and the one close counted as APPROVAL_STATE_UNKNOWN", s)
			}
			expectSettledOnce(t, next)
		})
	}
}

// TestTheLostHoldCodesTellTheFourAnswersApart: one lost hold, four answers
// from the store, four closings. Only an answer the plane can read and check
// names what the approver did; the call runs under none of them.
func TestTheLostHoldCodesTellTheFourAnswersApart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setUp   func(t *testing.T, store *fakeStore, pending gateway.Disposition)
		outcome controlv1.EventKind
		verdict controlv1.Verdict
		code    string
	}{
		{"the store fails", func(_ *testing.T, store *fakeStore, _ gateway.Disposition) { store.findErr = errStore },
			kindApprovalExpired, verdictIndeterminate, codeApprovalStateUnknown},
		{"the store answers garbage", func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ActionDigest = "sha256:" + digits })
		}, kindApprovalExpired, verdictIndeterminate, codeApprovalStateUnknown},
		{"the store answers an expired record", func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			answeredThen(t, store, pending, func(a *controlv1.Approval) { a.ExpiresAt = timestamppb.New(base().Add(time.Minute)) })
		}, kindApprovalExpired, verdictDeny, codeApprovalExpired},
		{"the store answers a rejection", func(t *testing.T, store *fakeStore, pending gateway.Disposition) {
			if err := store.Answer(pending.Pending.ApprovalID, rejected, "", "no", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
		}, kindApprovalDecided, verdictDeny, codeApprovalRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			first, _, next := lostUnder(t, store, base().Add(time.Minute), func(pending gateway.Disposition) { tc.setUp(t, store, pending) })
			expectClosedLostHold(t, first, tc.outcome, tc.verdict, tc.code)
			if s := next.p.Stats(); s.Executed != 0 || s.Blocks[tc.code] != 1 || len(s.Blocks) != 1 {
				t.Errorf("Stats = %+v; want nothing run and the close counted once as %s", s, tc.code)
			}
			expectSettledOnce(t, next)
		})
	}
}

// expectSettledOnce asserts the reconciliation told the ledger once that the
// request will not be resumed, whatever the close said, and that the ledger
// marks it so.
func expectSettledOnce(t *testing.T, next *harness) {
	t.Helper()
	if _, settles := next.spy.asked(); settles != 1 {
		t.Errorf("the ledger was asked to settle %d time(s); want once per closed hold", settles)
	}
}

// TestASiblingRecordDoesNotRelabelTheAnswer: a record filed under the lost
// hold's request id with another approval id, listed ahead of the one the
// plane minted, is not the plane's to read. The close names what the approver
// answered on the minted approval.
func TestASiblingRecordDoesNotRelabelTheAnswer(t *testing.T) {
	for _, tc := range []struct {
		name          string
		state, forged controlv1.ApprovalState
		code          string
	}{
		{"a rejection behind a forged grant", rejected, approved, codeApprovalRejected},
		{"a grant behind a forged rejection", approved, rejected, codeApprovalNotResumed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			first, pending, _ := lostUnder(t, store, base().Add(time.Minute), func(pending gateway.Disposition) {
				approver := ""
				if tc.state == approved {
					approver = "alice"
				}
				if err := store.Answer(pending.Pending.ApprovalID, tc.state, approver, "", base()); err != nil {
					t.Fatalf("Answer: %v", err)
				}
				store.listed = func(helds []gateway.Held) []gateway.Held {
					if len(helds) == 0 {
						return helds
					}
					sibling := helds[0]
					sibling.Approval = proto.CloneOf(sibling.Approval)
					sibling.Approval.ApprovalId, sibling.Approval.State, sibling.Approval.ApproverId = "sibling", tc.forged, "mallory"
					return append([]gateway.Held{sibling}, helds...)
				}
			})
			trail := expectClosedLostHold(t, first, kindApprovalDecided, verdictDeny, tc.code)
			if decided := trail[3].GetApproval(); decided.GetApprovalId() != pending.Pending.ApprovalID || decided.GetState() != tc.state {
				t.Errorf("APPROVAL_DECIDED carries %+v; want the minted approval as answered", decided)
			}
		})
	}
}

// TestTheReconciliationLeavesAnInterruptedCloseAlone: an entry that left held
// before the plane stopped says nothing about where its trail stands, so it
// is reported and counted and nothing is written to it.
func TestTheReconciliationLeavesAnInterruptedCloseAlone(t *testing.T) {
	for _, state := range []gateway.HoldState{gateway.HoldResuming, gateway.HoldClosing} {
		snap := snapshot(t, approveRefunds)
		j := &journalDouble{}
		first, _, next := holdLost(t, snap, j)
		if err := j.Mark(context.Background(), "req-1", state); err != nil {
			t.Fatalf("Mark: %v", err)
		}
		before := len(first.events())
		r := next.p.Reconcile(context.Background())
		if (r != gateway.Reconciliation{Interrupted: 1, Complete: true}) {
			t.Errorf("Reconcile over an entry in %d = %+v; want it reported and nothing closed", state, r)
		}
		if got := len(first.events()); got != before {
			t.Errorf("%d event(s) were written for an entry the plane cannot speak for", got-before)
		}
		if got, kept := j.state("req-1"); !kept || got != state {
			t.Errorf("the entry is %d, kept %v; want it left exactly as it was", got, kept)
		}
		if s := next.p.Stats(); s.HoldsUnmeasured != 1 || s.HoldsClosed != 0 {
			t.Errorf("Stats = %+v; want one entry unmeasured and none closed", s)
		}
	}
}

// TestAJournalEntryThatWillNotDecodeIsUnmeasured: what a journal cannot read
// is counted and reported, never taken for an empty journal, and a pass that
// met one has not seen every hold — so it says it is not done, whatever it
// closed beside it.
func TestAJournalEntryThatWillNotDecodeIsUnmeasured(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{unreadable: 2}
	_, _, next := holdLost(t, snap, j)
	r := next.p.Reconcile(context.Background())
	if r.Unreadable != 2 || r.Closed != 1 || r.Complete {
		t.Errorf("Reconcile = %+v; want the unreadable entries reported beside the closed one, and the pass unmeasured", r)
	}
	if s := next.p.Stats(); s.HoldsUnmeasured != 2 || !s.ReconcileIncomplete {
		t.Errorf("Stats = %+v; want two entries unmeasured and the pass reported so", s)
	}
}

// TestAnExecutionThatNeverClosedIsReportedAndNotReopened: the plane stopped
// between the action starting and its closing record, so its entry stands at
// resuming. The reconciliation cannot say what landed on that trail: it
// counts the entry, writes nothing to it, and spends and resolves nothing.
func TestAnExecutionThatNeverClosedIsReportedAndNotReopened(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	store := &gateway.MemoryApprovals{}
	ledger := &fakeLedger{}
	first := build(t, modeEnforce, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = store
		cfg.Ledger = ledger
	})
	pending := hold(t, first)
	if err := store.Answer(pending.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if run := first.admit(retry(t, "req-2"), refundArgs()); run.Action != core.Execute {
		t.Fatalf("the approved retry: Action = %d, want Execute", run.Action)
	}
	// Nothing closes that execution: the plane stops here.
	started := kindsOf(first.trailOf("req-1"))
	expectKinds(t, started, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})

	next := build(t, modeApprove, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = store
		cfg.Ledger = ledger
		cfg.Sink = first.sink
		cfg.NewID = restartIDs()
	})
	next.clock.set(base().Add(time.Minute))
	if r := next.p.Reconcile(context.Background()); (r != gateway.Reconciliation{Interrupted: 1, Complete: true}) {
		t.Errorf("Reconcile = %+v; want the interrupted execution reported and nothing closed", r)
	}
	expectKinds(t, kindsOf(first.trailOf("req-1")), started)
	if got, kept := j.state("req-1"); !kept || got != gateway.HoldResuming {
		t.Errorf("the entry is %d, kept %v; want it left at resuming for the report", got, kept)
	}
	if _, settles := ledger.asked(); settles != 0 {
		t.Errorf("the reconciliation settled %d approval(s) of an execution that may have run; want none", settles)
	}
	if s := next.p.Stats(); s.HoldsUnmeasured != 1 || s.HoldsClosed != 0 {
		t.Errorf("Stats = %+v; want one entry unmeasured and none closed", s)
	}
	// The same retry after the restart is the next identical call: the
	// approval it would spend is marked spent, so nothing runs twice.
	expectBlock(t, next.admit(retry(t, "req-3"), refundArgs()), verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)
	if s := next.p.Stats(); s.Executed != 0 {
		t.Errorf("the restarted plane ran %d call(s); want none", s.Executed)
	}
}

// TestAReconciliationThatHitsItsBoundReportsUnmeasured: the bound bites at
// two of three lost holds, and the pass says so rather than reporting itself
// done. The hold it did not reach keeps its entry, so the next pass can close
// it.
func TestAReconciliationThatHitsItsBoundReportsUnmeasured(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	first := build(t, modeEnforce, snap, func(cfg *gateway.Config) { cfg.Journal = j })
	for _, session := range []string{"sess-1", "sess-2", "sess-3"} {
		env := refundEnvelope(t, refundArgs())
		env.RequestId = "req-" + session
		env.Context.SessionId = session
		if d := first.admit(env, refundArgs()); d.Action != core.AwaitApproval {
			t.Fatalf("the hold of %s: Action = %d, want a hold", session, d.Action)
		}
	}
	next := build(t, modeApprove, snap, func(cfg *gateway.Config) {
		cfg.Journal = j
		cfg.Approvals = first.store
		cfg.Sink = first.sink
		cfg.NewID = restartIDs()
		cfg.ReconcileMax = 2
	})
	next.clock.set(base().Add(time.Minute))

	r := next.p.Reconcile(context.Background())
	if r.Complete || r.Closed != 2 {
		t.Errorf("Reconcile = %+v; want two closed and a pass that says it is not done", r)
	}
	if got := len(j.Entries()); got != 1 {
		t.Errorf("the journal holds %d entry(ies); want the one the bound left", got)
	}
	if s := next.p.Stats(); !s.ReconcileIncomplete || s.HoldsClosed != 2 {
		t.Errorf("Stats = %+v; want the pass reported unmeasured", s)
	}
}

// TestAJournalThatCannotBeListedMeasuresNothing: a pass that could not read
// the journal reports nothing closed and nothing complete, and never a plane
// with no lost holds.
func TestAJournalThatCannotBeListedMeasuresNothing(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{listErr: errJournal}
	first, _, next := holdLost(t, snap, j)
	before := len(first.events())
	if r := next.p.Reconcile(context.Background()); (r != gateway.Reconciliation{}) {
		t.Errorf("Reconcile over an unreadable journal = %+v; want nothing measured", r)
	}
	if got := len(first.events()); got != before {
		t.Errorf("%d event(s) were written from a journal that could not be read", got-before)
	}
	if s := next.p.Stats(); !s.ReconcileIncomplete {
		t.Errorf("Stats = %+v; want the pass reported unmeasured", s)
	}
}

// TestAHoldWhoseCloseCannotBeWrittenIsReportedAndKept: the sink refuses the
// closing record, so the trail stands where it stood and its entry is not
// forgotten; the pass reports it rather than counting it closed.
func TestAHoldWhoseCloseCannotBeWrittenIsReportedAndKept(t *testing.T) {
	snap := snapshot(t, approveRefunds)
	j := &journalDouble{}
	first, _, next := holdLost(t, snap, j)
	first.sink.refuseKind(kindApprovalExpired)
	r := next.p.Reconcile(context.Background())
	if (r != gateway.Reconciliation{Unclosed: 1, Complete: true}) {
		t.Errorf("Reconcile = %+v; want the hold reported unclosed", r)
	}
	expectKinds(t, kindsOf(first.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if got, kept := j.state("req-1"); !kept || got != gateway.HoldClosing {
		t.Errorf("the entry is %d, kept %v; want it left mid-close for a later pass to report", got, kept)
	}
	if s := next.p.Stats(); s.HoldsUnmeasured != 1 || s.HoldsClosed != 0 {
		t.Errorf("Stats = %+v; want the hold unmeasured and none closed", s)
	}
}

// expectClosedLostHold asserts the lost hold's trail ends in outcome and the
// plane's own block of verdict naming code, and validates as one chain.
func expectClosedLostHold(t *testing.T, h *harness, outcome controlv1.EventKind, verdict controlv1.Verdict, code string) []*controlv1.Event {
	t.Helper()
	trail := h.trailOf("req-1")
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, outcome, kindBlocked})
	if err := evidence.ValidateChain(trail); err != nil {
		t.Errorf("ValidateChain over the closed trail: %v", err)
	}
	if len(trail) != 5 {
		t.Fatalf("the trail holds %d event(s); the assertions below need the five", len(trail))
	}
	blocked := trail[4].GetDecision()
	if blocked.GetVerdict() != verdict || blocked.GetPdpType() != gateway.PDPType ||
		blocked.GetRequestId() != "req-1" || len(blocked.GetReasonCodes()) != 1 || blocked.GetReasonCodes()[0] != code {
		t.Errorf("ACTION_BLOCKED carries %+v; want this plane's %s naming %s", blocked, verdict, code)
	}
	return trail
}

// TestASettledHoldLeavesTheStore: a lost hold the reconciliation settles is
// forgotten by the store, so no approver is offered an answer nothing will
// read. A store that will not forget it is counted and the ledger's mark
// still holds. A hold whose approval the ledger marks spent keeps its record:
// TestALedgerThatFailsAfterItsWriteNeverRunsTheCallTwice refuses the next
// identical call on that record and that mark.
func TestASettledHoldLeavesTheStore(t *testing.T) {
	for _, c := range []struct {
		name       string
		releaseErr error
		gone, kept bool
		unheld     uint64
	}{
		{"settled and forgotten", nil, false, false, 0},
		{"a store that will not forget", errStore, false, true, 1},
		{"a record already gone", nil, true, false, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := newFakeStore()
			store.releaseErr = c.releaseErr
			var a *controlv1.Approval
			_, _, next := lostUnder(t, store, base().Add(time.Minute), func(pending gateway.Disposition) {
				a = approvalOfHold(t, store.MemoryApprovals, pending)
				if c.gone {
					if err := store.MemoryApprovals.Release(ctx(), bindingOfHeld(t, a), a.GetRequestId(), a.GetApprovalId()); err != nil {
						t.Fatal(err)
					}
				}
			})
			_, err := store.MemoryApprovals.Find(ctx(), bindingOfHeld(t, a), base().Add(time.Minute))
			if kept := err == nil; kept != c.kept {
				t.Errorf("the store keeps the settled record: %v (%v), want %v", kept, err, c.kept)
			}
			marks, err := next.spy.MemoryLedger.Lookup(ctx(), bindingOfHeld(t, a), base())
			if err != nil || marks[a.GetRequestId()] != gateway.ResolutionNotResumed {
				t.Errorf("the ledger marks %v, %v; want the hold settled", marks, err)
			}
			if s := next.p.Stats(); s.UnheldRecords != c.unheld {
				t.Errorf("Stats().UnheldRecords = %d, want %d", s.UnheldRecords, c.unheld)
			}
		})
	}
}

// TestMemoryApprovalsReleaseOnlyTheApprovalNamed: Release forgets the record
// of the approval and request it names, and nothing filed under another.
func TestMemoryApprovalsReleaseOnlyTheApprovalNamed(t *testing.T) {
	var store gateway.MemoryApprovals
	binding := approval.Binding("sha256:release")
	mustHold(t, &store, held(binding, "a-1", "req-1"))
	for name, call := range map[string]func() error{
		"another approval": func() error { return store.Release(ctx(), binding, "req-1", "a-2") },
		"another request":  func() error { return store.Release(ctx(), binding, "req-2", "a-1") },
		"another binding":  func() error { return store.Release(ctx(), "sha256:other", "req-1", "a-1") },
		"no approval":      func() error { return store.Release(ctx(), binding, "req-1", "") },
	} {
		if err := call(); !errors.Is(err, gateway.ErrNoApproval) {
			t.Errorf("Release of %s = %v, want ErrNoApproval", name, err)
		}
	}
	if found, err := store.Find(ctx(), binding, base()); err != nil || len(found) != 1 {
		t.Fatalf("after the refused releases the store keeps %d record(s), %v; want the one", len(found), err)
	}
	if err := store.Release(ctx(), binding, "req-1", "a-1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := store.Find(ctx(), binding, base()); !errors.Is(err, gateway.ErrNoApproval) {
		t.Errorf("Find after the release = %v, want ErrNoApproval", err)
	}
}
