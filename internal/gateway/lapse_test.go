package gateway_test

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
)

// slowJournal runs onResuming while it flips an entry to HoldResuming, the
// one write a resume makes between consuming its approval and recording it.
type slowJournal struct {
	gateway.MemoryHoldJournal
	onResuming func()
}

func (j *slowJournal) Mark(ctx context.Context, requestID string, state gateway.HoldState) error {
	if run := j.onResuming; run != nil && state == gateway.HoldResuming {
		run()
	}
	return j.MemoryHoldJournal.Mark(ctx, requestID, state)
}

// spendingStore edits what Find hands back when answer is set.
type spendingStore struct {
	gateway.ApprovalStore
	mu     sync.Mutex
	answer func(*controlv1.Approval)
}

func (s *spendingStore) Find(ctx context.Context, b approval.Binding, now time.Time) ([]gateway.Held, error) {
	helds, err := s.ApprovalStore.Find(ctx, b, now)
	s.mu.Lock()
	edit := s.answer
	s.mu.Unlock()
	for i := range helds {
		if edit != nil {
			edit(helds[i].Approval)
		}
	}
	return helds, err
}

// expectSpent asserts the ledger marks req-1's approval spent, and that the
// plane offered it exactly spends approvals.
func expectSpent(t *testing.T, l *fakeLedger, spends int) {
	t.Helper()
	if got, _ := l.asked(); got != spends {
		t.Errorf("the plane offered %d approval(s) to the ledger; want %d", got, spends)
	}
	marks, err := l.MemoryLedger.Lookup(ctx(), l.spentUnder(), base())
	if err != nil || marks["req-1"] != gateway.ResolutionConsumed {
		t.Errorf("the ledger marks %v, %v; want req-1 spent", marks, err)
	}
}

// lapseRig is a plane over approveRefunds whose held refund was approved,
// with a journal and a store the test can watch; the approval the plane
// minted expires at base() plus the TTL.
type lapseRig struct {
	*harness
	journal *slowJournal
	store   *spendingStore
	first   gateway.Disposition
}

const lapseTTL = 10 * time.Minute

func lapsing(t *testing.T) *lapseRig {
	t.Helper()
	return lapsingUnder(t, snapshot(t, approveRefunds))
}

// lapsingUnder is lapsing over snap, a snapshot of approveRefunds; mut edits
// the config after the rig's own edits.
func lapsingUnder(t *testing.T, snap *policy.Snapshot, mut ...func(*gateway.Config)) *lapseRig {
	t.Helper()
	r := &lapseRig{journal: &slowJournal{}}
	r.harness = build(t, modeEnforce, snap, append([]func(*gateway.Config){func(cfg *gateway.Config) {
		cfg.Journal = r.journal
		r.store = &spendingStore{ApprovalStore: cfg.Approvals}
		cfg.Approvals = r.store
		cfg.ApprovalTTL = lapseTTL
	}}, mut...)...)
	r.first = hold(t, r.harness)
	if got := r.first.Pending.ExpiresAt; !got.Equal(base().Add(lapseTTL)) {
		t.Fatalf("the hold expires at %s, want %s", got, base().Add(lapseTTL))
	}
	if err := r.harness.store.Answer(r.first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	r.clock.set(base().Add(2 * time.Minute))
	return r
}

// slowSteps are the two writes a resume waits on between consuming its
// approval and handing its call out, each made slow enough for the clock to
// reach at.
var slowSteps = []struct {
	name string
	slow func(r *lapseRig, at time.Time)
}{
	{"a slow journal", func(r *lapseRig, at time.Time) {
		r.journal.onResuming = func() { r.clock.set(at) }
	}},
	{"a slow sink", func(r *lapseRig, at time.Time) {
		r.sink.hook(kindApprovalDecided, func() { r.clock.set(at) })
	}},
}

// TestAnApprovalThatLapsesBeforeTheHandOutRunsNothing: an approval consumed
// while unexpired, whose expiry the plane's clock reaches while the journal
// or the sink is slow, sends nothing. The held trail closes with the plane's
// DENY naming APPROVAL_EXPIRED, its entry goes, the approval stays spent, and
// the next identical call runs nothing either. One tick earlier the same
// resume runs, so the expiry itself is what blocks.
func TestAnApprovalThatLapsesBeforeTheHandOutRunsNothing(t *testing.T) {
	expires := base().Add(lapseTTL)
	for _, step := range slowSteps {
		t.Run(step.name+", to the expiry", func(t *testing.T) {
			r := lapsing(t)
			step.slow(r, expires)
			expectLapsed(t, r, r.admit(retry(t, "req-2"), refundArgs()))
		})
		t.Run(step.name+", to a tick before the expiry", func(t *testing.T) {
			r := lapsing(t)
			step.slow(r, expires.Add(-time.Nanosecond))
			d := r.admit(retry(t, "req-2"), refundArgs())
			if d.Action != core.Execute || d.ExecutionID == "" {
				t.Fatalf("a resume a tick before the expiry: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
			}
			expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
		})
	}
}

// TestTheHandOutIsJudgedByTheStoresShorterExpiry: a store may answer with an
// expiry earlier than the one the plane minted, and the plane accepts it. The
// hand-out is then judged by that earlier expiry, not by the minted one.
func TestTheHandOutIsJudgedByTheStoresShorterExpiry(t *testing.T) {
	shorter := base().Add(5 * time.Minute)
	r := lapsing(t)
	r.store.mu.Lock()
	r.store.answer = func(a *controlv1.Approval) { a.ExpiresAt = timestamppb.New(shorter) }
	r.store.mu.Unlock()
	r.journal.onResuming = func() { r.clock.set(shorter) }
	expectLapsed(t, r, r.admit(retry(t, "req-2"), refundArgs()))
}

// expectLapsed asserts d is the plane's block of a resume whose approval
// lapsed before the hand-out: nothing sent, the held trail closed and its
// entry gone, the approval spent once, and the next identical call not run.
func expectLapsed(t *testing.T, r *lapseRig, d gateway.Disposition) {
	t.Helper()
	expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
	if got := d.Decision.GetReasonCodes(); !slices.Equal(got, []string{codeApprovalExpired}) {
		t.Errorf("the block names %v, want only %s", got, codeApprovalExpired)
	}
	if d.ExecutionID != "" {
		t.Errorf("a lapsed approval was handed execution %q", d.ExecutionID)
	}
	expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindBlocked})
	if entries := r.journal.Entries(); len(entries) != 0 {
		t.Errorf("the journal keeps %v after the held trail closed", entries)
	}
	if s := r.p.Stats(); s.Executed != 0 || s.Open != 0 || s.Held != 0 || s.Blocks[codeApprovalExpired] != 1 {
		t.Errorf("Stats = %+v; want nothing run, open or held, and one APPROVAL_EXPIRED block", s)
	}
	expectSpent(t, r.ledger, 1)

	next := r.admit(retry(t, "req-3"), refundArgs())
	if next.Action == core.Execute || next.Action == core.ExecuteWithObligations {
		t.Fatalf("the call after the lapse ran: codes %v", next.Decision.GetReasonCodes())
	}
	if got := r.spent(); got != 1 {
		t.Errorf("Spend was called %d time(s); want once, by the resume that lapsed", got)
	}
}

// TestAPauseInTheWindowOfALapseRunsNothing: a pause written and the expiry
// reached while the approval record is appended block the start once, with
// the plane's own cause first (ADR-0019), and the approval stays spent.
func TestAPauseInTheWindowOfALapseRunsNothing(t *testing.T) {
	r := lapsing(t)
	r.pause.set(clearAt(t, r.clock.read()))
	expires := base().Add(lapseTTL)
	r.sink.hook(kindApprovalDecided, func() {
		r.clock.set(expires)
		r.pause.set(pause.Read(pauseFile(t, pauseGlobal), expires, pauseInterval))
	})
	d := r.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictDeny, codePaused, gateway.PDPType)
	if got := d.Decision.GetReasonCodes(); !slices.Equal(got, []string{codePaused}) {
		t.Errorf("the block names %v, want only %s", got, codePaused)
	}
	if d.ExecutionID != "" {
		t.Errorf("a paused, lapsed resume was handed execution %q", d.ExecutionID)
	}
	expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindBlocked})
	if s := r.p.Stats(); s.Executed != 0 || s.Open != 0 || s.Blocks[codePaused] != 1 || len(s.Blocks) != 1 {
		t.Errorf("Stats = %+v; want nothing run and one block, counted as PAUSED", s)
	}
	expectSpent(t, r.ledger, 1)
}

// TestConcurrentRetriesOfALapsingApprovalRunAtMostOnce: many identical
// retries at once while the one that resumes waits on the sink. When the
// clock reaches the expiry in that wait, nothing runs and one retry closes
// the held trail as expired; a tick earlier, exactly one runs. No other retry
// consumes or runs anything in either case.
func TestConcurrentRetriesOfALapsingApprovalRunAtMostOnce(t *testing.T) {
	expires := base().Add(lapseTTL)
	for _, tc := range []struct {
		name              string
		at                time.Time
		executed, expired uint64
		closing           controlv1.EventKind
	}{
		{"to the expiry", expires, 0, 1, kindBlocked},
		{"to a tick before the expiry", expires.Add(-time.Nanosecond), 1, 0, kindStarted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := lapsing(t)
			r.sink.hook(kindApprovalDecided, func() { r.clock.set(tc.at) })
			const retries = 16
			var wg sync.WaitGroup
			results := make([]gateway.Disposition, retries)
			for i := range retries {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results[i] = r.admit(retry(t, "req-retry-"+strconv.Itoa(i)), refundArgs())
				}()
			}
			wg.Wait()
			executed, expired := tally(t, results, r.first.Pending.ApprovalID)
			if executed != tc.executed || expired != tc.expired {
				t.Errorf("%d executed and %d closed as expired; want %d and %d", executed, expired, tc.executed, tc.expired)
			}
			expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, tc.closing})
			if s := r.p.Stats(); s.Executed != tc.executed {
				t.Errorf("Stats.Executed = %d, want %d", s.Executed, tc.executed)
			}
		})
	}
}

// waiting reports whether d holds the retry: under a new approval of its own,
// or on the held approval still pending as this retry read it.
func waiting(d gateway.Disposition, heldApprovalID string, codes []string) bool {
	if d.Action != core.AwaitApproval || d.Pending == nil {
		return false
	}
	return d.Pending.ApprovalID != heldApprovalID || slices.Equal(codes, []string{codeApprovalRequired})
}

// tally counts the retries that ran and those that closed the held trail as
// expired. Every other answer must be a refusal as already used, a hold of
// its own under a new approval, or the held approval still pending as a retry
// read it while another retry was resuming it; anything else fails.
func tally(t *testing.T, results []gateway.Disposition, heldApprovalID string) (executed, expired uint64) {
	t.Helper()
	for _, d := range results {
		codes := d.Decision.GetReasonCodes()
		switch {
		case d.Action == core.Execute:
			executed++
		case d.Action == core.Block && slices.Equal(codes, []string{codeApprovalExpired}):
			expired++
		case d.Action == core.Block && slices.Equal(codes, []string{codeApprovalAlreadyUsed}):
		case waiting(d, heldApprovalID, codes):
		default:
			t.Errorf("a retry answered %d with %v", d.Action, codes)
		}
	}
	return executed, expired
}

// TestAnApprovalThatLapsesDuringTheStartedAppendIsNotHandedOut: the clock
// reaches the expiry while ACTION_STARTED is appended. The execution is
// aborted through the plane's own abort, ACTION_FAILED with a BLOCKED result
// naming APPROVAL_EXPIRED, and the call gets the plane's block with nothing to
// send. A tick earlier it is handed out.
func TestAnApprovalThatLapsesDuringTheStartedAppendIsNotHandedOut(t *testing.T) {
	expires := base().Add(lapseTTL)
	for _, at := range []time.Time{expires, expires.Add(time.Hour)} {
		t.Run(at.Sub(expires).String()+" past the expiry", func(t *testing.T) {
			r := lapsing(t)
			r.sink.hook(kindStarted, func() { r.clock.set(at) })
			d := r.admit(retry(t, "req-2"), refundArgs())
			expectAbortedLapse(t, r, d, at)
		})
	}
	t.Run("a tick before the expiry", func(t *testing.T) {
		r := lapsing(t)
		r.sink.hook(kindStarted, func() { r.clock.set(expires.Add(-time.Nanosecond)) })
		d := r.admit(retry(t, "req-2"), refundArgs())
		if d.Action != core.Execute || d.ExecutionID == "" {
			t.Fatalf("a resume a tick before the expiry: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
		}
	})
}

// expectAbortedLapse asserts d is the plane's block of a started execution
// whose approval lapsed during its ACTION_STARTED append: nothing handed out,
// the trail closed by the aborted record, both timed at the reading at, and
// the approval spent.
func expectAbortedLapse(t *testing.T, r *lapseRig, d gateway.Disposition, at time.Time) {
	t.Helper()
	expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
	if got := d.Decision.GetDecidedAt().AsTime(); !got.Equal(at) {
		t.Errorf("the block was decided at %s, want the reading after the append, %s", got, at)
	}
	if d.ExecutionID != "" {
		t.Errorf("a lapsed approval was handed execution %q", d.ExecutionID)
	}
	expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindFailed})
	expectAbortRecord(t, r.trailOf("req-1"), at)
	if entries := r.journal.Entries(); len(entries) != 0 {
		t.Errorf("the journal keeps %v after the held trail closed", entries)
	}
	if s := r.p.Stats(); s.Executed != 0 || s.Open != 0 || s.Blocks[codeApprovalExpired] != 1 {
		t.Errorf("Stats = %+v; want nothing run or open and one APPROVAL_EXPIRED block", s)
	}
	expectSpent(t, r.ledger, 1)
	expectRequestIDFreed(t, r)
}

// expectAbortRecord asserts the trail of six ends in ACTION_FAILED with a
// BLOCKED result naming APPROVAL_EXPIRED for the execution ACTION_STARTED
// named, nothing executed, ended at at.
func expectAbortRecord(t *testing.T, trail []*controlv1.Event, at time.Time) {
	t.Helper()
	if len(trail) != 6 {
		t.Errorf("the trail holds %d events, want 6 ending in the abort record", len(trail))
		return
	}
	aborted := trail[5].GetResult()
	if aborted.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_BLOCKED || aborted.GetToolProtocolStatus() != codeApprovalExpired ||
		aborted.GetExecutedActionDigest() != "" || aborted.GetExecutionId() != trail[4].GetExecutionId() ||
		!aborted.GetEndedAt().AsTime().Equal(at) {
		t.Errorf("ACTION_FAILED carries %+v; want a BLOCKED result naming %s and nothing executed", aborted, codeApprovalExpired)
	}
}

// expectRequestIDFreed asserts the closed trail of req-1 freed its request
// id: a later call under it writes a trail of its own instead of being
// refused as an open one.
func expectRequestIDFreed(t *testing.T, r *lapseRig) {
	t.Helper()
	before := len(r.trailOf("req-1"))
	later := r.admit(retry(t, "req-1"), refundArgs())
	if slices.Contains(later.Decision.GetReasonCodes(), codeInvalidFieldValue) || len(r.trailOf("req-1")) == before {
		t.Errorf("a later call under the closed request id was refused as open: codes %v", later.Decision.GetReasonCodes())
	}
}

// TestAStartedResumeTheClockCannotVouchForIsNotHandedOut: a zero clock
// reading after ACTION_STARTED proves nothing unexpired, so the execution is
// taken back; an abort record the sink refuses still hands out nothing, and
// the trail left open at ACTION_STARTED is counted.
func TestAStartedResumeTheClockCannotVouchForIsNotHandedOut(t *testing.T) {
	t.Run("a zero reading", func(t *testing.T) {
		r := lapsing(t)
		r.sink.hook(kindStarted, func() { r.clock.set(time.Time{}) })
		d := r.admit(retry(t, "req-2"), refundArgs())
		expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
		expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindFailed})
	})
	t.Run("an abort the sink refuses", func(t *testing.T) {
		r := lapsing(t)
		r.sink.hook(kindStarted, func() {
			r.clock.set(base().Add(lapseTTL))
			r.sink.refuseKind(kindFailed)
		})
		d := r.admit(retry(t, "req-2"), refundArgs())
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		if got := d.Decision.GetDecidedAt().AsTime(); !got.Equal(base().Add(lapseTTL)) {
			t.Errorf("the block was decided at %s, want the reading after the append", got)
		}
		if d.ExecutionID != "" {
			t.Errorf("a lapsed approval was handed execution %q", d.ExecutionID)
		}
		expectKinds(t, kindsOf(r.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
		if s := r.p.Stats(); s.Executed != 0 || s.Open != 0 || s.HeldTrailsLeftOpen != 1 || s.Blocks[codeEvidenceUnavailable] != 1 {
			t.Errorf("Stats = %+v; want nothing run or open, the open trail counted and one EVIDENCE_UNAVAILABLE block", s)
		}
		// The trail left open keeps its journal entry for the next start and
		// its request id, so no later call writes a second trail into it.
		if entry, kept := r.journal.Entries()["req-1"]; !kept || entry.State != gateway.HoldResuming {
			t.Errorf("the journal keeps %v for req-1; want its entry in HoldResuming", r.journal.Entries())
		}
		r.sink.accept()
		later := r.admit(retry(t, "req-1"), refundArgs())
		expectBlock(t, later, verdictIndeterminate, codeInvalidFieldValue, gateway.PDPType)
		expectKinds(t, kindsOf(r.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
	})
}
