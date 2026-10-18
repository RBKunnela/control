package gateway_test

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// unusableReadings are clock readings the kernel refuses to decide at, and
// none of them is the zero time an IsZero check would catch. Taken after a
// decision at base, each is also behind that decision's reading or past every
// expiry here, so the tests that use them hold whichever check catches it;
// TestARunAtAnUnusableClockWithNothingToRelyOnStartsNothing is the one only
// the range check decides.
var unusableReadings = []struct {
	name string
	at   time.Time
}{
	{"a second before the epoch", time.Date(1969, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"1600", time.Date(1600, time.January, 1, 0, 0, 0, 0, time.UTC)},
	{"the first instant of 10000", time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
}

// TestAResumeTheClockCannotVouchForBeforeTheStartRunsNothing: an unusable
// reading taken right before the hand-out proves no approval unexpired, so
// the resume closes its held trail as lapsed and starts nothing.
func TestAResumeTheClockCannotVouchForBeforeTheStartRunsNothing(t *testing.T) {
	for _, step := range slowSteps {
		for _, reading := range unusableReadings {
			t.Run(step.name+", "+reading.name, func(t *testing.T) {
				r := lapsing(t)
				step.slow(r, reading.at)
				expectLapsed(t, r, r.admit(retry(t, "req-2"), refundArgs()))
			})
		}
	}
}

// TestAStartedResumeAClockOutOfRangeCannotVouchForIsNotHandedOut: the same
// readings after ACTION_STARTED take the execution back, as the zero time does.
func TestAStartedResumeAClockOutOfRangeCannotVouchForIsNotHandedOut(t *testing.T) {
	for _, reading := range unusableReadings {
		t.Run(reading.name, func(t *testing.T) {
			r := lapsing(t)
			r.sink.hook(kindStarted, func() { r.clock.set(reading.at) })
			d := r.admit(retry(t, "req-2"), refundArgs())
			expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
			expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindFailed})
		})
	}
}

// TestARunTheClockCannotVouchForStartsNothing: an unusable reading taken
// after the decision and before the hand-out proves no opened run unexpired.
func TestARunTheClockCannotVouchForStartsNothing(t *testing.T) {
	for _, reading := range unusableReadings {
		t.Run(reading.name, func(t *testing.T) {
			runs := newRuns("root-1")
			h := build(t, modeObserve, snapshot(t, allowReads), withRuns(runs))
			h.sink.hook(kindDecided, func() { h.clock.set(reading.at) })
			r := opened("run-a", "root-1")
			r.Expires = base().Add(time.Hour)
			d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, sensSecret), r))
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			if slices.Contains(kindsOf(h.trailOf("r-1")), kindStarted) {
				t.Errorf("a run the clock cannot vouch for started: %v", kindsOf(h.trailOf("r-1")))
			}
		})
	}
}

// TestARunTheClockCannotVouchForWhileItsStartIsAppendedIsAborted: the same
// readings after ACTION_STARTED close the execution as never sent.
func TestARunTheClockCannotVouchForWhileItsStartIsAppendedIsAborted(t *testing.T) {
	for _, reading := range unusableReadings {
		t.Run(reading.name, func(t *testing.T) {
			runs := newRuns("root-1")
			h := build(t, modeObserve, snapshot(t, allowReads), withRuns(runs))
			h.sink.hook(kindStarted, func() { h.clock.set(reading.at) })
			r := opened("run-a", "root-1")
			r.Expires = base().Add(time.Hour)
			d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), r))
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			expectKinds(t, kindsOf(h.trailOf("r-1")), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindFailed})
		})
	}
}

// TestARunTheClockWasSetBackOnStartsNothing: once the kernel decided at a
// reading, a later reading behind it proves no opened run unexpired, whether
// the run expired before it or not, even when the snapshot was confirmed
// earlier still. The twin, a reading equal to the decision's and before the
// expiry, runs.
func TestARunTheClockWasSetBackOnStartsNothing(t *testing.T) {
	cases := []struct {
		name    string
		expires time.Time
		after   controlv1.EventKind
		at      time.Time
		runs    bool
	}{
		{"an expired run, set back after the decision", base().Add(-time.Minute), kindDecided, base().Add(-2 * time.Hour), false},
		{"a live run, a nanosecond behind the decision", base().Add(time.Hour), kindDecided, base().Add(-time.Nanosecond), false},
		{"a live run, set back while its start is appended", base().Add(time.Hour), kindStarted, base().Add(-time.Nanosecond), false},
		{"a live run, at the decision's reading", base().Add(time.Hour), kindDecided, base(), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshotAt(t, base().Add(-time.Minute), allowReads), withRuns(newRuns("root-1")))
			h.sink.hook(c.after, func() { h.clock.set(c.at) })
			r := opened("run-a", "root-1")
			r.Expires = c.expires
			d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), r))
			if c.runs {
				if d.Action != core.Execute || d.ExecutionID == "" {
					t.Fatalf("a reading equal to the decision's: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
				}
				return
			}
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
			if d.ExecutionID != "" {
				t.Errorf("a run behind its decision was handed execution %q", d.ExecutionID)
			}
		})
	}
}

// TestAResumeBehindItsRequestSpendsNothing: an approval requested at base
// proves nothing unexpired to a resume whose every reading is earlier than
// that. The retry is refused as expired on its own trail before the approval
// is consumed, so the hold stands, and a retry at the request's own instant
// runs on it.
func TestAResumeBehindItsRequestSpendsNothing(t *testing.T) {
	r := lapsingUnder(t, snapshotAt(t, base().Add(-5*time.Minute), approveRefunds))
	r.clock.set(base().Add(-time.Minute))
	d := r.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
	if got := r.store.consumed.Load(); got != 0 {
		t.Fatalf("Consume was called %d time(s) behind the request; want none", got)
	}
	if entries := r.journal.Entries(); len(entries) != 1 {
		t.Fatalf("the journal keeps %d entries, want the hold's", len(entries))
	}
	r.clock.set(base())
	again := r.admit(retry(t, "req-3"), refundArgs())
	if again.Action != core.Execute || again.ExecutionID == "" {
		t.Fatalf("a resume at the request's instant: Action = %d, codes %v", again.Action, again.Decision.GetReasonCodes())
	}
}

// scriptedClock reads through to next until armed; armed, it serves its
// readings in order, then the last of them, and counts every read it served.
type scriptedClock struct {
	mu       sync.Mutex
	next     func() time.Time
	readings []time.Time
	served   int
}

func (s *scriptedClock) read() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.readings) == 0 {
		return s.next()
	}
	at := s.readings[min(s.served, len(s.readings)-1)]
	s.served++
	return at
}

func (s *scriptedClock) arm(readings ...time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readings, s.served = readings, 0
}

func (s *scriptedClock) disarm() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	served := s.served
	s.readings, s.served = nil, 0
	return served
}

// TestAResumeBehindADecisionItReliedOnSpendsNothing: a resume reads the
// clock once at its start, the kernel reads it deciding the proposed refund
// and again deciding the capped one, and the resume reads it once more before
// consuming. A last reading behind a decision's reading, though after the
// request and the start, proves the approval unexpired at no instant the call
// may rely on, so nothing is consumed and the hold stands; the authorized
// decision's reading counts as much as the proposed one's. A retry the clock
// does not set back runs on the same approval.
func TestAResumeBehindADecisionItReliedOnSpendsNothing(t *testing.T) {
	start, decided, consumeAt := base().Add(2*time.Minute), base().Add(6*time.Minute), base().Add(4*time.Minute)
	for _, c := range []struct {
		name                 string
		proposed, authorized time.Time
	}{
		{"behind both decisions", decided, decided},
		{"behind the authorized decision only", start, decided},
	} {
		t.Run(c.name, func(t *testing.T) {
			sc := &scriptedClock{}
			r := lapsingUnder(t, snapshot(t, approveRefunds), func(cfg *gateway.Config) {
				sc.next = cfg.Clock
				cfg.Clock = sc.read
			})
			script := []time.Time{start, c.proposed, c.proposed, c.authorized, c.authorized, consumeAt}
			sc.arm(script...)
			d := r.admit(retry(t, "req-2"), refundArgs())
			served := sc.disarm()
			if got := r.store.consumed.Load(); got != 0 {
				t.Fatalf("Consume was called %d time(s) behind a decision; want none", got)
			}
			if served != len(script) {
				t.Fatalf("the resume read the clock %d time(s); the script is for %d", served, len(script))
			}
			expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
			if got := d.Decision.GetDecidedAt().AsTime(); !got.Equal(consumeAt) {
				t.Errorf("the block is dated %v; want the reading before the consume, %v", got, consumeAt)
			}
			trail := r.trailOf("req-2")
			if len(trail) < 2 || !trail[1].GetDecision().GetDecidedAt().AsTime().Equal(c.authorized) {
				t.Fatalf("the retry's recorded decision is not the authorized one at %v: %v", c.authorized, trail)
			}
			if entries := r.journal.Entries(); len(entries) != 1 {
				t.Fatalf("the journal keeps %d entries, want the hold's", len(entries))
			}
			r.clock.set(decided)
			again := r.admit(retry(t, "req-3"), refundArgs())
			if again.Action != core.Execute || again.ExecutionID == "" {
				t.Fatalf("a resume at the decision's reading: Action = %d, codes %v", again.Action, again.Decision.GetReasonCodes())
			}
		})
	}
}

// TestARunUnderObserveBehindTheVerifiedTimeStartsNothing: OBSERVE runs a call
// the kernel stopped on its clock, but a reading behind the time the plane
// verified for its snapshot proves no opened run unexpired, so a run-bound
// call starts nothing. The twin, at that time, runs.
func TestARunUnderObserveBehindTheVerifiedTimeStartsNothing(t *testing.T) {
	for _, c := range []struct {
		name string
		at   time.Time
		runs bool
	}{
		{"a nanosecond behind", base().Add(-time.Nanosecond), false},
		{"at it", base(), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, modeObserve, snapshot(t, allowReads), withRuns(newRuns("root-1")))
			h.clock.set(c.at)
			d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), opened("run-a", "root-1")))
			if c.runs {
				if d.Action != core.Execute || d.ExecutionID == "" {
					t.Fatalf("Action = %d, codes %v; want it run", d.Action, d.Decision.GetReasonCodes())
				}
				return
			}
			expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		})
	}
}

// TestAClockSetBackWhileTheStartIsAppendedHandsOutNothing: a reading the call
// already relied on before the hand-out, not only the decision's, is a floor
// for the reading after ACTION_STARTED. Set forward after the decision and
// back, still after it, while the start is appended, the call is taken back.
func TestAClockSetBackWhileTheStartIsAppendedHandsOutNothing(t *testing.T) {
	t.Run("an opened run", func(t *testing.T) {
		h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(newRuns("root-1")))
		h.sink.hook(kindDecided, func() {
			// The bundle is renewed at the reading it jumps to, so the policy
			// is current at hand-out and the run's floor is what is judged.
			h.clock.set(base().Add(50 * time.Minute))
			h.policy.set(snapshotAt(t, base().Add(50*time.Minute), allowReads))
		})
		h.sink.hook(kindStarted, func() { h.clock.set(base().Add(30 * time.Minute)) })
		d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), opened("run-a", "root-1")))
		expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		expectKinds(t, kindsOf(h.trailOf("r-1")), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindFailed})
	})
	t.Run("a resumed approval", func(t *testing.T) {
		r := lapsing(t)
		r.journal.onResuming = func() { r.clock.set(base().Add(5 * time.Minute)) }
		r.sink.hook(kindStarted, func() { r.clock.set(base().Add(3 * time.Minute)) })
		d := r.admit(retry(t, "req-2"), refundArgs())
		expectBlock(t, d, verdictDeny, codeApprovalExpired, gateway.PDPType)
		expectOneChain(t, r.harness, []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindFailed})
	})
}

// TestARunAtAnUnusableClockWithNothingToRelyOnStartsNothing: under OBSERVE
// with no snapshot the call relied on no instant at all, so only the range
// check stands between a reading before 1970 and a run that expires later.
func TestARunAtAnUnusableClockWithNothingToRelyOnStartsNothing(t *testing.T) {
	h := build(t, modeObserve, nil, withRuns(newRuns("root-1")))
	h.clock.set(time.Date(1969, time.December, 31, 23, 59, 59, 0, time.UTC))
	d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), opened("run-a", "root-1")))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if d.ExecutionID != "" {
		t.Errorf("a run at a reading before 1970 was handed execution %q", d.ExecutionID)
	}
}

// TestARunAfterAReadingPast9999StartsNothing: a call that read the clock
// after 9999 holds every later reading to it, so a clock that comes back
// before the hand-out proves no opened run unexpired either.
func TestARunAfterAReadingPast9999StartsNothing(t *testing.T) {
	h := build(t, modeObserve, snapshot(t, allowReads), withRuns(newRuns("root-1")))
	h.clock.set(time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC))
	h.sink.hook(kindDecided, func() { h.clock.set(base().Add(time.Minute)) })
	d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), opened("run-a", "root-1")))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
}

// TestARunBehindTheKernelsOwnReadingStartsNothing: the kernel reads the clock
// itself, after the call's first reading. A later reading behind the
// kernel's, though after the call's first, proves no opened run unexpired.
func TestARunBehindTheKernelsOwnReadingStartsNothing(t *testing.T) {
	var reads atomic.Int64
	h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(newRuns("root-1")), func(cfg *gateway.Config) {
		cfg.Clock = func() time.Time {
			switch n := reads.Add(1); {
			case n == 1:
				return base()
			case n <= 3:
				return base().Add(10 * time.Minute)
			}
			return base().Add(5 * time.Minute)
		}
	})
	d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, 0), opened("run-a", "root-1")))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	if got := d.Decision.GetDecidedAt().AsTime(); !got.Equal(base().Add(5 * time.Minute)) {
		t.Errorf("the block is dated %v; want the reading after the kernel's", got)
	}
}
