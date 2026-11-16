package reaction_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
)

func TestSnapshotStates(t *testing.T) {
	var zero reaction.Snapshot
	if zero.State() != reaction.Unknown || zero.Cause() != reaction.CauseNeverRead || reaction.Matches(zero, reaction.Subject{Tenant: "acme", Run: "run-a"}, clock0, time.Time{}).Has(reaction.StopRun) {
		t.Fatalf("the zero snapshot: %s %s", zero.State(), zero.Cause())
	}
	if d := reaction.DisabledSnapshot(); d.State() != reaction.Disabled || d.Cause() != "" || reaction.Matches(d, reaction.Subject{Tenant: "acme", Run: "run-a"}, clock0, time.Time{}).Has(reaction.StopRun) {
		t.Fatalf("the disabled snapshot: %s %s", d.State(), d.Cause())
	}
	r := listRoute(t)
	refused := reaction.Snapshot{}.Next(r, []byte("{}\n"), clock0, poll)
	if refused.State() != reaction.Unknown || refused.Cause() != reaction.CauseMalformed || refused.Detail() == "" {
		t.Fatalf("a malformed list: %s %s %q", refused.State(), refused.Cause(), refused.Detail())
	}
	if reaction.Matches(refused, reaction.Subject{Tenant: "acme", Run: "run-a"}, clock0, time.Time{}).Has(reaction.StopRun) || len(refused.Entries()) != 0 {
		t.Fatal("an unknown snapshot names an entry")
	}
}

func TestSnapshotOfAListReadWhole(t *testing.T) {
	r := listRoute(t)
	empty := reaction.Snapshot{}.Next(r, newList(t, r).bytes(), clock0, poll)
	if empty.State() != reaction.Clear || empty.Header().ListID != "list-1" || empty.ReadAt() != clock0 {
		t.Fatalf("a list of a header: %s", empty.State())
	}
	b := newList(t, r)
	b.stop("fnd-a1", "run-a", clock0.Add(-2*time.Hour), time.Hour)
	expired := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	if expired.State() != reaction.Clear || len(expired.Entries()) != 1 {
		t.Fatalf("a list whose one stop expired: %s, %d entries", expired.State(), len(expired.Entries()))
	}
	b.stop("fnd-b1", "run-b", clock0, time.Hour)
	stopped := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	if stopped.State() != reaction.Stopped || stopped.Usage().Lines != 3 {
		t.Fatalf("a list with a stop in force: %s", stopped.State())
	}
}

// lapsedLikeAnApproval is the gateway's reading of an approval's expiry: a
// clock it cannot trust ends what it guards. Reading a stop that way is the
// mutant the rows below must catch.
func lapsedLikeAnApproval(now, floor, expires time.Time) bool {
	return !policy.UsableTime(now) || now.Before(floor) || !now.Before(expires)
}

func TestActiveKeepsAStopUnderAClockItCannotTrust(t *testing.T) {
	r := listRoute(t)
	b := newList(t, r)
	b.stop("fnd-a1", "run-a", clock0, time.Hour)
	s := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	expires := clock0.Add(time.Hour)
	for _, tc := range []struct {
		name       string
		run        string
		tenant     string
		now, floor time.Time
		want       bool
		untrusted  bool
	}{
		{"its run at the read", "run-a", "acme", clock0, time.Time{}, true, false},
		{"a second before expiry", "run-a", "acme", expires.Add(-time.Second), clock0, true, false},
		{"at expiry", "run-a", "acme", expires, clock0, false, false},
		{"past expiry", "run-a", "acme", expires.Add(time.Hour), expires, false, false},
		{"the zero clock", "run-a", "acme", time.Time{}, time.Time{}, true, true},
		{"a clock past expiry but behind the floor", "run-a", "acme", expires.Add(time.Hour), expires.Add(2 * time.Hour), true, true},
		{"a clock past 9999", "run-a", "acme", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Time{}, true, true},
		{"another run", "run-b", "acme", clock0, time.Time{}, false, false},
		{"its run of another tenant", "run-a", "other", clock0, time.Time{}, false, false},
		{"no run", "", "acme", clock0, time.Time{}, false, false},
	} {
		if got := reaction.Matches(s, reaction.Subject{Tenant: tc.tenant, Run: tc.run}, tc.now, tc.floor).Has(reaction.StopRun); got != tc.want {
			t.Errorf("%s: Active = %v, want %v", tc.name, got, tc.want)
		}
		if tc.untrusted && !lapsedLikeAnApproval(tc.now, tc.floor, expires) {
			t.Errorf("%s: the row does not tell a stop's expiry from an approval's lapse", tc.name)
		}
	}
}

// TestActiveReadsAClearSnapshotsEntries: an entry expired at the read is
// back in force for a call whose clock cannot be trusted.
func TestActiveReadsAClearSnapshotsEntries(t *testing.T) {
	r := listRoute(t)
	b := newList(t, r)
	b.stop("fnd-a1", "run-a", clock0.Add(-2*time.Hour), time.Hour)
	s := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	if s.State() != reaction.Clear {
		t.Fatalf("state %s", s.State())
	}
	if reaction.Matches(s, reaction.Subject{Tenant: "acme", Run: "run-a"}, clock0, time.Time{}).Has(reaction.StopRun) {
		t.Fatal("an expired entry stops a call at a trusted clock")
	}
	if !reaction.Matches(s, reaction.Subject{Tenant: "acme", Run: "run-a"}, time.Time{}, time.Time{}).Has(reaction.StopRun) {
		t.Fatal("an expired entry does not stop a call at the zero clock")
	}
}

func TestALiftEndsOnlyTheStopsThroughItsLine(t *testing.T) {
	r := listRoute(t)
	b := newList(t, r)
	b.stop("fnd-a1", "run-a", clock0, time.Hour) // 2
	b.lift("run-a", 2)                           // 3
	lifted := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	if lifted.State() != reaction.Clear || reaction.Matches(lifted, reaction.Subject{Tenant: "acme", Run: "run-a"}, time.Time{}, time.Time{}).Has(reaction.StopRun) {
		t.Fatalf("a lifted stop: %s", lifted.State())
	}
	b.stop("fnd-a2", "run-a", clock0, time.Hour) // 4
	again := lifted.Next(r, b.bytes(), clock0, poll)
	if again.State() != reaction.Stopped || !reaction.Matches(again, reaction.Subject{Tenant: "acme", Run: "run-a"}, clock0, time.Time{}).Has(reaction.StopRun) {
		t.Fatalf("a stop after the lift: %s", again.State())
	}
}

func TestSnapshotAgeRule(t *testing.T) {
	r := listRoute(t)
	b := newList(t, r)
	b.stop("fnd-a1", "run-a", clock0, time.Hour)
	s := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	if got := s.At(clock0.Add(3 * poll)); got.State() != reaction.Stopped {
		t.Fatalf("three intervals old: %s", got.State())
	}
	for _, tc := range []struct {
		name string
		at   time.Time
		want reaction.Cause
	}{
		{"three intervals and a nanosecond old", clock0.Add(3*poll + 1), reaction.CauseStale},
		{"read a nanosecond after the clock", clock0.Add(-1), reaction.CauseAhead},
	} {
		got := s.At(tc.at)
		if got.State() != reaction.Unknown || got.Cause() != tc.want || got.Accepted() != s.Accepted() {
			t.Errorf("%s: %s %s", tc.name, got.State(), got.Cause())
		}
	}
	var never reaction.Snapshot
	if got := never.At(clock0); got.State() != reaction.Unknown || got.Cause() != reaction.CauseNeverRead {
		t.Fatalf("the zero snapshot at a time: %s", got.Cause())
	}
}

func TestActiveEntriesAreBounded(t *testing.T) {
	if reaction.MaxListedEntries != 64 {
		t.Fatalf("MaxListedEntries = %d", reaction.MaxListedEntries)
	}
	r := listRoute(t)
	for _, n := range []int{64, 65} {
		b := newList(t, r)
		b.stop("fnd-old", "run-old", clock0.Add(-2*time.Hour), time.Hour)
		for i := range n {
			b.stop("fnd-"+strconv.Itoa(i), "run-"+strconv.Itoa(i), clock0, time.Hour)
		}
		s := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
		listed, total := s.ActiveEntries(clock0, time.Time{})
		if len(listed) != 64 || total != n || listed[0].RunID != "run-0" {
			t.Errorf("%d active: listed %d, total %d", n, len(listed), total)
		}
	}
}

func TestCausesAreNamedOnce(t *testing.T) {
	seen := map[reaction.Cause]bool{}
	for _, c := range reaction.Causes() {
		if c == "" || seen[c] {
			t.Errorf("cause %q empty or named twice", c)
		}
		seen[c] = true
	}
	for _, tc := range []struct {
		err  error
		want reaction.Cause
	}{
		{reaction.ErrListTooLarge, reaction.CauseTooLarge},
		{reaction.ErrListLines, reaction.CauseTooLarge},
		{reaction.ErrListRoute, reaction.CauseRoute},
		{reaction.ErrListHeader, reaction.CauseHeader},
		{reaction.ErrListShrunk, reaction.CauseShrunk},
		{reaction.ErrListRewritten, reaction.CauseRewritten},
		{reaction.ErrStopRefused, reaction.CauseNotPermitted},
		{reaction.ErrDatedAhead, reaction.CauseDatedAhead},
		{reaction.ErrLiftUnsigned, reaction.CauseLift},
		{reaction.ErrLiftMismatch, reaction.CauseLift},
		{reaction.ErrJudgeClock, reaction.CauseClock},
		{reaction.ErrLiftOrder, reaction.CauseMalformed},
		{reaction.ErrEntryID, reaction.CauseMalformed},
	} {
		if got := reaction.CauseOf(tc.err); got != tc.want || !seen[got] {
			t.Errorf("CauseOf(%q) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestDetailIsBounded(t *testing.T) {
	s := reaction.Snapshot{}.Unknown(reaction.CauseMalformed, strings.Repeat("é", 300), clock0, poll)
	if d := s.Detail(); len(d) > 256+3 || !strings.HasSuffix(d, "...") || !strings.HasPrefix(d, "é") {
		t.Fatalf("detail of %d bytes", len(d))
	}
}
