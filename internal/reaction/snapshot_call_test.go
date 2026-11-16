package reaction_test

import (
	"math"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// TestForCallAppliesTheAgeRule: a Clear or Stopped read past three poll
// intervals, or read after the call's clock, answers unknown with that cause
// for every run, and within its age answers for the call's own run alone.
func TestForCallAppliesTheAgeRule(t *testing.T) {
	r := listRoute(t)
	clearRead := reaction.Snapshot{}.Next(r, newList(t, r).bytes(), clock0, poll)
	b := newList(t, r)
	b.stop("fnd-a1", "run-a", clock0, time.Hour)
	stopped := reaction.Snapshot{}.Next(r, b.bytes(), clock0, poll)
	refused := reaction.Snapshot{}.Next(r, []byte("{}\n"), clock0, poll)
	for _, tc := range []struct {
		name      string
		s         reaction.Snapshot
		run       string
		now       time.Time
		want      reaction.State
		wantCause reaction.Cause
	}{
		{"a clear read at its age", clearRead, "run-a", clock0.Add(3 * poll), reaction.Clear, ""},
		{"a clear read a nanosecond past its age", clearRead, "run-a", clock0.Add(3*poll + 1), reaction.Unknown, reaction.CauseStale},
		{"a clear read a day old", clearRead, "run-a", clock0.Add(24 * time.Hour), reaction.Unknown, reaction.CauseStale},
		{"a clear read after the call's clock", clearRead, "run-a", clock0.Add(-1), reaction.Unknown, reaction.CauseAhead},
		{"a clear read under the zero clock", clearRead, "run-a", time.Time{}, reaction.Unknown, reaction.CauseAhead},
		{"the stopped run", stopped, "run-a", clock0.Add(poll), reaction.Stopped, ""},
		{"another run under a stop", stopped, "run-b", clock0.Add(poll), reaction.Clear, ""},
		{"another run past the age", stopped, "run-b", clock0.Add(3*poll + 1), reaction.Unknown, reaction.CauseStale},
		{"a refused read", refused, "run-b", clock0, reaction.Unknown, reaction.CauseMalformed},
		{"the zero snapshot", reaction.Snapshot{}, "run-b", clock0, reaction.Unknown, reaction.CauseNeverRead},
		{"a plane with no route", reaction.DisabledSnapshot(), "run-a", clock0, reaction.Disabled, ""},
	} {
		got, cause, _ := tc.s.ForSubject(reaction.Subject{Tenant: "acme", Run: tc.run}, tc.now, time.Time{})
		if got != tc.want || cause != tc.wantCause {
			t.Errorf("%s: %s %q, want %s %q", tc.name, got, cause, tc.want, tc.wantCause)
		}
	}
	if got, _, _ := stopped.ForSubject(reaction.Subject{Tenant: "other", Run: "run-a"}, clock0, time.Time{}); got != reaction.Clear {
		t.Errorf("the stopped run of another tenant: %s, want clearRead", got)
	}
	late := clock0.Add(time.Hour)
	expired := reaction.Snapshot{}.Next(r, b.bytes(), late, poll)
	if got, _, _ := expired.ForSubject(reaction.Subject{Tenant: "acme", Run: "run-a"}, late, late); got != reaction.Clear {
		t.Errorf("an expired stop under a trusted clock: %s, want clearRead", got)
	}
	if got, _, _ := expired.ForSubject(reaction.Subject{Tenant: "acme", Run: "run-a"}, late, late.Add(time.Second)); got != reaction.Stopped {
		t.Errorf("an expired stop under a clock behind the floor: %s, want stopped", got)
	}
}

// TestTheAgeOfAHugeIntervalSaturates: three intervals past the largest
// duration are the largest duration, not a product that wrapped below zero
// and made every read stale at once.
func TestTheAgeOfAHugeIntervalSaturates(t *testing.T) {
	r := listRoute(t)
	b := newList(t, r)
	b.stop("fnd-a1", "run-a", clock0, time.Hour)
	for _, interval := range []time.Duration{1 << 62, math.MaxInt64/3 + 1, math.MaxInt64} {
		s := reaction.Snapshot{}.Next(r, b.bytes(), clock0, interval)
		if s.State() != reaction.Stopped {
			t.Fatalf("interval %d: %s %s", interval, s.State(), s.Detail())
		}
		if got := s.At(clock0.Add(time.Second)); got.State() != reaction.Stopped {
			t.Errorf("interval %d, a second old: %s %s", interval, got.State(), got.Cause())
		}
		if got, _, _ := s.ForSubject(reaction.Subject{Tenant: "acme", Run: "run-a"}, clock0.Add(time.Second), clock0); got != reaction.Stopped {
			t.Errorf("interval %d, a call a second later: %s", interval, got)
		}
	}
	largest := reaction.Snapshot{}.Next(r, b.bytes(), clock0, math.MaxInt64/3)
	if got := largest.At(clock0.Add(time.Second)); got.State() != reaction.Stopped {
		t.Errorf("the largest interval that does not saturate: %s %s", got.State(), got.Cause())
	}
}
