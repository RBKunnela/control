package core_test

import (
	"testing"
	"time"

	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
)

// recheckBudget is the budget the documents below and options() agree on.
const recheckBudget = 10 * time.Minute

func recheckDoc(rules ...string) []byte { return document(600, rules...) }

// basisAt decides env's request at the reading at against snap and returns
// the outcome, under opts.
func basisAt(t *testing.T, opts core.Options, at time.Time, effectWrite bool, snap *policy.Snapshot) core.Outcome {
	t.Helper()
	env := readEnvelope()
	if effectWrite {
		env = writeEnvelope()
	}
	return decide(kernel(t, opts, fixedClock(at)), request(env), snap)
}

// TestRecheckJudgesTheBasisAgain: each way a basis stands at a later reading,
// for a read decided fresh against a bundle confirmed at base().
func TestRecheckJudgesTheBasisAgain(t *testing.T) {
	doc := recheckDoc(allowReads)
	snap := snapshotAt(t, doc, base())
	out := basisAt(t, options(), base(), false, snap)
	if out.Action != core.Execute {
		t.Fatalf("the read decided %v, want it run", out.Decision.GetReasonCodes())
	}
	k := kernelAt(t, options())
	renewed := snapshotAt(t, doc, base().Add(5*time.Minute))
	for _, c := range []struct {
		name      string
		installed *policy.Snapshot
		now       time.Time
		floor     time.Time
		want      core.Standing
	}{
		{"the same bundle at the decision's reading", snap, base(), base(), core.StandingCurrent},
		{"the same bundle at the budget's end", snap, base().Add(recheckBudget), base(), core.StandingCurrent},
		{"the same bundle past the budget", snap, base().Add(recheckBudget + time.Nanosecond), base(), core.StandingStale},
		{"a renewal of the same bundle past the old budget", renewed, base().Add(recheckBudget + time.Minute), base(), core.StandingCurrent},
		{"another bundle", snapshotAt(t, recheckDoc(allowReads, allowWrites), base()), base(), base(), core.StandingReplaced},
		{"no bundle where the decision had one", nil, base(), base(), core.StandingUnknown},
		{"a reading behind the floor", snap, base().Add(time.Minute), base().Add(2 * time.Minute), core.StandingUnknown},
		{"a reading behind the installed bundle's verified time", renewed, base().Add(4 * time.Minute), base(), core.StandingUnknown},
		{"a reading before 1970", snap, time.Time{}, time.Time{}, core.StandingUnknown},
		{"a reading after 9999", snap, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), base(), core.StandingUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := k.Recheck(out.Basis, c.installed, c.now, c.floor); got != c.want {
				t.Errorf("Recheck = %d, want %d", got, c.want)
			}
		})
	}
}

// TestRecheckNeverStandsOnNothing: a basis no kernel made, and a kernel
// nobody built, judge nothing.
func TestRecheckNeverStandsOnNothing(t *testing.T) {
	snap := snapshotAt(t, recheckDoc(allowReads), base())
	if got := kernelAt(t, options()).Recheck(core.Basis{}, snap, base(), base()); got != core.StandingUnknown {
		t.Errorf("a zero basis: %d, want Unknown", got)
	}
	out := basisAt(t, options(), base(), false, snap)
	var nobody *core.Kernel
	if got := nobody.Recheck(out.Basis, snap, base(), base()); got != core.StandingUnknown {
		t.Errorf("a nil kernel: %d, want Unknown", got)
	}
	if got := (&core.Kernel{}).Recheck(out.Basis, snap, base(), base()); got != core.StandingUnknown {
		t.Errorf("a kernel nobody built: %d, want Unknown", got)
	}
}

// TestABasisStoodWhenItsPolicyLetTheCallRun: a decision under a fresh
// bundle, and a read the table opened, stood; a write under a stale bundle,
// and a read with no bundle and the setting off, did not.
func TestABasisStoodWhenItsPolicyLetTheCallRun(t *testing.T) {
	snap := snapshotAt(t, recheckDoc(allowReads, allowWrites), base())
	stale := base().Add(recheckBudget + time.Minute)
	for _, c := range []struct {
		name  string
		opts  core.Options
		at    time.Time
		write bool
		snap  *policy.Snapshot
		stood bool
	}{
		{"fresh", options(), base(), false, snap, true},
		{"a read the table opened", failOpen(), stale, false, snap, true},
		{"a write under a stale bundle", failOpen(), stale, true, snap, false},
		{"a read with no bundle and the setting off", options(), base(), false, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := basisAt(t, c.opts, c.at, c.write, c.snap).Basis.Stood(); got != c.stood {
				t.Errorf("Stood = %v, want %v", got, c.stood)
			}
		})
	}
	if (core.Basis{}).Stood() {
		t.Error("a zero basis stood")
	}
}

// TestRecheckKeepsAnOpenedReadInItsRow: a read the fail-closed table let run
// under a stale bundle stays current while the bundle is the same, and one
// it let run with no bundle while there is still none; another bundle, or
// one where there was none, replaces either.
func TestRecheckKeepsAnOpenedReadInItsRow(t *testing.T) {
	doc := recheckDoc(allowReads)
	snap := snapshotAt(t, doc, base())
	stale := base().Add(recheckBudget + time.Minute)
	k := kernel(t, failOpen(), fixedClock(stale))
	for _, c := range []struct {
		name      string
		decided   *policy.Snapshot
		installed *policy.Snapshot
		want      core.Standing
	}{
		{"stale, still stale", snap, snap, core.StandingCurrent},
		{"stale, replaced", snap, snapshotAt(t, recheckDoc(allowReads, allowWrites), base()), core.StandingReplaced},
		{"no bundle, still none", nil, nil, core.StandingCurrent},
		{"no bundle, given one", nil, snap, core.StandingReplaced},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := basisAt(t, failOpen(), stale, false, c.decided)
			if out.Action != core.Execute || !hasCode(out.Decision.GetReasonCodes(), codeFailOpenRead) {
				t.Fatalf("the read decided %v, action %d; want it opened by the table", out.Decision.GetReasonCodes(), out.Action)
			}
			if got := k.Recheck(out.Basis, c.installed, stale.Add(time.Minute), stale); got != c.want {
				t.Errorf("Recheck = %d, want %d", got, c.want)
			}
		})
	}
}

// TestRecheckHandsOutOnlyWhatADecisionThenWouldRun: over every combination
// of the setting, a read and a write, a decision fresh and stale, a hand-out
// reading at, inside and past the budget, and a renewal or none, a call the
// decision let run is current at hand-out exactly when deciding it again at
// that reading against the installed bundle lets it run, and either the
// table opened it the first time or the second decision is fresh. The second
// decision is the independent computation; Recheck never consults it.
func TestRecheckHandsOutOnlyWhatADecisionThenWouldRun(t *testing.T) {
	doc := recheckDoc(allowReads, allowWrites)
	confirmed := snapshotAt(t, doc, base())
	checked := 0
	for _, open := range []bool{false, true} {
		opts := options()
		opts.FailOpenRead = open
		for _, write := range []bool{false, true} {
			for _, decidedAge := range []time.Duration{0, recheckBudget + time.Minute} {
				decidedAt := base().Add(decidedAge)
				first := basisAt(t, opts, decidedAt, write, confirmed)
				if first.Action != core.Execute {
					continue
				}
				opened := hasCode(first.Decision.GetReasonCodes(), codeFailOpenRead)
				for _, later := range []time.Duration{0, time.Minute, recheckBudget, recheckBudget + time.Second} {
					for _, renewed := range []bool{false, true} {
						now := decidedAt.Add(later)
						installed := confirmed
						if renewed {
							installed = snapshotAt(t, doc, now.Add(-time.Minute))
						}
						again := basisAt(t, opts, now, write, installed)
						want := again.Action == core.Execute && (opened || again.Decision.GetPolicyFreshness() == fresh)
						got := kernel(t, opts, fixedClock(now)).Recheck(first.Basis, installed, now, decidedAt)
						if (got == core.StandingCurrent) != want {
							t.Errorf("open %v, write %v, decided at +%v, hand-out +%v, renewed %v: Recheck %d, a decision then runs it: %v",
								open, write, decidedAge, later, renewed, got, want)
						}
						checked++
					}
				}
			}
		}
	}
	if checked < 40 {
		t.Fatalf("%d combinations checked; the grid reached too few decisions that run", checked)
	}
}

func hasCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
