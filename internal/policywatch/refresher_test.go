package policywatch_test

import (
	"context"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policywatch"
)

// expectStats fails unless the refresher counted exactly the refusals in
// refused, and the other counters as given.
func (r *rig) expectStats(refused map[policywatch.Cause]uint64, awaitingStatement, awaitingBundle, confirmations, installs uint64) {
	r.t.Helper()
	s := r.refresher.Stats()
	if !maps.Equal(s.Refused, refused) {
		r.t.Errorf("refused %v, want %v", s.Refused, refused)
	}
	if s.AwaitingStatement != awaitingStatement || s.AwaitingBundle != awaitingBundle || s.Confirmations != confirmations || s.Installs != installs {
		r.t.Errorf("awaiting a statement %d, a bundle %d, %d confirmation(s), %d install(s); want %d, %d, %d, %d",
			s.AwaitingStatement, s.AwaitingBundle, s.Confirmations, s.Installs, awaitingStatement, awaitingBundle, confirmations, installs)
	}
}

// Reading the same bundle and statement again moves nothing: the snapshot is
// the one installed, confirmed where it was, and the floor is not written.
func TestTheSameFilesAgainLeaveTheConfirmation(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.startConfirmed()
	before := r.holder.Current()
	_, writes := r.store.stored()
	for range 3 {
		r.clock.advance(interval)
		r.poll()
	}
	if r.holder.Current() != before {
		t.Fatal("a poll of unchanged files replaced the snapshot")
	}
	r.expectSnapshot(2, digest, t0)
	if _, after := r.store.stored(); after != writes {
		t.Errorf("polls of unchanged files wrote the floor %d time(s)", after-writes)
	}
	r.expectStats(map[policywatch.Cause]uint64{}, 0, 0, 0, 0)
	if got := r.refresher.Stats().Polls; got != 3 {
		t.Errorf("%d polls counted, want 3", got)
	}
}

// A renewal of the current bundle moves its confirmation to the renewal's
// issuedAt and raises the floor.
func TestARenewalConfirmsAgain(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.startConfirmed()
	renewed := t0.Add(20 * time.Second)
	r.writeStatement(2, digest, renewed)
	r.poll()
	r.expectSnapshot(2, digest, renewed)
	r.expectFloor(2, digest, renewed)
	r.expectStats(map[policywatch.Cause]uint64{}, 0, 0, 1, 0)
}

// replacement is one change to the files a plane must refuse, and the cause
// it is counted under.
type replacement struct {
	name  string
	cause policywatch.Cause
	// at is how long after t0 the poll runs; 0 is the rig's 30 s.
	at     time.Duration
	change func(r *rig, current string)
}

func refusedReplacements() []replacement {
	return []replacement{
		{name: "a torn bundle", cause: policywatch.CauseBundleInvalid, change: func(r *rig, _ string) {
			digest := r.writeBundle(3, "v3", 600)
			r.writeStatement(3, digest, t0.Add(time.Second))
			raw, err := os.ReadFile(r.opts.BundlePath)
			if err != nil {
				r.t.Fatal(err)
			}
			r.write(r.opts.BundlePath, raw[:len(raw)/2])
		}},
		{name: "a missing bundle", cause: policywatch.CauseBundleUnreadable, change: func(r *rig, _ string) {
			if err := os.Remove(r.opts.BundlePath); err != nil {
				r.t.Fatal(err)
			}
		}},
		{name: "an unsigned bundle", cause: policywatch.CauseBundleInvalid, change: func(r *rig, _ string) {
			b := signed(r.t, doc(planeID, 3, "v3", 600), bundleKey)
			b.Signature = nil
			r.write(r.opts.BundlePath, marshal(r.t, b))
			r.writeStatement(3, b.GetRef().GetDigest(), t0.Add(time.Second))
		}},
		{name: "a bundle signed under another key", cause: policywatch.CauseBundleInvalid, change: func(r *rig, _ string) {
			b := signed(r.t, doc(planeID, 3, "v3", 600), otherKey)
			r.write(r.opts.BundlePath, marshal(r.t, b))
			r.writeStatement(3, b.GetRef().GetDigest(), t0.Add(time.Second))
		}},
		{name: "a bundle of another id", cause: policywatch.CauseBundleID, change: func(r *rig, _ string) {
			b := signed(r.t, doc("other", 3, "v3", 600), bundleKey)
			r.write(r.opts.BundlePath, marshal(r.t, b))
			r.write(r.opts.StatementPath, statementBytes(r.t, "other", 3, b.GetRef().GetDigest(), t0.Add(time.Second), freshKey, freshKeyID))
		}},
		{name: "a lower serial", cause: policywatch.CauseRollback, change: func(r *rig, _ string) {
			r.writeStatement(1, r.writeBundle(1, "v1", 600), t0.Add(time.Second))
		}},
		{name: "the same serial with another digest", cause: policywatch.CauseSerialReused, change: func(r *rig, _ string) {
			r.writeStatement(2, r.writeBundle(2, "v2-other", 600), t0.Add(time.Second))
		}},
		{name: "a budget not longer than the interval", cause: policywatch.CauseBundleBudget, change: func(r *rig, _ string) {
			r.writeStatement(3, r.writeBundle(3, "v3", int64(interval/time.Second)), t0.Add(time.Second))
		}},
		{name: "a torn statement", cause: policywatch.CauseStatementInvalid, change: func(r *rig, _ string) {
			raw := statementBytes(r.t, planeID, 3, r.writeBundle(3, "v3", 600), t0.Add(time.Second), freshKey, freshKeyID)
			r.write(r.opts.StatementPath, raw[:len(raw)/2])
		}},
		{name: "a statement under another key", cause: policywatch.CauseStatementInvalid, change: func(r *rig, _ string) {
			r.write(r.opts.StatementPath, statementBytes(r.t, planeID, 3, r.writeBundle(3, "v3", 600), t0.Add(time.Second), otherKey, freshKeyID))
		}},
		{name: "a statement under the bundle key", cause: policywatch.CauseStatementInvalid, change: func(r *rig, _ string) {
			r.write(r.opts.StatementPath, statementBytes(r.t, planeID, 3, r.writeBundle(3, "v3", 600), t0.Add(time.Second), bundleKey, bundleKeyID))
		}},
		{name: "a missing statement", cause: policywatch.CauseStatementMissing, change: func(r *rig, _ string) {
			r.writeBundle(3, "v3", 600)
			if err := os.Remove(r.opts.StatementPath); err != nil {
				r.t.Fatal(err)
			}
		}},
		{name: "a statement of another id", cause: policywatch.CauseStatementUnbound, change: func(r *rig, current string) {
			r.write(r.opts.StatementPath, statementBytes(r.t, "other", 2, current, t0.Add(time.Second), freshKey, freshKeyID))
		}},
		{name: "a statement naming an older bundle", cause: policywatch.CauseStatementUnbound, change: func(r *rig, _ string) {
			r.writeStatement(1, r.digests["1v1"], t0.Add(time.Second))
		}},
		{name: "a future-dated statement", cause: policywatch.CauseStatementFuture, change: func(r *rig, _ string) {
			r.writeStatement(3, r.writeBundle(3, "v3", 600), t0.Add(31*time.Second))
		}},
		{name: "a future-dated renewal", cause: policywatch.CauseStatementFuture, change: func(r *rig, current string) {
			r.writeStatement(2, current, t0.Add(31*time.Second))
		}},
		{name: "an expired statement", cause: policywatch.CauseStatementExpired, at: 700 * time.Second, change: func(r *rig, _ string) {
			r.writeStatement(3, r.writeBundle(3, "v3", 600), t0.Add(time.Second))
		}},
		{name: "a renewal below the floor", cause: policywatch.CauseBelowFloor, change: func(r *rig, current string) {
			r.writeStatement(2, current, t0.Add(-time.Second))
		}},
		{name: "a statement of the current serial with another digest", cause: policywatch.CauseStatementUnbound, change: func(r *rig, current string) {
			r.writeStatement(2, current[:len(current)-1]+"0", t0.Add(time.Second))
		}},
		{name: "a statement path that is not a file", cause: policywatch.CauseStatementUnreadable, change: func(r *rig, _ string) {
			if err := os.Remove(r.opts.StatementPath); err != nil {
				r.t.Fatal(err)
			}
			if err := os.Mkdir(r.opts.StatementPath, 0o700); err != nil {
				r.t.Fatal(err)
			}
		}},
		{name: "a clock behind the floor's latest issuedAt", cause: policywatch.CauseClockBehindFloor, change: func(r *rig, current string) {
			r.store.mu.Lock()
			defer r.store.mu.Unlock()
			ahead, err := policy.NewFloor(planeID, 2, current, t0, t0.Add(time.Minute))
			if err != nil {
				r.t.Fatal(err)
			}
			r.store.floor = ahead
			r.writeStatement(2, current, t0.Add(time.Second))
		}},
	}
}

// TestEveryRefusedReplacementMovesNothing: each replacement leaves the last
// good snapshot served, its confirmation where it was and the floor
// unwritten, and is counted under its cause.
func TestEveryRefusedReplacementMovesNothing(t *testing.T) {
	for _, c := range refusedReplacements() {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, emptyFloor(t))
			r.digests["1v1"] = signed(t, doc(planeID, 1, "v1", 600), bundleKey).GetRef().GetDigest()
			digest := r.startConfirmed()
			before := r.holder.Current()
			_, writes := r.store.stored()
			c.change(r, digest)
			if c.at != 0 {
				r.clock.advance(c.at - 30*time.Second)
			}
			r.poll()
			if r.holder.Current() != before {
				t.Fatal("the refused replacement replaced the snapshot")
			}
			r.expectSnapshot(2, digest, t0)
			r.expectFloor(2, digest, t0)
			if _, after := r.store.stored(); after != writes {
				t.Errorf("the refused replacement wrote the floor")
			}
			r.expectStats(map[policywatch.Cause]uint64{c.cause: 1}, 0, 0, 0, 0)
		})
	}
}

// A new bundle whose statement still names the current one awaits its
// statement, and is installed, confirmed, once the statement arrives.
func TestAnUnpairedBundleAwaitsItsStatement(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	current := r.startConfirmed()
	next := r.writeBundle(3, "v3", 600)
	r.poll()
	r.poll()
	r.expectSnapshot(2, current, t0)
	r.expectStats(map[policywatch.Cause]uint64{}, 2, 0, 0, 0)
	issued := t0.Add(10 * time.Second)
	r.writeStatement(3, next, issued)
	r.poll()
	r.expectSnapshot(3, next, issued)
	r.expectFloor(3, next, issued)
	r.expectStats(map[policywatch.Cause]uint64{}, 2, 0, 1, 1)
}

// A statement deployed ahead of its bundle awaits the bundle; the current
// snapshot stays until the bundle arrives.
func TestAStatementAheadOfItsBundleAwaitsTheBundle(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	current := r.startConfirmed()
	nextBundle := signed(t, doc(planeID, 3, "v3", 600), bundleKey)
	issued := t0.Add(10 * time.Second)
	r.writeStatement(3, nextBundle.GetRef().GetDigest(), issued)
	r.poll()
	r.expectSnapshot(2, current, t0)
	r.expectStats(map[policywatch.Cause]uint64{}, 0, 1, 0, 0)
	r.write(r.opts.BundlePath, marshal(t, nextBundle))
	r.poll()
	r.expectSnapshot(3, nextBundle.GetRef().GetDigest(), issued)
	r.expectStats(map[policywatch.Cause]uint64{}, 0, 1, 1, 1)
}

// A statement first read dated ahead of the clock is taken, its bytes
// unchanged, once the clock reaches its time: the time is judged at every
// poll and never kept with the bytes.
func TestAStatementDatedAheadIsTakenOnceItsTimeComes(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	r.startConfirmed()
	ahead := r.clock.Wall().Add(10 * time.Second)
	next := r.writeBundle(3, "v3", 600)
	r.writeStatement(3, next, ahead)
	r.poll()
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseStatementFuture: 1}, 0, 0, 0, 0)
	r.clock.advance(10 * time.Second)
	r.poll()
	r.expectSnapshot(3, next, ahead)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseStatementFuture: 1}, 0, 0, 1, 1)
}

// A floor that could not be raised refuses the install, and the next poll
// tries it again.
func TestAFailedRaiseIsTriedAgain(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	current := r.startConfirmed()
	next := r.writeBundle(3, "v3", 600)
	issued := t0.Add(10 * time.Second)
	r.writeStatement(3, next, issued)
	r.store.mu.Lock()
	r.store.failRaise = true
	r.store.mu.Unlock()
	r.poll()
	r.expectSnapshot(2, current, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}, 0, 0, 0, 0)
	r.store.mu.Lock()
	r.store.failRaise = false
	r.store.mu.Unlock()
	r.poll()
	r.expectSnapshot(3, next, issued)
	r.expectFloor(3, next, issued)
}

// A floor another plane raised past a renewal refuses the renewal.
func TestAFloorRaisedElsewhereRefusesAnOlderRenewal(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.startConfirmed()
	r.store.mu.Lock()
	raised, err := r.store.floor.Raise(statementOf(t, 2, digest, t0.Add(20*time.Second)), t0.Add(20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	r.store.floor = raised
	r.store.mu.Unlock()
	r.writeStatement(2, digest, t0.Add(10*time.Second))
	r.poll()
	r.expectSnapshot(2, digest, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseBelowFloor: 1}, 0, 0, 0, 0)
}

// An unchanged, confirmed statement still has the floor read at every poll: a
// floor another plane raised to a later serial, and a floor that cannot be
// read, are each counted while the files stay as they are, and the last good
// snapshot keeps its confirmation.
func TestAnUnchangedStatementHasTheFloorReadAtEveryPoll(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.startConfirmed()
	r.store.mu.Lock()
	r.store.failRead = true
	r.store.mu.Unlock()
	r.clock.advance(interval)
	r.poll()
	r.expectSnapshot(2, digest, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}, 0, 0, 0, 0)

	r.store.mu.Lock()
	r.store.failRead = false
	elsewhere := t0.Add(5 * time.Second)
	raised, err := r.store.floor.Raise(statementOf(t, 3, "sha256:"+strings.Repeat("3", 64), elsewhere), elsewhere)
	if err != nil {
		r.store.mu.Unlock()
		t.Fatal(err)
	}
	r.store.floor = raised
	r.store.mu.Unlock()
	_, writes := r.store.stored()
	r.clock.advance(interval)
	r.poll()
	r.expectSnapshot(2, digest, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseFloor: 1, policywatch.CauseBelowFloor: 1}, 0, 0, 0, 0)
	if floor, after := r.store.stored(); after != writes || floor.Serial() != 3 {
		t.Errorf("the poll wrote the floor %d time(s) and left serial %d, want none and 3", after-writes, floor.Serial())
	}

	other, err := policy.EmptyFloor("another-plane")
	if err != nil {
		t.Fatal(err)
	}
	r.store.mu.Lock()
	r.store.floor = other
	r.store.mu.Unlock()
	r.clock.advance(interval)
	r.poll()
	r.expectSnapshot(2, digest, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseFloor: 2, policywatch.CauseBelowFloor: 1}, 0, 0, 0, 0)
}

// A poll that settles on an unchanged statement judges the floor read back as
// a raise of that statement would, at the poll's reading of the wall clock:
// the floor's serial with another digest, the floor's serial renewed later
// elsewhere, and a clock behind the floor's latest issuedAt are each refused;
// a latest issuedAt at the reading itself is not. A floor read back below
// the statement this plane confirmed, which only a restored copy can be, is
// counted under the floor and leaves the floor as it is.
func TestASettledPollJudgesTheFloorAsARaiseWould(t *testing.T) {
	polled := t0.Add(30*time.Second + interval)
	cases := []struct {
		name   string
		floor  func(digest string) (policy.Floor, error)
		causes map[policywatch.Cause]uint64
	}{
		{"the floor's serial, another digest", func(string) (policy.Floor, error) {
			return policy.NewFloor(planeID, 2, "sha256:"+strings.Repeat("7", 64), t0, t0)
		}, map[policywatch.Cause]uint64{policywatch.CauseSerialReused: 1}},
		{"the floor's serial, renewed a second later", func(digest string) (policy.Floor, error) {
			return policy.NewFloor(planeID, 2, digest, t0.Add(time.Second), t0.Add(time.Second))
		}, map[policywatch.Cause]uint64{policywatch.CauseBelowFloor: 1}},
		{"a latest issuedAt a second past the reading", func(digest string) (policy.Floor, error) {
			return policy.NewFloor(planeID, 2, digest, t0, polled.Add(time.Second))
		}, map[policywatch.Cause]uint64{policywatch.CauseClockBehindFloor: 1}},
		{"a latest issuedAt at the reading", func(digest string) (policy.Floor, error) {
			return policy.NewFloor(planeID, 2, digest, t0, polled)
		}, map[policywatch.Cause]uint64{}},
		{"a floor restored below the confirmed serial", func(string) (policy.Floor, error) {
			return policy.NewFloor(planeID, 1, "sha256:"+strings.Repeat("1", 64), t0.Add(-time.Hour), t0.Add(-time.Hour))
		}, map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}},
		{"a floor restored empty", func(string) (policy.Floor, error) {
			return policy.EmptyFloor(planeID)
		}, map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}},
		{"the confirmed serial, restored to an earlier statement", func(digest string) (policy.Floor, error) {
			return policy.NewFloor(planeID, 2, digest, t0.Add(-time.Minute), t0.Add(-time.Minute))
		}, map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, emptyFloor(t))
			digest := r.startConfirmed()
			f, err := c.floor(digest)
			if err != nil {
				t.Fatal(err)
			}
			r.store.mu.Lock()
			r.store.floor = f
			r.store.mu.Unlock()
			r.clock.advance(interval)
			if !r.clock.Wall().Equal(polled) {
				t.Fatalf("the poll reads %v, want %v", r.clock.Wall(), polled)
			}
			r.poll()
			r.expectSnapshot(2, digest, t0)
			r.expectStats(c.causes, 0, 0, 0, 0)
			if stored, _ := r.store.stored(); !stored.Equal(f) {
				t.Error("a settled poll moved the floor")
			}
		})
	}
}

// A floor whose latest statement, read back, is older than the latest one a
// settled poll read before is a restored copy: it would let a clock behind
// that statement through, so it is counted under the floor and moves
// nothing.
func TestASettledPollRefusesAFloorWhoseLatestStatementWentBack(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.startConfirmed()
	later, err := policy.NewFloor(planeID, 2, digest, t0, t0.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	r.store.mu.Lock()
	r.store.floor = later
	r.store.mu.Unlock()
	r.clock.advance(interval)
	r.poll()
	r.expectStats(map[policywatch.Cause]uint64{}, 0, 0, 0, 0)
	restored, err := policy.NewFloor(planeID, 2, digest, t0, t0)
	if err != nil {
		t.Fatal(err)
	}
	r.store.mu.Lock()
	r.store.floor = restored
	r.store.mu.Unlock()
	r.clock.advance(interval)
	r.poll()
	r.expectSnapshot(2, digest, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}, 0, 0, 0, 0)
}

// A floor raised elsewhere past the confirmed statement refuses the poll,
// and is still remembered: restoring the older floor after it is a floor
// going back, refused too.
func TestAFloorRestoredAfterARefusedOneIsStillSeenGoingBack(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.startConfirmed()
	elsewhere := t0.Add(5 * time.Second)
	r.store.mu.Lock()
	older := r.store.floor
	raised, err := older.Raise(statementOf(t, 3, "sha256:"+strings.Repeat("3", 64), elsewhere), elsewhere)
	if err != nil {
		r.store.mu.Unlock()
		t.Fatal(err)
	}
	r.store.floor = raised
	r.store.mu.Unlock()
	r.clock.advance(interval)
	r.poll()
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseBelowFloor: 1}, 0, 0, 0, 0)
	r.store.mu.Lock()
	r.store.floor = older
	r.store.mu.Unlock()
	r.clock.advance(interval)
	r.poll()
	r.expectSnapshot(2, digest, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseBelowFloor: 1, policywatch.CauseFloor: 1}, 0, 0, 0, 0)
}

// The floor read of a poll that settles is given up at the poll interval, so
// a store that never answers holds the poll no longer than a raise would.
func TestASettledPollGivesUpAFloorReadAtTheInterval(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	r.opts.Interval = 200 * time.Millisecond
	digest := r.startConfirmed()
	blocked := make(chan struct{})
	r.store.mu.Lock()
	r.store.readBlocked = blocked
	r.store.mu.Unlock()
	took := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		r.poll()
		took <- time.Since(start)
	}()
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("the poll never read the floor")
	}
	select {
	case d := <-took:
		if d < r.opts.Interval {
			t.Errorf("the read was given up after %v, before the interval", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a poll whose floor read never answered did not return within 5s at a 200ms interval")
	}
	r.expectSnapshot(2, digest, t0)
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}, 0, 0, 0, 0)
}

func TestNewRefusesIncompleteOptions(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	for name, edit := range map[string]func(*policywatch.Options){
		"no bundle id":       func(o *policywatch.Options) { o.BundleID = "" },
		"no holder":          func(o *policywatch.Options) { o.Holder = nil },
		"no floor":           func(o *policywatch.Options) { o.Floor = nil },
		"no wall clock":      func(o *policywatch.Options) { o.Wall = nil },
		"no monotonic clock": func(o *policywatch.Options) { o.Mono = nil },
		"no interval":        func(o *policywatch.Options) { o.Interval = 0 },
		"no freshness key":   func(o *policywatch.Options) { o.FreshnessKeys = nil },
	} {
		o := r.opts
		edit(&o)
		if _, err := policywatch.New(o); err == nil {
			t.Errorf("New took options with %s", name)
		}
	}
}

// Run polls every interval until its context ends, and then returns.
func TestRunPollsUntilItsContextEnds(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	r.opts.Interval = 10 * time.Millisecond
	r.startConfirmed()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.refresher.Run(ctx)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for r.refresher.Stats().Polls < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("Run polled %d time(s) in 10s at a 10ms interval", r.refresher.Stats().Polls)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return once its context ended")
	}
}

// A refresher over a holder Start never filled refuses every poll, counted.
func TestAPollOfAnEmptyHolderIsRefused(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	r.writeStatement(2, r.writeBundle(2, "v2", 600), t0)
	r.newRefresher()
	r.poll()
	if r.holder.Current() != nil {
		t.Fatal("a poll installed a bundle Start never installed")
	}
	r.expectStats(map[policywatch.Cause]uint64{policywatch.CauseFloor: 1}, 0, 0, 0, 0)
}

// SincePoll is the monotonic time since the last completed poll, or since
// New before any: it shows whether the refresher is alive.
func TestSincePollShowsTheRefresherIsAlive(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	r.startConfirmed()
	r.clock.advance(3 * time.Second)
	if got := r.refresher.SincePoll(); got != 3*time.Second {
		t.Errorf("3s after New and no poll, SincePoll is %v", got)
	}
	r.poll()
	r.clock.advance(2 * time.Second)
	if got := r.refresher.SincePoll(); got != 2*time.Second {
		t.Errorf("2s after a poll, SincePoll is %v", got)
	}
	r.clock.tick(time.Second, -time.Hour)
	if got := r.refresher.SincePoll(); got != 3*time.Second {
		t.Errorf("a wall clock set back changed SincePoll to %v; it is monotonic time", got)
	}
}

// An unchanged statement whose budget ran out is counted as expired at every
// poll that finds it, and the snapshot it confirmed is left as it was.
func TestAnUnchangedStatementPastItsBudgetIsCountedExpired(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.startConfirmed()
	r.clock.advance(569 * time.Second)
	r.poll()
	r.expectStats(map[policywatch.Cause]uint64{}, 0, 0, 0, 0)
	r.clock.advance(2 * time.Second)
	r.poll()
	r.poll()
	r.expectSnapshot(2, digest, t0)
	if got := r.refresher.Stats().Refused[policywatch.CauseStatementExpired]; got != 2 {
		t.Errorf("polls of a statement past its budget counted %d expiries, want 2", got)
	}
}

// TestAnUnchangedStatementExpiredWhileTheFloorWasReadIsCountedExpired: a
// poll a second before the budget ends whose floor read waits two seconds
// counts the statement expired.
func TestAnUnchangedStatementExpiredWhileTheFloorWasReadIsCountedExpired(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	r.startConfirmed()
	r.clock.advance(569 * time.Second)
	r.store.readHeld, r.store.readRelease = make(chan struct{}, 1), make(chan struct{})
	done := make(chan struct{})
	go func() { r.poll(); close(done) }()
	select {
	case <-r.store.readHeld:
	case <-time.After(10 * time.Second):
		t.Fatal("the poll never read the floor")
	}
	r.clock.advance(2 * time.Second)
	close(r.store.readRelease)
	<-done
	if got := r.refresher.Stats().Refused[policywatch.CauseStatementExpired]; got != 1 {
		t.Errorf("a poll whose floor read waited past the budget counted %d expiries, want 1", got)
	}
}

// TestAPollWhoseRaiseWaitsPastExpiryConfirmsNothing: a poll finds a
// statement a second before its budget runs out, for a new bundle and for a
// renewal of the current one, and the floor's raise waits two seconds on the
// lock. The poll counts it expired, and the holder and the floor are as they
// were. The control's raise waits no time and confirms.
func TestAPollWhoseRaiseWaitsPastExpiryConfirmsNothing(t *testing.T) {
	for _, install := range []bool{true, false} {
		for _, wait := range []time.Duration{0, 2 * time.Second} {
			r := newRig(t, emptyFloor(t))
			sr := &slowRaise{memFloor: r.store, clock: r.clock}
			h, err := policy.NewFloorHolder(planeID, sr)
			if err != nil {
				t.Fatal(err)
			}
			r.holder, r.opts.Holder = h, h
			digest := r.startConfirmed()
			r.clock.advance(600 * time.Second)
			sr.wait = wait
			issued := r.clock.Wall().Add(-599 * time.Second)
			if install {
				r.writeStatement(3, r.writeBundle(3, "v3", 600), issued)
			} else {
				r.writeStatement(2, digest, issued)
			}
			r.poll()
			stats := r.refresher.Stats()
			if wait == 0 {
				if stats.Confirmations != 1 {
					t.Errorf("install %v, the control, a raise that waits no time: %d confirmations, want 1", install, stats.Confirmations)
				}
				continue
			}
			if got := stats.Refused[policywatch.CauseStatementExpired]; got != 1 || stats.Confirmations != 0 {
				t.Errorf("install %v, a raise that waited past the budget: %d expiries and %d confirmations, want 1 and 0", install, got, stats.Confirmations)
			}
			r.expectSnapshot(2, digest, t0)
			r.expectFloor(2, digest, t0)
		}
	}
}
