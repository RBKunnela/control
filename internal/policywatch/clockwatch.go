package policywatch

import (
	"context"
	"sync"
	"time"

	"github.com/guardana/control/internal/policy"
)

// clockEvery bounds how often Run judges the clock on its own timer. A step
// back may extend freshness by one poll interval and one second; the poll
// interval is at least a second, so judging every second, or every interval
// when shorter, withdraws within that whatever a poll is waiting on.
const clockEvery = time.Second

// JudgeClock reads both clocks and reports whether the wall clock stands more
// than a second below the mark, withdrawing the confirmation when it does.
// It takes no lock a poll holds while it reads the files, so Run calls it on
// a timer of its own; a confirm in progress holds the clock's lock, so a
// withdrawal never lands between that confirm's judgement and its publish.
func (r *Refresher) JudgeClock() bool {
	_, back := r.judgeClock()
	return back
}

// judgeClock is JudgeClock, also returning the wall reading it judged.
func (r *Refresher) judgeClock() (time.Time, bool) {
	r.clockMu.Lock()
	defer r.clockMu.Unlock()
	now := r.o.Wall()
	if !r.clock.back(now, r.o.Mono()) {
		return now, false
	}
	r.withdraw()
	return now, true
}

// SincePoll is the monotonic time since the last completed poll, or since
// New before any: a refresher whose polls are stuck shows it here long
// before its confirmation runs out.
func (r *Refresher) SincePoll() time.Duration {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.o.Mono() - r.polled
}

// polledNow records a completed poll.
func (r *Refresher) polledNow() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.polled = r.o.Mono()
}

// watchClock judges the clock every clockEvery, or every interval when
// shorter, until ctx ends.
func (r *Refresher) watchClock(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(min(clockEvery, r.o.Interval))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.JudgeClock()
		}
	}
}

// Bounded is s with every call given up when its context ends, whatever s
// does with it. A store may ignore the context once it holds its lock, while
// it writes and syncs; the holder keeps its own lock across a raise and the
// clock rule needs that lock to withdraw, so a raise on a disk that stopped
// answering would hold the clock rule off for good. A call given up goes on
// in the background, and a raise it completes there is never lower: a failed
// raise may have raised the floor. Calls take turns: one given up keeps the
// turn until the store returns, so a store that stopped answering holds one
// call in the background, not one per attempt.
func Bounded(s policy.FloorStore) policy.FloorStore {
	return &bounded{s: s, turn: make(chan struct{}, 1)}
}

type bounded struct {
	s    policy.FloorStore
	turn chan struct{}
}

type floorResult struct {
	f   policy.Floor
	err error
}

func (b *bounded) Floor(ctx context.Context, bundleID string) (policy.Floor, error) {
	return b.wait(ctx, func() (policy.Floor, error) { return b.s.Floor(ctx, bundleID) })
}

func (b *bounded) Raise(ctx context.Context, st policy.Statement, now time.Time) (policy.Floor, error) {
	return b.wait(ctx, func() (policy.Floor, error) { return b.s.Raise(ctx, st, now) })
}

// wait takes the turn, runs call and returns its answer, or ctx's error once
// ctx ends first. The turn is given back when call returns, not when wait does.
func (b *bounded) wait(ctx context.Context, call func() (policy.Floor, error)) (policy.Floor, error) {
	select {
	case b.turn <- struct{}{}:
	case <-ctx.Done():
		return policy.Floor{}, ctx.Err()
	}
	done := make(chan floorResult, 1)
	go func() {
		defer func() { <-b.turn }()
		f, err := call()
		done <- floorResult{f, err}
	}()
	select {
	case res := <-done:
		return res.f, res.err
	case <-ctx.Done():
		return policy.Floor{}, ctx.Err()
	}
}
