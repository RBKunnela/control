//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package stopwrite_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// holdLock takes the lock a writer takes, as another process would, and
// returns what releases it.
func holdLock(t *testing.T, dir string) func() {
	t.Helper()
	d, err := os.Open(dir) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return func() { _ = d.Close() }
}

// TestAWriterWaitsForTheLockUntilItsContextEnds: a lock held elsewhere keeps
// every writer out, Init included, and each says so rather than write around
// it; released, the same write goes through.
func TestAWriterWaitsForTheLockUntilItsContextEnds(t *testing.T) {
	r := testRoute(t)
	dir, _ := initDir(t, r)
	before := content(t, dir)
	empty := emptyDir(t)
	release := holdLock(t, dir)
	releaseEmpty := holdLock(t, empty)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := stopwrite.AppendStop(ctx, dir, r, stopOf(t, "f-1", "run-1", clock0), clock0); !errors.Is(err, stopwrite.ErrLocked) {
		t.Errorf("AppendStop under a held lock = %v, want ErrLocked", err)
	}
	if _, err := stopwrite.Init(ctx, empty, r, clock0); !errors.Is(err, stopwrite.ErrLocked) {
		t.Errorf("Init under a held lock = %v, want ErrLocked", err)
	}
	if got := content(t, dir); !bytes.Equal(got, before) {
		t.Error("a writer kept out wrote")
	}
	release()
	releaseEmpty()
	if _, err := stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-1", "run-1", clock0), clock0); err != nil {
		t.Errorf("AppendStop after the lock was released: %v", err)
	}
}

// TestASecondWriterWaitsForTheFirstsWrite: a writer that judged its line
// and has not written it yet holds the lock, so a second writer naming the
// same finding never judges the list until the first line is in it, and is
// then refused for naming the finding again.
func TestASecondWriterWaitsForTheFirstsWrite(t *testing.T) {
	r := testRoute(t)
	dir, _ := initDir(t, r)
	if _, err := stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-0", "run-1", clock0), clock0); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	second := make(chan error, 1)
	overlapped := make(chan struct{})
	defer stopwrite.SetJudged(func() {
		switch calls.Add(1) {
		case 1:
			go func() {
				_, err := stopwrite.AppendCovered(bg, dir, r, coveredOf("f-same", "run-1", clock0), clock0)
				second <- err
			}()
			select {
			case <-overlapped:
			case <-time.After(200 * time.Millisecond):
			}
		default:
			close(overlapped)
		}
	})()
	if _, err := stopwrite.AppendCovered(bg, dir, r, coveredOf("f-same", "run-1", clock0), clock0); err != nil {
		t.Fatalf("the first writer: %v", err)
	}
	if err := <-second; !errors.Is(err, reaction.ErrFindingAgain) {
		t.Errorf("the second writer = %v, want ErrFindingAgain", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("%d writers judged the list before it was written to, want 1", n)
	}
}

// TestTwoWritersAreSerialised: writers racing to name one finding leave one
// line naming it, the rest refused as naming it again; writers racing with
// distinct findings all land, each on a line of its own, and the plane
// accepts the list they made.
func TestTwoWritersAreSerialised(t *testing.T) {
	const writers = 16
	r := testRoute(t)
	dir, _ := initDir(t, r)
	if _, err := stopwrite.AppendStop(bg, dir, r, stopOf(t, "f-0", "run-1", clock0), clock0); err != nil {
		t.Fatal(err)
	}
	race := func(finding func(i int) string) []error {
		errs := make([]error, writers)
		var start, done sync.WaitGroup
		start.Add(1)
		for i := range writers {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				_, errs[i] = stopwrite.AppendCovered(bg, dir, r, coveredOf(finding(i), "run-1", clock0), clock0)
			}()
		}
		start.Done()
		done.Wait()
		return errs
	}
	won := 0
	for _, err := range race(func(int) string { return "f-same" }) {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, reaction.ErrFindingAgain):
			t.Errorf("a writer that lost the race: %v, want ErrFindingAgain", err)
		}
	}
	if won != 1 {
		t.Errorf("%d writers named one finding, want 1", won)
	}
	for i, err := range race(func(i int) string { return fmt.Sprintf("f-%d", i+1) }) {
		if err != nil {
			t.Errorf("writer %d of distinct findings: %v", i, err)
		}
	}
	if n := bytes.Count(content(t, dir), []byte{'\n'}); n != 3+writers {
		t.Errorf("the list holds %d lines, want %d", n, 3+writers)
	}
	if s := planeOn(t, dir, r).Current(); s.State() != reaction.Stopped {
		t.Errorf("the plane over the raced list: %s (%s)", s.State(), s.Detail())
	}
}

// TestCarryHoldsTheOldListsLockUntilItWrites: between reading the old list
// and writing the new one, no writer can append to the old list, so no stop,
// covered line or lift falls between the two; once the carry is done, one
// can.
func TestCarryHoldsTheOldListsLockUntilItWrites(t *testing.T) {
	from, to := testRoute(t), routeOf(t, 4, false)
	old, _ := initDir(t, from)
	var during error
	defer stopwrite.SetCarrying(func() {
		ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
		defer cancel()
		_, during = stopwrite.AppendStop(ctx, old, from, stopOf(t, "f-between", "run-1", clock0), clock0)
	})()
	if _, err := stopwrite.Carry(bg, old, from, emptyDir(t), to, clock0); err != nil {
		t.Fatalf("Carry: %v", err)
	}
	if !errors.Is(during, stopwrite.ErrLocked) {
		t.Errorf("an append to the old list during the carry = %v, want ErrLocked", during)
	}
	if _, err := stopwrite.AppendStop(bg, old, from, stopOf(t, "f-after", "run-1", clock0), clock0); err != nil {
		t.Errorf("an append to the old list after the carry = %v, want written", err)
	}
}

// TestWritersRacingForOneRunStopItOnce: eight writers, each with a finding of
// one run that holds no stop, leave one stop and seven covered lines, whatever
// order the lock lets them in.
func TestWritersRacingForOneRunStopItOnce(t *testing.T) {
	r := testRoute(t)
	dir, _ := initDir(t, r)
	const writers = 8
	var wg sync.WaitGroup
	var stops atomic.Int32
	for i := range writers {
		wg.Go(func() {
			_, covered, err := appendFinding(bg, dir, r, stopOf(t, fmt.Sprintf("f-%d", i), "run-1", clock0), clock0)
			if err != nil {
				t.Errorf("writer %d: %v", i, err)
			}
			if !covered {
				stops.Add(1)
			}
		})
	}
	wg.Wait()
	list, err := reaction.Judge(r, reaction.Prefix{}, content(t, dir), clock0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(list.Entries()); stops.Load() != 1 || got != 1 || list.Usage().Lines != writers+1 {
		t.Errorf("%d writers said stop, the list holds %d stop(s) in %d lines; want 1 stop and %d lines", stops.Load(), got, list.Usage().Lines, writers+1)
	}
}

// TestAFindingIsStoppedAtTheClockReadUnderTheLock: the writer reads its clock
// only while it holds the lock, which another opener of the directory cannot
// take then, and the stop is the one made from that reading.
func TestAFindingIsStoppedAtTheClockReadUnderTheLock(t *testing.T) {
	r := testRoute(t)
	dir, _ := initDir(t, r)
	reading := clock0.Add(time.Minute)
	clock := func() time.Time {
		d, err := os.Open(dir) //nolint:gosec // G304: the test's own temporary directory
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = d.Close() }()
		if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Errorf("taking the lock while the clock is read = %v, want EWOULDBLOCK", err)
		}
		return reading
	}
	var made time.Time
	_, s, covered, err := stopwrite.AppendFinding(bg, dir, r, clock, func(now time.Time) (reaction.Stop, error) {
		made = now
		return stopOf(t, "f-1", "run-1", now), nil
	})
	if err != nil || covered || !made.Equal(reading) || !s.CreatedAt.Equal(reading) {
		t.Fatalf("AppendFinding = %+v, covered %v, %v; made at %s, want a stop created at %s", s, covered, err, made, reading)
	}
	list, err := reaction.Judge(r, reaction.Prefix{}, content(t, dir), reading, 0)
	if err != nil || len(list.Entries()) != 1 || !list.Entries()[0].CreatedAt.Equal(reading) {
		t.Fatalf("the list holds %+v (%v), want one stop created at %s", list.Entries(), err, reading)
	}
}
