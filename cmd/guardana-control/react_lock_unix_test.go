//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/runs"
)

// holdStopsLock takes the lock a writer of the list in dir takes, as another
// writer would, and returns what releases it.
func holdStopsLock(t *testing.T, dir string) func() {
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

// TestALockHeldPastTheWaitStopsThePassAfterItsLines: another writer takes
// the lock after the first stop and holds it past the wait. The pass keeps
// the first stop, refuses on the second finding with the lock named, and a
// later pass with the lock free writes the second stop and names the first
// as already on the list.
func TestALockHeldPastTheWaitStopsThePassAfterItsLines(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	release := func() {}
	defer func() { release() }()
	lookups := 0
	r, records := readyReactor(context.Background(), t, tr, log, now, func(plane lookupRun) lookupRun {
		return func(ctx context.Context, id string) (runs.Record, error) {
			if lookups++; lookups == 2 {
				release = holdStopsLock(t, tr.stops)
			}
			return plane(ctx, id)
		}
	})
	r.lockWait = 50 * time.Millisecond
	started := time.Now()
	err := r.each(records)
	if !errors.Is(err, stopwrite.ErrLocked) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("each = %v, want the lock's wait run out", err)
	}
	if waited := time.Since(started); waited < r.lockWait {
		t.Errorf("the pass gave up after %v, before its wait of %v", waited, r.lockWait)
	}
	if r.stops != 1 || len(r.written) != 1 || len(r.unwritten) != 0 {
		t.Errorf("%d stops, written %q, unwritten %q; want the first stop alone", r.stops, r.written, r.unwritten)
	}
	release()
	release = func() {}
	var out, errOut bytes.Buffer
	code := react(context.Background(), tr.reactArgs(log), clockAt(now), &out, &errOut)
	if want := "already named 1, not stopping 0, not written 0\n"; code != exitOK || !bytes.HasSuffix(out.Bytes(), []byte("stops 1, covered 0, "+want)) {
		t.Fatalf("the pass after the lock: react answered %d: %q\n%s", code, errOut.String(), out.String())
	}
}

// TestReactPrintsItsCountWhenTheLockIsNeverFree: a lock held throughout
// leaves the list as it was, and react still prints its count line before it
// names the lock and exits 1.
func TestReactPrintsItsCountWhenTheLockIsNeverFree(t *testing.T) {
	tr := newStopTree(t)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	before := tr.listBytes(t)
	defer holdStopsLock(t, tr.stops)()
	a := tr.reactArgs(log)
	a.lockWait = 50 * time.Millisecond
	var out, errOut bytes.Buffer
	code := react(context.Background(), a, time.Now, &out, &errOut)
	if code != exitFail || out.String() != "stops 0, covered 0, already named 0, not stopping 0, not written 0\n" ||
		!bytes.Contains(errOut.Bytes(), []byte(string(stopwrite.ErrLocked))) {
		t.Fatalf("react answered %d: %q\n%s", code, errOut.String(), out.String())
	}
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Error("a pass that never took the lock changed the list")
	}
}

// TestATerminationEndsAPassWaitingForTheLock: the command as an operator runs
// it, waiting on a lock another writer holds, ends on SIGTERM well before its
// wait of ten seconds would run out, names the finding it was writing and
// prints its count line. The test takes SIGTERM itself first, so a signal that
// arrives before the command listens is never the default's, and signals only
// once the pass is about to wait, so a slow start ends no earlier step.
func TestATerminationEndsAPassWaitingForTheLock(t *testing.T) {
	tr := newStopTree(t)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	before := tr.listBytes(t)
	defer holdStopsLock(t, tr.stops)()
	caught := make(chan os.Signal, 64)
	signal.Notify(caught, syscall.SIGTERM)
	defer func() {
		time.Sleep(100 * time.Millisecond)
		signal.Stop(caught)
	}()
	started := time.Now()
	got := terminatedAtTheLock(t, append([]string{"react", "--findings", log, "--runs", tr.runs, "--stops", tr.stops}, tr.routeArgs()...))
	if took := time.Since(started); took > stopsLockWait/2 {
		t.Errorf("the pass ended after %v; a termination should end its lock wait at once", took)
	}
	if got.code != exitFail || got.stdout != "stops 0, covered 0, already named 0, not stopping 0, not written 0\n" ||
		!strings.Contains(got.stderr, "finding "+fid(1)+" run "+tr.open+": "+string(stopwrite.ErrLocked)) ||
		!strings.Contains(got.stderr, context.Canceled.Error()) {
		t.Fatalf("react answered %d: %q\n%s", got.code, got.stderr, got.stdout)
	}
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Error("a terminated pass changed the list")
	}
}

// commandAnswer is what one in-process run of the command answered.
type commandAnswer struct {
	code           int
	stdout, stderr string
}

// terminatedAtTheLock runs the command with args and sends this process
// SIGTERM every 20ms from the moment the pass is about to wait for the lock
// on --stops until the command ends. A command that ends before it waits
// fails the test.
func terminatedAtTheLock(t *testing.T, args []string) commandAnswer {
	t.Helper()
	waiting := make(chan struct{})
	var once sync.Once
	beforeStopsLock = func() { once.Do(func() { close(waiting) }) }
	t.Cleanup(func() { beforeStopsLock = func() {} })
	done := make(chan commandAnswer, 1)
	go func() {
		code, stdout, stderr := invoke(t, args...)
		done <- commandAnswer{code, stdout, stderr}
	}()
	select {
	case got := <-done:
		t.Fatalf("react ended before it waited for the lock: %d: %q\n%s", got.code, got.stderr, got.stdout)
	case <-waiting:
	}
	for {
		select {
		case got := <-done:
			return got
		case <-time.After(20 * time.Millisecond):
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// fillList writes the list in the tree's stops directory out to its bound of
// lines, every line after the header covering a run of another tenant.
func fillList(t *testing.T, tr stopTree, now time.Time) {
	t.Helper()
	var b bytes.Buffer
	b.Write(tr.listBytes(t))
	for i := range reaction.MaxListLines - 1 {
		line, err := reaction.Covered{FindingID: fid(100000 + i), TenantID: "acme", RunID: tr.alien,
			CreatedAt: now.Add(-time.Minute).Truncate(time.Second)}.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	writeFixture(t, filepath.Join(tr.stops, stoplist.FileName), b.String())
}

// TestAFullListIsNotLockedAgainForEachFinding: once the list refuses a line
// for its bounds, the pass names every later finding as not written without
// taking the lock, so a writer that takes the lock meanwhile, such as a lift,
// is not shut out and the pass does not fail on it.
func TestAFullListIsNotLockedAgainForEachFinding(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	fillList(t, tr, now)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	release := func() {}
	defer func() { release() }()
	lookups := 0
	r, records := readyReactor(context.Background(), t, tr, log, now, func(plane lookupRun) lookupRun {
		return func(ctx context.Context, id string) (runs.Record, error) {
			if lookups++; lookups == 2 {
				release = holdStopsLock(t, tr.stops)
			}
			return plane(ctx, id)
		}
	})
	r.lockWait = 50 * time.Millisecond
	if err := r.each(records); err != nil {
		t.Fatalf("each = %v, want both findings named not written", err)
	}
	if r.stops != 0 || len(r.unwritten) != 2 || lookups != 2 {
		t.Fatalf("%d stops, unwritten %q, %d lookups", r.stops, r.unwritten, lookups)
	}
	for i, f := range []struct{ id, run string }{{fid(1), tr.open}, {fid(2), tr.second}} {
		if want := "not written: finding " + f.id + " run " + f.run + ": " + string(stopwrite.ErrFull); !strings.HasPrefix(r.unwritten[i], want) {
			t.Errorf("unwritten %d is %q, want it to start %q", i, r.unwritten[i], want)
		}
	}
}

// TestEachWriteWaitsForTheLockOnItsOwn: another writer holds the lock for
// most of the wait before each of two writes. Each write waits on its own and
// both are written; a wait shared across the pass would run out at the second.
func TestEachWriteWaitsForTheLockOnItsOwn(t *testing.T) {
	const wait, held = 2 * time.Second, 1200 * time.Millisecond
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	released := make(chan struct{}, 2)
	r, records := readyReactor(context.Background(), t, tr, log, now, func(plane lookupRun) lookupRun {
		return func(ctx context.Context, id string) (runs.Record, error) {
			release := holdStopsLock(t, tr.stops)
			time.AfterFunc(held, func() { release(); released <- struct{}{} })
			return plane(ctx, id)
		}
	})
	r.lockWait = wait
	if err := r.each(records); err != nil {
		t.Fatalf("each = %v, want both stops written", err)
	}
	if r.stops != 2 || len(r.unwritten) != 0 {
		t.Fatalf("%d stops, unwritten %q; want two stops", r.stops, r.unwritten)
	}
	<-released
	<-released
}

// TestTheCommandWaitsTheLockWaitItDocuments: the command's flags give every
// lock wait the ten seconds reaction.md states.
func TestTheCommandWaitsTheLockWaitItDocuments(t *testing.T) {
	if _, a := reactFlags(reactName, io.Discard); a.lockWait != 10*time.Second {
		t.Fatalf("react waits %v for the lock, want 10s", a.lockWait)
	}
}
