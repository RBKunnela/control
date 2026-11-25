//go:build linux || darwin

package files_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/files"
)

// flocked takes a flock of path, how being LOCK_EX or LOCK_SH, on an open of
// its own, as another writer of this package, a caller holding its directory
// or a reader of the file does, and returns its release.
func flocked(t *testing.T, path string, how int) func() {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = f.Close()
		}
	}
	t.Cleanup(release)
	return release
}

// TestAWriterThatWaitedOnTheLockFindsTheNameChanged: while another writer
// holds the judged file's lock, the replace waits; that writer puts its own
// file at the name and lets go, and the replace is refused with nothing
// written, the other writer's file at the name.
func TestAWriterThatWaitedOnTheLockFindsTheNameChanged(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	release := flocked(t, out, syscall.LOCK_EX)
	opened := make(chan struct{})
	files.BeforeLocked(t, func(name string) {
		if name == "out" {
			close(opened)
		}
	})
	done := make(chan error, 1)
	go func() { done <- files.ReplaceJudged(t.Context(), dir, "out", []byte("refused"), 0o644, judged) }()
	select {
	case <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("the replace never opened the judged file")
	}
	select {
	case err := <-done:
		t.Fatalf("the replace answered %v while another writer held the judged file's lock", err)
	case <-time.After(200 * time.Millisecond):
	}
	renamedIn(t, dir, "out", "the first writer's")
	release()
	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the replace still waits once the lock was let go")
	}
	if !errors.Is(err, files.ErrNotJudged) || !errors.Is(err, files.ErrNothingWritten) {
		t.Errorf("a replace whose judged file was replaced while it waited = %v, want ErrNotJudged with nothing written", err)
	}
	if got := readBody(t, out); got != "the first writer's" {
		t.Errorf("the name holds %q, want the first writer's file", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v, want the one name", got)
	}
}

// TestACallerHoldingItsDirectoryLockStillReplaces: callers hold an exclusive
// flock of the directory while they write; the replace locks the judged
// file, never the directory, so it neither waits on nor refuses that lock.
func TestACallerHoldingItsDirectoryLockStillReplaces(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o600)
	judged := lstat(t, out)
	flocked(t, dir, syscall.LOCK_EX)
	done := make(chan error, 1)
	go func() { done <- files.ReplaceJudged(t.Context(), dir, "out", []byte("new"), 0o644, judged) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a replace under the caller's directory lock: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the replace waits on the caller's directory lock")
	}
	if got := readBody(t, out); got != "new" {
		t.Errorf("the name holds %q, want the new file", got)
	}
}

// replaceWithin runs replace and fails the test when it has not answered
// within limit, well past any wait the test allows it.
func replaceWithin(t *testing.T, limit time.Duration, replace func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- replace() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("the replace is still running after %v", limit)
		return nil
	}
}

// lockRefused fails the test unless err is ErrLockHeld, not marked
// ErrNothingWritten, naming the file and saying nothing was written, and the
// directory holds only the judged file, unchanged.
func lockRefused(t *testing.T, err error, dir string) {
	t.Helper()
	if !errors.Is(err, files.ErrLockHeld) || errors.Is(err, files.ErrNothingWritten) {
		t.Errorf("the replace = %v, want ErrLockHeld without ErrNothingWritten", err)
	}
	if err != nil && (!strings.Contains(err.Error(), `"out"`) || !strings.Contains(err.Error(), "nothing was written")) {
		t.Errorf("the refusal %q does not name the file and say nothing was written", err)
	}
	if got := readBody(t, filepath.Join(dir, "out")); got != "judged" {
		t.Errorf("the name holds %q, want the judged file", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v, want the one name", got)
	}
}

// TestAReaderHoldingALockOfTheJudgedFileRefusesTheReplaceWhenTheContextEnds:
// a shared flock of the judged file, which any account that can read it may
// take, holds the replace off only until its context ends; the replace is
// then refused with nothing written.
func TestAReaderHoldingALockOfTheJudgedFileRefusesTheReplaceWhenTheContextEnds(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o644)
	judged := lstat(t, out)
	flocked(t, out, syscall.LOCK_SH)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err := replaceWithin(t, 5*time.Second, func() error {
		return files.ReplaceJudged(ctx, dir, "out", []byte("new"), 0o644, judged)
	})
	lockRefused(t, err, dir)
}

// TestAReplaceWaitsForALockLetGoWithinItsContext: a lock of the judged file
// let go before the context ends is waited for, and the replace is made.
func TestAReplaceWaitsForALockLetGoWithinItsContext(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o644)
	judged := lstat(t, out)
	release := flocked(t, out, syscall.LOCK_SH)
	let := make(chan struct{})
	files.BeforeLocked(t, func(name string) {
		if name == "out" {
			time.AfterFunc(100*time.Millisecond, func() { release(); close(let) })
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := replaceWithin(t, 10*time.Second, func() error {
		return files.ReplaceJudged(ctx, dir, "out", []byte("new"), 0o644, judged)
	})
	<-let
	if err != nil {
		t.Fatalf("a replace whose lock was let go within its context: %v", err)
	}
	if got := readBody(t, out); got != "new" {
		t.Errorf("the name holds %q, want the new file", got)
	}
}

// TestALockHeldOfTheNewFileRefusesTheReplaceWhenTheContextEnds: the new file
// is locked before it takes the name; another open that locked it first,
// which only a process that read the directory can make, holds the replace
// off until its context ends, and the new file is removed.
func TestALockHeldOfTheNewFileRefusesTheReplaceWhenTheContextEnds(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o644)
	judged := lstat(t, out)
	locked := false
	files.BeforeLocked(t, func(name string) {
		if files.IsTemp(name) {
			locked = true
			flocked(t, filepath.Join(dir, name), syscall.LOCK_SH)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err := replaceWithin(t, 5*time.Second, func() error {
		return files.ReplaceJudged(ctx, dir, "out", []byte("new"), 0o644, judged)
	})
	if !locked {
		t.Fatal("the replace never locked its new file")
	}
	lockRefused(t, err, dir)
}

// TestAWriterThatJudgedTheNewFileWaitsUntilTheReplaceSettles: a second
// writer that judges the new file once it took the name waits on the new
// file's lock until the first writer settled, both while the first compares
// what came out of the exchange and while it settles; the first answers nil,
// and the second then replaces the new file.
func TestAWriterThatJudgedTheNewFileWaitsUntilTheReplaceSettles(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	writeFile(t, out, []byte("judged"), 0o644)
	judged := lstat(t, out)
	second := make(chan error, 1)
	var answered atomic.Bool
	waiting := func(when string) {
		if answered.Load() {
			return
		}
		select {
		case err := <-second:
			answered.Store(true)
			t.Errorf("the second writer answered %v %s", err, when)
		case <-time.After(300 * time.Millisecond):
		}
	}
	var exchanged, settling atomic.Bool
	files.BetweenExchanges(t, func(*os.Root, string) {
		if exchanged.CompareAndSwap(false, true) {
			first := lstat(t, out)
			go func() { second <- files.ReplaceJudged(t.Context(), dir, "out", []byte("second"), 0o644, first) }()
			waiting("before the first compared what came out of the exchange")
		}
	})
	files.InSettle(t, func() {
		if settling.CompareAndSwap(false, true) {
			waiting("while the first settled")
		}
	})
	if err := files.ReplaceJudged(t.Context(), dir, "out", []byte("first"), 0o644, judged); err != nil {
		t.Errorf("the first writer = %v, want nil: the name held its file once it settled", err)
	}
	if !answered.Load() {
		secondReplaced(t, dir, second)
	}
}

// secondReplaced fails the test unless the second writer, which answers on
// second, replaced the first writer's file and left the one name in dir.
func secondReplaced(t *testing.T, dir string, second <-chan error) {
	t.Helper()
	select {
	case err := <-second:
		if err != nil {
			t.Errorf("the second writer = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second writer still waits once the first settled")
	}
	if got := readBody(t, filepath.Join(dir, "out")); got != "second" {
		t.Errorf("the name holds %q, want the second writer's file", got)
	}
	if got := entries(t, dir); len(got) != 1 {
		t.Errorf("the directory holds %v, want the one name", got)
	}
}
