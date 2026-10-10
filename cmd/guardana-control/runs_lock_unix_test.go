//go:build unix

package main

import (
	"context"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// TestRunsCloseGivesUpOnAHeldLockAtItsBound: a runs directory whose lock
// another operator command holds fails runs close once runsLockWait has
// passed, opening the directory included, rather than waiting until the lock
// is released.
func TestRunsCloseGivesUpOnAHeldLockAtItsBound(t *testing.T) {
	t.Parallel()
	dir := runsDir(t)
	a, err := runs.InitAdmin(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(dir) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		done <- runsCloseCommand([]string{dir, "run-0123456789abcdef0123456789abcdef"}, io.Discard, io.Discard)
	}()
	select {
	case code := <-done:
		if code == exitOK {
			t.Fatalf("runs close = %d under a held lock, want a failure", code)
		}
	case <-time.After(runsLockWait + 5*time.Second):
		_ = held.Close()
		t.Fatalf("runs close was still waiting %v in, past runsLockWait %v; it ended with %d only once the lock was released", runsLockWait+5*time.Second, runsLockWait, <-done)
	}
}
