//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package pause

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/files"
)

// TestALockIsTakenOnTheJudgedDirectory: a lock held on the judged directory
// refuses a writer whose path was swapped for another directory once the root
// was opened. A writer that took its lock by path would lock the directory
// swapped in and write past the lock that is held.
func TestALockIsTakenOnTheJudgedDirectory(t *testing.T) {
	path := ownPauseFile(t)
	held, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	swapped := swapAt(t, stepRooted, path, decoyDir(t, path, globalBody))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err = Remove(ctx, path, "g")
	if !*swapped {
		t.Fatal("the write never reached the step, so this case examined nothing")
	}
	if !errors.Is(err, ErrLocked) {
		t.Errorf("Remove = %v, want ErrLocked: the lock was not taken on the judged directory", err)
	}
}

// sharedLocked takes a shared flock of path on an open of its own, as a
// reader of the file may, and returns that open; closing it lets the lock go.
func sharedLocked(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestAReaderLockOfTheSignedFileRefusesTheWriteWhenTheContextEnds: the
// plane's account reads a signed pause file through its group and may hold a
// shared flock of it; a signed write waits for that lock only until its
// context ends, is refused with nothing written, and lets the directory's
// lock go, so the next writer is not refused by it.
func TestAReaderLockOfTheSignedFileRefusesTheWriteWhenTheContextEnds(t *testing.T) {
	p := newSignedPlane(t)
	if err := InitSigned(t.Context(), p.path, header("alice", 1), signer("alice")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	reader := sharedLocked(t, p.path)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := AddSigned(ctx, p.path, globalEntry, signer("carol"))
		done <- err
	}()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("AddSigned with a 300ms context is still running after 5s")
	}
	if !errors.Is(err, files.ErrLockHeld) || errors.Is(err, ErrLocked) {
		t.Errorf("AddSigned = %v, want files.ErrLockHeld and not the directory's ErrLocked", err)
	}
	if after, readErr := os.ReadFile(p.path); readErr != nil || !bytes.Equal(after, before) {
		t.Errorf("the pause file changed under a refused write: %v", readErr)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := AddSigned(t.Context(), p.path, globalEntry, signer("carol")); err != nil {
		t.Errorf("AddSigned once the reader let go = %v, want nil", err)
	}
}
