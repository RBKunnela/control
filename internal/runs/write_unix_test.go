//go:build unix

package runs_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// TestEveryFileARunWritesIsItsOwnersAlone: under a umask that narrows
// nothing, a run's record, its root's state and its lock file are each
// readable and writable by their owner and nobody else, after the writes that
// open, raise and close it.
func TestEveryFileARunWritesIsItsOwnersAlone(t *testing.T) {
	dir := newDir(t)
	old := syscall.Umask(0)
	id, err := openRaiseAndClose(t, dir)
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{id + ".run.json", id + ".state.json", id + ".lock"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s: mode %04o, want 0600", name, got)
		}
	}
}

func openRaiseAndClose(t *testing.T, dir string) (string, error) {
	t.Helper()
	a, err := runs.InitAdmin(context.Background(), dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = a.Close() }()
	rec, _, err := a.Open(t.Context(), runs.OpenRequest{Who: alice, TTL: time.Hour, Now: opened})
	if err != nil {
		return "", err
	}
	p, err := runs.OpenPlane(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = p.Close() }()
	return rec.ID, errors.Join(
		p.Raise(t.Context(), rec.ID, taint),
		a.CloseRun(t.Context(), rec.ID, opened.Add(time.Minute)),
	)
}

// TestALeftoverTemporaryFileDoesNotStopTheNextWrite: a crash between the
// exclusive create of a temporary file and its rename leaves it at its fixed
// name. The next raise and the next close write all the same, and leave no
// temporary file behind.
func TestALeftoverTemporaryFileDoesNotStopTheNextWrite(t *testing.T) {
	dir, a, p := setup(t)
	rec, _ := openRoot(t, a)
	for _, name := range []string{rec.ID + ".state.tmp", rec.ID + ".run.tmp"} {
		writeFile(t, filepath.Join(dir, name), []byte("torn"))
	}
	if err := p.Raise(t.Context(), rec.ID, taint); err != nil {
		t.Fatalf("Raise beside a leftover: %v", err)
	}
	if err := a.CloseRun(t.Context(), rec.ID, opened.Add(time.Minute)); err != nil {
		t.Fatalf("CloseRun beside a leftover: %v", err)
	}
	if s, err := p.State(t.Context(), rec.ID); err != nil || !s.Untrusted {
		t.Fatalf("the state after the raise: %+v, %v", s, err)
	}
	for _, name := range []string{rec.ID + ".state.tmp", rec.ID + ".run.tmp"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s outlived the write: %v", name, err)
		}
	}
}
