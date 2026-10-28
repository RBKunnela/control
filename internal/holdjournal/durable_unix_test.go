//go:build unix

package holdjournal_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/guardana/control/internal/holdjournal"
)

// TestEveryFileTheJournalWritesIsItsOwnersAlone: under a umask that narrows
// nothing, the marker, a recorded entry and a flipped one are each readable
// and writable by their owner and nobody else.
func TestEveryFileTheJournalWritesIsItsOwnersAlone(t *testing.T) {
	dir := newDir(t)
	old := syscall.Umask(0)
	j, err := holdjournal.Open(dir)
	if err == nil {
		err = errors.Join(
			j.Record(context.Background(), heldEntry("req-1")),
			j.Record(context.Background(), heldEntry("req-2")),
			j.Mark(context.Background(), "req-2", holdjournal.StateResuming),
			j.Close(),
		)
	}
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	names := append(entryFiles(t, dir), "journal.meta")
	if len(names) != 3 {
		t.Fatalf("the directory holds %v, want two entries and the marker", names)
	}
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s: mode %04o, want 0600", name, got)
		}
	}
}

// TestARecordThatCannotBeMadeDurableMayBeFiled: the entry is linked, and then
// the directory cannot be opened to force it to disk. Record reports an entry
// that may be filed, the entry stands and lists as held, so the caller can
// move it out of held and forget it as it would a filed one.
func TestARecordThatCannotBeMadeDurableMayBeFiled(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser opens a directory whatever its mode")
	}
	dir := newDir(t)
	j := openJournal(t, dir)
	if err := os.Chmod(dir, 0o300); err != nil { //nolint:gosec // G302: write and search without read, so only the directory's own open fails
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: as newDir leaves it
	err := j.Record(context.Background(), heldEntry("req-1"))
	if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil { //nolint:gosec // G302: as newDir leaves it
		t.Fatal(chmodErr)
	}
	if !errors.Is(err, holdjournal.ErrMaybeRecorded) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Record with a directory it cannot force to disk = %v, want ErrMaybeRecorded with fs.ErrPermission", err)
	}
	if names := entryFiles(t, dir); len(names) != 1 {
		t.Fatalf("a record that may be filed left %v, want its entry", names)
	}
	l, err := j.List(context.Background(), 10)
	if err != nil || len(l.Held) != 1 || l.Interrupted+l.Unreadable != 0 || !l.Complete {
		t.Fatalf("listing after a record that may be filed: %+v, %v", l, err)
	}
	mark(t, j, "req-1", holdjournal.StateClosing)
	if err := j.Forget(context.Background(), "req-1"); err != nil {
		t.Fatalf("forgetting the entry: %v", err)
	}
	record(t, j, "req-1")
}
