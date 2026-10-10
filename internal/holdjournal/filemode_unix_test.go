//go:build unix

package holdjournal_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/holdjournal"
)

// looseModes are modes at which a group or another account may write a file.
var looseModes = []fs.FileMode{0o666, 0o620, 0o602}

// TestAnEntryOthersMayWriteIsNotRead: a group or the world that may write an
// entry may rewrite it in place, which a directory only this account may
// write does not prevent. Such an entry is unreadable and is not flipped.
func TestAnEntryOthersMayWriteIsNotRead(t *testing.T) {
	for _, mode := range looseModes {
		t.Run(mode.String(), func(t *testing.T) {
			ctx := context.Background()
			dir := newDir(t)
			j := openJournal(t, dir)
			record(t, j, "req-loose")
			record(t, j, "req-kept")
			if err := os.Chmod(entryFileOf(t, dir, "req-loose"), mode); err != nil {
				t.Fatal(err)
			}
			listing, err := j.List(ctx, 8)
			if err != nil || len(listing.Held) != 1 || listing.Held[0].IDs.RequestID != "req-kept" ||
				listing.Unreadable != 1 || listing.Complete {
				t.Errorf("a pass over an entry at %04o reported %+v, %v; want it unreadable and the other held", mode, listing, err)
			}
			if err := j.Mark(ctx, "req-loose", holdjournal.StateClosing); !errors.Is(err, holdjournal.ErrForeignFile) {
				t.Errorf("flipping an entry at %04o: %v, want ErrForeignFile", mode, err)
			}
		})
	}
}

// TestAnEntryAtItsOwnersModeIsRead: the same pass and flip over an entry only
// its owner may write, so what refuses the loose modes is the mode.
func TestAnEntryAtItsOwnersModeIsRead(t *testing.T) {
	dir := newDir(t)
	j := openJournal(t, dir)
	record(t, j, "req-loose")
	record(t, j, "req-kept")
	if err := os.Chmod(entryFileOf(t, dir, "req-loose"), 0o600); err != nil {
		t.Fatal(err)
	}
	listing, err := j.List(context.Background(), 8)
	if err != nil || len(listing.Held) != 2 || listing.Unreadable != 0 || !listing.Complete {
		t.Errorf("a pass over entries at the owner's mode reported %+v, %v", listing, err)
	}
	mark(t, j, "req-loose", holdjournal.StateClosing)
}

// TestAMarkerOthersMayWriteOpensNoJournal: neither a plane nor a reader opens
// over a marker a group or the world may write, and both open over the same
// marker once only its owner may write it.
func TestAMarkerOthersMayWriteOpensNoJournal(t *testing.T) {
	dir := newDir(t)
	if err := openJournal(t, dir).Close(); err != nil {
		t.Fatalf("closing the journal that made the directory: %v", err)
	}
	marker := filepath.Join(dir, "journal.meta")
	opens := map[string]func(string, ...holdjournal.Option) (*holdjournal.Journal, error){
		"a plane":  holdjournal.Open,
		"a reader": holdjournal.OpenReadOnly,
	}
	for _, mode := range looseModes {
		if err := os.Chmod(marker, mode); err != nil {
			t.Fatal(err)
		}
		for name, open := range opens {
			j, err := open(dir)
			if !errors.Is(err, holdjournal.ErrForeignFile) || j != nil {
				t.Errorf("%s over a marker at %04o: %v; want ErrForeignFile", name, mode, err)
			}
			if j != nil {
				_ = j.Close()
			}
		}
	}
	if err := os.Chmod(marker, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, open := range opens {
		j, err := open(dir)
		if err != nil {
			t.Fatalf("%s over the owner's marker: %v", name, err)
		}
		if err := j.Close(); err != nil {
			t.Errorf("closing %s: %v", name, err)
		}
	}
}
