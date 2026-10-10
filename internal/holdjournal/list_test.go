package holdjournal_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"sync"
	"testing"

	"github.com/guardana/control/internal/holdjournal"
)

// TestAListingCountsTheStatesApart: one entry in each state, so held and
// interrupted are counted from what the entries say and not from how many
// files there are.
func TestAListingCountsTheStatesApart(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	for _, id := range []string{"req-held", "req-resuming", "req-closing"} {
		record(t, j, id)
	}
	mark(t, j, "req-resuming", holdjournal.StateResuming)
	mark(t, j, "req-closing", holdjournal.StateClosing)

	listing, err := j.List(ctx, 16)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	switch {
	case len(listing.Held) != 1 || listing.Held[0].IDs.RequestID != "req-held":
		t.Fatalf("the pass held %+v", listing.Held)
	case listing.Interrupted != 2:
		t.Fatalf("the pass counted %d interrupted, want 2", listing.Interrupted)
	case listing.Unreadable != 0 || !listing.Complete:
		t.Fatalf("a pass that read every entry reported %+v", listing)
	}
}

// TestAnEntryThatWillNotDecodeLeavesThePassUnmeasured: it is counted, never
// skipped, and the pass that met it may not call itself done. Repairing that
// one file, and nothing else, is what turns the same pass complete.
func TestAnEntryThatWillNotDecodeLeavesThePassUnmeasured(t *testing.T) {
	ctx := context.Background()
	dir := newDir(t)
	j := openJournal(t, dir)
	record(t, j, "req-held")
	record(t, j, "req-broken")
	broken := entryFileOf(t, dir, "req-broken")
	whole := readFile(t, broken)
	writeFile(t, broken, whole[:len(whole)-1])

	listing, err := j.List(ctx, 16)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	switch {
	case len(listing.Held) != 1 || listing.Held[0].IDs.RequestID != "req-held":
		t.Fatalf("the pass held %+v", listing.Held)
	case listing.Unreadable != 1:
		t.Fatalf("the pass counted %d unreadable, want 1", listing.Unreadable)
	case listing.Complete:
		t.Fatal("a pass that could not read an entry reported itself complete")
	}

	writeFile(t, broken, whole)
	repaired, err := j.List(ctx, 16)
	if err != nil {
		t.Fatalf("listing the repaired journal: %v", err)
	}
	switch {
	case len(repaired.Held) != 2:
		t.Fatalf("the repaired pass held %+v", repaired.Held)
	case repaired.Unreadable != 0 || !repaired.Complete:
		t.Fatalf("the repaired pass reported %+v", repaired)
	}
}

// TestABoundedPassIsNeverDone: the bound that stops a pass, and the bound at
// which the same journal reads out whole.
func TestABoundedPassIsNeverDone(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	for _, id := range []string{"req-1", "req-2", "req-3"} {
		record(t, j, id)
	}
	stopped, err := j.List(ctx, 2)
	if err != nil {
		t.Fatalf("listing under a bound: %v", err)
	}
	if len(stopped.Held) != 2 || stopped.Complete {
		t.Fatalf("a pass stopped by its bound reported %+v", stopped)
	}
	whole, err := j.List(ctx, 3)
	if err != nil {
		t.Fatalf("listing at the bound the journal fits in: %v", err)
	}
	if len(whole.Held) != 3 || !whole.Complete {
		t.Fatalf("a pass that read every entry reported %+v", whole)
	}
}

// TestAPassThatExaminedNothingHasNotFoundTheJournalEmpty: a non-positive bound
// reads nothing and says so, rather than reporting an empty journal, which
// would mean every hold was closed.
func TestAPassThatExaminedNothingHasNotFoundTheJournalEmpty(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	record(t, j, "req-1")
	for _, bound := range []int{0, -1} {
		listing, err := j.List(ctx, bound)
		if err != nil {
			t.Fatalf("listing under a bound of %d: %v", bound, err)
		}
		if len(listing.Held) != 0 || listing.Interrupted != 0 || listing.Unreadable != 0 {
			t.Fatalf("a pass under a bound of %d read %+v", bound, listing)
		}
		if listing.Complete {
			t.Fatalf("a pass under a bound of %d reported itself complete", bound)
		}
	}
	// An empty journal, read at a positive bound, is the one case that is
	// complete and empty.
	empty, err := openJournal(t, newDir(t)).List(ctx, 8)
	if err != nil {
		t.Fatalf("listing an empty journal: %v", err)
	}
	if !empty.Complete || len(empty.Held) != 0 {
		t.Fatalf("an empty journal listed %+v", empty)
	}
}

// TestTheDirectoryHoldsNoMoreEntriesThanItsBound: the hold at which the bound
// bites, and the same hold taken at a bound one larger.
func TestTheDirectoryHoldsNoMoreEntriesThanItsBound(t *testing.T) {
	ctx := context.Background()
	dir := newDir(t)
	tight := openJournal(t, dir, holdjournal.WithMaxEntries(2))
	record(t, tight, "req-1")
	record(t, tight, "req-2")
	if err := tight.Record(ctx, heldEntry("req-3")); !errors.Is(err, holdjournal.ErrTooManyEntries) {
		t.Fatalf("the third hold under a bound of two: %v, want ErrTooManyEntries", err)
	}
	if err := tight.Close(); err != nil {
		t.Fatalf("closing the journal: %v", err)
	}

	loose := openJournal(t, dir, holdjournal.WithMaxEntries(3))
	if err := loose.Record(ctx, heldEntry("req-3")); err != nil {
		t.Fatalf("the third hold under a bound of three: %v", err)
	}
	if err := loose.Close(); err != nil {
		t.Fatalf("closing the journal: %v", err)
	}

	// A journal reopened under a bound the directory is already past reads
	// what it can and says it is not done.
	reader := openJournal(t, dir, holdjournal.WithMaxEntries(2))
	listing, err := reader.List(ctx, 16)
	if err != nil {
		t.Fatalf("listing past the bound: %v", err)
	}
	if len(listing.Held) != 2 || listing.Complete {
		t.Fatalf("a pass over a directory past its bound reported %+v", listing)
	}
}

// TestAnEntryOverItsByteBoundIsRefusedInBothDirections: on the way in, and on
// the way out of a journal reopened under a tighter bound, where it counts as
// unmeasured rather than as a hold that is not there.
func TestAnEntryOverItsByteBoundIsRefusedInBothDirections(t *testing.T) {
	ctx := context.Background()
	dir := newDir(t)
	tight := openJournal(t, dir, holdjournal.WithMaxEntryBytes(64))
	if err := tight.Record(ctx, heldEntry("req-1")); !errors.Is(err, holdjournal.ErrEntryTooLarge) {
		t.Fatalf("recording an entry over the byte bound: %v, want ErrEntryTooLarge", err)
	}
	if err := tight.Close(); err != nil {
		t.Fatalf("closing the journal: %v", err)
	}

	loose := openJournal(t, dir)
	if err := loose.Record(ctx, heldEntry("req-1")); err != nil {
		t.Fatalf("recording the same entry under the default bound: %v", err)
	}
	if err := loose.Close(); err != nil {
		t.Fatalf("closing the journal: %v", err)
	}

	listing, err := openJournal(t, dir, holdjournal.WithMaxEntryBytes(64)).List(ctx, 8)
	if err != nil {
		t.Fatalf("listing under a tighter byte bound: %v", err)
	}
	if len(listing.Held) != 0 || listing.Unreadable != 1 || listing.Complete {
		t.Fatalf("a pass over an entry past its byte bound reported %+v", listing)
	}
}

// TestAFileNameThatDisagreesWithItsEntryIsRefused: the name is how an entry is
// found and the content is what a close is written from, so an entry filed
// under another request's name speaks for neither.
func TestAFileNameThatDisagreesWithItsEntryIsRefused(t *testing.T) {
	ctx := context.Background()
	dir := newDir(t)
	j := openJournal(t, dir)
	record(t, j, "req-1")
	record(t, j, "req-2")
	writeFile(t, entryFileOf(t, dir, "req-2"), readFile(t, entryFileOf(t, dir, "req-1")))

	if err := j.Mark(ctx, "req-2", holdjournal.StateClosing); !errors.Is(err, holdjournal.ErrNameMismatch) {
		t.Fatalf("flipping an entry filed under another name: %v, want ErrNameMismatch", err)
	}
	listing, err := j.List(ctx, 8)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	if len(listing.Held) != 1 || listing.Held[0].IDs.RequestID != "req-1" {
		t.Fatalf("the pass held %+v", listing.Held)
	}
	if listing.Unreadable != 1 || listing.Complete {
		t.Fatalf("the pass reported %d unreadable, complete %v", listing.Unreadable, listing.Complete)
	}
}

// TestAPassReportsTheDirectoryAndNotACachedCount: an entry that left the
// directory is not a hold, whatever the journal counted when it opened.
func TestAPassReportsTheDirectoryAndNotACachedCount(t *testing.T) {
	ctx := context.Background()
	dir := newDir(t)
	j := openJournal(t, dir)
	record(t, j, "req-1")
	if err := os.Remove(entryFileOf(t, dir, "req-1")); err != nil {
		t.Fatalf("removing the entry from under the pass: %v", err)
	}
	// The journal's own count still says one entry is there; the pass reads
	// the directory instead.
	listing, err := j.List(ctx, 8)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	if len(listing.Held) != 0 || listing.Unreadable != 0 || !listing.Complete {
		t.Fatalf("a pass over a directory nothing is in reported %+v", listing)
	}
}

// TestManyCallersShareOneJournal: the methods are called from several
// goroutines at once under -race, each on its own request, and every entry
// ends where its caller left it.
func TestManyCallersShareOneJournal(t *testing.T) {
	ctx := context.Background()
	j := openJournal(t, newDir(t))
	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers*4)
	for c := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("req-%d", c)
			if err := j.Record(ctx, heldEntry(id)); err != nil {
				errs <- err
				return
			}
			if _, err := j.List(ctx, 64); err != nil {
				errs <- err
			}
			if err := j.Mark(ctx, id, holdjournal.StateClosing); err != nil {
				errs <- err
			}
			if c%2 == 0 {
				if err := j.Forget(ctx, id); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a caller was refused: %v", err)
	}
	listing, err := j.List(ctx, 64)
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	if listing.Interrupted != callers/2 || len(listing.Held) != 0 || !listing.Complete {
		t.Fatalf("after %d callers the listing is %+v", callers, listing)
	}
}

// reframe puts a new header on body: the eight-byte magic, the body's length
// and its CRC32C, both big-endian, as a writer of the directory would.
func reframe(body []byte) []byte {
	out := []byte("HOLDJRNL")
	out = binary.BigEndian.AppendUint32(out, uint32(len(body))) //nolint:gosec // G115: a test body is small
	out = binary.BigEndian.AppendUint32(out, crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	return append(out, body...)
}

// TestAnEntryWhoseApprovalIsOfAnotherMajorIsUnreadable: the approval a close
// is written from is read whole or not at all, so one this build does not read
// leaves its entry unreadable and the pass unmeasured, however well the
// entry's own version reads. The same file with its approval at 1.0 is held.
func TestAnEntryWhoseApprovalIsOfAnotherMajorIsUnreadable(t *testing.T) {
	ctx := context.Background()
	dir := newDir(t)
	j := openJournal(t, dir)
	record(t, j, "req-1")
	path := entryFileOf(t, dir, "req-1")
	body := readFile(t, path)[16:]
	if !bytes.Contains(body, []byte(`"schemaVersion":"1.0",`)) {
		t.Fatalf("the entry carries no approval version to change: %s", body)
	}
	for _, edit := range [][]byte{[]byte(`"schemaVersion":"2.0",`), []byte(`"schemaVersion":"",`), nil} {
		writeFile(t, path, reframe(bytes.Replace(body, []byte(`"schemaVersion":"1.0",`), edit, 1)))
		listing, err := j.List(ctx, 8)
		if err != nil || len(listing.Held) != 0 || listing.Unreadable != 1 || listing.Complete {
			t.Errorf("a pass over an approval as %q reported %+v, %v; want it unreadable", edit, listing, err)
		}
	}
	writeFile(t, path, reframe(body))
	listing, err := j.List(ctx, 8)
	if err != nil || len(listing.Held) != 1 || listing.Unreadable != 0 || !listing.Complete {
		t.Errorf("a pass over the entry as written reported %+v, %v", listing, err)
	}
}
