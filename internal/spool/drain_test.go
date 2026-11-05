package spool_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/spool"
)

// quarantined is a spool directory, closed, whose quarantine holds first and
// second and nothing else, and the bytes the two take there.
func quarantined(t *testing.T) (dir string, events []*controlv1.Event, size int64) {
	t.Helper()
	dir = t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
	s := open(t, opts)
	first := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	second := event(controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, "req-1", 2)
	mustAppend(t, s, first)
	mustAppend(t, s, second)
	r := reader(t, s)
	last := deliveredCursors(t, r, 2)[1]
	if written, err := r.Quarantine([]*controlv1.Event{first, second}); err != nil || written != 2 {
		t.Fatalf("Quarantine = %d, %v", written, err)
	}
	if err := r.Ack(last); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, []*controlv1.Event{first, second}, recordSize(t, first) + recordSize(t, second)
}

// drainedEvents decodes a drained file by the format: one JSONL line per
// record.
func drainedEvents(t *testing.T, path string) []*controlv1.Event {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	events, err := evidence.DecodeJSONL(bytes.NewReader(raw), 16)
	if err != nil {
		t.Fatalf("the drained file: %v", err)
	}
	return events
}

func sameEvents(got, want []*controlv1.Event) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !proto.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}

// quarantineAfter is what a spool opened on dir counts in its quarantine.
func quarantineAfter(t *testing.T, dir string) spool.Stats {
	t.Helper()
	s := open(t, spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	st := stats(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestADrainMovesTheQuarantineIntoAFileOfItsOwnersAlone: the records leave
// the quarantine for the drained file, which only its owner may read, and the
// budget no longer counts them.
func TestADrainMovesTheQuarantineIntoAFileOfItsOwnersAlone(t *testing.T) {
	dir, events, size := quarantined(t)
	out := filepath.Join(t.TempDir(), "drained.jsonl")
	d, err := spool.Drain(dir, out)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if d != (spool.Drained{Records: 2, Bytes: size}) {
		t.Errorf("Drain = %+v, want 2 records of %d bytes", d, size)
	}
	if got := drainedEvents(t, out); !sameEvents(got, events) {
		t.Errorf("the drained file holds %v, want the two quarantined events", got)
	}
	if info, err := os.Stat(out); err != nil {
		t.Errorf("the drained file: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("the drained file has mode %v, want 0600", info.Mode().Perm())
	}
	expectEmptyQuarantine(t, dir)
	if st := quarantineAfter(t, dir); st.QuarantinedRecords != 0 || st.QuarantinedBytes != 0 || st.Bytes != 0 {
		t.Errorf("a spool opened after the drain counts %+v, want nothing", st)
	}
}

// TestADrainStoppedBeforeTheTruncateLosesNothing: a drain stopped once its
// file is on disk leaves the records in the file and in the quarantine; a
// second drain into the same file is refused and changes nothing, and one into
// a new file empties the quarantine. Every record is in a drained file.
func TestADrainStoppedBeforeTheTruncateLosesNothing(t *testing.T) {
	dir, events, _ := quarantined(t)
	outDir := t.TempDir()
	first, second := filepath.Join(outDir, "first.jsonl"), filepath.Join(outDir, "second.jsonl")
	killed := errors.New("killed")
	if _, err := spool.DrainStoppedAfterWrite(dir, first, func() error { return killed }); !errors.Is(err, killed) {
		t.Fatalf("a stopped drain: %v, want the stop", err)
	}
	if got := drainedEvents(t, first); !sameEvents(got, events) {
		t.Errorf("the stopped drain's file holds %v, want both events", got)
	}
	if st := quarantineAfter(t, dir); st.QuarantinedRecords != 2 {
		t.Errorf("after a stopped drain the quarantine holds %d records, want 2", st.QuarantinedRecords)
	}
	if _, err := spool.Drain(dir, first); !errors.Is(err, fs.ErrExist) {
		t.Errorf("a drain into a file that exists: %v, want fs.ErrExist", err)
	}
	if got := drainedEvents(t, first); !sameEvents(got, events) {
		t.Errorf("a refused drain changed the file it was refused: %v", got)
	}
	if st := quarantineAfter(t, dir); st.QuarantinedRecords != 2 {
		t.Errorf("a refused drain left %d records in the quarantine, want 2", st.QuarantinedRecords)
	}
	if d, err := spool.Drain(dir, second); err != nil || d.Records != 2 {
		t.Fatalf("the second drain = %+v, %v", d, err)
	}
	if got := drainedEvents(t, second); !sameEvents(got, events) {
		t.Errorf("the second drain's file holds %v, want both events", got)
	}
	if st := quarantineAfter(t, dir); st.QuarantinedRecords != 0 {
		t.Errorf("after the second drain the quarantine holds %d records, want none", st.QuarantinedRecords)
	}
}

// TestADrainIsRefusedWhileASpoolIsOpen: a plane holding the spool holds its
// lock, so the drain is refused and creates nothing; once it closes, the same
// drain runs.
func TestADrainIsRefusedWhileASpoolIsOpen(t *testing.T) {
	dir, _, _ := quarantined(t)
	s := open(t, spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	out := filepath.Join(t.TempDir(), "drained.jsonl")
	if _, err := spool.Drain(dir, out); !errors.Is(err, spool.ErrLocked) {
		t.Errorf("a drain while a spool is open: %v, want ErrLocked", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused drain left %s: %v", out, err)
	}
	if st := stats(t, s); st.QuarantinedRecords != 2 {
		t.Errorf("a refused drain left %d records, want 2", st.QuarantinedRecords)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if d, err := spool.Drain(dir, out); err != nil || d.Records != 2 {
		t.Errorf("the control, a drain once the spool closed = %+v, %v", d, err)
	}
}

// TestADrainWritesNowhereItCannotOwn: a file in the spool's own directory,
// which the next start would refuse, and a link at the name, which the drain
// would write through, are refused, and the quarantine is kept whole.
func TestADrainWritesNowhereItCannotOwn(t *testing.T) {
	dir, _, _ := quarantined(t)
	if _, err := spool.Drain(dir, filepath.Join(dir, "drained.jsonl")); !errors.Is(err, spool.ErrDrainTarget) {
		t.Errorf("a drain into the spool's directory: %v, want ErrDrainTarget", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "drained.jsonl")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused drain left a file in the spool: %v", err)
	}
	elsewhere := t.TempDir()
	target := filepath.Join(elsewhere, "target")
	link := filepath.Join(elsewhere, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Drain(dir, link); !errors.Is(err, fs.ErrExist) {
		t.Errorf("a drain onto a link: %v, want fs.ErrExist", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a drain onto a link wrote through it: %v", err)
	}
	if st := quarantineAfter(t, dir); st.QuarantinedRecords != 2 {
		t.Errorf("refused drains left %d records, want 2", st.QuarantinedRecords)
	}
}

// TestADrainCutsATornTailWithTheRest: bytes past the last whole record are
// counted, left out of the drained file and cut.
func TestADrainCutsATornTailWithTheRest(t *testing.T) {
	dir, events, size := quarantined(t)
	f, err := os.OpenFile(filepath.Join(dir, quarantineFile), os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the spool's file under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "drained.jsonl")
	d, err := spool.Drain(dir, out)
	if err != nil || d != (spool.Drained{Records: 2, Bytes: size, Torn: 3}) {
		t.Fatalf("Drain = %+v, %v; want 2 records of %d bytes and 3 torn", d, err, size)
	}
	if got := drainedEvents(t, out); !sameEvents(got, events) {
		t.Errorf("the drained file holds %v", got)
	}
	expectEmptyQuarantine(t, dir)
}

// expectEmptyQuarantine holds dir's quarantine to being there and empty.
func expectEmptyQuarantine(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, quarantineFile))
	if err != nil {
		t.Fatalf("the quarantine after a drain: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("the quarantine after a drain holds %d bytes, want it empty", info.Size())
	}
}
