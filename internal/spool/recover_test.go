package spool_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/spool"
)

// sixRecordsInThreeSegments writes six records two to a segment, closes the
// spool and returns its options and one record's size.
func sixRecordsInThreeSegments(t *testing.T) (spool.Options, int64) {
	t.Helper()
	size := recordSize(t, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 0))
	opts := spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 2 * size}
	s := open(t, opts)
	for i := range 6 {
		mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if names := segmentNames(t, opts.Dir); len(names) != 3 {
		t.Fatalf("six records two to a segment gave %v", names)
	}
	return opts, size
}

// snapshot is every file under dir and its bytes.
func snapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: a file the test wrote under its temp dir
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = b
	}
	return files
}

func flipBit(t *testing.T, path string, at int64) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a segment the test wrote under its temp dir
	if err != nil {
		t.Fatal(err)
	}
	b[at] ^= 0x01
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// expectCorruptAndUntouched opens opts.Dir, requires ErrCorrupt, and requires
// every file to be on disk with the bytes it had before.
func expectCorruptAndUntouched(t *testing.T, opts spool.Options) {
	t.Helper()
	before := snapshot(t, opts.Dir)
	s, err := spool.Open(opts)
	if !errors.Is(err, spool.ErrCorrupt) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatalf("Open = %v, want ErrCorrupt", err)
	}
	after := snapshot(t, opts.Dir)
	if len(after) != len(before) {
		t.Fatalf("Open refused and still changed the directory: %d files before, %d after", len(before), len(after))
	}
	for name, b := range before {
		if !bytes.Equal(after[name], b) {
			t.Errorf("Open refused and still changed %s", name)
		}
	}
}

// TestABitFlipBeforeTheLastSegmentIsCorruption: the segments before the last
// were synced whole, so a record in one that does not check is not a torn
// write, and Open neither truncates it nor drops what follows.
func TestABitFlipBeforeTheLastSegmentIsCorruption(t *testing.T) {
	for _, tc := range []struct {
		name    string
		segment int
		record  int64
	}{
		{"second record of the first segment", 0, 1},
		{"first record of the middle segment", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, size := sixRecordsInThreeSegments(t)
			names := segmentNames(t, opts.Dir)
			flipBit(t, filepath.Join(opts.Dir, names[tc.segment]), tc.record*size+20)
			expectCorruptAndUntouched(t, opts)
		})
	}
}

// TestBytesAfterTheRecordsOfAnEarlierSegmentAreCorruption: the record count
// is right, so the sequence holds, and the bytes past the last record are
// still not a tear: nothing was being written there.
func TestBytesAfterTheRecordsOfAnEarlierSegmentAreCorruption(t *testing.T) {
	opts, _ := sixRecordsInThreeSegments(t)
	path := filepath.Join(opts.Dir, segmentNames(t, opts.Dir)[0])
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: a segment the test wrote under its temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	expectCorruptAndUntouched(t, opts)
}

// TestARecordAfterOneThatDoesNotCheckIsCorruption: in the last segment a
// record that does not check is a tear only when nothing that checks follows.
func TestARecordAfterOneThatDoesNotCheckIsCorruption(t *testing.T) {
	opts, size := sixRecordsInThreeSegments(t)
	names := segmentNames(t, opts.Dir)
	flipBit(t, filepath.Join(opts.Dir, names[2]), 20)
	expectCorruptAndUntouched(t, opts)

	// The same flip in the last record of the last segment is a torn tail.
	flipBit(t, filepath.Join(opts.Dir, names[2]), 20)
	flipBit(t, filepath.Join(opts.Dir, names[2]), size+20)
	s := open(t, opts)
	if st := stats(t, s); st.Truncated != size || st.Segments != 3 {
		t.Errorf("Stats after a tear in the last record = %+v; want %d truncated and three segments", st, size)
	}
}

// TestAnEmptySegmentBeforeTheLastIsCorruption: a segment is created only to
// take a record, and synced with it before the next one exists.
func TestAnEmptySegmentBeforeTheLastIsCorruption(t *testing.T) {
	opts, _ := sixRecordsInThreeSegments(t)
	names := segmentNames(t, opts.Dir)
	if err := os.Truncate(filepath.Join(opts.Dir, names[1]), 0); err != nil {
		t.Fatal(err)
	}
	expectCorruptAndUntouched(t, opts)
}

// TestASequenceOutOfRangeIsCorruption: a segment numbered 0, and one whose
// records would carry the sequence past its range, name no record.
func TestASequenceOutOfRangeIsCorruption(t *testing.T) {
	for name, seq := range map[string]string{
		"segment zero":              "00000000000000000000.seg",
		"sequence past its range":   "18446744073709551615.seg",
		"one short of the overflow": "18446744073709551614.seg",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
			s := open(t, opts)
			mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1))
			mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 2))
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, segmentNames(t, dir)[0]), filepath.Join(dir, seq)); err != nil {
				t.Fatal(err)
			}
			expectCorruptAndUntouched(t, opts)
		})
	}
	// Two records starting at 2^64-3 end at 2^64-1, which is in range.
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
	s := open(t, opts)
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1))
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 2))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, segmentNames(t, dir)[0]), filepath.Join(dir, "18446744073709551613.seg")); err != nil {
		t.Fatal(err)
	}
	s = open(t, opts)
	if st := stats(t, s); st.Segments != 1 || st.Oldest != (spool.Cursor{Segment: 18446744073709551613}) {
		t.Errorf("Stats of a segment ending at the top of the range = %+v", st)
	}
}

// TestOneSpoolPerDirectory: a second Open of a directory another spool holds
// is refused, and succeeds once the first is closed.
func TestOneSpoolPerDirectory(t *testing.T) {
	opts := spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
	first := open(t, opts)
	second, err := spool.Open(opts)
	if !errors.Is(err, spool.ErrLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("a second Open of a held directory = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	open(t, opts)
}

// TestUnderTheTimerTheLastSegmentEndsAtTheFirstRecordThatDoesNotCheck: the
// strict rule rests on every record being forced to disk before the next one,
// which FsyncInterval does not do. A power loss may then keep a later record
// and not an earlier one, and a plane that refuses to start would refuse over
// a loss the operator's own setting accepted.
func TestUnderTheTimerTheLastSegmentEndsAtTheFirstRecordThatDoesNotCheck(t *testing.T) {
	size := recordSize(t, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 0))
	base := spool.Options{MaxBytes: 1 << 20, SegmentBytes: 4 * size}
	for name, policy := range map[string]spool.FsyncPolicy{
		"every record": spool.FsyncEveryRecord,
		"on the timer": spool.FsyncInterval,
	} {
		t.Run(name, func(t *testing.T) {
			opts := base
			opts.Dir, opts.Fsync = t.TempDir(), policy
			if policy == spool.FsyncInterval {
				opts.Interval = time.Hour
			}
			s := open(t, opts)
			var want []*controlv1.Event
			for i := range 3 {
				ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i)
				mustAppend(t, s, ev)
				want = append(want, ev)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			// The second record of the one segment loses a bit; the third is
			// whole behind it.
			flipBit(t, filepath.Join(opts.Dir, segmentNames(t, opts.Dir)[0]), size+20)
			again, err := spool.Open(opts)
			if policy == spool.FsyncEveryRecord {
				if !errors.Is(err, spool.ErrCorrupt) {
					if again != nil {
						_ = again.Close()
					}
					t.Fatalf("Open under every-record fsync = %v, want ErrCorrupt", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open under the timer = %v, want the log ended at the first record that does not check", err)
			}
			t.Cleanup(func() { _ = again.Close() })
			if st := stats(t, again); st.Truncated != 2*size || st.Bytes != size {
				t.Errorf("Stats = %+v, want the first record kept and the two after it truncated", st)
			}
			expectRecords(t, reader(t, again), want[:1])
		})
	}
}

// TestATailThatCostsTooMuchToReadIsCorruption: the search for a committed
// record behind a torn one is bounded; a tail crafted to make it expensive is
// an unknown, and an unknown tail is not a tear.
func TestATailThatCostsTooMuchToReadIsCorruption(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 30, SegmentBytes: 1 << 20}
	s := open(t, opts)
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A tail in which one offset in four reads as a plausible length, each
	// naming a long record.
	const tail = 1 << 19
	garbage := make([]byte, tail)
	var word [4]byte
	binary.BigEndian.PutUint32(word[:], tail/2)
	for i := range garbage {
		garbage[i] = word[i%4]
	}
	path := filepath.Join(dir, segmentNames(t, dir)[0])
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: a segment the test wrote under its temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(garbage); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	again, err := spool.Open(opts)
	took := time.Since(start)
	if again != nil {
		_ = again.Close()
	}
	if !errors.Is(err, spool.ErrCorrupt) {
		t.Fatalf("Open over a crafted tail = %v, want ErrCorrupt", err)
	}
	if took > 2*time.Second {
		t.Errorf("Open over a %d byte crafted tail took %v", tail, took)
	}
	t.Logf("Open over a %d byte crafted tail: %v after %v", tail, err, took)
}

// TestARecordThatStopsCheckingWhileTheSpoolIsOpenIsNotDelivered: the checksum
// is read every time a record is read, not only at Open. A record whose bytes
// change under a spool that is already open is refused, the reader stays where
// it is rather than delivering something the writer never wrote, and the
// cursor of that record is no longer a position a reader may be given.
func TestARecordThatStopsCheckingWhileTheSpoolIsOpenIsNotDelivered(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
	s := open(t, opts)
	first := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	second := event(controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, "req-1", 2)
	mustAppend(t, s, first)
	mustAppend(t, s, second)
	r := reader(t, s)
	at := deliveredCursors(t, r, 1)[0]
	if err := r.Ack(at); err != nil {
		t.Fatal(err)
	}
	// One bit of the second record's line, which the spool has already
	// reported durable and nobody has read yet.
	flipBit(t, filepath.Join(dir, segmentNames(t, dir)[0]), at.Offset+20)

	ev, _, err := r.Next(contextWithin(t, 5*time.Second))
	if !errors.Is(err, spool.ErrCorrupt) {
		t.Fatalf("Next over a record that stopped checking = %v, %v; want ErrCorrupt", ev, err)
	}
	if ev != nil {
		t.Errorf("Next handed out %v beside the refusal", ev)
	}
	// The reader did not move: the record is refused again, not skipped.
	if _, _, err := r.Next(contextWithin(t, 5*time.Second)); !errors.Is(err, spool.ErrCorrupt) {
		t.Errorf("the second Next = %v, want ErrCorrupt again", err)
	}
	if st := stats(t, s); st.Unacknowledged != recordSize(t, second) {
		t.Errorf("Stats = %+v, want the record still unacknowledged", st)
	}
	// A cursor is checked by the same checksum, so the damaged record's own
	// position is no longer one a reader may start at or acknowledge.
	if _, err := s.Reader(at); err != nil {
		t.Errorf("Reader at the acknowledged position = %v", err)
	}
	past := spool.Cursor{Segment: at.Segment, Offset: at.Offset + recordSize(t, second)}
	if err := r.Ack(past); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Ack past a record that does not check = %v, want ErrCursor", err)
	}
	// Mended, it is delivered as it was written.
	flipBit(t, filepath.Join(dir, segmentNames(t, dir)[0]), at.Offset+20)
	expectRecords(t, r, []*controlv1.Event{second})
}
