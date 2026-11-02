package spool_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/spool"
)

const quarantineFile = "quarantine.log"

// readQuarantine parses the quarantine file by the format itself: a big-endian
// length, a big-endian CRC32C over the line, the line.
func readQuarantine(t *testing.T, dir string) []*controlv1.Event {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, quarantineFile)) //nolint:gosec // G304: the spool's file under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	var events []*controlv1.Event
	for len(raw) > 0 {
		if len(raw) < 8 {
			t.Fatalf("%d bytes left, less than a header", len(raw))
		}
		length := binary.BigEndian.Uint32(raw[0:4])
		sum := binary.BigEndian.Uint32(raw[4:8])
		line := raw[8 : 8+length]
		if crc32.Checksum(line, crc32.MakeTable(crc32.Castagnoli)) != sum {
			t.Fatal("a quarantined record does not check")
		}
		got, err := evidence.DecodeJSONL(bytes.NewReader(line), 1)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, got...)
		raw = raw[8+length:]
	}
	return events
}

// TestQuarantineKeepsTheRecordsDurablyAndForGood: what goes into the
// quarantine is framed as a segment is, counted, kept across a reopen, and
// not released by acknowledging the segments.
func TestQuarantineKeepsTheRecordsDurablyAndForGood(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
	s := open(t, opts)
	first := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	second := event(controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, "req-1", 2)
	mustAppend(t, s, first)
	mustAppend(t, s, second)
	r := reader(t, s)
	last := deliveredCursors(t, r, 2)[1]
	if written, err := r.Quarantine([]*controlv1.Event{first, second}); err != nil || written != 2 {
		t.Fatal(err)
	}
	if err := r.Ack(last); err != nil {
		t.Fatal(err)
	}
	quarantined := recordSize(t, first) + recordSize(t, second)
	want := spool.Stats{Bytes: quarantined, QuarantinedRecords: 2, QuarantinedBytes: quarantined, Oldest: spool.Cursor{Segment: 3}}
	if st := stats(t, s); st != want {
		t.Errorf("Stats after quarantining and acknowledging both = %+v, want %+v", st, want)
	}
	got := readQuarantine(t, dir)
	if len(got) != 2 || !proto.Equal(got[0], first) || !proto.Equal(got[1], second) {
		t.Errorf("the quarantine holds %v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, opts)
	if st := stats(t, s); st.QuarantinedRecords != 2 || st.QuarantinedBytes != quarantined || st.Bytes != quarantined {
		t.Errorf("Stats after reopen = %+v, want the quarantine counted", st)
	}
}

// TestTheQuarantineCountsAgainstTheBudget: a record that fits the budget
// beside the segments alone is refused once the quarantine holds bytes, and
// the quarantine itself is not refused by a full budget.
func TestTheQuarantineCountsAgainstTheBudget(t *testing.T) {
	ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	size := recordSize(t, ev)
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 2 * size, SegmentBytes: size})
	mustAppend(t, s, ev)
	mustAppend(t, s, ev)
	r := reader(t, s)
	cursors := deliveredCursors(t, r, 2)
	if _, err := r.Quarantine([]*controlv1.Event{ev}); err != nil {
		t.Fatalf("Quarantine on a full budget = %v, want it taken", err)
	}
	if err := r.Ack(cursors[0]); err != nil {
		t.Fatal(err)
	}
	// One segment of one record and the quarantine's one record: full.
	if err := s.Append(context.Background(), ev); !errors.Is(err, spool.ErrFull) {
		t.Errorf("Append with the budget held by a segment and the quarantine = %v, want ErrFull", err)
	}
	if err := r.Ack(cursors[1]); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, ev)
}

// writeQuarantined opens a spool, appends n events, has a reader deliver them
// and quarantines them, then closes the spool, returning the options, the
// events and the quarantine file's bytes. The delivery is what covers the
// quarantine's bytes, as it does in the export.
func writeQuarantined(t *testing.T, n int) (spool.Options, []*controlv1.Event, []byte) {
	t.Helper()
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}
	s := open(t, opts)
	var events []*controlv1.Event
	for i := 1; i <= n; i++ {
		ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i)
		mustAppend(t, s, ev)
		events = append(events, ev)
	}
	r := reader(t, s)
	deliveredCursors(t, r, n)
	if _, err := r.Quarantine(events); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, quarantineFile)) //nolint:gosec // G304: the spool's file under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	return opts, events, raw
}

// TestDamageInsideTheQuarantineIsRefused: a quarantined record that does not
// check with a record that checks after it is not a torn append; it is
// evidence the spool reported durable, and Open leaves the file as it was.
func TestDamageInsideTheQuarantineIsRefused(t *testing.T) {
	for name, damage := range map[string]func([]byte) []byte{
		"a flipped bit in the first record": func(b []byte) []byte { b[20] ^= 0x01; return b },
		"a cut length in the first record":  func(b []byte) []byte { b[3] ^= 0x01; return b },
	} {
		t.Run(name, func(t *testing.T) {
			opts, _, raw := writeQuarantined(t, 2)
			if err := os.WriteFile(filepath.Join(opts.Dir, quarantineFile), damage(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			expectCorruptAndUntouched(t, opts)
		})
	}
}

// TestATornQuarantineAppendEndsTheQuarantine is the same property the log
// has, for the file the exporter appends to: an append that never returned
// left a partial record at the end, so cutting the quarantine at any byte
// leaves every record before the cut and Open goes on. A crash inside a
// quarantine append may not keep the plane from starting.
func TestATornQuarantineAppendEndsTheQuarantine(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 6).Draw(rt, "records")
		opts, events, raw := writeQuarantined(t, n)
		ends := recordEnds(t, events)
		if ends[len(ends)-1] != int64(len(raw)) {
			rt.Fatalf("the quarantine holds %d bytes, the records account for %d", len(raw), ends[len(ends)-1])
		}
		cut := int64(rapid.IntRange(0, len(raw)).Draw(rt, "cut"))
		if err := os.WriteFile(filepath.Join(opts.Dir, quarantineFile), raw[:cut], 0o600); err != nil {
			rt.Fatal(err)
		}
		whole, kept := 0, int64(0)
		for _, end := range ends {
			if end <= cut {
				whole, kept = whole+1, end
			}
		}
		s, err := spool.Open(opts)
		if err != nil {
			rt.Fatalf("Open after a cut at %d of %d: %v", cut, len(raw), err)
		}
		defer s.Close() //nolint:errcheck // the assertions are above
		st, err := s.Stats()
		if err != nil {
			rt.Fatal(err)
		}
		if st.QuarantinedRecords != whole || st.QuarantinedBytes != kept || st.Truncated != cut-kept {
			rt.Fatalf("cut at %d of %d: Stats = %+v; want %d records of %d bytes and %d truncated",
				cut, len(raw), st, whole, kept, cut-kept)
		}
		expectQuarantined(rt, t, opts.Dir, events[:whole])
		// The next quarantine lands on the records that survived. The spool
		// still holds the events themselves, so delivering one covers it.
		fresh := event(controlv1.EventKind_EVENT_KIND_FINDING_RAISED, "", 1000)
		next := reader(t, s)
		deliveredCursors(t, next, 1)
		if _, err := next.Quarantine([]*controlv1.Event{fresh}); err != nil {
			rt.Fatalf("Quarantine after the cut: %v", err)
		}
		expectQuarantined(rt, t, opts.Dir, append(events[:whole:whole], fresh))
	})
}

// recordEnds is the offset just past each event's record, computed from the
// format.
func recordEnds(t *testing.T, events []*controlv1.Event) []int64 {
	t.Helper()
	var ends []int64
	var at int64
	for _, ev := range events {
		at += recordSize(t, ev)
		ends = append(ends, at)
	}
	return ends
}

// expectQuarantined reads the quarantine file and requires it to hold exactly
// want, in order.
func expectQuarantined(rt *rapid.T, t *testing.T, dir string, want []*controlv1.Event) {
	t.Helper()
	got := readQuarantine(t, dir)
	if len(got) != len(want) {
		rt.Fatalf("the quarantine replays %d records, want %d", len(got), len(want))
	}
	for i, ev := range got {
		if !proto.Equal(ev, want[i]) {
			rt.Fatalf("quarantined record %d = %v, want %v", i, ev, want[i])
		}
	}
}

func TestQuarantineRefusesWhatTheSpoolCannotHold(t *testing.T) {
	var zero spool.Reader
	if _, err := zero.Quarantine([]*controlv1.Event{event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)}); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Quarantine on the zero reader = %v, want ErrClosed", err)
	}
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	r := reader(t, s)
	if _, err := r.Quarantine([]*controlv1.Event{nil}); !errors.Is(err, evidence.ErrNilEvent) {
		t.Errorf("Quarantine of a nil event = %v, want ErrNilEvent", err)
	}
	if st := stats(t, s); st.QuarantinedRecords != 0 {
		t.Errorf("a refused quarantine counted records: %+v", st)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Quarantine([]*controlv1.Event{event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)}); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Quarantine after Close = %v, want ErrClosed", err)
	}
}

// TestTheQuarantineTakesNoMoreThanTheAcknowledgementReleases: the quarantine
// is the one append the budget cannot refuse for its own bytes, so what it
// takes between two acknowledgements is bounded by what the next one releases.
// Without that, quarantining the same record again and again puts the spool
// past MaxBytes for good.
func TestTheQuarantineTakesNoMoreThanTheAcknowledgementReleases(t *testing.T) {
	first := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	second := event(controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, "req-1", 2)
	size := recordSize(t, first)
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 4 * size, SegmentBytes: size})
	mustAppend(t, s, first)
	r := reader(t, s)
	cursors := deliveredCursors(t, r, 1)
	if written, err := r.Quarantine([]*controlv1.Event{first}); err != nil || written != 1 {
		t.Fatalf("Quarantine of the delivered record = %d, %v", written, err)
	}
	// Nothing more was delivered, so nothing more is covered.
	if _, err := r.Quarantine([]*controlv1.Event{second}); !errors.Is(err, spool.ErrFull) {
		t.Fatalf("a second Quarantine with nothing further delivered = %v, want ErrFull", err)
	}
	for i := range 40 {
		if _, err := r.Quarantine([]*controlv1.Event{second}); !errors.Is(err, spool.ErrFull) {
			t.Fatalf("Quarantine %d = %v, want ErrFull", i, err)
		}
	}
	if st := stats(t, s); st.Bytes > 4*size || st.QuarantinedRecords != 1 {
		t.Fatalf("Stats = %+v, want the quarantine inside the budget with one record", st)
	}
	// The acknowledgement releases the record, and the next delivery covers
	// the next quarantine.
	if err := r.Ack(cursors[0]); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, second)
	deliveredCursors(t, r, 1)
	if written, err := r.Quarantine([]*controlv1.Event{second}); err != nil || written != 1 {
		t.Fatalf("Quarantine after the acknowledgement = %d, %v", written, err)
	}
}

// TestTheQuarantineHoldsOneCopyOfARecord: a caller stopped between
// quarantining and acknowledging repeats both, and the record is not written
// twice.
func TestTheQuarantineHoldsOneCopyOfARecord(t *testing.T) {
	ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	size := recordSize(t, ev)
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 8 * size, SegmentBytes: size}
	s := open(t, opts)
	mustAppend(t, s, ev)
	r := reader(t, s)
	deliveredCursors(t, r, 1)
	if written, err := r.Quarantine([]*controlv1.Event{ev, ev}); err != nil || written != 1 {
		t.Fatalf("Quarantine of one record named twice = %d, %v; want one written", written, err)
	}
	if written, err := r.Quarantine([]*controlv1.Event{ev}); err != nil || written != 0 {
		t.Fatalf("Quarantine of a record the quarantine holds = %d, %v; want nothing written", written, err)
	}
	if st := stats(t, s); st.QuarantinedRecords != 1 || st.QuarantinedBytes != size {
		t.Fatalf("Stats = %+v, want one copy of the record", st)
	}
	// The tail is read back at Open, so the second run knows it too.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, opts)
	mustAppend(t, s, ev)
	r = reader(t, s)
	deliveredCursors(t, r, 1)
	if written, err := r.Quarantine([]*controlv1.Event{ev}); err != nil || written != 0 {
		t.Fatalf("Quarantine after a reopen = %d, %v; want nothing written", written, err)
	}
	if got := readQuarantine(t, dir); len(got) != 1 {
		t.Errorf("the quarantine holds %d records, want one", len(got))
	}
}

// TestTheQuarantineTellsRecordsApartByContent: a record carrying the event
// identifier of one the quarantine holds, or no identifier like one it holds,
// with other content is written, in the same call and after a reopen; only a
// record repeated byte for byte is not.
func TestTheQuarantineTellsRecordsApartByContent(t *testing.T) {
	first := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	sameID := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-2", 1)
	noID, otherNoID := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-3", 3), event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-4", 4)
	noID.EventId, otherNoID.EventId = "", ""
	batch := []*controlv1.Event{first, sameID, noID, otherNoID}
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxBytes: 64 * recordSize(t, first), SegmentBytes: 4 * recordSize(t, first)}
	s := open(t, opts)
	for _, ev := range batch {
		mustAppend(t, s, ev)
	}
	r := reader(t, s)
	deliveredCursors(t, r, 4)
	if written, err := r.Quarantine([]*controlv1.Event{first, sameID, noID}); err != nil || written != 3 {
		t.Fatalf("Quarantine of three records, two sharing an identifier = %d, %v; want three written", written, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, opts)
	for _, ev := range batch {
		mustAppend(t, s, ev)
	}
	r = reader(t, s)
	deliveredCursors(t, r, 8)
	if written, err := r.Quarantine(batch); err != nil || written != 1 {
		t.Fatalf("Quarantine after a reopen = %d, %v; want only the record with no identifier and other content written", written, err)
	}
	got := readQuarantine(t, dir)
	if len(got) != 4 || !proto.Equal(got[1], sameID) || !proto.Equal(got[3], otherNoID) {
		t.Errorf("the quarantine holds %d records, want first, sameID, noID and otherNoID in order", len(got))
	}
}
