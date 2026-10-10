package spool_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/spool"
)

// TestZeroValueRefusesEverything: a spool nobody opened writes nothing and
// hands nothing out, so a caller that skipped Open blocks rather than records
// into the void.
func TestZeroValueRefusesEverything(t *testing.T) {
	var s spool.Spool
	if err := s.Append(context.Background(), &controlv1.Event{EventId: "e-1"}); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Append on the zero value = %v, want ErrClosed", err)
	}
	if r, err := s.Reader(spool.Cursor{}); r != nil || !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Reader on the zero value = %v, %v; want nil, ErrClosed", r, err)
	}
	if err := s.Close(); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Close on the zero value = %v, want ErrClosed", err)
	}
	if st, err := s.Stats(); st != (spool.Stats{}) || !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Stats on the zero value = %+v, %v; want zero, ErrClosed", st, err)
	}
	var r spool.Reader
	if ev, _, err := r.Next(context.Background()); ev != nil || !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Next on the zero reader = %v, %v; want nil, ErrClosed", ev, err)
	}
	if err := r.Ack(spool.Cursor{}); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Ack on the zero reader = %v, want ErrClosed", err)
	}
}

func TestSafeDefaults(t *testing.T) {
	var policy spool.FsyncPolicy
	if policy != spool.FsyncEveryRecord {
		t.Errorf("the zero fsync policy is %d, want FsyncEveryRecord", policy)
	}
}

func TestOpenRefusesOptionsThatCannotMakeALog(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]spool.Options{
		"missing dir":             {Dir: filepath.Join(dir, "missing"), MaxBytes: 1 << 20, SegmentBytes: 1 << 16},
		"zero MaxBytes":           {Dir: dir, SegmentBytes: 1 << 16},
		"zero SegmentBytes":       {Dir: dir, MaxBytes: 1 << 20},
		"SegmentBytes > MaxBytes": {Dir: dir, MaxBytes: 1 << 16, SegmentBytes: 1<<16 + 1},
		"Interval under every":    {Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, Interval: time.Second},
		"no Interval under timer": {Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, Fsync: spool.FsyncInterval},
		"unknown policy":          {Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, Fsync: 7, Interval: time.Second},
		"reserve past the budget": {Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, ClosingReserve: 1<<20 + 1},
		"negative ClosingReserve": {Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, ClosingReserve: -1},
		"dir is a file":           {Dir: writeFile(t, dir, "plain", "x"), MaxBytes: 1 << 20, SegmentBytes: 1 << 16},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := spool.Open(opts)
			if s != nil || !errors.Is(err, spool.ErrInvalidOptions) {
				t.Errorf("Open = %v, %v; want nil, ErrInvalidOptions", s, err)
			}
		})
	}
	// The bounds themselves are allowed: a segment as large as the budget and
	// a reserve as large as the budget.
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 16, SegmentBytes: 1 << 16, ClosingReserve: 1 << 16})
	if st := stats(t, s); st != (spool.Stats{Oldest: spool.Cursor{Segment: 1}}) {
		t.Errorf("Stats of an empty spool = %+v", st)
	}
}

func TestOpenRefusesAForeignFileAndAGapInTheSequence(t *testing.T) {
	t.Run("foreign file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "notes.txt", "hello")
		if _, err := spool.Open(spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16}); !errors.Is(err, spool.ErrForeignFile) {
			t.Errorf("Open with a stray file = %v, want ErrForeignFile", err)
		}
	})
	t.Run("gap", func(t *testing.T) {
		dir := t.TempDir()
		s := open(t, spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1})
		for i := range 3 {
			mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i))
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		names := segmentNames(t, dir)
		if len(names) != 3 {
			t.Fatalf("one record per segment should give 3 files, got %v", names)
		}
		if err := os.Remove(filepath.Join(dir, names[1])); err != nil {
			t.Fatal(err)
		}
		if _, err := spool.Open(spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1}); !errors.Is(err, spool.ErrCorrupt) {
			t.Errorf("Open over a missing middle segment = %v, want ErrCorrupt", err)
		}
	})
}

func TestAppendThenReadInOrderThenAck(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	want := []*controlv1.Event{
		event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1),
		event(controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, "req-1", 2),
		event(controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED, "req-1", 3),
	}
	for _, ev := range want {
		mustAppend(t, s, ev)
	}
	size := recordSize(t, want[0]) + recordSize(t, want[1]) + recordSize(t, want[2])
	wantStats := spool.Stats{Segments: 1, Bytes: size, Unacknowledged: size, Oldest: spool.Cursor{Segment: 1}}
	if st := stats(t, s); st != wantStats {
		t.Errorf("Stats after three appends = %+v, want %+v", st, wantStats)
	}
	r := reader(t, s)
	last := expectRecords(t, r, want)
	if err := r.Ack(last); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if st := stats(t, s); st != (spool.Stats{Oldest: spool.Cursor{Segment: 4}}) {
		t.Errorf("Stats after acknowledging everything = %+v, want the segment released and the oldest at record 4", st)
	}
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-2", 4))
	expectRecords(t, r, []*controlv1.Event{event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-2", 4)})
}

func TestNextBlocksUntilAnAppendOrTheContext(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		ev  *controlv1.Event
		err error
	}
	got := make(chan result, 1)
	go func() {
		ev, _, err := r.Next(context.Background())
		got <- result{ev, err}
	}()
	select {
	case res := <-got:
		t.Fatalf("Next returned %v, %v before any append", res.ev, res.err)
	case <-time.After(30 * time.Millisecond):
	}
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_FINDING_RAISED, "", 9))
	select {
	case res := <-got:
		if res.err != nil || res.ev.GetEventId() != "evt-9" {
			t.Errorf("Next after the append = %v, %v", res.ev, res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Next did not wake for the append")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Next(context.Background()); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Next after Close = %v, want ErrClosed", err)
	}
	if _, err := s.Stats(); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Stats after Close = %v, want ErrClosed", err)
	}
}

// TestAckReleasesWholeSegmentsOnly: a segment acknowledged up to its last byte
// leaves the budget; one acknowledged short of that stays, whole.
func TestAckReleasesWholeSegmentsOnly(t *testing.T) {
	ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	size := recordSize(t, ev)
	// Two records per segment, three segments.
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 6 * size, SegmentBytes: 2 * size})
	for i := range 6 {
		mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i))
	}
	if st := stats(t, s); st.Segments != 3 || st.Bytes != 6*size {
		t.Fatalf("Stats = %+v, want 3 segments of %d bytes", st, 2*size)
	}
	r := reader(t, s)
	cursors := deliveredCursors(t, r, 6)
	steps := []struct {
		ack                   spool.Cursor
		segments              int
		bytes, unacknowledged int64
		what                  string
	}{
		{cursors[0], 3, 6 * size, 5 * size, "half a segment"},
		{cursors[1], 2, 4 * size, 4 * size, "the first segment whole"},
		{cursors[4], 1, 2 * size, size, "into the current segment"},
		{cursors[5], 0, 0, 0, "everything"},
	}
	for _, step := range steps {
		if err := r.Ack(step.ack); err != nil {
			t.Fatalf("Ack %s: %v", step.what, err)
		}
		st := stats(t, s)
		if st.Segments != step.segments || st.Bytes != step.bytes || st.Unacknowledged != step.unacknowledged {
			t.Errorf("after acknowledging %s: %+v; want %d segments, %d bytes, %d unacknowledged",
				step.what, st, step.segments, step.bytes, step.unacknowledged)
		}
	}
	// Backwards and past-delivery acknowledgements are refused.
	if err := r.Ack(cursors[2]); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Ack before the acknowledged position = %v, want ErrCursor", err)
	}
	if err := r.Ack(spool.Cursor{Segment: cursors[5].Segment + 100}); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Ack past what was delivered = %v, want ErrCursor", err)
	}
}

// TestTheBudgetCountsBytesOnDisk: a segment acknowledged in part still holds
// its bytes, so the budget refuses; acknowledged whole it leaves, even when it
// is the segment being written, so a spool whose one segment is its whole
// budget takes the next record once everything is exported.
func TestTheBudgetCountsBytesOnDisk(t *testing.T) {
	ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	size := recordSize(t, ev)
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 2 * size, SegmentBytes: 2 * size})
	mustAppend(t, s, ev)
	mustAppend(t, s, ev)
	if err := s.Append(context.Background(), ev); !errors.Is(err, spool.ErrFull) {
		t.Fatalf("third Append into a two-record budget = %v, want ErrFull", err)
	}
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	_, first, _ := r.Next(context.Background())
	_, second, _ := r.Next(context.Background())
	if err := r.Ack(first); err != nil {
		t.Fatal(err)
	}
	if st := stats(t, s); st.Bytes != 2*size || st.Unacknowledged != size {
		t.Fatalf("Stats after a half acknowledgement = %+v", st)
	}
	if err := s.Append(context.Background(), ev); !errors.Is(err, spool.ErrFull) {
		t.Errorf("Append with the budget held by a half-acknowledged segment = %v, want ErrFull", err)
	}
	if err := r.Ack(second); err != nil {
		t.Fatal(err)
	}
	if st := stats(t, s); st.Segments != 0 || st.Bytes != 0 {
		t.Fatalf("Stats after acknowledging the current segment whole = %+v", st)
	}
	mustAppend(t, s, ev)
	if got, _, err := r.Next(context.Background()); err != nil || !proto.Equal(got, ev) {
		t.Errorf("Next after the current segment was released = %v, %v", got, err)
	}
}

func TestReaderRefusesACursorInsideARecord(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1))
	mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 2))
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := r.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reader(spool.Cursor{Segment: c.Segment, Offset: c.Offset - 1}); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Reader one byte inside a record = %v, want ErrCursor", err)
	}
	if _, err := s.Reader(spool.Cursor{Segment: c.Segment, Offset: c.Offset + 1}); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Reader one byte past a boundary = %v, want ErrCursor", err)
	}
	if _, err := s.Reader(c); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Reader at a boundary past the acknowledged position = %v, want ErrCursor", err)
	}
	if err := r.Ack(spool.Cursor{Segment: c.Segment, Offset: c.Offset - 1}); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Ack one byte inside a record = %v, want ErrCursor", err)
	}
	if err := r.Ack(c); err != nil {
		t.Errorf("Ack at the boundary = %v", err)
	}
	if err := r.Ack(spool.Cursor{Segment: c.Segment, Offset: c.Offset - 1}); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Ack before the acknowledged position = %v, want ErrCursor", err)
	}
	if _, err := s.Reader(c); err != nil {
		t.Errorf("Reader at the acknowledged position = %v", err)
	}
}

// TestAReaderStartsAtTheAcknowledgedPosition: a reader created at a later
// boundary could acknowledge records another reader delivered and nobody
// exported, so only the acknowledged position is a start.
func TestAReaderStartsAtTheAcknowledgedPosition(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	for i := 1; i <= 3; i++ {
		mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i))
	}
	first := reader(t, s)
	cursors := deliveredCursors(t, first, 3)
	for i, c := range cursors {
		if _, err := s.Reader(c); !errors.Is(err, spool.ErrCursor) {
			t.Errorf("Reader at the boundary after record %d, nothing acknowledged = %v, want ErrCursor", i+1, err)
		}
	}
	if _, err := s.Reader(spool.Cursor{Segment: 1}); err != nil {
		t.Errorf("Reader at the acknowledged position named in full = %v", err)
	}
	if err := first.Ack(cursors[0]); err != nil {
		t.Fatal(err)
	}
	second, err := s.Reader(cursors[0])
	if err != nil {
		t.Fatalf("Reader at the new acknowledged position = %v", err)
	}
	expectRecords(t, second, []*controlv1.Event{
		event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 2),
		event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 3),
	})
	if _, err := s.Reader(cursors[1]); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Reader past the new acknowledged position = %v, want ErrCursor", err)
	}
}

// TestAReaderAcknowledgesOnlyWhatItDelivered: a cursor that names a real
// record boundary in the log, handed out by another reader, is still refused
// past what this reader delivered.
func TestAReaderAcknowledgesOnlyWhatItDelivered(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	for i := 1; i <= 3; i++ {
		mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i))
	}
	slow, fast := reader(t, s), reader(t, s)
	deliveredCursors(t, slow, 1)
	third := deliveredCursors(t, fast, 3)[2]
	if err := slow.Ack(third); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Ack of record 3 by a reader that delivered record 1 = %v, want ErrCursor", err)
	}
	if st := stats(t, s); st.Unacknowledged != st.Bytes {
		t.Errorf("a refused Ack released evidence: %+v", st)
	}
}

// TestRewindDeliversAgainWhatNobodyAcknowledged: a reader that delivered and
// was not acknowledged starts over from the acknowledged position.
func TestRewindDeliversAgainWhatNobodyAcknowledged(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	var want []*controlv1.Event
	for i := 1; i <= 3; i++ {
		ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i)
		mustAppend(t, s, ev)
		want = append(want, ev)
	}
	r := reader(t, s)
	cursors := deliveredCursors(t, r, 2)
	if err := r.Ack(cursors[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.Rewind(); err != nil {
		t.Fatal(err)
	}
	expectRecords(t, r, want[1:])
	var zero spool.Reader
	if err := zero.Rewind(); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("Rewind on the zero reader = %v, want ErrClosed", err)
	}
}

func TestARecordLargerThanTheBudgetIsFull(t *testing.T) {
	ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", 1)
	size := recordSize(t, ev)
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: size - 1, SegmentBytes: size - 1})
	if err := s.Append(context.Background(), ev); !errors.Is(err, spool.ErrFull) {
		t.Errorf("Append of a record one byte over the budget = %v, want ErrFull", err)
	}
	s = open(t, spool.Options{Dir: t.TempDir(), MaxBytes: size, SegmentBytes: size})
	mustAppend(t, s, ev)
	if err := s.Append(context.Background(), nil); !errors.Is(err, evidence.ErrNoEvent) {
		t.Errorf("Append(nil) = %v, want ErrNoEvent", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Append(ctx, ev); !errors.Is(err, context.Canceled) {
		t.Errorf("Append under a cancelled context = %v, want Canceled", err)
	}
}

func TestSeveralAppendersAndOneReader(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 4 << 10})
	const writers, each = 8, 25
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				ev := event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-"+strconv.Itoa(w), i)
				if err := s.Append(context.Background(), ev); err != nil {
					t.Errorf("Append: %v", err)
				}
			}
		}()
	}
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	var last spool.Cursor
	for range writers * each {
		ev, c, err := r.Next(contextWithin(t, 5*time.Second))
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		seen[ev.GetRequestId()]++
		last = c
	}
	wg.Wait()
	for w := range writers {
		if seen["req-"+strconv.Itoa(w)] != each {
			t.Errorf("writer %d delivered %d records, want %d", w, seen["req-"+strconv.Itoa(w)], each)
		}
	}
	if err := r.Ack(last); err != nil {
		t.Fatal(err)
	}
	if st := stats(t, s); st.Bytes != 0 {
		t.Errorf("Stats after acknowledging everything = %+v", st)
	}
}

// Helpers.

func open(t *testing.T, opts spool.Options) *spool.Spool {
	t.Helper()
	s, err := spool.Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustAppend(t *testing.T, s *spool.Spool, ev *controlv1.Event) {
	t.Helper()
	if err := s.Append(context.Background(), ev); err != nil {
		t.Fatalf("Append %s: %v", ev.GetEventId(), err)
	}
}

func stats(t *testing.T, s *spool.Spool) spool.Stats {
	t.Helper()
	st, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	return st
}

func event(kind controlv1.EventKind, request string, n int) *controlv1.Event {
	return &controlv1.Event{
		EventId:       "evt-" + strconv.Itoa(n),
		Kind:          kind,
		RequestId:     request,
		RunId:         "run-1",
		ProjectId:     "proj-1",
		TenantId:      "tenant-1",
		SchemaVersion: evidence.SchemaVersion,
	}
}

// recordSize is what one event costs on disk: its JSONL line and the eight
// byte header the format puts before it.
func recordSize(t *testing.T, ev *controlv1.Event) int64 {
	t.Helper()
	var line bytes.Buffer
	if err := evidence.EncodeJSONL(&line, []*controlv1.Event{ev}); err != nil {
		t.Fatal(err)
	}
	return int64(line.Len()) + 8
}

func reader(t *testing.T, s *spool.Spool) *spool.Reader {
	t.Helper()
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	return r
}

// expectRecords reads exactly want from r, in order, and then nothing; it
// returns the cursor past the last one.
func expectRecords(t *testing.T, r *spool.Reader, want []*controlv1.Event) spool.Cursor {
	t.Helper()
	var last spool.Cursor
	for i, ev := range want {
		got, c, err := r.Next(contextWithin(t, 5*time.Second))
		if err != nil {
			t.Fatalf("Next %d: %v", i, err)
		}
		if !proto.Equal(got, ev) {
			t.Errorf("record %d = %v, want %v", i, got, ev)
		}
		if !cursorAfter(c, last) {
			t.Errorf("cursor %d = %+v does not follow %+v", i, c, last)
		}
		last = c
	}
	if ev, _, err := r.Next(contextWithin(t, 20*time.Millisecond)); ev != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Next past the end = %v, %v; want nil, DeadlineExceeded", ev, err)
	}
	return last
}

func deliveredCursors(t *testing.T, r *spool.Reader, n int) []spool.Cursor {
	t.Helper()
	var cursors []spool.Cursor
	for range n {
		_, c, err := r.Next(contextWithin(t, 5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		cursors = append(cursors, c)
	}
	return cursors
}

func cursorAfter(c, prev spool.Cursor) bool {
	return c.Segment > prev.Segment || (c.Segment == prev.Segment && c.Offset > prev.Offset)
}

func contextWithin(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func segmentNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".seg") {
			names = append(names, e.Name())
		}
	}
	return names
}

// TestTheMarkOfWhatWasDeliveredBoundsAck: the reader remembers the furthest it
// delivered to, and a Rewind does not lower it, so an acknowledgement of what
// it delivered still goes through while one past that is refused.
func TestTheMarkOfWhatWasDeliveredBoundsAck(t *testing.T) {
	s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	for i := 1; i <= 3; i++ {
		mustAppend(t, s, event(controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, "req-1", i))
	}
	r := reader(t, s)
	cursors := deliveredCursors(t, r, 2)
	if err := r.Rewind(); err != nil {
		t.Fatal(err)
	}
	// A reader that delivered two records may acknowledge them after a Rewind:
	// the mark says it delivered them, whatever its position is now.
	if err := r.Ack(cursors[1]); err != nil {
		t.Fatalf("Ack of the second record after a Rewind = %v", err)
	}
	// The third was never delivered by this reader, by any position.
	other := reader(t, s)
	third := deliveredCursors(t, other, 1)[0]
	if err := r.Ack(third); !errors.Is(err, spool.ErrCursor) {
		t.Errorf("Ack of a record this reader never delivered = %v, want ErrCursor", err)
	}
	if st := stats(t, s); st.Segments != 1 {
		t.Errorf("Stats = %+v, want the third record still held", st)
	}
}

// TestAReserveAtTheTypesLimitIsFull: a closing reserve as large as the budget
// cannot be held beside the record that asks for it, even where the sum of
// the two does not fit in an int64.
func TestAReserveAtTheTypesLimitIsFull(t *testing.T) {
	for name, limit := range map[string]int64{"2^62": 1 << 62, "MaxInt64": math.MaxInt64} {
		t.Run(name, func(t *testing.T) {
			s := open(t, spool.Options{Dir: t.TempDir(), MaxBytes: limit, SegmentBytes: 1 << 20, ClosingReserve: limit})
			err := s.Append(context.Background(), event(controlv1.EventKind_EVENT_KIND_ACTION_STARTED, "req-1", 1))
			if !errors.Is(err, spool.ErrFull) {
				t.Fatalf("ACTION_STARTED with a reserve of the whole budget = %v, want ErrFull", err)
			}
		})
	}
}
