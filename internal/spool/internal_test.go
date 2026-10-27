package spool

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// countingFile is the file seam with the sync calls counted; the bytes go to
// a real file so readers see them.
type countingFile struct {
	*os.File
	syncs  *atomic.Int64
	failOn func() error
}

func (f *countingFile) Sync() error {
	f.syncs.Add(1)
	if f.failOn != nil {
		if err := f.failOn(); err != nil {
			return err
		}
	}
	return f.File.Sync()
}

// firstSegmentPath is where the spool keeps its first segment under dir.
func firstSegmentPath(dir string) string {
	return filepath.Join(dir, segmentFileName(1))
}

func countingOpener(syncs *atomic.Int64, failOn func() error) func(*os.Root, string, int) (segmentFile, error) {
	return func(root *os.Root, name string, flag int) (segmentFile, error) {
		f, err := root.OpenFile(name, flag, 0o600)
		if err != nil {
			return nil, err
		}
		return &countingFile{File: f, syncs: syncs, failOn: failOn}, nil
	}
}

func sample(n int) *controlv1.Event {
	return &controlv1.Event{EventId: "evt-" + strconv.Itoa(n), Kind: controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, RequestId: "req", PrevEventId: strconv.Itoa(n)}
}

// TestFsyncEveryRecordSyncsOncePerAppend observes the policy through the
// file's own calls rather than assuming it.
func TestFsyncEveryRecordSyncsOncePerAppend(t *testing.T) {
	var syncs atomic.Int64
	s, err := Open(Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16, openFile: countingOpener(&syncs, nil)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertions are above
	for i := range 3 {
		if err := s.Append(context.Background(), sample(i)); err != nil {
			t.Fatal(err)
		}
		if got := syncs.Load(); got != int64(i+1) {
			t.Fatalf("after %d appends the file saw %d syncs, want one per append", i+1, got)
		}
	}
}

// TestFsyncIntervalSyncsOnTheTimerOnly: appends never sync, the tick does,
// and Close syncs whatever no tick reached. The first half's interval is too
// long to tick during the test, so a slow append cannot pass for the timer.
func TestFsyncIntervalSyncsOnTheTimerOnly(t *testing.T) {
	open := func(t *testing.T, interval time.Duration, syncs *atomic.Int64) *Spool {
		t.Helper()
		s, err := Open(Options{
			Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16,
			Fsync: FsyncInterval, Interval: interval,
			openFile: countingOpener(syncs, nil),
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("appends and Close", func(t *testing.T) {
		var syncs atomic.Int64
		s := open(t, time.Hour, &syncs)
		for i := range 3 {
			if err := s.Append(context.Background(), sample(i)); err != nil {
				t.Fatal(err)
			}
		}
		if got := syncs.Load(); got != 0 {
			t.Fatalf("under FsyncInterval the appends synced %d times with no tick", got)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if syncs.Load() == 0 {
			t.Error("Close synced nothing of three appends no tick reached")
		}
	})
	t.Run("the tick", func(t *testing.T) {
		var syncs atomic.Int64
		s := open(t, 40*time.Millisecond, &syncs)
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
		if err := s.Append(context.Background(), sample(0)); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for syncs.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if syncs.Load() == 0 {
			t.Fatal("no sync within two seconds of a 40ms interval")
		}
	})
}

// TestASyncFailureUnderTheTimerRefusesEverything: which records reached the
// disk is unknown after it, so the spool stops rather than guesses.
func TestASyncFailureUnderTheTimerRefusesEverything(t *testing.T) {
	var syncs atomic.Int64
	boom := errors.New("disk gone")
	s, err := Open(Options{
		Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16,
		Fsync: FsyncInterval, Interval: 10 * time.Millisecond,
		openFile: countingOpener(&syncs, func() error { return boom }),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the failure is the point
	if err := s.Append(context.Background(), sample(0)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := s.Append(context.Background(), sample(1)); errors.Is(err, boom) {
			if _, err := s.Reader(Cursor{}); !errors.Is(err, boom) {
				t.Errorf("Reader after the sync failure = %v, want the failure", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("appends kept succeeding after the timer's sync failed")
}

// TestASyncFailurePerRecordLeavesNoTornRecord: the record whose sync failed
// is cut back, and the cut synced, so the next append lands on a clean tail,
// and the reader never sees it.
func TestASyncFailurePerRecordLeavesNoTornRecord(t *testing.T) {
	var syncs atomic.Int64
	boom := errors.New("disk gone")
	var fail atomic.Bool
	failOn := func() error {
		if fail.CompareAndSwap(true, false) {
			return boom
		}
		return nil
	}
	s, err := Open(Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16, openFile: countingOpener(&syncs, failOn)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertions are above
	if err := s.Append(context.Background(), sample(0)); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := s.Append(context.Background(), sample(1)); !errors.Is(err, boom) {
		t.Fatalf("Append with a failing sync = %v, want the failure", err)
	}
	fail.Store(false)
	if err := s.Append(context.Background(), sample(2)); err != nil {
		t.Fatalf("Append after the repair: %v", err)
	}
	if got := replayed(t, s, 2); got != "0 2" {
		t.Errorf("replayed %q, want \"0 2\": the record whose sync failed is not evidence", got)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Segments != 1 {
		t.Errorf("Stats after the repair = %+v, want the one segment continued", st)
	}
}

// replayed returns the prev_event_id of the next n records, space separated.
func replayed(t *testing.T, s *Spool, n int) string {
	t.Helper()
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for range n {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ev, _, err := r.Next(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev.GetPrevEventId())
	}
	return strings.Join(got, " ")
}

// FuzzFrame is the framing parser's target: over arbitrary bytes the scan
// neither panics nor claims more than is there, what it accepts re-frames to
// exactly the prefix it accepted, and readRecord agrees with it record by
// record.
func FuzzFrame(f *testing.F) {
	line := []byte(`{"eventId":"evt-1","kind":"EVENT_KIND_ACTION_PROPOSED","requestId":"req-1"}` + "\n")
	f.Add([]byte{})
	f.Add(frame(line))
	f.Add(append(frame(line), frame(line)...))
	f.Add(frame(line)[:5])
	f.Add(append(frame(line), 0, 0, 0, 0))
	f.Add(append(frame(line), frame(line)[:12]...))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0})
	f.Add(frame([]byte{}))
	f.Fuzz(func(t *testing.T, data []byte) {
		found, err := scan(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("scan over a byte reader: %v", err)
		}
		if found.good > int64(len(data)) || found.good < 0 {
			t.Fatalf("scan accepted %d bytes of %d", found.good, len(data))
		}
		if found.records == 0 && found.good != 0 {
			t.Fatalf("no record and %d good bytes", found.good)
		}
		var reframed []byte
		off := int64(0)
		for i := 0; i < found.records; i++ {
			line, next, err := readRecord(bytes.NewReader(data), off, found.good)
			if err != nil {
				t.Fatalf("record %d at %d: readRecord disagrees with scan: %v", i, off, err)
			}
			reframed = append(reframed, frame(line)...)
			off = next
		}
		if off != found.good {
			t.Fatalf("records end at %d, scan accepted %d", off, found.good)
		}
		if !bytes.Equal(reframed, data[:found.good]) {
			t.Fatal("re-framing the accepted records does not reproduce the accepted bytes")
		}
		if _, _, err := readRecord(bytes.NewReader(data), found.good, int64(len(data))); err == nil {
			t.Fatalf("readRecord accepted a record at %d that scan ended the log on", found.good)
		}
	})
}

// TestARollSyncsTheRetiredSegmentAndTheDirectory observes, under a timer that
// never fires, the two syncs a roll owes: the segment it leaves, before the
// next exists, and the directory entry of every segment it creates.
func TestARollSyncsTheRetiredSegmentAndTheDirectory(t *testing.T) {
	var fileSyncs, dirSyncs atomic.Int64
	s, err := Open(Options{
		Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1,
		Fsync: FsyncInterval, Interval: time.Hour,
		openFile: countingOpener(&fileSyncs, nil),
		syncDir: func(root *os.Root) error {
			dirSyncs.Add(1)
			return syncDir(root)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertions are below
	for i := range 3 {
		if err := s.Append(context.Background(), sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	// One record per segment: three segments created, two of them retired.
	if got := dirSyncs.Load(); got != 3 {
		t.Errorf("three segments created, %d directory syncs", got)
	}
	if got := fileSyncs.Load(); got != 2 {
		t.Errorf("two segments retired under FsyncInterval, %d file syncs", got)
	}
}

// TestABrokenSpoolWakesItsReaders: a reader waiting for the next record
// learns of the failure when it happens, and Stats reports it beside the
// numbers.
func TestABrokenSpoolWakesItsReaders(t *testing.T) {
	var syncs atomic.Int64
	boom := errors.New("disk gone")
	var fail atomic.Bool
	s, err := Open(Options{
		Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16,
		Fsync: FsyncInterval, Interval: 10 * time.Millisecond,
		openFile: countingOpener(&syncs, func() error {
			if fail.Load() {
				return boom
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the failure is the point
	if err := s.Append(context.Background(), sample(0)); err != nil {
		t.Fatal(err)
	}
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	woke := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err := r.Next(ctx)
		woke <- err
	}()
	time.Sleep(50 * time.Millisecond)
	fail.Store(true)
	select {
	case err := <-woke:
		if !errors.Is(err, boom) {
			t.Errorf("the waiting reader woke with %v, want the failure", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiting reader slept through the failure")
	}
	st, err := s.Stats()
	if !errors.Is(err, boom) {
		t.Errorf("Stats of a broken spool = %v, want the failure", err)
	}
	if st.Segments != 1 || st.Bytes == 0 {
		t.Errorf("Stats of a broken spool = %+v, want its numbers", st)
	}
}

// TestAFailedQuarantineIsCutBack: a quarantine append whose sync fails is
// reported, uncounted, and gone from the file, so the next one lands on the
// records that were durable.
func TestAFailedQuarantineIsCutBack(t *testing.T) {
	boom := errors.New("disk gone")
	var fail atomic.Bool
	dir := t.TempDir()
	s, r := spoolWithDelivered(t, dir, 2, func() error {
		if fail.CompareAndSwap(true, false) {
			return boom
		}
		return nil
	})
	if _, err := r.Quarantine([]*controlv1.Event{sample(0)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, quarantineName))
	if err != nil {
		t.Fatal(err)
	}
	durable := info.Size()
	fail.Store(true)
	if _, err := r.Quarantine([]*controlv1.Event{sample(1)}); !errors.Is(err, boom) {
		t.Fatalf("Quarantine with a failing sync = %v, want the failure", err)
	}
	if info, err := os.Stat(filepath.Join(dir, quarantineName)); err != nil || info.Size() != durable {
		t.Errorf("the quarantine after a failed append: %v, %v; want %d bytes", info.Size(), err, durable)
	}
	st, err := s.Stats()
	if err != nil || st.QuarantinedRecords != 1 || st.QuarantinedBytes != durable {
		t.Errorf("Stats after a failed quarantine = %+v, %v; want one record of %d bytes", st, err, durable)
	}
}

// bruteRecordAfter is the reference recordAfter is checked against: every
// offset past from, in the range a committed record can begin in, checked with
// no window and no work bound.
func bruteRecordAfter(data []byte, from int64) bool {
	size := int64(len(data))
	last := min(size, from+2*headerBytes+maxLineBytes)
	for at := from + 1; at+headerBytes <= last; at++ {
		length := int64(binary.BigEndian.Uint32(data[at:]))
		end := at + headerBytes + length
		if length == 0 || length > maxLineBytes || end > size {
			continue
		}
		if crc32.Checksum(data[at+headerBytes:end], castagnoli) == binary.BigEndian.Uint32(data[at+4:]) {
			return true
		}
	}
	return false
}

// TestRecordAfterReachesTheFurthestARecordCanBegin: an interrupted append left
// at most one record's bytes past the record that does not check, so a
// committed record behind them begins at from+headerBytes+maxLineBytes at the
// furthest. The search reaches exactly that offset.
func TestRecordAfterReachesTheFurthestARecordCanBegin(t *testing.T) {
	record := frame([]byte(`{"eventId":"evt-1","kind":"EVENT_KIND_ACTION_PROPOSED"}` + "\n"))
	furthest := int64(headerBytes + maxLineBytes)
	for _, tc := range []struct {
		name string
		at   int64
		want bool
	}{
		{"the furthest a record can begin", furthest, true},
		{"one byte past that", furthest + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 0xff bytes read as a length no record can have, so nothing but
			// the planted record checks.
			data := make([]byte, tc.at+int64(len(record)))
			for i := range data {
				data[i] = 0xff
			}
			copy(data[tc.at:], record)
			got, err := recordAfter(bytes.NewReader(data), 0, int64(len(data)))
			if err != nil {
				t.Fatalf("recordAfter over %d bytes: %v", len(data), err)
			}
			if got != tc.want {
				t.Errorf("recordAfter with a record at %d = %v, want %v", tc.at, got, tc.want)
			}
			if want := bruteRecordAfter(data, 0); got != want {
				t.Errorf("recordAfter = %v, the reference = %v", got, want)
			}
		})
	}
}

// FuzzRecordAfter holds the bounded search to the reference over arbitrary
// bytes: the same answer, no panic, and a refusal rather than unbounded work.
func FuzzRecordAfter(f *testing.F) {
	line := []byte(`{"eventId":"evt-1","kind":"EVENT_KIND_ACTION_PROPOSED"}` + "\n")
	f.Add([]byte{}, 0)
	f.Add(frame(line), 0)
	f.Add(append(frame(line), frame(line)...), 0)
	f.Add(append([]byte{1, 2, 3}, frame(line)...), 1)
	f.Add(append(frame(line)[:9], frame(line)...), 0)
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0}, 0)
	f.Fuzz(func(t *testing.T, data []byte, from int) {
		if len(data) == 0 || from < 0 || int64(from) >= int64(len(data)) {
			t.Skip("an offset outside the input leaves nothing to search")
		}
		got, err := recordAfter(bytes.NewReader(data), int64(from), int64(len(data)))
		if errors.Is(err, errTailCost) {
			return
		}
		if err != nil {
			t.Fatalf("recordAfter over %d bytes from %d: %v", len(data), from, err)
		}
		if want := bruteRecordAfter(data, int64(from)); got != want {
			t.Fatalf("recordAfter = %v, the reference = %v (%d bytes, from %d)", got, want, len(data), from)
		}
	})
}

// spoolWithDelivered opens a spool under dir whose file syncs go through
// failOn, appends n records and has one reader deliver them all, which is what
// covers a quarantine append.
func spoolWithDelivered(t *testing.T, dir string, n int, failOn func() error) (*Spool, *Reader) {
	t.Helper()
	var syncs atomic.Int64
	s, err := Open(Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16, openFile: countingOpener(&syncs, failOn)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := range n {
		if err := s.Append(context.Background(), sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		if _, _, err := r.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return s, r
}

// failingClose is the file seam with Close made to fail while fail is set.
type failingClose struct {
	segmentFile
	fail *atomic.Bool
}

func (f failingClose) Close() error {
	err := f.segmentFile.Close()
	if f.fail.Load() {
		return errors.Join(err, errors.New("close failed"))
	}
	return err
}

// TestAQuarantineCloseThatFailsBreaksTheSpool: the records are synced when the
// close fails, so they are on disk without being counted, and nothing after
// may land behind them.
func TestAQuarantineCloseThatFailsBreaksTheSpool(t *testing.T) {
	var fail atomic.Bool
	s, err := Open(Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16, openFile: func(root *os.Root, name string, flag int) (segmentFile, error) {
		f, err := openOSFile(root, name, flag)
		if err != nil {
			return nil, err
		}
		return failingClose{segmentFile: f, fail: &fail}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the close is made to fail
	if err := s.Append(context.Background(), sample(1)); err != nil {
		t.Fatal(err)
	}
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if _, err := r.Quarantine([]*controlv1.Event{sample(0)}); err == nil {
		t.Fatal("Quarantine reported a failed close as success")
	}
	fail.Store(false)
	if err := s.Append(context.Background(), sample(2)); err == nil {
		t.Error("Append after a failed quarantine close went through")
	}
}

// TestAQuarantineWhoseEntrySyncFailedIsSyncedByTheNextAppend: the file stays
// after the failed sync, so the next append does not create it, yet its
// directory entry is still not known to be on disk.
func TestAQuarantineWhoseEntrySyncFailedIsSyncedByTheNextAppend(t *testing.T) {
	var syncs, dirSyncs atomic.Int64
	var fail atomic.Bool
	s, err := Open(Options{
		Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16,
		openFile: countingOpener(&syncs, nil),
		syncDir: func(root *os.Root) error {
			dirSyncs.Add(1)
			if fail.Load() {
				return errors.New("directory sync failed")
			}
			return syncDir(root)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // the assertions are below
	for i := 1; i <= 2; i++ {
		if err := s.Append(context.Background(), sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := r.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	fail.Store(true)
	if _, err := r.Quarantine([]*controlv1.Event{sample(1)}); err == nil {
		t.Fatal("Quarantine reported a failed directory sync as success")
	}
	fail.Store(false)
	before := dirSyncs.Load()
	if _, err := r.Quarantine([]*controlv1.Event{sample(2)}); err != nil {
		t.Fatal(err)
	}
	if got := dirSyncs.Load() - before; got != 1 {
		t.Errorf("the append after a failed entry sync made %d directory syncs, want 1", got)
	}
}
