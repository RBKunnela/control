package trailfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/segmentlog"
)

// twoPerSegment is a segment bound that holds two lines of event(n) for a
// one-digit n and seals before a third.
const twoPerSegment = 2*int64(len(firstLine)) + 4

func logConfig(dir string) LogConfig {
	return LogConfig{Dir: dir, Tenant: "t1", Project: "p1", SegmentBytes: twoPerSegment, MaxBytes: 1 << 20,
		Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
}

func openTestLog(t *testing.T, cfg LogConfig) *Log {
	t.Helper()
	l, err := OpenLog(cfg)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func appendTo(t *testing.T, l *Log, events ...*controlv1.Event) {
	t.Helper()
	if err := l.Append(context.Background(), events); err != nil {
		t.Fatalf("Append = %v", err)
	}
}

// liveText is what the live segment of the log in dir holds.
func liveText(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, segmentlog.LiveName)) //nolint:gosec // G304: the test's own directory
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(raw)
}

// TestALogTakesOnlyItsTenantsAndProjectsEvents: an append holding one event
// of another project or tenant is refused whole, for good, and writes
// nothing; the same append of its own events is taken.
func TestALogTakesOnlyItsTenantsAndProjectsEvents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	other := event(2)
	other.ProjectId = "p2"
	tenant := event(3)
	tenant.TenantId = "t2"
	for _, ev := range []*controlv1.Event{other, tenant} {
		err := l.Append(context.Background(), []*controlv1.Event{event(1), ev})
		if !errors.Is(err, ErrBinding) || !errors.Is(err, otel.ErrSinkRefused) {
			t.Errorf("an append with %s/%s: %v, want ErrBinding and ErrSinkRefused", ev.GetTenantId(), ev.GetProjectId(), err)
		}
	}
	if got := liveText(t, dir); got != "" {
		t.Errorf("a refused append wrote %q", got)
	}
	appendTo(t, l, event(1), event(2))
	if got := liveText(t, dir); got != lines(t, event(1), event(2)) {
		t.Errorf("the live segment holds %q", got)
	}
}

// TestAResendAcrossASealIsWrittenOnce: an event sent again after its segment
// was sealed is not written again, before and after a reopen, and its id
// with other content is a conflict wherever the line is.
func TestAResendAcrossASealIsWrittenOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	cfg := logConfig(dir)
	l := openTestLog(t, cfg)
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3))
	if m := l.Manifest(); len(m.Segments) != 1 {
		t.Fatalf("no seal before the third line: %+v", m)
	}
	appendTo(t, l, event(1))
	if got := liveText(t, dir); got != lines(t, event(3)) {
		t.Errorf("a resend across the seal was written: the live segment holds %q", got)
	}
	changed := event(1)
	changed.RunId = "other"
	if err := l.Append(context.Background(), []*controlv1.Event{changed}); !errors.Is(err, ErrConflict) {
		t.Errorf("e1 with other content: %v, want ErrConflict", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = openTestLog(t, cfg)
	appendTo(t, l, event(2), event(3))
	if got := liveText(t, dir); got != lines(t, event(3)) {
		t.Errorf("a resend after a reopen was written: the live segment holds %q", got)
	}
}

// TestALogHoldingAnotherProjectsLineIsRefusedAtOpen: a line of another
// project in a segment is no line this log writes, so the open is refused.
func TestALogHoldingAnotherProjectsLineIsRefusedAtOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1))
	_ = l.Close()
	other := event(2)
	other.ProjectId = "p2"
	f, err := os.OpenFile(filepath.Join(dir, segmentlog.LiveName), os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(lines(t, other)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := OpenLog(logConfig(dir)); !errors.Is(err, ErrBinding) || !errors.Is(err, ErrDamaged) {
		t.Errorf("OpenLog = %v, want ErrDamaged and ErrBinding", err)
	}
}

// exportIDs is the event ids an export of the log in dir after cursor
// writes, the trailer's next cursor and the file the header names.
func exportIDs(t *testing.T, dir, cursor string, limit int) ([]string, string, string) {
	t.Helper()
	var out bytes.Buffer
	if _, err := ExportLog(dir, Query{After: cursor, Limit: limit}, &out); err != nil {
		t.Fatalf("ExportLog after %q: %v", cursor, err)
	}
	header, body, trailer := frame(t, out.String())
	var ids []string
	for _, r := range body {
		if r.Type != "event" {
			t.Fatalf("a %s record in a log's export: %s", r.Type, out.String())
		}
		var ev struct{ EventID string }
		if err := json.Unmarshal(r.Event, &ev); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, ev.EventID)
	}
	return ids, trailer.NextCursor, filepath.Base(header.File)
}

// drain exports the log from cursor at limit records each, until an export
// writes nothing, and returns every id written and the cursor it ends at.
func drain(t *testing.T, dir, cursor string, limit int) ([]string, string) {
	t.Helper()
	var all []string
	for range 100 {
		ids, next, _ := exportIDs(t, dir, cursor, limit)
		if len(ids) == 0 {
			return all, cursor
		}
		all, cursor = append(all, ids...), next
	}
	t.Fatal("an export never ran dry")
	return nil, ""
}

func ids(from, to int) []string {
	var out []string
	for n := from; n <= to; n++ {
		out = append(out, "e"+strconv.Itoa(n))
	}
	return out
}

// TestAnExportInterruptedAtEveryRecordResumes: exports of a log of several
// segments, cut at every limit from one record up and resumed from each
// trailer's cursor, write every event once and in order, across every seal;
// events written between the exports, sealing the live segment, follow
// them.
func TestAnExportInterruptedAtEveryRecordResumes(t *testing.T) {
	for limit := 1; limit <= 6; limit++ {
		dir := filepath.Join(t.TempDir(), "log")
		l := openTestLog(t, logConfig(dir))
		for n := 1; n <= 5; n++ {
			appendTo(t, l, event(n))
		}
		got, cursor := drain(t, dir, "", limit)
		if !slices.Equal(got, ids(1, 5)) {
			t.Fatalf("limit %d: the exports wrote %v", limit, got)
		}
		for n := 6; n <= 9; n++ {
			appendTo(t, l, event(n))
		}
		more, _ := drain(t, dir, cursor, limit)
		if !slices.Equal(more, ids(6, 9)) {
			t.Errorf("limit %d: after the next appends the exports wrote %v", limit, more)
		}
		_ = l.Close()
	}
}

// TestACursorAtTheEndOfASealedSegmentWaitsForTheNext: at the end of a sealed
// segment with an empty live one after it, an export writes nothing and
// keeps the cursor, and once the live segment holds a line it moves there.
func TestACursorAtTheEndOfASealedSegmentWaitsForTheNext(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	cfg := logConfig(dir)
	l := openTestLog(t, cfg)
	appendTo(t, l, event(1), event(2))
	rl := l.rl
	if err := rl.Seal(); err != nil {
		t.Fatal(err)
	}
	got, cursor, file := exportIDs(t, dir, "", 10)
	if !slices.Equal(got, ids(1, 2)) || file != "segment-00000001.jsonl" {
		t.Fatalf("the first export wrote %v from %s", got, file)
	}
	again, next, file := exportIDs(t, dir, cursor, 10)
	if len(again) != 0 || next != cursor || file != "segment-00000001.jsonl" {
		t.Errorf("at the end with nothing after: %v, cursor %q from %s, want nothing and the same cursor", again, next, file)
	}
	appendTo(t, l, event(3))
	if after, _, file := exportIDs(t, dir, cursor, 10); !slices.Equal(after, ids(3, 3)) || file != segmentlog.LiveName {
		t.Errorf("once the live segment holds a line: %v from %s", after, file)
	}
}

// TestAnExpiredOrForeignCursorIsRefused: a cursor of a pruned segment is
// ErrCursorExpired, one of a file not in the log ErrCursorOtherFile, one not
// spelled as a cursor ErrCursorMalformed, and none of them writes a byte.
func TestAnExpiredOrForeignCursorIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3), event(4))
	appendTo(t, l, event(5))
	_, inFirst, _ := exportIDs(t, dir, "", 1)
	other := cursorAfter(file(lineE1, lineE2), 1)
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	for cursor, want := range map[string]error{inFirst: ErrCursorExpired, other: ErrCursorOtherFile, "v1:x": ErrCursorMalformed} {
		var out bytes.Buffer
		if _, err := ExportLog(dir, Query{After: cursor, Limit: 10}, &out); !errors.Is(err, want) || out.Len() != 0 {
			t.Errorf("after %q: %v and %d bytes, want %v and nothing", cursor, err, out.Len(), want)
		}
	}
	if got, _ := drain(t, dir, "", 10); !slices.Equal(got, ids(3, 5)) {
		t.Errorf("from the start after the prune the exports wrote %v", got)
	}
}

// TestASealOrAPruneUnderAnOpenExportCompletesFromItsDescriptor: a segment an
// export opened, then sealed and then pruned before a byte of it was read,
// is exported whole from the descriptor.
func TestASealOrAPruneUnderAnOpenExportCompletesFromItsDescriptor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	src, after, done, err := openForExport(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = done() }()
	appendTo(t, l, event(3))
	appendTo(t, l, event(4), event(5))
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := export(src, Query{Limit: 10}, after, &out); err != nil {
		t.Fatal(err)
	}
	_, body, trailer := frame(t, out.String())
	if len(body) != 2 || trailer.EndReached == nil || !*trailer.EndReached {
		t.Errorf("the export read through its descriptor: %s", out.String())
	}
}

// TestReadingALogReadsEverySegmentNotPruned: the trail read of a log is the
// read of its segments not pruned, in order, and says when a writer holds
// the live segment with a line part written.
func TestReadingALogReadsEverySegmentNotPruned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	evs := chain("p1", "r1", kindProposed, kindDecided, kindStarted, kindCompleted)
	appendTo(t, l, evs[0], evs[1])
	appendTo(t, l, evs[2], evs[3])
	rep, err := ReadPath(dir, DefaultMaxLines)
	if err != nil || rep.Lines != 4 || len(rep.Trails) != 1 || rep.Trails[0].Verdict != Passed {
		t.Fatalf("ReadPath = %+v, %v", rep, err)
	}
	logBytesAreBounded(t, dir, lines(t, evs...))
	appendLive(t, dir, partialTail)
	if rep, err := ReadPath(dir, DefaultMaxLines); err != nil || rep.Unread != int64(len(partialTail)) || !rep.Held {
		t.Errorf("with a line part written: %+v, %v", rep, err)
	}
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	if rep, err := ReadPath(dir, DefaultMaxLines); err != nil || rep.Lines != 2 || rep.Trails[0].Verdict != Failed {
		t.Errorf("after the prune: %+v, %v; want the rest of the trail, failing the chain check", rep, err)
	}
}

// appendLive writes text at the end of the live segment of the log in dir,
// past its writer.
func appendLive(t *testing.T, dir, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, segmentlog.LiveName), os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// logBytesAreBounded checks LogBytes reads the log in dir as want, and
// refuses it one byte under its size.
func logBytesAreBounded(t *testing.T, dir, want string) {
	t.Helper()
	raw, err := LogBytes(dir, 1<<20)
	if err != nil || string(raw) != want {
		t.Errorf("LogBytes = %q, %v", raw, err)
	}
	if _, err := LogBytes(dir, int64(len(want))-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("LogBytes one byte under the log: %v, want ErrTooLarge", err)
	}
	if _, err := LogBytes(dir, int64(len(want))); err != nil {
		t.Errorf("LogBytes at the log's size: %v", err)
	}
}

// exportTrailer is the trailer of an export of the log in dir after cursor at
// limit records, and the event ids it wrote.
func exportTrailer(t *testing.T, dir, cursor string, limit int) ([]string, record) {
	t.Helper()
	var out bytes.Buffer
	if _, err := ExportLog(dir, Query{After: cursor, Limit: limit}, &out); err != nil {
		t.Fatalf("ExportLog after %q: %v", cursor, err)
	}
	_, body, trailer := frame(t, out.String())
	var got []string
	for _, r := range body {
		var ev struct{ EventID string }
		if err := json.Unmarshal(r.Event, &ev); err != nil {
			t.Fatal(err)
		}
		got = append(got, ev.EventID)
	}
	return got, trailer
}

// TestFollowingNextCursorUntilTheEndReadsEveryLineOnce: a reader that
// follows next_cursor until end_reached, as the contract says, reads every
// line of every segment once and in order; end_reached is false at the end of
// a sealed segment a later one follows, and true only at the log's end.
func TestFollowingNextCursorUntilTheEndReadsEveryLineOnce(t *testing.T) {
	for limit := 1; limit <= 6; limit++ {
		dir := filepath.Join(t.TempDir(), "log")
		l := openTestLog(t, logConfig(dir))
		for n := 1; n <= 7; n++ {
			appendTo(t, l, event(n))
		}
		var all []string
		cursor := ""
		for range 100 {
			got, tr := exportTrailer(t, dir, cursor, limit)
			all = append(all, got...)
			cursor = tr.NextCursor
			if *tr.EndReached {
				break
			}
		}
		if !slices.Equal(all, ids(1, 7)) {
			t.Errorf("limit %d: following until the end read %v", limit, all)
		}
		if _, tr := exportTrailer(t, dir, "", 1000); *tr.EndReached {
			t.Errorf("limit %d: the first segment's export says the end of a log of four segments was reached", limit)
		}
		_ = l.Close()
	}
}

// TestALiveSegmentSealedBetweenAViewAndItsOpenIsMoved: a view taken while the
// live segment held no line does not open the live segment a seal made
// since, and an export started then reads the sealed segment first.
func TestALiveSegmentSealedBetweenAViewAndItsOpenIsMoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	v, err := segmentlog.Inspect(dir, evidence.MaxLineBytes)
	if err != nil {
		t.Fatal(err)
	}
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3))
	if m := l.Manifest(); len(m.Segments) != 1 {
		t.Fatalf("want one sealed segment, got %+v", m)
	}
	if _, _, _, err := openSource(dir, v, v.First().Segment(), ""); !errors.Is(err, segmentlog.ErrMoved) {
		t.Errorf("the live segment after a seal opened under the old view: %v, want ErrMoved", err)
	}
	if got, _ := drain(t, dir, "", 100); !slices.Equal(got, ids(1, 3)) {
		t.Errorf("an export begun after the seal read %v", got)
	}
}

// TestTwoSegmentsBeginningWithOneLineKeepTheirCursorsApart: an event with no
// id written first in two segments gives each its own key, so a reader moves
// on from the first to the second and reads every line once.
func TestTwoSegmentsBeginningWithOneLineKeepTheirCursorsApart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	noID := event(9)
	noID.EventId = ""
	appendTo(t, l, noID)
	appendTo(t, l, event(1))
	appendTo(t, l, noID)
	appendTo(t, l, event(2))
	if m := l.Manifest(); len(m.Segments) != 1 || m.Segments[0].First != m.Live.First {
		t.Fatalf("want two segments beginning with one line, got %+v", m)
	}
	if got, _ := drain(t, dir, "", 1); !slices.Equal(got, []string{"", "e1", "", "e2"}) {
		t.Errorf("following the two segments read %q", got)
	}
}

// TestACursorAtASegmentsEndNamesItsLastLine: a cursor at the end of a sealed
// segment a later one follows moves on only when its line digest is that of
// the segment's last line; with another it is refused as changed and writes
// nothing.
func TestACursorAtASegmentsEndNamesItsLastLine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	for n := 1; n <= 5; n++ {
		appendTo(t, l, event(n))
	}
	_, cursor, file := exportIDs(t, dir, "", 1000)
	parts := strings.Split(cursor, ":")
	if len(parts) != 4 || file != "segment-00000001.jsonl" {
		t.Fatalf("the first export ended at %q in %s", cursor, file)
	}
	forged := strings.Join([]string{parts[0], parts[1], parts[2], strings.Repeat("0", 64)}, ":")
	var out bytes.Buffer
	if _, err := ExportLog(dir, Query{After: forged, Limit: 1000}, &out); !errors.Is(err, ErrCursorChanged) || out.Len() != 0 {
		t.Errorf("a cursor at the segment's end naming another line: %v and %d bytes, want ErrCursorChanged and nothing", err, out.Len())
	}
	if got, _, _ := exportIDs(t, dir, cursor, 1000); !slices.Equal(got, ids(3, 4)) {
		t.Errorf("the cursor the export gave moved on to %v, want e3 and e4", got)
	}
}

// TestALiveSegmentOpensInTheDirectoryTheLogHolds: after a seal, the next live
// segment is made in the directory the log locked, though another directory
// was put at its path since.
func TestALiveSegmentOpensInTheDirectoryTheLogHolds(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1))
	if err := l.rl.Seal(); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	appendTo(t, l, event(2))
	if _, err := os.Stat(filepath.Join(dir, segmentlog.LiveName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a live segment at the path swapped in: %v, want none", err)
	}
	if got := liveText(t, moved); got != lines(t, event(2)) {
		t.Errorf("the locked directory's live segment holds %q, want event 2", got)
	}
}

// TestALogWhoseLiveFileChangedTakesNothingMore: once an append finds the live
// segment changed under the writer, the log seals, prunes and appends nothing
// more, so it writes no manifest that disagrees with the file, and the log
// opened again holds what the file holds.
func TestALogWhoseLiveFileChangedTakesNothingMore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	cfg := logConfig(dir)
	l := openTestLog(t, cfg)
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3))
	appendLive(t, dir, lines(t, event(4)))
	if err := l.Append(context.Background(), []*controlv1.Event{event(5)}); !errors.Is(err, ErrChanged) {
		t.Fatalf("an append after the live file changed = %v, want ErrChanged", err)
	}
	big := event(6)
	big.RequestId = strings.Repeat("r", int(twoPerSegment))
	for name, step := range map[string]func() error{
		"an append that seals": func() error { return l.Append(context.Background(), []*controlv1.Event{big}) },
		"an append":            func() error { return l.Append(context.Background(), []*controlv1.Event{event(7)}) },
		"a prune":              func() error { return l.Prune(1) },
	} {
		if err := step(); !errors.Is(err, segmentlog.ErrFailed) {
			t.Errorf("%s after the live file changed = %v, want segmentlog.ErrFailed", name, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	want := lines(t, event(3), event(4))
	if got := liveText(t, dir); got != want {
		t.Errorf("the live segment holds %q, want %q", got, want)
	}
	again := openTestLog(t, cfg)
	if m := again.Manifest(); len(m.Segments) != 1 || m.Segments[0].State != segmentlog.StateSealed || m.Live.Lines != 2 {
		t.Errorf("opened again the log is %+v, want segment 1 sealed and two live lines", m)
	}
}

// TestAnEventResentAfterItsSegmentWasPrunedIsWrittenAgain: the index covers
// the segments not pruned, so on the same open log an event whose only line
// was pruned is written again, and one still held is not.
func TestAnEventResentAfterItsSegmentWasPrunedIsWrittenAgain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3))
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	appendTo(t, l, event(1), event(3))
	if got, want := liveText(t, dir), lines(t, event(3), event(1)); got != want {
		t.Errorf("after the resend the live segment holds %q, want %q", got, want)
	}
}

// stopAtRename leaves the log in dir as a seal stopped between its manifest
// and its rename leaves it: the manifest names segment seq sealed, its file
// is not there, and live.jsonl holds its bytes.
func stopAtRename(t *testing.T, dir string, seq int) {
	t.Helper()
	sealed := filepath.Join(dir, fmt.Sprintf("segment-%08d.jsonl", seq))
	if err := os.Remove(filepath.Join(dir, segmentlog.LiveName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(sealed, filepath.Join(dir, segmentlog.LiveName)); err != nil {
		t.Fatal(err)
	}
}

// TestAnExportInASealsStoppedRenameIsRefused: an export after a cursor at the
// end of a segment a seal named sealed and has not renamed would read its
// bytes again as the next live segment, so it is refused as moved, writing
// nothing; the log opened again completes the seal, and the export moves on.
func TestAnExportInASealsStoppedRenameIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	cfg := logConfig(dir)
	l := openTestLog(t, cfg)
	appendTo(t, l, event(1), event(2))
	got, cursor, _ := exportIDs(t, dir, "", 10)
	if !slices.Equal(got, ids(1, 2)) {
		t.Fatalf("the first export wrote %v", got)
	}
	appendTo(t, l, event(3))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	stopAtRename(t, dir, 1)
	var out bytes.Buffer
	if _, err := ExportLog(dir, Query{After: cursor, Limit: 10}, &out); !errors.Is(err, segmentlog.ErrMoved) || out.Len() != 0 {
		t.Errorf("an export at the end of a segment whose rename stopped: %v and %d bytes, want ErrMoved and nothing", err, out.Len())
	}
	_ = openTestLog(t, cfg).Close()
	if after, _, file := exportIDs(t, dir, cursor, 10); len(after) != 0 || file != "segment-00000001.jsonl" {
		t.Errorf("after the seal was completed: %v from %s, want nothing more after the cursor", after, file)
	}
}

// TestAnIndexThatCannotBeReadAfterAPruneFailsTheLog: the append after a
// prune reads the segments left into the index first; when that read fails,
// the append is refused, saying the prune completed, nothing is written and
// the log takes nothing more.
func TestAnIndexThatCannotBeReadAfterAPruneFailsTheLog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3), event(4))
	appendTo(t, l, event(5))
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "segment-00000002.jsonl")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{6, 7} {
		err := l.Append(context.Background(), []*controlv1.Event{event(n)})
		if !errors.Is(err, segmentlog.ErrFailed) || !strings.Contains(err.Error(), "the prune completed") {
			t.Errorf("append %d after the index could not be read: %v, want segmentlog.ErrFailed saying the prune completed", n, err)
		}
	}
	if got, want := liveText(t, dir), lines(t, event(5)); got != want {
		t.Errorf("the live segment holds %q, want %q", got, want)
	}
}

// TestAnAppendThatSealsALiveFileChangedUnderItIsRefused: the first append
// after the live segment was extended under the writer, one that needs a
// seal, seals nothing and fails the log, so no manifest names the changed
// file with the counts the log held; the log opened again holds the file.
func TestAnAppendThatSealsALiveFileChangedUnderItIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	cfg := logConfig(dir)
	l := openTestLog(t, cfg)
	appendTo(t, l, event(1), event(2))
	appendLive(t, dir, lines(t, event(3)))
	if err := l.Append(context.Background(), []*controlv1.Event{event(4)}); !errors.Is(err, segmentlog.ErrFailed) {
		t.Errorf("a sealing append after the live file changed = %v, want segmentlog.ErrFailed", err)
	}
	if n := len(l.Manifest().Segments); n != 0 {
		t.Errorf("the log sealed %d segment(s) over the changed file, want none", n)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if m := openTestLog(t, cfg).Manifest(); len(m.Segments) != 0 || m.Live.Lines != 3 {
		t.Errorf("opened again the log is %+v, want three live lines", m)
	}
}

// TestADuplicateAfterTheLogFailedIsRefused: once an append failed the log, an
// append whose events the index holds is refused too, not taken as written.
func TestADuplicateAfterTheLogFailedIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1))
	if err := os.Truncate(filepath.Join(dir, segmentlog.LiveName), 0); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(context.Background(), []*controlv1.Event{event(2)}); !errors.Is(err, segmentlog.ErrFailed) {
		t.Fatalf("an append after the live file was cut = %v, want segmentlog.ErrFailed", err)
	}
	if err := l.Append(context.Background(), []*controlv1.Event{event(1)}); !errors.Is(err, segmentlog.ErrFailed) {
		t.Errorf("a resend of an event the cut file lost = %v, want segmentlog.ErrFailed", err)
	}
}

// TestAnIndexAfterAPruneIsNotReadFromAnotherDirectory: a directory put at the
// log's path after a prune, holding an event the log does not, is not read
// into the index, so that event sent to the log is not taken as written.
func TestAnIndexAfterAPruneIsNotReadFromAnotherDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3), event(4))
	appendTo(t, l, event(5))
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "other")
	b := openTestLog(t, logConfig(other))
	appendTo(t, b, event(6))
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, dir); err != nil {
		t.Fatal(err)
	}
	err := l.Append(context.Background(), []*controlv1.Event{event(6)})
	if got := liveText(t, moved); err == nil && got != lines(t, event(5), event(6)) {
		t.Errorf("the append after the directory was replaced = nil, and the log's live segment holds %q: event 6 taken as written", got)
	}
}
