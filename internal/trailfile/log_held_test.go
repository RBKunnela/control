package trailfile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/segmentlog"
)

// firstSegment is the file of the first sealed segment of a log.
const firstSegment = "segment-00000001.jsonl"

// sealedLog is a log holding events 1 and 2 in its first segment, sealed,
// and event 3 in its live one.
func sealedLog(t *testing.T) (*Log, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	appendTo(t, l, event(3))
	if m := l.Manifest(); len(m.Segments) != 1 || m.Live.Lines != 1 {
		t.Fatalf("want one sealed segment of two lines and a live one of one, got %+v", m)
	}
	return l, dir
}

// refusedRepeat checks an append of events, which repeats one the log
// indexed, is refused as a failure of the log, and writes nothing.
func refusedRepeat(t *testing.T, l *Log, dir, what string, events ...*controlv1.Event) {
	t.Helper()
	live := liveText(t, dir)
	if err := l.Append(context.Background(), events); !errors.Is(err, segmentlog.ErrFailed) {
		t.Errorf("%s = %v, want segmentlog.ErrFailed", what, err)
	}
	if got := liveText(t, dir); got != live {
		t.Errorf("%s wrote to the live segment: %q", what, got)
	}
}

// TestARepeatWhoseSealedSegmentWasRemovedIsRefused: a sealed segment removed
// under the log, a resend of an event only it held is refused, failing the
// log, and the event beside it is not written either.
func TestARepeatWhoseSealedSegmentWasRemovedIsRefused(t *testing.T) {
	l, dir := sealedLog(t)
	if err := os.Remove(filepath.Join(dir, firstSegment)); err != nil {
		t.Fatal(err)
	}
	refusedRepeat(t, l, dir, "a resend of an event of the removed segment, beside a new one", event(1), event(9))
}

// TestARepeatAfterTheLiveFileWasRefilledToItsLengthIsRefused: the live file
// cut and filled again to its length with other bytes, a resend of the event
// it held is refused, failing the log.
func TestARepeatAfterTheLiveFileWasRefilledToItsLengthIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1))
	live := filepath.Join(dir, segmentlog.LiveName)
	if err := os.Truncate(live, 0); err != nil {
		t.Fatal(err)
	}
	writeFile(t, live, strings.Repeat(" ", len(firstLine)-1)+"\n")
	refusedRepeat(t, l, dir, "a resend of the event the refilled file lost", event(1))
}

// TestARepeatWhoseSealedSegmentWasCutIsRefused: a sealed segment cut after
// its first line, a resend of the event of that line is still taken, and of
// the event the cut took is refused.
func TestARepeatWhoseSealedSegmentWasCutIsRefused(t *testing.T) {
	l, dir := sealedLog(t)
	if err := os.Truncate(filepath.Join(dir, firstSegment), int64(len(firstLine))); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(context.Background(), []*controlv1.Event{event(1)}); err != nil {
		t.Errorf("a resend of the event the cut segment still holds = %v", err)
	}
	refusedRepeat(t, l, dir, "a resend of the event the cut took", event(2))
}

// TestARepeatWhoseSealedLineWasRewrittenIsRefused: a sealed line rewritten
// to its own length with other bytes, a resend of its event is refused.
func TestARepeatWhoseSealedLineWasRewrittenIsRefused(t *testing.T) {
	l, dir := sealedLog(t)
	path := filepath.Join(dir, firstSegment)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte(`"requestId":"r1"`), []byte(`"requestId":"r9"`), 1)
	if bytes.Equal(changed, raw) {
		t.Fatal("the first segment holds no request r1")
	}
	writeFile(t, path, string(changed))
	refusedRepeat(t, l, dir, "a resend of the rewritten line's event", event(1))
}

// TestARepeatWhoseSealedSegmentIsALinkIsRefused: a link put at a sealed
// segment's name, to a file beside it holding its very bytes, is not the
// segment the log wrote, and a resend of its event is refused.
func TestARepeatWhoseSealedSegmentIsALinkIsRefused(t *testing.T) {
	l, dir := sealedLog(t)
	path := filepath.Join(dir, firstSegment)
	if err := os.Rename(path, filepath.Join(dir, "copy")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("copy", path); err != nil {
		t.Fatal(err)
	}
	refusedRepeat(t, l, dir, "a resend of an event of the segment a link stands for", event(1))
}

// TestAnUntouchedRepeatIsTakenAndWritesNothing: resends of events a sealed
// and the live segment hold are taken and write nothing, the manifest
// included; after a prune they are found where the segments left now hold
// them.
func TestAnUntouchedRepeatIsTakenAndWritesNothing(t *testing.T) {
	l, dir := sealedLog(t)
	appendTo(t, l, event(4))
	appendTo(t, l, event(5))
	manifest := l.Manifest()
	live := liveText(t, dir)
	appendTo(t, l, event(2), event(3), event(5))
	appendTo(t, l, event(1))
	if got := liveText(t, dir); got != live {
		t.Errorf("the resends wrote to the live segment: %q", got)
	}
	if got := l.Manifest(); got.Retained != manifest.Retained || len(got.Segments) != len(manifest.Segments) {
		t.Errorf("the resends changed the log: %+v, was %+v", got, manifest)
	}
	if err := l.Prune(1); err != nil {
		t.Fatal(err)
	}
	appendTo(t, l, event(4), event(3), event(5))
	if got := liveText(t, dir); got != live {
		t.Errorf("the resends after the prune wrote to the live segment: %q", got)
	}
}

// TestARefusedRepeatFailsTheLogUntilItOpensAgain: once a resend was refused
// for a segment gone, putting the segment back does not make the log take a
// resend, a new event or a prune again; opening it again does.
func TestARefusedRepeatFailsTheLogUntilItOpensAgain(t *testing.T) {
	l, dir := sealedLog(t)
	path := filepath.Join(dir, firstSegment)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	refusedRepeat(t, l, dir, "a resend of an event of the removed segment", event(1))
	writeFile(t, path, string(raw))
	refusedRepeat(t, l, dir, "the same resend once the segment is back", event(1))
	refusedRepeat(t, l, dir, "a new event once the segment is back", event(9))
	if err := l.Prune(1); !errors.Is(err, segmentlog.ErrFailed) {
		t.Errorf("a prune once the segment is back = %v, want segmentlog.ErrFailed", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	again := openTestLog(t, logConfig(dir))
	appendTo(t, again, event(1))
}

// TestALogNamedThroughALinkAndDotDotReadsItsOwnLines: a log named P/l/../log,
// l a link to O/x in another directory O that holds a log directory too, is
// P/log, and a resend is read back from there and taken.
func TestALogNamedThroughALinkAndDotDotReadsItsOwnLines(t *testing.T) {
	parent, other := t.TempDir(), t.TempDir()
	for _, name := range []string{"x", "log"} {
		if err := os.Mkdir(filepath.Join(other, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(other, "x"), filepath.Join(parent, "l")); err != nil {
		t.Fatal(err)
	}
	l := openTestLog(t, logConfig(parent+"/l/../log"))
	appendTo(t, l, event(1))
	if err := l.Append(context.Background(), []*controlv1.Event{event(1)}); err != nil {
		t.Errorf("a resend to the log named through l/.. = %v", err)
	}
	if got := liveText(t, filepath.Join(parent, "log")); got != firstLine {
		t.Errorf("the log in %s/log holds %q, want event 1 once", parent, got)
	}
}

// TestReadingALogRefusesAnotherProjectsEvent: a line of another tenant or
// project in a log bound to one, which the log refuses at open, refuses a
// read of the log and its bytes, as an export of it is.
func TestReadingALogRefusesAnotherProjectsEvent(t *testing.T) {
	for name, change := range map[string]func(*controlv1.Event){
		"project": func(ev *controlv1.Event) { ev.ProjectId = "p2" },
		"tenant":  func(ev *controlv1.Event) { ev.TenantId = "t2" },
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "log")
			l := openTestLog(t, logConfig(dir))
			appendTo(t, l, event(1))
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			other := event(2)
			change(other)
			appendLive(t, dir, lines(t, other))
			if rep, err := ReadPath(dir, DefaultMaxLines); !errors.Is(err, ErrBinding) || !errors.Is(err, ErrDamaged) {
				t.Errorf("ReadPath = %+v, %v; want ErrDamaged and ErrBinding", rep, err)
			}
			if raw, err := LogBytes(dir, 1<<20); !errors.Is(err, ErrBinding) || !errors.Is(err, ErrDamaged) || raw != nil {
				t.Errorf("LogBytes = %q, %v; want ErrDamaged and ErrBinding", raw, err)
			}
		})
	}
}
