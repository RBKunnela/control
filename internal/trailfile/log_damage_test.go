package trailfile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/segmentlog"
)

// TestARepeatAfterTheLiveFileWasCutIsRefused: the live file cut under the log
// before anything new arrives, a resend of an event only that file held is
// refused, failing the log, and not taken as written; a resend while the file
// is as the log left it is taken.
func TestARepeatAfterTheLiveFileWasCutIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1))
	appendTo(t, l, event(1))
	if err := os.Truncate(filepath.Join(dir, segmentlog.LiveName), 0); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(context.Background(), []*controlv1.Event{event(1)}); !errors.Is(err, segmentlog.ErrFailed) {
		t.Errorf("a resend of the event the cut file lost = %v, want segmentlog.ErrFailed", err)
	}
	if err := l.Append(context.Background(), []*controlv1.Event{event(2)}); !errors.Is(err, segmentlog.ErrFailed) {
		t.Errorf("the next append = %v, want segmentlog.ErrFailed", err)
	}
}

// TestARepeatHeldInASealedSegmentNeedsNoLiveFile: an event whose line is in a
// sealed segment, with no live file after it, is taken again as written.
func TestARepeatHeldInASealedSegmentNeedsNoLiveFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1))
	if err := l.rl.Seal(); err != nil {
		t.Fatal(err)
	}
	appendTo(t, l, event(1))
	if got := liveText(t, dir); got != "" {
		t.Errorf("the repeat was written: the live segment holds %q", got)
	}
}

// TestAnExportOfALogRefusesAnotherProjectsEvent: a line of another project
// in the live segment of a log bound to one, which the log refuses at open,
// ends the export before its record, with no trailer.
func TestAnExportOfALogRefusesAnotherProjectsEvent(t *testing.T) {
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
			var out bytes.Buffer
			_, err := ExportLog(dir, Query{Limit: 10}, &out)
			if !errors.Is(err, ErrBinding) || !errors.Is(err, ErrDamaged) {
				t.Errorf("ExportLog = %v, want ErrDamaged and ErrBinding", err)
			}
			if strings.Contains(out.String(), `"eventId":"e2"`) || strings.Contains(out.String(), `"type":"trailer"`) {
				t.Errorf("the export wrote the other %s's event or a trailer:\n%s", name, out.String())
			}
		})
	}
}

// TestATornLiveSegmentAfterASealIsNotHidden: a sealed segment followed by a
// live one holding only bytes no newline ends, with no writer holding the
// log, does not end the log: its export says the end was not reached, and the
// export after its cursor reports the bytes as a partial tail.
func TestATornLiveSegmentAfterASealIsNotHidden(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	l := openTestLog(t, logConfig(dir))
	appendTo(t, l, event(1), event(2))
	if err := l.rl.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	torn := `{"eventId":"e3"`
	writeFile(t, filepath.Join(dir, segmentlog.LiveName), torn)
	got, tr := exportTrailer(t, dir, "", 10)
	if len(got) != 2 || *tr.EndReached {
		t.Fatalf("the sealed segment's export wrote %v and says the end was reached: %v", got, *tr.EndReached)
	}
	var out bytes.Buffer
	if _, err := ExportLog(dir, Query{After: tr.NextCursor, Limit: 10}, &out); err != nil {
		t.Fatal(err)
	}
	_, body, trailer := frame(t, out.String())
	if len(body) != 1 || body[0].short() != "gap@0:partial_tail" || *trailer.TailBytes != int64(len(torn)) || *trailer.WriterHeld {
		t.Errorf("the export after the sealed segment's end:\n%s\nwant a partial tail of %d bytes", out.String(), len(torn))
	}
}

// TestAnEventHoldingANullIsAGap: a line the codec reads, whose member is
// null, is a malformed gap and not an event, as no writer spells a member so
// and a reader of the export refuses a record holding a null.
func TestAnEventHoldingANullIsAGap(t *testing.T) {
	null := `{"schemaVersion":"1.0","eventId":"e1","occurredAt":null}`
	quoted := `{"schemaVersion":"1.0","eventId":"e2","requestId":"null"}`
	body := file(null, quoted)
	e := runExport(t, body, false, query())
	equal(t, "records", e.shorts(), []string{"gap@0:malformed", fmt.Sprintf("event@%d", offsetOf(body, 2))})
}
