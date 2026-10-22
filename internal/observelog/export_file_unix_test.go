//go:build unix

package observelog

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/lineexport"
	"github.com/guardana/control/internal/observe"
)

// TestTheExportReadsALogAWriterHolds: the bytes after the last newline are a
// line still being written while the log is held, and a gap once it is not.
func TestTheExportReadsALogAWriterHolds(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"))
	path := filepath.Join(dir, FileName)
	appendTo(t, path, `{"observation":`)
	var held bytes.Buffer
	tr, err := ExportFile(path, Query{Limit: DefaultExportLimit}, &held)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.WriterHeld || tr.TailBytes != 15 || tr.Counts[lineexport.Gap] != 0 || tr.Counts["observation"] != 1 || tr.Counts["import_report"] != 1 {
		t.Errorf("while held: trailer %+v, want the writer held, 15 tail bytes, no gap", tr)
	}
	mustDo(t, l.Close())
	var free bytes.Buffer
	if tr, err = ExportFile(path, Query{Limit: DefaultExportLimit}, &free); err != nil {
		t.Fatal(err)
	}
	if tr.WriterHeld || tr.Counts[lineexport.Gap] != 1 || !strings.Contains(free.String(), `"reason":"partial_tail"`) {
		t.Errorf("once released: trailer %+v, want a partial_tail gap", tr)
	}
}

// TestTheExportEndsAtTheLastImportReport: an observation line after the
// last report belongs to a write a crash left open, which the next writer's
// Open cuts, so it is the tail: pending while the log is held, a gap once it
// is not, and never exported as an observation.
func TestTheExportEndsAtTheLastImportReport(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"))
	path := filepath.Join(dir, FileName)
	line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{
		Observation: observation(spanB, "write_file", "2026-10-04T10:06:00Z")}})
	mustDo(t, err)
	appendTo(t, path, string(line))
	for _, held := range []bool{true, false} {
		if !held {
			mustDo(t, l.Close())
		}
		var out bytes.Buffer
		tr, err := ExportFile(path, Query{Limit: DefaultExportLimit}, &out)
		if err != nil {
			t.Fatal(err)
		}
		gaps := 0
		if !held {
			gaps = 1
		}
		if tr.WriterHeld != held || tr.TailBytes != int64(len(line)) || tr.Counts["observation"] != 1 ||
			tr.Counts["import_report"] != 1 || tr.Counts[lineexport.Gap] != gaps || strings.Contains(out.String(), "write_file") {
			t.Errorf("held %v: trailer %+v, want %d tail bytes, one observation, %d gaps and no write_file", held, tr, len(line), gaps)
		}
	}
}

// TestACursorIntoAWriteStillOpenIsPastTheEnd: a cursor naming the end of an
// observation line no report has closed yet is refused, and holds once a
// report closes that write.
func TestACursorIntoAWriteStillOpenIsPastTheEnd(t *testing.T) {
	dir := logDir(t)
	write(t, openLog(t, dir), report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"))
	path := filepath.Join(dir, FileName)
	line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{
		Observation: observation(spanB, "write_file", "2026-10-04T10:06:00Z")}})
	mustDo(t, err)
	appendTo(t, path, string(line))
	body := contents(t, path)
	first := sha256.Sum256(body[:bytes.IndexByte(body, '\n')+1])
	last := sha256.Sum256(line)
	after := fmt.Sprintf("v1:%x:%d:%x", first, len(body), last)
	if _, err := ExportFile(path, Query{After: after, Limit: DefaultExportLimit}, &bytes.Buffer{}); !errors.Is(err, ErrCursorPastEnd) {
		t.Fatalf("a cursor into the open write: %v, want ErrCursorPastEnd", err)
	}
	closing, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: report("2026-10-04T10:06:00Z")}})
	mustDo(t, err)
	appendTo(t, path, string(closing))
	tr, err := ExportFile(path, Query{After: after, Limit: DefaultExportLimit}, &bytes.Buffer{})
	if err != nil || tr.Counts["import_report"] != 1 || tr.Counts["observation"] != 0 {
		t.Fatalf("once committed: %+v, %v; want the closing report alone", tr, err)
	}
}

// TestADamagedLogIsExportedToItsLastNewline: no writer cuts a log it
// refuses, so a line after the last report is read and judged: here one no
// version this build reads, a gap.
func TestADamagedLogIsExportedToItsLastNewline(t *testing.T) {
	dir := logDir(t)
	write(t, openLog(t, dir), report("2026-10-04T10:05:00Z"))
	path := filepath.Join(dir, FileName)
	appendTo(t, path, "{\"observation\":{}}\n")
	var out bytes.Buffer
	tr, err := ExportFile(path, Query{Limit: DefaultExportLimit}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if tr.TailBytes != 0 || tr.Counts[lineexport.Gap] != 1 || tr.Counts["import_report"] != 1 {
		t.Errorf("trailer %+v, want no tail, the report and the line a gap", tr)
	}
}

func TestTheExportRefusesWhatIsNoRegularFile(t *testing.T) {
	dir := logDir(t)
	fifo := filepath.Join(dir, "fifo")
	mustDo(t, syscall.Mkfifo(fifo, 0o600))
	for _, path := range []string{dir, fifo} {
		var out bytes.Buffer
		if _, err := ExportFile(path, Query{Limit: 1}, &out); !errors.Is(err, ErrNotRegular) || out.Len() != 0 {
			t.Errorf("%s: ExportFile = %v, wrote %d bytes; want ErrNotRegular and nothing", path, err, out.Len())
		}
	}
	if _, err := ExportFile(filepath.Join(dir, "missing"), Query{Limit: 1}, &bytes.Buffer{}); err == nil {
		t.Error("ExportFile of a missing file passed")
	}
}

// TestTheExportJudgesTheFileAsTheReaderDoes: a link, even to the log itself,
// a log the group or others may reach, one of another account and one with a
// second name are refused before a byte is written; the log itself exports.
func TestTheExportJudgesTheFileAsTheReaderDoes(t *testing.T) {
	export := func(path string) (string, error) {
		var out bytes.Buffer
		_, err := ExportFile(path, Query{Limit: DefaultExportLimit}, &out)
		return out.String(), err
	}
	fresh := func() string {
		dir := logDir(t)
		write(t, openLog(t, dir), report("2026-10-04T10:05:00Z"))
		return filepath.Join(dir, FileName)
	}
	path := fresh()
	if out, err := export(path); err != nil || !strings.Contains(out, `"type":"trailer"`) {
		t.Fatalf("the log itself: %v, %q; want an export", err, out)
	}
	link := filepath.Join(filepath.Dir(path), "link")
	mustDo(t, os.Symlink(FileName, link))
	if out, err := export(link); !errors.Is(err, ErrNotRegular) || out != "" {
		t.Errorf("a link to the log: %v, wrote %q; want ErrNotRegular and nothing", err, out)
	}

	for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601} {
		path := fresh()
		mustDo(t, os.Chmod(path, mode))
		if out, err := export(path); !errors.Is(err, ErrFileMode) || out != "" {
			t.Errorf("mode %04o: %v, wrote %q; want ErrFileMode and nothing", mode, err, out)
		}
	}

	path = fresh()
	mustDo(t, os.Link(path, filepath.Join(filepath.Dir(path), "second")))
	if out, err := export(path); !errors.Is(err, ErrLinks) || out != "" {
		t.Errorf("a second name: %v, wrote %q; want ErrLinks and nothing", err, out)
	}

	path = fresh()
	wantOwner(t, func(fs.FileInfo) int { return os.Geteuid() + 1 })
	if out, err := export(path); !errors.Is(err, ErrOwner) || out != "" {
		t.Errorf("another account's: %v, wrote %q; want ErrOwner and nothing", err, out)
	}
}

// TestAskingWhetherAWriterHoldsTheFileLetsItGo: the export's probe takes a
// shared lock, and one it kept would refuse every writer while the export
// runs.
func TestAskingWhetherAWriterHoldsTheFileLetsItGo(t *testing.T) {
	dir := logDir(t)
	mustDo(t, openLogAndClose(dir))
	f, err := os.Open(filepath.Join(dir, FileName)) //nolint:gosec // G304: the log this test made in its own directory
	mustDo(t, err)
	defer func() { _ = f.Close() }()
	if held, err := heldByWriter(f); held || err != nil {
		t.Fatalf("heldByWriter = %v, %v; want no writer", held, err)
	}
	openLog(t, dir)
}
