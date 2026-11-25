//go:build unix

package findinglog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestReadFileReturnsWhatTheWriterWroteWhileItHoldsTheLog: the read takes no
// lock, so it reads a log another writer holds, and writes nothing.
func TestReadFileReturnsWhatTheWriterWroteWhileItHoldsTheLog(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, finding(idA, confirmed, "repeated_denial"))
	write(t, l, finding(idB, suspected, "outside"))
	before := contents(t, filepath.Join(dir, FileName))
	sameRecords(t, "the log", readBack(t, dir),
		findingRecord(finding(idA, confirmed, "repeated_denial")), writtenReport(1),
		findingRecord(finding(idB, suspected, "outside")), writtenReport(1))
	if got := contents(t, filepath.Join(dir, FileName)); string(got) != string(before) {
		t.Error("ReadFile changed the file")
	}
}

// TestReadFileLeavesOutWhatNoReportCloses: a torn line and whole findings
// after the last report are left out, and the file is left as it is.
func TestReadFileLeavesOutWhatNoReportCloses(t *testing.T) {
	b := line(t, findingRecord(finding(idB, suspected, "outside")))
	for name, tail := range map[string]string{
		"a torn finding":            b[:50],
		"a finding with no newline": strings.TrimSuffix(b, "\n"),
		"a finding and no report":   b,
		"a torn report":             b + line(t, writtenReport(1))[:60],
	} {
		dir, whole := logWithTail(t, tail)
		sameRecords(t, name, readBack(t, dir), findingRecord(finding(idA, confirmed, "repeated_denial")), writtenReport(1))
		if got := len(contents(t, filepath.Join(dir, FileName))); got != whole+len(tail) {
			t.Errorf("%s: ReadFile changed the file to %d bytes", name, got)
		}
	}
}

// TestReadFileNamesADamagedLineByItsOffsetAndNeverItsBytes: the decoder's
// own complaint quotes the member it refused, so the error must not carry it.
func TestReadFileNamesADamagedLineByItsOffsetAndNeverItsBytes(t *testing.T) {
	a := line(t, findingRecord(finding(idA, confirmed, "repeated_denial")))
	planted := strings.Replace(a, `"tenantId":`, `"planted":"x","tenantId":`, 1)
	for name, tail := range map[string]string{
		"committed":       planted + line(t, writtenReport(1)),
		"uncommitted":     planted,
		"a tail no write": "planted",
	} {
		dir, whole := logWithTail(t, tail)
		got, err := ReadFile(filepath.Join(dir, FileName))
		if !errors.Is(err, ErrDamaged) || got != nil {
			t.Errorf("%s: ReadFile = %v, %v; want ErrDamaged", name, got, err)
			continue
		}
		if want := fmt.Sprintf("line 4, at byte %d", whole); strings.HasSuffix(tail, "\n") && !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %q does not name %q", name, err, want)
		}
		if strings.Contains(err.Error(), "planted") {
			t.Errorf("%s: %q carries the line's bytes", name, err)
		}
	}
}

// TestReadFileTakesALineOfTheBoundAndRefusesOneByteMore: the longer line is
// refused by the scanner's bound before it is decoded.
func TestReadFileTakesALineOfTheBoundAndRefusesOneByteMore(t *testing.T) {
	at := line(t, padded(t, MaxLineBytes))
	closing := line(t, writtenReport(1))
	path := filepath.Join(logDir(t), FileName)
	writeFile(t, path, at+closing)
	got, err := ReadFile(path)
	mustDo(t, err)
	sameRecords(t, "a line of the bound", got, padded(t, MaxLineBytes), writtenReport(1))
	over := strings.Replace(at, `"ruleId":"r`, `"ruleId":"rr`, 1)
	writeFile(t, path, over+closing)
	if got, err := ReadFile(path); !errors.Is(err, ErrDamaged) || !strings.Contains(fmt.Sprint(err), "line 1, at byte 0, is over 65536 bytes") || got != nil {
		t.Errorf("a line of one byte more: ReadFile = %v, %v; want it refused as over the bound", got, err)
	}
}

// TestReadFileRefusesWhatIsNoRegularFile: a link is refused even when it
// names the log itself, and a dangling one is not a log never written.
func TestReadFileRefusesWhatIsNoRegularFile(t *testing.T) {
	dir := logDir(t)
	write(t, openLog(t, dir))
	link, dangling, fifo := filepath.Join(dir, "link"), filepath.Join(dir, "dangling"), filepath.Join(dir, "fifo")
	mustDo(t, os.Symlink(FileName, link))
	mustDo(t, os.Symlink("nothing.jsonl", dangling))
	mustDo(t, syscall.Mkfifo(fifo, 0o600))
	for _, path := range []string{link, dangling, dir, fifo} {
		if got, err := ReadFile(path); !errors.Is(err, ErrNotRegular) || got != nil {
			t.Errorf("%s: ReadFile = %v, %v; want ErrNotRegular", path, got, err)
		}
	}
}

func TestReadFileRefusesALogFileTheGroupOrOthersMayReach(t *testing.T) {
	for _, mode := range []fs.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601} {
		dir := logDir(t)
		write(t, openLog(t, dir))
		path := filepath.Join(dir, FileName)
		mustDo(t, os.Chmod(path, mode))
		if got, err := ReadFile(path); !errors.Is(err, ErrFileMode) || got != nil {
			t.Errorf("mode %04o: ReadFile = %v, %v; want ErrFileMode", mode, got, err)
		}
	}
}

func TestReadFileRefusesALogFileOfAnotherAccountOrWithASecondName(t *testing.T) {
	dir := logDir(t)
	write(t, openLog(t, dir))
	path := filepath.Join(dir, FileName)
	wantOwner(t, func(fs.FileInfo) int { return os.Geteuid() + 1 })
	if got, err := ReadFile(path); !errors.Is(err, ErrOwner) || got != nil {
		t.Errorf("another account: ReadFile = %v, %v; want ErrOwner", got, err)
	}
	wantOwner(t, func(fs.FileInfo) int { return os.Geteuid() })
	mustDo(t, os.Link(path, filepath.Join(dir, "second")))
	if got, err := ReadFile(path); !errors.Is(err, ErrLinks) || got != nil {
		t.Errorf("a second name: ReadFile = %v, %v; want ErrLinks", got, err)
	}
}

// TestReadFileRefusesALogLargerThanTheWriterOpens: both files are sparse and
// hold no newline, so the one at the bound passes it and is refused as
// damaged.
func TestReadFileRefusesALogLargerThanTheWriterOpens(t *testing.T) {
	for _, c := range []struct {
		size int64
		want error
	}{{1 << 30, ErrDamaged}, {1<<30 + 1, ErrTooLarge}} {
		path := filepath.Join(logDir(t), FileName)
		writeFile(t, path, "")
		mustDo(t, os.Truncate(path, c.size))
		_, err := ReadFile(path)
		if !errors.Is(err, c.want) || (errors.Is(c.want, ErrDamaged) && errors.Is(err, ErrTooLarge)) {
			t.Errorf("%d bytes: ReadFile = %v, want %v", c.size, err, c.want)
		}
	}
}

// TestReadFileOfNoFileIsNotExistAndCreatesNothing: the caller tells a log
// never written from one it cannot read by this error.
func TestReadFileOfNoFileIsNotExistAndCreatesNothing(t *testing.T) {
	dir := logDir(t)
	path := filepath.Join(dir, FileName)
	for _, p := range []string{path, filepath.Join(dir, "absent", FileName)} {
		if got, err := ReadFile(p); !errors.Is(err, fs.ErrNotExist) || got != nil {
			t.Errorf("%s: ReadFile = %v, %v; want fs.ErrNotExist", p, got, err)
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile left a file: %v", err)
	}
}

func TestReadFileOfAnEmptyFileIsNoRecords(t *testing.T) {
	path := filepath.Join(logDir(t), FileName)
	writeFile(t, path, "")
	if got, err := ReadFile(path); err != nil || len(got) != 0 {
		t.Errorf("ReadFile = %v, %v; want no records and no error", got, err)
	}
}

// TestReadFileTailCountsWhatNoReportCloses: the tail is every byte past the
// last report, a whole finding and a torn line alike, held only while a
// writer holds the log, and nothing for a log whose last write is closed.
func TestReadFileTailCountsWhatNoReportCloses(t *testing.T) {
	b := line(t, findingRecord(finding(idB, suspected, "outside")))
	for name, tail := range map[string]string{
		"nothing past the last report": "",
		"a torn finding":               b[:50],
		"a finding and no report":      b,
		"a torn report":                b + line(t, writtenReport(1))[:60],
	} {
		for _, held := range []bool{false, true} {
			dir, _ := logWithTail(t, tail)
			if held {
				holdLock(t, dir)
			}
			got, tl, err := ReadFileTail(filepath.Join(dir, FileName))
			mustDo(t, err)
			sameRecords(t, name, got[1:], findingRecord(finding(idA, confirmed, "repeated_denial")), writtenReport(1))
			want := Tail{Bytes: int64(len(tail)), Held: held && tail != ""}
			if tl != want {
				t.Errorf("%s, held %v: tail %+v, want %+v", name, held, tl, want)
			}
		}
	}
}
