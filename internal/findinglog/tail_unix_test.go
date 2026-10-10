//go:build unix

package findinglog

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// logWithTail is a log holding one committed write, followed by tail, and
// the length of that write.
func logWithTail(t *testing.T, tail string) (string, int) {
	t.Helper()
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, finding(idA, confirmed, "repeated_denial"))
	mustDo(t, l.Close())
	path := filepath.Join(dir, FileName)
	whole := len(contents(t, path))
	appendTo(t, path, tail)
	return dir, whole
}

// TestOpenCutsWhatACrashLeftAfterTheLastReport: the start of a line, a
// whole record without its newline, or whole findings with no report; none
// of it was reported written.
func TestOpenCutsWhatACrashLeftAfterTheLastReport(t *testing.T) {
	b := line(t, findingRecord(finding(idB, suspected, "outside")))
	r := line(t, writtenReport(1))
	for name, tail := range map[string]string{
		"an opening brace":            `{`,
		"the start of a finding":      `{"findingRecord":{"schemaVer`,
		"the start of a report":       `{"superviseReport":{"schemaVersion":"0.1","tenantId":"t`,
		"a finding with no newline":   strings.TrimSuffix(b, "\n"),
		"a finding and no report":     b,
		"a finding and a torn report": b + r[:40],
		"a report with no newline":    b + strings.TrimSuffix(r, "\n"),
	} {
		dir, whole := logWithTail(t, tail)
		l := openLog(t, dir)
		if got := len(contents(t, filepath.Join(dir, FileName))); got != whole {
			t.Errorf("%s: after Open the file holds %d bytes, want %d", name, got, whole)
		}
		if got := write(t, l, finding(idB, suspected, "outside")); got.Written != 1 {
			t.Errorf("%s: the cut finding was indexed: %+v", name, got)
		}
	}
}

// TestOpenRefusesAWholeLogNoWriterLeaves: the refused Open names the line
// and its offset, carries none of its bytes and changes nothing.
func TestOpenRefusesAWholeLogNoWriterLeaves(t *testing.T) {
	a := line(t, findingRecord(finding(idA, confirmed, "repeated_denial")))
	again := line(t, findingRecord(finding(idA, confirmed, "planted")))
	r := line(t, writtenReport(1))
	planted := strings.Replace(a, `"tenantId":`, `"planted":"x","tenantId":`, 1)
	for name, c := range map[string]struct {
		tail   string
		number int
	}{
		"an unknown member, committed":                {planted + r, 4},
		"an unknown member, uncommitted":              {planted, 4},
		"a key the log holds":                         {again + r, 4},
		"a key twice in one write":                    {line(t, findingRecord(finding(idB, suspected, "outside"))) + line(t, findingRecord(finding(idB, suspected, "planted"))), 5},
		"a report counting a finding its write lacks": {r, 4},
		"a report counting fewer than its write holds": {line(t, findingRecord(finding(idB, suspected, "outside"))) +
			line(t, writtenReport(0)), 5},
		"a carriage return":        {strings.Replace(r, "\n", "\r\n", 1), 4},
		"a line that is no record": {"{}\n" + r, 4},
		"a line over the bound":    {`{"findingRecord":"` + strings.Repeat("p", MaxLineBytes) + "\"}\n" + r, 4},
	} {
		dir, whole := logWithTail(t, c.tail)
		l, err := Open(dir)
		if !errors.Is(err, ErrDamaged) || l != nil {
			t.Errorf("%s: Open = %v, %v; want ErrDamaged", name, l, err)
			continue
		}
		offset := whole + strings.Index(c.tail, "\n") + 1
		if c.number == 4 {
			offset = whole
		}
		if want := fmt.Sprintf("line %d, at byte %d", c.number, offset); !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %q does not name %q", name, err, want)
		}
		if strings.Contains(err.Error(), "planted") || strings.Contains(err.Error(), "ppp") {
			t.Errorf("%s: %q carries the line's bytes", name, err)
		}
		if got := len(contents(t, filepath.Join(dir, FileName))); got != whole+len(c.tail) {
			t.Errorf("%s: the refused Open changed the file to %d bytes", name, got)
		}
	}
}

func TestOpenRefusesATailNoWriteLeaves(t *testing.T) {
	for _, tail := range []string{"x", `{"eventId":"e`, `{"findingRecord":{}}x`, `{"findingRecord":{}}`, "{}", `{"findingRecord":{}}{"findingRecord":`} {
		dir, whole := logWithTail(t, tail)
		if l, err := Open(dir); !errors.Is(err, ErrDamaged) || l != nil {
			t.Errorf("tail %q: Open = %v, %v; want ErrDamaged", tail, l, err)
		}
		if got := len(contents(t, filepath.Join(dir, FileName))); got != whole+len(tail) {
			t.Errorf("tail %q: the refused Open changed the file to %d bytes", tail, got)
		}
	}
}

// TestATailLongerThanAnyLineIsDamaged: the tail is the start of a line in
// both cases; only its length tells them apart.
func TestATailLongerThanAnyLineIsDamaged(t *testing.T) {
	head := `{"findingRecord":{"schemaVersion":"`
	for _, c := range []struct {
		size int
		want error
	}{{MaxLineBytes, nil}, {MaxLineBytes + 1, ErrDamaged}} {
		dir := logDir(t)
		writeFile(t, filepath.Join(dir, FileName), head+strings.Repeat("a", c.size-len(head)))
		l, err := Open(dir)
		if !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("a tail of %d bytes: Open = %v, want %v", c.size, err, c.want)
		}
		if l != nil {
			mustDo(t, l.Close())
		}
	}
}

// openHeldBeforeLock starts an Open of dir, returns once it has judged the
// log file and before it locks it, and gives back what lets it go on.
func openHeldBeforeLock(t *testing.T, dir string) (resume func() (*Log, error)) {
	t.Helper()
	held, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	prev := ownerWanted
	ownerWanted = func(info fs.FileInfo) int {
		if info.Mode().IsRegular() {
			stop := false
			first.Do(func() { stop = true })
			if stop {
				close(held)
				<-release
			}
		}
		return prev(info)
	}
	type opened struct {
		l   *Log
		err error
	}
	done := make(chan opened, 1)
	go func() {
		l, err := Open(dir)
		done <- opened{l, err}
	}()
	<-held
	var r opened
	var finish sync.Once
	resume = func() (*Log, error) {
		finish.Do(func() {
			close(release)
			r = <-done
		})
		return r.l, r.err
	}
	t.Cleanup(func() {
		if l, _ := resume(); l != nil {
			_ = l.Close()
		}
		ownerWanted = prev
	})
	return resume
}

// TestOpenCutsByTheLengthItFindsUnderItsLock: a second Open takes the log
// while the first waits to lock it, cuts the torn tail and commits a write;
// the first then keeps that write and indexes it.
func TestOpenCutsByTheLengthItFindsUnderItsLock(t *testing.T) {
	dir, whole := logWithTail(t, `{`)
	path := filepath.Join(dir, FileName)
	resume := openHeldBeforeLock(t, dir)

	b := openLog(t, dir)
	write(t, b, finding(idB, suspected, "outside"))
	mustDo(t, b.Close())
	committed := contents(t, path)
	if len(committed) <= whole {
		t.Fatalf("the second Open's write left %d bytes, no more than the %d before it", len(committed), whole)
	}

	a, err := resume()
	if err != nil {
		t.Fatalf("the first Open = %v", err)
	}
	if got := contents(t, path); !bytes.Equal(got, committed) {
		t.Errorf("after the first Open the file holds %d bytes, want the %d the second one committed", len(got), len(committed))
	}
	if got := write(t, a, finding(idB, suspected, "outside")); got.Written != 0 || got.Duplicates != 1 {
		t.Errorf("writing the second Open's finding again = %+v, want a duplicate", got)
	}
}

// TestOpenJudgesTheLogFileAgainUnderItsLock: the file is judged as it is
// once locked, not only as it was before.
func TestOpenJudgesTheLogFileAgainUnderItsLock(t *testing.T) {
	for name, c := range map[string]struct {
		change func(t *testing.T, path string)
		want   error
	}{
		"a mode the group may read": {func(t *testing.T, path string) {
			mustDo(t, os.Chmod(path, 0o640)) //nolint:gosec // G302: the mode under test
		}, ErrFileMode},
		"a second name": {func(t *testing.T, path string) { mustDo(t, os.Link(path, path+".2")) }, ErrLinks},
	} {
		t.Run(name, func(t *testing.T) {
			dir, whole := logWithTail(t, `{`)
			path := filepath.Join(dir, FileName)
			resume := openHeldBeforeLock(t, dir)
			c.change(t, path)
			if l, err := resume(); !errors.Is(err, c.want) || l != nil {
				t.Errorf("Open = %v, %v; want %v", l, err, c.want)
			}
			if got := len(contents(t, path)); got != whole+1 {
				t.Errorf("the refused Open changed the file to %d bytes, want %d", got, whole+1)
			}
		})
	}
}
