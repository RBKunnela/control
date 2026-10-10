//go:build unix

package observelog

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

func TestTheFixtureKeyHasTheIDTheObserveFixtureSpells(t *testing.T) {
	if got := observation(spanA, "read_file", "2026-10-04T10:05:00Z").GetObservationId(); got != idA {
		t.Fatalf("observation id = %s, want %s", got, idA)
	}
}

func TestWriteAppendsTheObservationsThenTheReportWithItsCounts(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	rep := report("2026-10-04T10:05:00Z")
	rep.Counts.Duplicate, rep.Counts.Conflict = 5, 7
	got := write(t, l, rep, observation(spanA, "read_file", "2026-10-04T10:05:00Z"), observation(spanB, "write_file", "2026-10-04T10:05:00Z"))
	if got != (Written{Observations: 2}) {
		t.Errorf("Written = %+v, want 2 observations", got)
	}
	recs := records(t, filepath.Join(dir, FileName))
	if len(recs) != 3 {
		t.Fatalf("the log holds %d records, want 3", len(recs))
	}
	if recs[0].GetObservation().GetObservationId() != idA || recs[1].GetObservation().GetSubject().GetName() != "write_file" {
		t.Errorf("the observations are not first, in order: %v", recs[:2])
	}
	c := recs[2].GetImportReport().GetCounts()
	if c.GetDuplicate() != 5 || c.GetConflict() != 7 || c.GetRead() != 2 {
		t.Errorf("the report's counts = %v, want duplicate 5, conflict 7, read 2", c)
	}
	if rep.Counts.Duplicate != 5 || rep.Counts.Conflict != 7 {
		t.Errorf("Write changed the caller's report: %v", rep.Counts)
	}
}

// TestAReimportAfterReopeningIsCountedAsDuplicates: the second import reads
// the same spans later and through a changed descriptor, which the content
// digest leaves aside, so the index rebuilt on open finds both.
func TestAReimportAfterReopeningIsCountedAsDuplicates(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"), observation(spanB, "write_file", "2026-10-04T10:05:00Z"))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = openLog(t, dir)
	a, b := observation(spanA, "read_file", "2026-10-04T11:00:00Z"), observation(spanB, "write_file", "2026-10-04T11:00:00Z")
	a.Source.DescriptorSha256, b.Source.DescriptorSha256 = "d2", "d2"
	if got := write(t, l, report("2026-10-04T11:00:00Z"), a, b); got != (Written{Duplicates: 2}) {
		t.Errorf("Written = %+v, want 2 duplicates", got)
	}
	recs := records(t, filepath.Join(dir, FileName))
	if len(recs) != 4 || recs[3].GetImportReport().GetCounts().GetDuplicate() != 2 || recs[3].GetImportReport().GetCounts().GetConflict() != 0 {
		t.Fatalf("the log holds %d records ending in %v; want 4, the last report counting 2 duplicates", len(recs), recs[len(recs)-1])
	}
}

func TestAResendWithOtherContentIsAConflictAndNotWritten(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = openLog(t, dir)
	got := write(t, l, report("2026-10-04T11:00:00Z"), observation(spanA, "delete_file", "2026-10-04T10:05:00Z"), observation(spanB, "write_file", "2026-10-04T10:05:00Z"))
	if got != (Written{Observations: 1, Conflicts: 1}) {
		t.Errorf("Written = %+v, want 1 observation and 1 conflict", got)
	}
	if bytes.Contains(contents(t, filepath.Join(dir, FileName)), []byte("delete_file")) {
		t.Error("the conflicting observation was written")
	}
	recs := records(t, filepath.Join(dir, FileName))
	if c := recs[len(recs)-1].GetImportReport().GetCounts(); c.GetConflict() != 1 || c.GetDuplicate() != 0 {
		t.Errorf("the report's counts = %v, want conflict 1", c)
	}
}

// TestADuplicateWithinOneBatchIsCounted: the batch holds the first span
// three times, the second read later and the third with another tool.
func TestADuplicateWithinOneBatchIsCounted(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, dir)
	got := write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"),
		observation(spanA, "read_file", "2026-10-04T10:06:00Z"), observation(spanA, "delete_file", "2026-10-04T10:05:00Z"))
	if got != (Written{Observations: 1, Duplicates: 1, Conflicts: 1}) {
		t.Errorf("Written = %+v, want 1 of each", got)
	}
	if recs := records(t, filepath.Join(dir, FileName)); len(recs) != 2 {
		t.Errorf("the log holds %d records, want the observation and the report", len(recs))
	}
}

func TestWriteRefusesARecordTheCodecRefusesAndWritesNothing(t *testing.T) {
	bad := observation(spanB, "write_file", "2026-10-04T10:05:00Z")
	bad.SchemaVersion = "0.2"
	badReport := report("2026-10-04T10:05:00Z")
	badReport.TenantId = ""
	for name, c := range map[string]struct {
		obs []*observev1.Observation
		rep *observev1.ImportReport
	}{
		"nil report":          {[]*observev1.Observation{observation(spanA, "read_file", "2026-10-04T10:05:00Z")}, nil},
		"nil observation":     {[]*observev1.Observation{observation(spanA, "read_file", "2026-10-04T10:05:00Z"), nil}, report("2026-10-04T10:05:00Z")},
		"refused observation": {[]*observev1.Observation{observation(spanA, "read_file", "2026-10-04T10:05:00Z"), bad}, report("2026-10-04T10:05:00Z")},
		"refused report":      {[]*observev1.Observation{observation(spanA, "read_file", "2026-10-04T10:05:00Z")}, badReport},
	} {
		dir := logDir(t)
		l := openLog(t, dir)
		if _, err := l.Write(c.obs, c.rep); !errors.Is(err, ErrRecord) {
			t.Errorf("%s: Write = %v, want ErrRecord", name, err)
		}
		if b := contents(t, filepath.Join(dir, FileName)); len(b) != 0 {
			t.Errorf("%s: the refused Write left %q", name, b)
		}
		if got := write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z")); got.Observations != 1 {
			t.Errorf("%s: the refused Write indexed the observation: %+v", name, got)
		}
	}
}

func TestAFailedWriteIsCutBackAndLeavesTheIndexAsItWas(t *testing.T) {
	failing := errors.New("disk full")
	for name, ops := range map[string]fileOps{
		"write": {write: func(f *os.File, b []byte) (int, error) { n, _ := f.Write(b[:len(b)/2]); return n, failing }, sync: (*os.File).Sync, truncate: (*os.File).Truncate},
		"sync":  {write: (*os.File).Write, sync: func(*os.File) error { return failing }, truncate: (*os.File).Truncate},
	} {
		dir := logDir(t)
		l := openLog(t, dir)
		write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"))
		before := contents(t, filepath.Join(dir, FileName))
		l.ops = ops
		if _, err := l.Write([]*observev1.Observation{observation(spanB, "write_file", "2026-10-04T10:05:00Z")}, report("2026-10-04T10:06:00Z")); !errors.Is(err, ErrWrite) || !errors.Is(err, failing) {
			t.Errorf("%s: Write = %v, want ErrWrite carrying the cause", name, err)
		}
		if got := contents(t, filepath.Join(dir, FileName)); !bytes.Equal(got, before) {
			t.Errorf("%s: the failed write left %q", name, got[len(before):])
		}
		l.ops = osOps
		if got := write(t, l, report("2026-10-04T10:07:00Z"), observation(spanB, "write_file", "2026-10-04T10:05:00Z")); got.Observations != 1 {
			t.Errorf("%s: the failed write indexed the observation: %+v", name, got)
		}
	}
}

func TestAFileChangedUnderTheWriterRefusesEveryLaterWrite(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, path string){
		"renamed":  func(t *testing.T, path string) { mustDo(t, os.Rename(path, path+".old")) },
		"extended": func(t *testing.T, path string) { appendTo(t, path, "{") },
		"replaced": func(t *testing.T, path string) {
			mustDo(t, os.Rename(path, path+".old"))
			writeFile(t, path, "")
		},
	} {
		dir := logDir(t)
		l := openLog(t, dir)
		path := filepath.Join(dir, FileName)
		write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"))
		before := contents(t, path)
		change(t, path)
		held := path
		if name != "extended" {
			held = path + ".old"
		}
		changedTo := contents(t, held)
		for range 2 {
			if _, err := l.Write(nil, report("2026-10-04T10:06:00Z")); !errors.Is(err, ErrChanged) {
				t.Errorf("%s: Write = %v, want ErrChanged", name, err)
			}
		}
		if got := contents(t, held); !bytes.Equal(got, changedTo) || len(got) < len(before) {
			t.Errorf("%s: the refused writes reached the file the log holds: %q", name, got[len(before):])
		}
	}
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own file
	mustDo(t, err)
	_, err = f.WriteString(s)
	mustDo(t, errors.Join(err, f.Close()))
}

// logWithTail is a log holding one observation and a report, followed by
// tail, and the length of the whole lines.
func logWithTail(t *testing.T, tail string) (string, int) {
	t.Helper()
	dir := logDir(t)
	l := openLog(t, dir)
	write(t, l, report("2026-10-04T10:05:00Z"), observation(spanA, "read_file", "2026-10-04T10:05:00Z"))
	mustDo(t, l.Close())
	path := filepath.Join(dir, FileName)
	whole := len(contents(t, path))
	appendTo(t, path, tail)
	return dir, whole
}

// TestOpenCutsATornLastLine: a crash in the middle of a write leaves the
// start of a line, or a whole record without its newline; neither was
// reported written.
func TestOpenCutsATornLastLine(t *testing.T) {
	line, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: observation(spanB, "write_file", "2026-10-04T10:05:00Z")}})
	mustDo(t, err)
	for _, tail := range []string{`{`, `{"observation":{"schemaVer`, `{"importReport":{"schemaVersion":"0.1","tenantId":"t`, string(line[:len(line)-1])} {
		dir, whole := logWithTail(t, tail)
		l := openLog(t, dir)
		if got := len(contents(t, filepath.Join(dir, FileName))); got != whole {
			t.Errorf("tail %.30q: the file is %d bytes after Open, want %d", tail, got, whole)
		}
		if got := write(t, l, report("2026-10-04T10:06:00Z"), observation(spanB, "write_file", "2026-10-04T10:05:00Z")); got.Observations != 1 {
			t.Errorf("tail %.30q: the cut record was indexed: %+v", tail, got)
		}
	}
}

func TestOpenRefusesATailNoWriteLeaves(t *testing.T) {
	for _, tail := range []string{"x", `{"eventId":"e`, `{"observation":{}}x`, `{"observation":{}}`, "{}", `{"observation":{}}{"observation":`} {
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
	head := `{"observation":{"schemaVersion":"`
	for _, c := range []struct {
		size int
		want error
	}{{observe.MaxLineBytes, nil}, {observe.MaxLineBytes + 1, ErrDamaged}} {
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

func TestOpenRefusesAWholeLineNoWriteLeaves(t *testing.T) {
	a, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: observation(spanA, "read_file", "2026-10-04T10:05:00Z")}})
	mustDo(t, err)
	other, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: observation(spanA, "delete_file", "2026-10-04T10:05:00Z")}})
	mustDo(t, err)
	later, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: observation(spanA, "read_file", "2026-10-04T11:05:00Z")}})
	mustDo(t, err)
	crlf := strings.TrimSuffix(string(a), "\n") + "\r\n"
	for name, body := range map[string]string{
		"not a record":        "{}\n",
		"not json":            "x\n",
		"an unknown version":  strings.Replace(string(a), `"0.1"`, `"0.2"`, 1),
		"a carriage return":   crlf,
		"one id two contents": string(a) + string(other),
		"a raw C1 control":    strings.Replace(string(a), "read_file", "read\u009bfile", 1),
		"a snake_case member": strings.Replace(string(a), `"tenantId"`, `"tenant_id"`, 1),
		"a space":             strings.Replace(string(a), `"tenantId":`, `"tenantId": `, 1),
	} {
		dir := logDir(t)
		writeFile(t, filepath.Join(dir, FileName), body)
		if l, err := Open(dir); !errors.Is(err, ErrDamaged) || l != nil {
			t.Errorf("%s: Open = %v, %v; want ErrDamaged", name, l, err)
		}
	}
	dir := logDir(t)
	rep, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: report("2026-10-04T11:05:00Z")}})
	mustDo(t, err)
	body := string(a) + string(later) + string(rep)
	writeFile(t, filepath.Join(dir, FileName), body)
	openLog(t, dir)
	if got := string(contents(t, filepath.Join(dir, FileName))); got != body {
		t.Errorf("Open changed an accepted log to %q", got)
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
// while the first waits to lock it, cuts the torn tail and commits a batch;
// the first then keeps that batch and indexes it.
func TestOpenCutsByTheLengthItFindsUnderItsLock(t *testing.T) {
	dir, whole := logWithTail(t, `{`)
	path := filepath.Join(dir, FileName)
	resume := openHeldBeforeLock(t, dir)

	b := openLog(t, dir)
	write(t, b, report("2026-10-04T10:06:00Z"), observation(spanB, "write_file", "2026-10-04T10:06:00Z"))
	mustDo(t, b.Close())
	committed := contents(t, path)
	if len(committed) <= whole {
		t.Fatalf("the second Open's batch left %d bytes, no more than the %d before it", len(committed), whole)
	}

	a, err := resume()
	if err != nil {
		t.Fatalf("the first Open = %v", err)
	}
	if got := contents(t, path); !bytes.Equal(got, committed) {
		t.Errorf("after the first Open the file holds %d bytes, want the %d the second one committed", len(got), len(committed))
	}
	if got := write(t, a, report("2026-10-04T10:07:00Z"), observation(spanB, "write_file", "2026-10-04T10:06:00Z")); got != (Written{Duplicates: 1}) {
		t.Errorf("importing the second Open's observation again = %+v, want a duplicate", got)
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
