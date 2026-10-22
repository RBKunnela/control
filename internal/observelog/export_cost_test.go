package observelog

import (
	"bytes"
	"fmt"
	"io"
	"sync/atomic"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

// countingReader counts the bytes read through it.
type countingReader struct {
	r    io.ReaderAt
	read atomic.Int64
}

func (c *countingReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.read.Add(int64(n))
	return n, err
}

// TestAnExportOfOneRecordReadsNoMoreThanItsEnds: a log of 10,000
// observations in writes of 1,000, with an open write of three after the
// last report, exports one record by reading the file's ends, never the
// whole log, and still counts the open write as its tail.
func TestAnExportOfOneRecordReadsNoMoreThanItsEnds(t *testing.T) {
	var log bytes.Buffer
	line := func(r *observev1.Record) int {
		b, err := observe.MarshalLine(r)
		if err != nil {
			t.Fatal(err)
		}
		log.Write(b)
		return len(b)
	}
	tail := 0
	for i := range 10_003 {
		n := line(&observev1.Record{Record: &observev1.Record_Observation{
			Observation: observation(fmt.Sprintf("%016x", i+1), "read_file", "2026-10-04T10:05:00Z")}})
		if i >= 10_000 {
			tail += n
		}
		if i%1000 == 999 {
			line(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: report("2026-10-04T10:05:00Z")}})
		}
	}
	r := &countingReader{r: bytes.NewReader(log.Bytes())}
	var out bytes.Buffer
	tr, err := exportLog("log", r, int64(log.Len()), func() (bool, error) { return true, nil }, Query{Limit: 1}, &out)
	if err != nil {
		t.Fatal(err)
	}
	const bound = 8 * (observe.MaxLineBytes + 1)
	if got := r.read.Load(); got > bound || int64(log.Len()) < 8*bound {
		t.Errorf("read %d of %d bytes, want at most %d", got, log.Len(), bound)
	}
	if tr.TailBytes != int64(tail) || tr.Counts["observation"] != 1 || !tr.WriterHeld {
		t.Errorf("trailer %+v, want one observation and %d tail bytes held", tr, tail)
	}
}

// TestALineLongerThanAWriterWritesStopsTheWalk: a 4 MiB line after the last
// report is no write a writer leaves, so the walk back gives up within one
// line's bound and the log is exported to its last newline.
func TestALineLongerThanAWriterWritesStopsTheWalk(t *testing.T) {
	b, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: report("2026-10-04T10:05:00Z")}})
	if err != nil {
		t.Fatal(err)
	}
	log := append(b, append(bytes.Repeat([]byte("x"), 4<<20), '\n')...)
	r := &countingReader{r: bytes.NewReader(log)}
	end, cuttable, err := committedEnd(r, int64(len(log)))
	if err != nil || cuttable || end != 0 {
		t.Fatalf("committedEnd = %d, %v, %v; want a log not cut", end, cuttable, err)
	}
	if got, bound := r.read.Load(), int64(3*(observe.MaxLineBytes+1)); got > bound {
		t.Errorf("read %d bytes, want at most %d", got, bound)
	}
}
