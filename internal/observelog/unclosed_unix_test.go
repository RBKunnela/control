//go:build unix

package observelog

import (
	"path/filepath"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
)

// TestReadCommittedSaysAWriteIsLeftOut: the records after the last import
// report, whole lines or a line cut short, are left out of what is read and
// said to be there, so a reader does not take the log for all its source
// sent; a log whose every write is closed says none is.
func TestReadCommittedSaysAWriteIsLeftOut(t *testing.T) {
	a := observation(spanA, "read_file", "2026-10-04T10:05:00Z")
	b := observation(spanB, "write_file", "2026-10-04T10:06:00Z")
	first := report("2026-10-04T10:05:00Z")
	closed := []*observev1.Record{observationRecord(a), reportRecord(first)}
	for name, c := range map[string]struct {
		after    string
		unclosed bool
	}{
		"every write closed":      {"", false},
		"an observation unclosed": {line(t, observationRecord(b)), true},
		"a line cut short":        {line(t, observationRecord(b))[:20], true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := logDir(t)
			write(t, openLog(t, dir), first, a)
			path := filepath.Join(dir, FileName)
			if c.after != "" {
				appendTo(t, path, c.after)
			}
			got, err := ReadCommitted(path)
			if err != nil {
				t.Fatalf("ReadCommitted = %v", err)
			}
			sameRecords(t, got.Records, closed)
			if got.Unclosed != c.unclosed {
				t.Fatalf("Unclosed = %v, want %v", got.Unclosed, c.unclosed)
			}
		})
	}
}
