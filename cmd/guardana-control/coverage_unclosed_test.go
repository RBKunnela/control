package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/observelog"
)

// TestCoverageOfASourceWithAnUnclosedWriteIsNoPass: a log that holds a write
// no import report closes may hold a call around the plane the map never
// read, so a path the plane enforces no longer exits 0 and the source gets
// its row.
func TestCoverageOfASourceWithAnUnclosedWriteIsNoPass(t *testing.T) {
	for name, c := range map[string]struct {
		tail string
		code int
	}{
		"every write closed": {"", exitOK},
		"a write not closed": {`{"observation":{"sche`, exitFail},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newCoverageTree(t, "")
			tr.importFresh(t)
			if c.tail != "" {
				f, err := os.OpenFile(filepath.Join(tr.log, observelog.FileName), os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteString(c.tail); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			code, stdout, stderr := invoke(t, tr.args("--plane", tr.plane)...)
			row := "unclosed write by agent-runtime: "
			if code != c.code || stderr != "" || strings.Contains(stdout, row) != (c.tail != "") {
				t.Errorf("exit %d, stderr %q, stdout\n%s\nwant %d, the row %q only for an unclosed write", code, stderr, stdout, c.code, row)
			}
		})
	}
}
