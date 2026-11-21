package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

// closedStdout is a standard output that takes no write.
type closedStdout struct{}

func (closedStdout) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// TestAReportNobodyCouldReadIsNoPass: what dev --scenario and scenario run
// report through turns a pass whose report was not written whole into 2, and
// leaves a failure, or a report written whole, as it was.
func TestAReportNobodyCouldReadIsNoPass(t *testing.T) {
	report := func(status int) func(io.Writer) int {
		return func(w io.Writer) int {
			writeLine(w, "a.json passed")
			return status
		}
	}
	var stderr strings.Builder
	if got := reported("dev", closedStdout{}, &stderr, report(exitOK)); got != exitCouldNotRun ||
		stderr.String() != brand.Gateway+": dev: writing the report: no space left on device\n" {
		t.Fatalf("a pass on a stdout that takes nothing: %d, %q", got, stderr.String())
	}
	stderr.Reset()
	if got := reported("dev", closedStdout{}, &stderr, report(exitDiffered)); got != exitDiffered || stderr.Len() == 0 {
		t.Fatalf("a difference on a stdout that takes nothing: %d, %q", got, stderr.String())
	}
	var stdout strings.Builder
	stderr.Reset()
	if got := reported("dev", &stdout, &stderr, report(exitOK)); got != exitOK || stdout.String() != "a.json passed\n" || stderr.Len() != 0 {
		t.Fatalf("a pass written whole: %d, %q, %q", got, stdout.String(), stderr.String())
	}
}
