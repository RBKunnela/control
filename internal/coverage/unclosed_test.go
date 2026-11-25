package coverage_test

import (
	"testing"

	"github.com/guardana/control/internal/coverage"
)

// TestASourceWithAnUnclosedWriteIsARow: a log holding a write no import
// report closes may hold a call the map never read, so the source gets a row
// before the standing one and the exit is 1; the same source closed adds no
// row and exits 0.
func TestASourceWithAnUnclosedWriteIsARow(t *testing.T) {
	for name, tc := range map[string]struct {
		unclosed bool
		rows     []string
		exit     int
	}{
		"closed":   {false, nil, coverage.ExitCovered},
		"unclosed": {true, []string{"unclosed write by s1: its log holds a write no import report closes, so what follows its last report is unread"}, coverage.ExitGaps},
	} {
		src := liveSource(selfReported, observedA.record())
		src.Unclosed = tc.unclosed
		r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{src}})
		want := append([]string{
			"gh-create observed, self_reported, sampled: sources s1",
			"  source s1: observed, self_reported, sampled: last heard 2026-10-05T11:59:50Z, heartbeat 300 s",
		}, append(tc.rows, "undeclared paths: unknown")...)
		if got := r.Lines(); joined(got) != joined(want) {
			t.Errorf("%s: lines:\n%s\nwant:\n%s", name, joined(got), joined(want))
		}
		if got := coverage.ExitStatus(r, nil); got != tc.exit {
			t.Errorf("%s: exit %d, want %d", name, got, tc.exit)
		}
	}
}
