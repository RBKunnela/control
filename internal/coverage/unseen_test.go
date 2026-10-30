package coverage_test

import (
	"testing"
	"time"

	"github.com/guardana/control/internal/coverage"
)

// TestAnEgressSourceNotLiveIsARow: an egress source no path names, beside a
// covered tool path, gets a row before the standing one when it is never
// heard, lapsed or ahead of now, and the row makes the exit 1; a live one adds
// no row.
func TestAnEgressSourceNotLiveIsARow(t *testing.T) {
	never := egressSource("e1", independent, 0)
	never.Records = nil
	for name, tc := range map[string]struct {
		src coverage.Source
		row string
	}{
		"never heard": {never,
			"unseen egress by e1: never heard; connections since its last import are unseen; no plane decides egress"},
		"lapsed": {egressSource("e1", independent, 10*time.Minute),
			"unseen egress by e1: past its heartbeat: last heard 2026-10-05T11:50:00Z, heartbeat 300 s; " +
				"connections since its last import are unseen; no plane decides egress"},
		"ahead": {egressSource("e1", independent, -time.Minute),
			"unseen egress by e1: last heard 2026-10-05T12:01:00Z, heartbeat 300 s: after now, so the clocks disagree; " +
				"connections since its last import are unseen; no plane decides egress"},
	} {
		r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{liveSource(selfReported, observedA.record()), tc.src}})
		want := []string{
			"gh-create observed, self_reported, sampled: sources s1",
			"  source s1: observed, self_reported, sampled: last heard 2026-10-05T11:59:50Z, heartbeat 300 s",
			tc.row,
			"undeclared paths: unknown",
		}
		if got := r.Lines(); joined(got) != joined(want) {
			t.Errorf("%s: lines:\n%s\nwant:\n%s", name, joined(got), joined(want))
		}
		if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
			t.Errorf("%s: exit %d, want %d", name, got, coverage.ExitGaps)
		}
	}
	live := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{
		liveSource(selfReported, observedA.record()), egressSource("e1", independent, 10*time.Second)}})
	if got := coverage.ExitStatus(live, nil); got != coverage.ExitCovered || len(live.Unseen) != 0 {
		t.Errorf("a live egress source: exit %d, rows %+v, want 0 and none", got, live.Unseen)
	}
}

// TestAnUnseenRowAloneMakesTheExitOne: a report a caller holds with only an
// unseen source still has connections nobody saw.
func TestAnUnseenRowAloneMakesTheExitOne(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{liveSource(selfReported, observedA.record())}})
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitCovered {
		t.Fatalf("before the row: exit %d", got)
	}
	r.Unseen = []coverage.UnseenSource{{SourceID: "e1"}}
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
		t.Errorf("exit %d, want %d", got, coverage.ExitGaps)
	}
}

// TestAnEgressPathKeepsItsStateBesideTheUnseenRow: a path naming a lapsed
// source stays unknown on its own line, and the source's row follows its
// refused row and precedes the standing one.
func TestAnEgressPathKeepsItsStateBesideTheUnseenRow(t *testing.T) {
	refused := refusing("t1", egressKind, 1, map[string]uint64{"destination": 1})
	refused.GetImportReport().LatestEventTime = nil
	src := egressSource("e1", independent, 10*time.Minute, conn("e1", "api.example.com", 443), refused)
	r := mustMap(t, coverage.Input{Inventory: egressInventory(t, "api.example.com", "api.example.com"), Sources: []coverage.Source{src}})
	want := []string{
		"out unknown: sources e1; no plane decides egress",
		"  source e1: unknown: past its heartbeat: last heard 2026-10-05T11:50:00Z, heartbeat 300 s",
		"refused egress by e1: 1 line refused, so their connections are unknown: destination 1; no plane decides egress",
		"unseen egress by e1: past its heartbeat: last heard 2026-10-05T11:50:00Z, heartbeat 300 s; " +
			"connections since its last import are unseen; no plane decides egress",
		"undeclared paths: unknown",
	}
	if got := r.Lines(); joined(got) != joined(want) {
		t.Errorf("lines:\n%s\nwant:\n%s", joined(got), joined(want))
	}
}
