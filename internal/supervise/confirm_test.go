package supervise_test

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/supervise"
)

// neverConfirmed are the rules whose verdict rests on something not seen.
var neverConfirmed = []string{"CONTINUED_AFTER_FAILURE", "REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER"}

func TestOnlyTheRulesThatRestOnWhatWasSeenCanConfirm(t *testing.T) {
	want := map[string]bool{
		"REPEATED_DENIAL": true, "STEP_OUTSIDE_PROCEDURE": true, "DEADLINE_EXCEEDED": true,
		"REQUIRED_STEP_SKIPPED": false, "STEP_OUT_OF_ORDER": false, "CONTINUED_AFTER_FAILURE": false,
		"": false, "repeated_denial": false, "REPEATED_DENIAL ": false,
	}
	for id, can := range want {
		if got := supervise.CanConfirm(id); got != can {
			t.Errorf("CanConfirm(%q) = %v, want %v", id, got, can)
		}
	}
	ids := supervise.RuleIDs()
	if len(ids) != 6 {
		t.Fatalf("RuleIDs() = %q", ids)
	}
	ids[0] = "changed"
	if supervise.RuleIDs()[0] != "REPEATED_DENIAL" {
		t.Fatal("RuleIDs hands out the package's own array")
	}
}

// TestTheRulesThatCannotConfirmFireUnconfirmed: on a closed run with one
// whole export and no source in doubt, the strongest each absence rule can
// say is SUSPECTED. Every fixture of this package holds its findings to
// CanConfirm through evaluate; this one makes each of the three fire.
func TestTheRulesThatCannotConfirmFireUnconfirmed(t *testing.T) {
	p := procWith(t)
	fired := map[string]bool{}
	for _, calls := range [][]call{skipped(), {
		{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
		{req: "r3", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
	}} {
		res := closedRun(t, p, export(calls...))
		for _, f := range res.Findings {
			fired[f.GetFinding().GetRuleId()] = true
			if f.GetFinding().GetVerdict() != suspected {
				t.Errorf("%s is %s", f.GetFinding().GetRuleId(), f.GetFinding().GetVerdict())
			}
		}
	}
	if got := slices.Sorted(maps.Keys(fired)); !slices.Equal(got, neverConfirmed) {
		t.Fatalf("fired %q, want each of %q", got, neverConfirmed)
	}
}

// TestAStoppedRunsBlocksAreNoDenial: RUN_STOPPED is the plane's block, with a
// decision of its own beside the kernel's, so a run the plane stopped raises
// no REPEATED_DENIAL from it, however often it tried and though the kernel
// would have denied each call, and its blocks are counted by that code.
func TestAStoppedRunsBlocksAreNoDenial(t *testing.T) {
	p := procWith(t)
	calls := []call{{req: "r1", tool: "get_order", upstream: "shop"}}
	for i := range 5 {
		calls = append(calls, call{req: "s" + string(rune('1'+i)), tool: "issue_refund", upstream: "pay",
			at: time.Duration(10*(i+1)) * time.Second, outcome: "stopped"})
	}
	res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(calls...)}})
	sameFindings(t, res.Findings)
	if want := map[string]uint64{"RUN_STOPPED": 5}; !maps.Equal(res.PlaneBlocks, want) {
		t.Fatalf("plane blocks %v, want %v", res.PlaneBlocks, want)
	}
}

// TestAStoppedAgentsBlocksAreNoDenial: AGENT_OR_PRINCIPAL_STOPPED is the
// plane's block as RUN_STOPPED is, alone or after it, so a stopped agent's
// retries raise no REPEATED_DENIAL that would stop it again, and its blocks
// are counted by their first code.
func TestAStoppedAgentsBlocksAreNoDenial(t *testing.T) {
	p := procWith(t)
	calls := []call{{req: "r1", tool: "get_order", upstream: "shop"}}
	for i := range 6 {
		outcome := "agent stopped"
		if i%2 == 1 {
			outcome = "both stopped"
		}
		calls = append(calls, call{req: "s" + string(rune('1'+i)), tool: "issue_refund", upstream: "pay",
			at: time.Duration(10*(i+1)) * time.Second, outcome: outcome})
	}
	res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(calls...)}})
	sameFindings(t, res.Findings)
	if want := map[string]uint64{"AGENT_OR_PRINCIPAL_STOPPED": 3, "RUN_STOPPED": 3}; !maps.Equal(res.PlaneBlocks, want) {
		t.Fatalf("plane blocks %v, want %v", res.PlaneBlocks, want)
	}
}
