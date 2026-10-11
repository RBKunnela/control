package supervise_test

import (
	"testing"
	"time"

	"github.com/guardana/control/internal/supervise"
)

// TestAFindingCarriesItsOwnRulesVersion: with REPEATED_DENIAL's version
// changed in the table, its finding and its report row carry the new
// version and its id hashes it in place of the table's; another rule keeps
// its own.
func TestAFindingCarriesItsOwnRulesVersion(t *testing.T) {
	supervise.SetRuleVersion(t, supervise.RuleRepeatedDenial, "7")
	calls := denials(4, call{req: "w1", tool: "wipe_disk", upstream: "ops", at: 70 * time.Second})
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Exports: []supervise.Export{export(calls...)}})
	wantID := handID(tenant, proj, runID, "refund", "1", "REPEATED_DENIAL", "7", "issue_refund", "pay")
	if len(res.Findings) != 2 {
		t.Fatalf("%d findings:\n%s", len(res.Findings), dump(res.Findings))
	}
	if f := res.Findings[0].GetFinding(); f.GetRuleVersion() != "7" || f.GetFindingId() != wantID {
		t.Fatalf("REPEATED_DENIAL at %q with id %s; want 7 and %s", f.GetRuleVersion(), f.GetFindingId(), wantID)
	}
	if f := res.Findings[1].GetFinding(); f.GetRuleVersion() != "1" || f.GetFindingId() != id("STEP_OUTSIDE_PROCEDURE", "wipe_disk", "ops") {
		t.Fatalf("STEP_OUTSIDE_PROCEDURE at %q with id %s", f.GetRuleVersion(), f.GetFindingId())
	}
	for _, r := range res.Report.GetRules() {
		want := map[bool]string{true: "7", false: ruleVersions[r.GetRuleId()]}[r.GetRuleId() == supervise.RuleRepeatedDenial]
		if r.GetRuleVersion() != want {
			t.Errorf("report: %s at %q, want %q", r.GetRuleId(), r.GetRuleVersion(), want)
		}
	}
}
