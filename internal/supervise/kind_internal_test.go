package supervise

import (
	"slices"
	"testing"
)

func TestRuleIDsIsTheRulesAReportLists(t *testing.T) {
	if got := RuleIDs(); !slices.Equal(got, ruleIDs[:]) {
		t.Fatalf("RuleIDs() = %q, want %q", got, ruleIDs)
	}
}
