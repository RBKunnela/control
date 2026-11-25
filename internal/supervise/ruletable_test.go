package supervise_test

import (
	"regexp"
	"slices"
	"testing"

	"github.com/guardana/control/internal/supervise"
)

var schema01Rules = []string{
	"REPEATED_DENIAL", "STEP_OUTSIDE_PROCEDURE", "DEADLINE_EXCEEDED",
	"REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE",
}

var schema02Rules = append(slices.Clone(schema01Rules),
	"RESOURCE_OUTSIDE_RUN", "DENIED_ACTION_RETRIED_ARGUMENTS", "DENIED_ACTION_RETRIED_RESOURCE",
	"DENIED_ACTION_RETRIED_AROUND", "EXCEPTION_TAKEN")

func TestEachSchemaKnowsItsRulesInReportOrder(t *testing.T) {
	if got := supervise.RuleIDsOf("0.1"); !slices.Equal(got, schema01Rules) {
		t.Errorf("RuleIDsOf(0.1) = %q", got)
	}
	if got := supervise.RuleIDsOf("0.2"); !slices.Equal(got, schema02Rules) {
		t.Errorf("RuleIDsOf(0.2) = %q", got)
	}
	if got := supervise.RuleIDs(); !slices.Equal(got, schema01Rules) {
		t.Errorf("RuleIDs() = %q, want the 0.1 rules", got)
	}
	for _, schema := range []string{"", "0.3", "0.10", "1.0"} {
		if got := supervise.RuleIDsOf(schema); got != nil {
			t.Errorf("RuleIDsOf(%q) = %q, want nil", schema, got)
		}
	}
	ids := supervise.RuleIDsOf("0.2")
	ids[0] = "changed"
	if supervise.RuleIDsOf("0.2")[0] != "REPEATED_DENIAL" {
		t.Fatal("RuleIDsOf hands out the table's own slice")
	}
}

// TestEveryRuleIsAtItsVersion: each rule is at the version ruleVersions
// spells, and no other id is a rule's.
func TestEveryRuleIsAtItsVersion(t *testing.T) {
	if len(ruleVersions) != len(schema02Rules) {
		t.Fatalf("%d versions spelled for %d rules", len(ruleVersions), len(schema02Rules))
	}
	for _, id := range schema02Rules {
		if v, ok := supervise.RuleVersionOf(id); !ok || v != ruleVersions[id] {
			t.Errorf("RuleVersionOf(%q) = %q, %v; want %q", id, v, ok, ruleVersions[id])
		}
	}
	for _, id := range []string{"", "repeated_denial", "REPEATED_DENIAL ", "DENIED_ACTION_RETRIED", "RESOURCE_OUTSIDE"} {
		if v, ok := supervise.RuleVersionOf(id); ok || v != "" {
			t.Errorf("RuleVersionOf(%q) = %q, %v; want no rule", id, v, ok)
		}
	}
}

func TestOnlyTheThreeTheRecordListsMayStop(t *testing.T) {
	want := map[string]bool{"REPEATED_DENIAL": true, "STEP_OUTSIDE_PROCEDURE": true, "RESOURCE_OUTSIDE_RUN": true}
	for _, id := range append(slices.Clone(schema02Rules), "", "repeated_denial", "STOP_EVERYTHING") {
		if got := supervise.MayStop(id); got != want[id] {
			t.Errorf("MayStop(%q) = %v, want %v", id, got, want[id])
		}
	}
}

func TestTheNewRulesConfirmAsTheRecordSays(t *testing.T) {
	for id, want := range map[string]bool{
		"RESOURCE_OUTSIDE_RUN": true, "DENIED_ACTION_RETRIED_ARGUMENTS": false,
		"DENIED_ACTION_RETRIED_RESOURCE": false, "DENIED_ACTION_RETRIED_AROUND": false, "EXCEPTION_TAKEN": true,
	} {
		if got := supervise.CanConfirm(id); got != want {
			t.Errorf("CanConfirm(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestRuleIDsAreUpperSnakeCase(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	for _, bad := range []string{"repeated_denial", "1RULE", "A-B", "A.B", "", "_A"} {
		if pattern.MatchString(bad) {
			t.Fatalf("the pattern admits %q", bad)
		}
	}
	for _, id := range supervise.RuleIDsOf("0.2") {
		if !pattern.MatchString(id) {
			t.Errorf("rule id %q is not upper snake case", id)
		}
	}
}
