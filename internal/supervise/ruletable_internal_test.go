package supervise

import (
	"maps"
	"slices"
	"testing"
)

// TestTheTableIsWhole reads the table itself rather than an id list derived
// from it, so a row no schema lists cannot hide from the may-stop set.
func TestTheTableIsWhole(t *testing.T) {
	stops := map[string]bool{}
	seen := map[string]bool{}
	for _, r := range ruleTable {
		if seen[r.id] {
			t.Errorf("rule %s has two rows", r.id)
		}
		seen[r.id] = true
		if len(r.schemas) == 0 {
			t.Errorf("rule %s is known to no schema", r.id)
		}
		if r.mayStop {
			stops[r.id] = true
			if !r.canConfirm {
				t.Errorf("rule %s may stop but is never CONFIRMED", r.id)
			}
		}
	}
	want := []string{"REPEATED_DENIAL", "RESOURCE_OUTSIDE_RUN", "STEP_OUTSIDE_PROCEDURE"}
	if got := slices.Sorted(maps.Keys(stops)); !slices.Equal(got, want) {
		t.Fatalf("may stop: %q, want %q", got, want)
	}
	waivable := []string{}
	for _, r := range ruleTable {
		if r.waivable {
			waivable = append(waivable, r.id)
		}
	}
	slices.Sort(waivable)
	if want := []string{"CONTINUED_AFTER_FAILURE", "REQUIRED_STEP_SKIPPED", "STEP_OUTSIDE_PROCEDURE", "STEP_OUT_OF_ORDER"}; !slices.Equal(waivable, want) {
		t.Fatalf("waivable: %q, want %q", waivable, want)
	}
}

func TestRuleIDsIsTheTablesSchema01Rows(t *testing.T) {
	if !slices.Equal(ruleIDs, RuleIDsOf(ProcedureSchema01)) {
		t.Fatalf("ruleIDs = %q", ruleIDs)
	}
}

// TestRules02IsTheTablesRowsOnlySchema02Knows: the rules a 0.2 procedure
// adds on the calls seen, in report order, without EXCEPTION_TAKEN.
func TestRules02IsTheTablesRowsOnlySchema02Knows(t *testing.T) {
	want := []string{"RESOURCE_OUTSIDE_RUN", "DENIED_ACTION_RETRIED_ARGUMENTS", "DENIED_ACTION_RETRIED_RESOURCE",
		"DENIED_ACTION_RETRIED_AROUND"}
	if !slices.Equal(rules02, want) {
		t.Fatalf("rules02 = %q, want %q", rules02, want)
	}
}
