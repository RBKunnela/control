package supervise

import (
	"testing"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestARuleNeverConfirmedIsCappedWhereTheRecordIsMade: a draft that asks for
// CONFIRMED on confirming references is recorded SUSPECTED for every rule the
// table marks never confirmed, and an unknown id, and CONFIRMED for the rest.
func TestARuleNeverConfirmedIsCappedWhereTheRecordIsMade(t *testing.T) {
	s := scope{tenant: "t", project: "p", run: "r", proc: &Procedure{id: "proc", version: "1", schema: ProcedureSchema01}}
	event := ref{r: &findingv1alpha1.Reference{Ref: &findingv1alpha1.Reference_Event{
		Event: &findingv1alpha1.EventRef{EventId: "e1", RequestId: "q1"}}}, v: confirmed, run: "r"}
	want := map[string]controlv1.FindingVerdict{
		RuleRepeatedDenial: confirmed, RuleStepOutsideProcedure: confirmed, RuleDeadlineExceeded: suspected,
		RuleRequiredStepSkipped: suspected, RuleStepOutOfOrder: suspected, RuleContinuedAfterFailure: suspected,
		RuleResourceOutsideRun: confirmed, RuleDeniedActionRetriedArguments: suspected,
		RuleDeniedActionRetriedResource: suspected, RuleDeniedActionRetriedAround: suspected,
		RuleExceptionTaken: confirmed, "NO_SUCH_RULE": suspected,
	}
	if len(want) != len(ruleTable)+1 {
		t.Fatalf("%d cases for %d rows", len(want), len(ruleTable))
	}
	for id, v := range want {
		got := s.record(draft{rule: id, version: "1", cap: confirmed, refs: []ref{event}}).GetFinding().GetVerdict()
		if got != v {
			t.Errorf("%s: %v, want %v", id, got, v)
		}
	}
}
