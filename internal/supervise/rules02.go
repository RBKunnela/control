package supervise

import (
	"slices"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
)

// rules02 are the rules a 0.2 procedure adds that rest on the calls seen, in
// the order a report lists them: every rule 0.1 does not know but
// EXCEPTION_TAKEN, which rests on what the rules applied before it waived.
var rules02 = slices.DeleteFunc(RuleIDsOf(ProcedureSchema02), func(id string) bool {
	return id == RuleExceptionTaken || slices.Contains(ruleIDs, id)
})

// states02 says which of rules02 apply, from base, the state of a rule that
// rests on what was seen: an open run or an export not whole leaves each as
// base says. EXCEPTION_TAKEN follows the rules its exceptions waive.
func (e *evaluation) states02(out map[string]ruleState, base ruleState) {
	if e.p.schema != ProcedureSchema02 {
		return
	}
	for _, id := range rules02 {
		out[id] = base
	}
	if base.state == checked.state {
		e.uncheckable02(out)
	}
	if !e.p.binds() {
		out[RuleResourceOutsideRun] = ruleState{state: findingv1alpha1.RuleState_RULE_STATE_OFF,
			why: "no step or allowed tool binds a resource"}
	}
	out[RuleExceptionTaken] = e.takenState(out, base)
}

// silentWhy is why a rule that reads a source's reports is not checked while
// a source is silent, never heard or not read.
const silentWhy = "a source is silent, never heard or not read"

// uncheckable02 marks those of rules02 that have nothing to compare.
func (e *evaluation) uncheckable02(out map[string]ruleState) {
	if !e.anyHeld() {
		out[RuleResourceOutsideRun] = notChecked("no call of a binding carries a resource id of its type")
	}
	switch {
	case len(e.in.Sources) == 0:
		out[RuleDeniedActionRetriedAround] = notChecked("no observation source was read")
	case e.anySilent:
		// A report that did not arrive is a retry around no one saw.
		out[RuleDeniedActionRetriedAround] = notChecked(silentWhy)
	}
}
