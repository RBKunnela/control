package supervise

import "slices"

// The procedure schemas this package reads.
const (
	ProcedureSchema01 = "0.1"
	ProcedureSchema02 = "0.2"
)

// The rules a procedure configures, in the order a report lists them.
const (
	RuleRepeatedDenial               = "REPEATED_DENIAL"
	RuleStepOutsideProcedure         = "STEP_OUTSIDE_PROCEDURE"
	RuleDeadlineExceeded             = "DEADLINE_EXCEEDED"
	RuleRequiredStepSkipped          = "REQUIRED_STEP_SKIPPED"
	RuleStepOutOfOrder               = "STEP_OUT_OF_ORDER"
	RuleContinuedAfterFailure        = "CONTINUED_AFTER_FAILURE"
	RuleResourceOutsideRun           = "RESOURCE_OUTSIDE_RUN"
	RuleDeniedActionRetriedArguments = "DENIED_ACTION_RETRIED_ARGUMENTS"
	RuleDeniedActionRetriedResource  = "DENIED_ACTION_RETRIED_RESOURCE"
	RuleDeniedActionRetriedAround    = "DENIED_ACTION_RETRIED_AROUND"
	RuleExceptionTaken               = "EXCEPTION_TAKEN"
)

// ruleRow is one rule. version is the version of the rule's code, so a
// change to what it fires on in an unchanged document is a new version and
// so a new finding id; what a document configures is named by its digest.
type ruleRow struct {
	id, version string
	// canConfirm is false for a rule whose verdict rests on something not
	// seen, or on a source's report alone.
	canConfirm bool
	mayStop    bool
	// waivable is whether a 0.2 exception may name the rule.
	waivable bool
	schemas  []string
}

var bothSchemas = []string{ProcedureSchema01, ProcedureSchema02}

var ruleTable = [...]ruleRow{
	{RuleRepeatedDenial, "2", true, true, false, bothSchemas},
	{RuleStepOutsideProcedure, "1", true, true, true, bothSchemas},
	{RuleDeadlineExceeded, "1", true, true, false, bothSchemas},
	{RuleRequiredStepSkipped, "1", false, false, true, bothSchemas},
	{RuleStepOutOfOrder, "2", false, false, true, bothSchemas},
	{RuleContinuedAfterFailure, "2", false, false, true, bothSchemas},
	{RuleResourceOutsideRun, "1", true, true, false, []string{ProcedureSchema02}},
	{RuleDeniedActionRetriedArguments, "1", true, true, false, []string{ProcedureSchema02}},
	{RuleDeniedActionRetriedResource, "1", true, true, false, []string{ProcedureSchema02}},
	{RuleDeniedActionRetriedAround, "1", false, false, false, []string{ProcedureSchema02}},
	{RuleExceptionTaken, "1", true, false, false, []string{ProcedureSchema02}},
}

var ruleIDs = RuleIDsOf(ProcedureSchema01)

func ruleOf(id string) (ruleRow, bool) {
	for _, r := range ruleTable {
		if r.id == id {
			return r, true
		}
	}
	return ruleRow{}, false
}

// RuleIDsOf is every rule a document of schema configures, in the order a
// report lists them, or nil for a schema this package does not read. The
// slice is a copy.
func RuleIDsOf(schema string) []string {
	var out []string
	for _, r := range ruleTable {
		if slices.Contains(r.schemas, schema) {
			out = append(out, r.id)
		}
	}
	return out
}

// RuleVersionOf is the version of rule id, and false for an id that is no
// rule's.
func RuleVersionOf(id string) (string, bool) {
	r, ok := ruleOf(id)
	return r.version, ok
}

// MayStop reports whether a confirmed finding of rule id may stop a run. An
// id that is no rule's never may.
func MayStop(id string) bool {
	r, ok := ruleOf(id)
	return ok && r.mayStop
}

// CanConfirm reports whether a finding of rule id can be CONFIRMED. An id
// that is no rule's never can.
func CanConfirm(id string) bool {
	r, ok := ruleOf(id)
	return ok && r.canConfirm
}
