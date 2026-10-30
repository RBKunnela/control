package match

import (
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// tally is what one evaluation found, in document order.
type tally struct {
	matched       []*rule
	undetermined  []*rule
	external      []*rule
	unknownAllows []UnknownAllow
}

// record files a rule's value, and the rule when that value turns on the
// external answer. An unknown ALLOW is no match, and is kept apart so a
// caller can tell "nothing could allow this" from "a field the call left out
// decides it". An unknown rule of any other effect restricts, and a call
// that leaves out the field it reads must not slip past it onto a broader
// allow (ADR-0012).
func (t *tally) record(r *rule, v truth, turnsOnExternal bool, env *controlv1.ActionEnvelope, in *Inputs) {
	if turnsOnExternal {
		t.external = append(t.external, r)
	}
	switch {
	case v == yes:
		t.matched = append(t.matched, r)
	case v == unknown && r.effect != controlv1.Verdict_VERDICT_ALLOW:
		t.undetermined = append(t.undetermined, r)
	case v == unknown:
		t.unknownAllows = append(t.unknownAllows, UnknownAllow{ID: r.id, Needs: r.lacked(env, in)})
	}
}

func (t *tally) result() Result {
	verdict, determinate := t.verdicts()
	return Result{
		Verdict:       verdict,
		Determinate:   determinate,
		RuleIDs:       ids(t.matched),
		Indeterminate: ids(t.undetermined),
		ReasonCodes:   t.reasonCodes(),
		Obligations:   t.obligations(verdict),
		ReadExternal:  ids(t.external),
		UnknownAllows: t.unknownAllows,
	}
}

// verdicts is ADR-0012's table: a matched DENY wins; then INDETERMINATE; then
// REQUIRE_APPROVAL, ALLOW_WITH_OBLIGATIONS, ALLOW; nothing matched is DENY.
// The determinate verdict is the same table with the indeterminate rules left
// out. Precedence is this order and never a comparison of enum numbers.
func (t *tally) verdicts() (verdict, determinate controlv1.Verdict) {
	switch {
	case t.matchedAny(controlv1.Verdict_VERDICT_DENY):
		return controlv1.Verdict_VERDICT_DENY, controlv1.Verdict_VERDICT_DENY
	case t.matchedAny(controlv1.Verdict_VERDICT_REQUIRE_APPROVAL):
		determinate = controlv1.Verdict_VERDICT_REQUIRE_APPROVAL
	case t.matchedAny(controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS):
		determinate = controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS
	case t.matchedAny(controlv1.Verdict_VERDICT_ALLOW):
		determinate = controlv1.Verdict_VERDICT_ALLOW
	default:
		// There is no implicit allow.
		determinate = controlv1.Verdict_VERDICT_DENY
	}
	if len(t.undetermined) > 0 {
		return controlv1.Verdict_VERDICT_INDETERMINATE, determinate
	}
	return determinate, determinate
}

func (t *tally) matchedAny(effect controlv1.Verdict) bool {
	return slices.ContainsFunc(t.matched, func(r *rule) bool { return r.effect == effect })
}

// reasonCodes is what evaluation contributes to the decision's codes
// (ADR-0012): the reason of every matched rule in document order, once each;
// then RULE_UNDETERMINED if any rule is indeterminate; then NO_MATCHING_RULE
// if none matched and none is.
func (t *tally) reasonCodes() []string {
	codes := make([]string, 0, 4)
	for _, r := range t.matched {
		if !slices.Contains(codes, r.reason) {
			codes = append(codes, r.reason)
		}
	}
	if len(t.undetermined) > 0 {
		codes = append(codes, codeRuleUndetermined)
	}
	if len(t.matched) == 0 && len(t.undetermined) == 0 {
		codes = append(codes, codeNoMatchingRule)
	}
	return codes
}

// obligations is the union over the matched rules, in document order and then
// each rule's own, one kept of any two with the same type, parameters and
// advisory flag. Only ALLOW_WITH_OBLIGATIONS and REQUIRE_APPROVAL rules carry
// any, which Compile holds them to, and they bind only a call that proceeds.
func (t *tally) obligations(verdict controlv1.Verdict) []*controlv1.Obligation {
	if verdict != controlv1.Verdict_VERDICT_REQUIRE_APPROVAL && verdict != controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS {
		return nil
	}
	var out []*controlv1.Obligation
	seen := make(map[string]bool)
	for _, r := range t.matched {
		for i := range r.obligations {
			o := &r.obligations[i]
			if !seen[o.key] {
				seen[o.key] = true
				out = append(out, o.fresh())
			}
		}
	}
	return out
}

func ids(rs []*rule) []string {
	if len(rs) == 0 {
		return nil
	}
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.id
	}
	return out
}

// unavailable is the answer of a program nobody compiled: nothing evaluated
// the call, which is neither a match nor "no rule matched".
func unavailable() Result {
	return Result{
		Verdict:     controlv1.Verdict_VERDICT_INDETERMINATE,
		Determinate: controlv1.Verdict_VERDICT_DENY,
		ReasonCodes: []string{codePolicyUnavailable},
	}
}
