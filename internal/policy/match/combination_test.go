package match_test

import (
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
)

// The codes the tables below expect, spelled once so that a row fits on a
// line. They are literals here and in the package; neither reads the other.
const (
	ruleAllow        = "RULE_ALLOW"
	attached         = "OBLIGATIONS_ATTACHED"
	approvalRequired = "APPROVAL_REQUIRED"
	ruleDeny         = "RULE_DENY"
	ruleUndetermined = "RULE_UNDETERMINED"
	noMatchingRule   = "NO_MATCHING_RULE"
)

// TestCombinationTable crosses the five things a rule can contribute: a matched
// DENY (D), a restrictive rule whose match is unknown (I), a matched
// REQUIRE_APPROVAL (R), a matched ALLOW_WITH_OBLIGATIONS (O) and a matched
// ALLOW (A). Each row is ADR-0012's table read by hand for that cell:
//
//	a matched DENY wins; then INDETERMINATE, whatever caused it; then
//	REQUIRE_APPROVAL, ALLOW_WITH_OBLIGATIONS, ALLOW; nothing matched is DENY,
//	NO_MATCHING_RULE.
//
// Determinate is the same reading with I left out. Obligations are carried
// under REQUIRE_APPROVAL and ALLOW_WITH_OBLIGATIONS only.
//
// I is each of the three restrictive effects in turn, and every row holds for
// each: an unknown rule is not passed over for sharing its effect with a
// matched rule, nor for being less restrictive than what matched.
//
// The document holds the five rules in the order A, O, R, I, D, the reverse of
// their precedence, so ids or codes listed in precedence order fail here. A
// rule a row leaves out is present and false. For I that means a false
// constraint beside an unknown one, which has to make the rule false.
func TestCombinationTable(t *testing.T) {
	env := with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "" })
	for _, effect := range []controlv1.Verdict{deny, approval, withObligations} {
		t.Run("I is "+effect.String(), func(t *testing.T) {
			for _, c := range combinationCells() {
				t.Run(c.holds, func(t *testing.T) {
					got := compile(t, tableRules(t, c.holds, effect)...).Evaluate(env, match.Inputs{})
					assertResult(t, got, want{
						verdict: c.verdict, determinate: c.determinate,
						ids: c.ids, undetermined: c.undetermined, codes: c.codes, obligations: c.obligations,
					})
				})
			}
		})
	}
}

// combinationCell is one row of TestCombinationTable.
type combinationCell struct {
	holds                string
	verdict, determinate controlv1.Verdict
	ids, undetermined    []string
	codes                []string
	obligations          []*controlv1.Obligation
}

func combinationCells() []combinationCell {
	capAmount := &controlv1.Obligation{Type: "cap_amount", Params: map[string]string{"max": "100"}}
	secondApprover := &controlv1.Obligation{Type: "second_approver"}
	both := []*controlv1.Obligation{capAmount, secondApprover}
	return []combinationCell{
		{".....", deny, deny, nil, nil, list(noMatchingRule), nil},
		{"....A", allow, allow, list("allow"), nil, list(ruleAllow), nil},
		{"...O.", withObligations, withObligations, list("oblige"), nil, list(attached), []*controlv1.Obligation{capAmount}},
		{"...OA", withObligations, withObligations, list("allow", "oblige"), nil, list(ruleAllow, attached), []*controlv1.Obligation{capAmount}},
		{"..R..", approval, approval, list("approve"), nil, list(approvalRequired), []*controlv1.Obligation{secondApprover}},
		{"..R.A", approval, approval, list("allow", "approve"), nil, list(ruleAllow, approvalRequired), []*controlv1.Obligation{secondApprover}},
		{"..RO.", approval, approval, list("oblige", "approve"), nil, list(attached, approvalRequired), both},
		{"..ROA", approval, approval, list("allow", "oblige", "approve"), nil, list(ruleAllow, attached, approvalRequired), both},

		{".I...", indeterminate, deny, nil, list("unknown"), list(ruleUndetermined), nil},
		{".I..A", indeterminate, allow, list("allow"), list("unknown"), list(ruleAllow, ruleUndetermined), nil},
		{".I.O.", indeterminate, withObligations, list("oblige"), list("unknown"), list(attached, ruleUndetermined), nil},
		{".I.OA", indeterminate, withObligations, list("allow", "oblige"), list("unknown"), list(ruleAllow, attached, ruleUndetermined), nil},
		{".IR..", indeterminate, approval, list("approve"), list("unknown"), list(approvalRequired, ruleUndetermined), nil},
		{".IR.A", indeterminate, approval, list("allow", "approve"), list("unknown"), list(ruleAllow, approvalRequired, ruleUndetermined), nil},
		{".IRO.", indeterminate, approval, list("oblige", "approve"), list("unknown"), list(attached, approvalRequired, ruleUndetermined), nil},
		{".IROA", indeterminate, approval, list("allow", "oblige", "approve"), list("unknown"), list(ruleAllow, attached, approvalRequired, ruleUndetermined), nil},

		{"D....", deny, deny, list("deny"), nil, list(ruleDeny), nil},
		{"D...A", deny, deny, list("allow", "deny"), nil, list(ruleAllow, ruleDeny), nil},
		{"D..O.", deny, deny, list("oblige", "deny"), nil, list(attached, ruleDeny), nil},
		{"D..OA", deny, deny, list("allow", "oblige", "deny"), nil, list(ruleAllow, attached, ruleDeny), nil},
		{"D.R..", deny, deny, list("approve", "deny"), nil, list(approvalRequired, ruleDeny), nil},
		{"D.R.A", deny, deny, list("allow", "approve", "deny"), nil, list(ruleAllow, approvalRequired, ruleDeny), nil},
		{"D.RO.", deny, deny, list("oblige", "approve", "deny"), nil, list(attached, approvalRequired, ruleDeny), nil},
		{"D.ROA", deny, deny, list("allow", "oblige", "approve", "deny"), nil, list(ruleAllow, attached, approvalRequired, ruleDeny), nil},

		{"DI...", deny, deny, list("deny"), list("unknown"), list(ruleDeny, ruleUndetermined), nil},
		{"DI..A", deny, deny, list("allow", "deny"), list("unknown"), list(ruleAllow, ruleDeny, ruleUndetermined), nil},
		{"DI.O.", deny, deny, list("oblige", "deny"), list("unknown"), list(attached, ruleDeny, ruleUndetermined), nil},
		{"DI.OA", deny, deny, list("allow", "oblige", "deny"), list("unknown"), list(ruleAllow, attached, ruleDeny, ruleUndetermined), nil},
		{"DIR..", deny, deny, list("approve", "deny"), list("unknown"), list(approvalRequired, ruleDeny, ruleUndetermined), nil},
		{"DIR.A", deny, deny, list("allow", "approve", "deny"), list("unknown"), list(ruleAllow, approvalRequired, ruleDeny, ruleUndetermined), nil},
		{"DIRO.", deny, deny, list("oblige", "approve", "deny"), list("unknown"), list(attached, approvalRequired, ruleDeny, ruleUndetermined), nil},
		{"DIROA", deny, deny, list("allow", "oblige", "approve", "deny"), list("unknown"), list(ruleAllow, attached, approvalRequired, ruleDeny, ruleUndetermined), nil},
	}
}

// tableRules builds the five rules of TestCombinationTable in the order A, O,
// R, I, D, with I of the effect given. holds names, by position D I R O A, the
// rules that hold, and '.' the ones that do not. It builds input only; every
// expectation is in the table.
func tableRules(t *testing.T, holds string, unknownEffect controlv1.Verdict) []rules.Rule {
	t.Helper()
	const letters = "DIROA"
	if len(holds) != len(letters) {
		t.Fatalf("cell %q: want five positions, D I R O A", holds)
	}
	on := make(map[byte]bool, len(letters))
	for i := range len(letters) {
		switch holds[i] {
		case letters[i]:
			on[letters[i]] = true
		case '.':
		default:
			t.Fatalf("cell %q: position %d is %q, want %q or '.'", holds, i, holds[i], letters[i])
		}
	}
	name := func(letter byte) *rules.ActionWhen {
		if on[letter] {
			return &rules.ActionWhen{Name: []string{"refund"}}
		}
		return &rules.ActionWhen{Name: []string{"archive"}}
	}
	// The envelope carries no resource environment, so this rule is unknown
	// when its name holds and false when it does not. The obligation it
	// carries, where its effect allows one, would show in any result that
	// took it for a match.
	unknown := rules.Rule{ID: "unknown", Effect: unknownEffect, When: rules.When{
		Action: name('I'), Resource: &rules.ResourceWhen{Environment: []string{"prod"}},
	}}
	if unknownEffect != deny {
		unknown.Obligations = []rules.Obligation{{Type: "redact_fields", Params: map[string]string{"field": "ssn"}}}
	}
	return []rules.Rule{
		{ID: "allow", Effect: allow, When: rules.When{Action: name('A')}},
		{ID: "oblige", Effect: withObligations, When: rules.When{Action: name('O')},
			Obligations: []rules.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}}},
		{ID: "approve", Effect: approval, When: rules.When{Action: name('R')},
			Obligations: []rules.Obligation{{Type: "second_approver"}}},
		unknown,
		{ID: "deny", Effect: deny, When: rules.When{Action: name('D')}},
	}
}

// TestUnknownOnEachEffect covers what the table fixes: an unknown ALLOW is no
// match, and an unknown rule of each of the other three effects is
// indeterminate, beside a matched rule of its own effect or a more
// restrictive one as well.
func TestUnknownOnEachEffect(t *testing.T) {
	env := with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "" })
	unknownWhen := func() rules.When { return rules.When{Resource: &rules.ResourceWhen{Environment: []string{"prod"}}} }
	capAmount := func() []rules.Obligation {
		return []rules.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}}
	}
	redact := func() []rules.Obligation {
		return []rules.Obligation{{Type: "redact_fields", Params: map[string]string{"field": "ssn"}}}
	}
	for _, c := range []struct {
		name string
		doc  []rules.Rule
		want want
	}{
		{"an unknown ALLOW alone matches nothing and is reported",
			[]rules.Rule{{ID: "unknown-allow", Effect: allow, When: unknownWhen()}},
			want{verdict: deny, determinate: deny, codes: list(noMatchingRule), unknownAllows: list("unknown-allow")}},
		{"an unknown ALLOW changes nothing beside a matched rule",
			[]rules.Rule{
				{ID: "unknown-allow", Effect: allow, When: unknownWhen()},
				{ID: "oblige", Effect: withObligations, When: actionNamed("refund"), Obligations: capAmount()},
			},
			want{verdict: withObligations, determinate: withObligations, ids: list("oblige"), codes: list(attached),
				obligations:   []*controlv1.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}},
				unknownAllows: list("unknown-allow")}},
		{"a matched DENY decides beside an unknown ALLOW",
			[]rules.Rule{
				{ID: "unknown-allow", Effect: allow, When: unknownWhen()},
				{ID: "deny", Effect: deny, When: actionNamed("refund")},
			},
			want{verdict: deny, determinate: deny, ids: list("deny"), codes: list(ruleDeny), unknownAllows: list("unknown-allow")}},
		{"unknown ALLOWs are reported in document order, a false one not at all",
			[]rules.Rule{
				{ID: "second", Effect: allow, When: unknownWhen()},
				{ID: "false-allow", Effect: allow, When: actionNamed("archive")},
				{ID: "first", Effect: allow, When: unknownWhen()},
			},
			want{verdict: deny, determinate: deny, codes: list(noMatchingRule), unknownAllows: list("second", "first")}},
		{"an unknown REQUIRE_APPROVAL beside a matched ALLOW",
			[]rules.Rule{
				{ID: "allow", Effect: allow, When: actionNamed("refund")},
				{ID: "unknown-approve", Effect: approval, When: unknownWhen()},
			},
			want{verdict: indeterminate, determinate: allow, ids: list("allow"), undetermined: list("unknown-approve"),
				codes: list(ruleAllow, ruleUndetermined)}},
		{"an unknown ALLOW_WITH_OBLIGATIONS beside a matched ALLOW",
			[]rules.Rule{
				{ID: "allow", Effect: allow, When: actionNamed("refund")},
				{ID: "unknown-oblige", Effect: withObligations, When: unknownWhen(), Obligations: capAmount()},
			},
			want{verdict: indeterminate, determinate: allow, ids: list("allow"), undetermined: list("unknown-oblige"),
				codes: list(ruleAllow, ruleUndetermined)}},
		{"an unknown ALLOW_WITH_OBLIGATIONS beside a matched one",
			[]rules.Rule{
				{ID: "cap", Effect: withObligations, When: actionNamed("refund"), Obligations: capAmount()},
				{ID: "redact", Effect: withObligations, When: unknownWhen(), Obligations: redact()},
			},
			want{verdict: indeterminate, determinate: withObligations, ids: list("cap"), undetermined: list("redact"),
				codes: list(attached, ruleUndetermined)}},
		{"an unknown REQUIRE_APPROVAL beside a matched one",
			[]rules.Rule{
				{ID: "approve", Effect: approval, When: actionNamed("refund")},
				{ID: "approve-capped", Effect: approval, When: unknownWhen(), Obligations: capAmount()},
			},
			want{verdict: indeterminate, determinate: approval, ids: list("approve"), undetermined: list("approve-capped"),
				codes: list(approvalRequired, ruleUndetermined)}},
		{"an unknown ALLOW_WITH_OBLIGATIONS beside a matched REQUIRE_APPROVAL",
			[]rules.Rule{
				{ID: "approve", Effect: approval, When: actionNamed("refund")},
				{ID: "redact", Effect: withObligations, When: unknownWhen(), Obligations: redact()},
			},
			want{verdict: indeterminate, determinate: approval, ids: list("approve"), undetermined: list("redact"),
				codes: list(approvalRequired, ruleUndetermined)}},
		{"two unknown rules give the code once",
			[]rules.Rule{
				{ID: "unknown-approve", Effect: approval, When: unknownWhen()},
				{ID: "unknown-deny", Effect: deny, When: unknownWhen()},
			},
			want{verdict: indeterminate, determinate: deny, undetermined: list("unknown-approve", "unknown-deny"),
				codes: list(ruleUndetermined)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assertResult(t, compile(t, c.doc...).Evaluate(env, match.Inputs{}), c.want)
		})
	}
}

// TestReasonCodesFollowDocumentOrder is the table's order reversed: rules
// listed in precedence order give their codes in that order, so neither order
// is the one the codes are sorted into.
func TestReasonCodesFollowDocumentOrder(t *testing.T) {
	p := compile(t,
		rules.Rule{ID: "deny", Effect: deny, When: actionNamed("refund")},
		rules.Rule{ID: "approve", Effect: approval, When: actionNamed("refund")},
		rules.Rule{ID: "oblige", Effect: withObligations, When: actionNamed("refund"),
			Obligations: []rules.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}}},
		rules.Rule{ID: "allow", Effect: allow, When: actionNamed("refund")},
	)
	assertResult(t, p.Evaluate(envelope(), match.Inputs{}), want{
		verdict: deny, determinate: deny,
		ids:   list("deny", "approve", "oblige", "allow"),
		codes: list(ruleDeny, approvalRequired, attached, ruleAllow),
	})
}

// TestEachReasonOnce: a matched rule contributes its reason, the authored one
// or its effect's own, once each in document order, at the place of the first
// rule that gives it.
func TestEachReasonOnce(t *testing.T) {
	denying := func(id, reason, action string) rules.Rule {
		return rules.Rule{ID: id, Effect: deny, Reason: reason, When: actionNamed(action)}
	}
	for _, c := range []struct {
		name  string
		doc   []rules.Rule
		ids   []string
		codes []string
	}{
		{"reasons that repeat in the order they first came",
			[]rules.Rule{
				denying("boundary", "ENVIRONMENT_BOUNDARY", "refund"),
				denying("plain", "", "refund"),
				denying("boundary-again", "ENVIRONMENT_BOUNDARY", "refund"),
				denying("spelled-out", "RULE_DENY", "refund"),
				denying("scope", "OUT_OF_SCOPE_ACTION", "refund"),
				denying("toxic", "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL", "refund"),
				denying("not-this-one", "OUT_OF_SCOPE_ACTION", "archive"),
			},
			list("boundary", "plain", "boundary-again", "spelled-out", "scope", "toxic"),
			list("ENVIRONMENT_BOUNDARY", ruleDeny, "OUT_OF_SCOPE_ACTION", "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL")},
		// Kept at its last place, the repeated reason would come second.
		{"a reason that repeats after one that does not",
			[]rules.Rule{
				denying("boundary", "ENVIRONMENT_BOUNDARY", "refund"),
				denying("plain", "", "refund"),
				denying("boundary-again", "ENVIRONMENT_BOUNDARY", "refund"),
			},
			list("boundary", "plain", "boundary-again"),
			list("ENVIRONMENT_BOUNDARY", ruleDeny)},
	} {
		t.Run(c.name, func(t *testing.T) {
			assertResult(t, compile(t, c.doc...).Evaluate(envelope(), match.Inputs{}), want{
				verdict: deny, determinate: deny, ids: c.ids, codes: c.codes,
			})
		})
	}
}
