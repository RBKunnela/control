package policycompare

import (
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
)

func decided(v controlv1.Verdict, a core.EnforcementAction, codes ...string) side {
	return side{evaluated: true, verdict: v, action: a, codes: codes}
}

func with(s side, obligations ...*controlv1.Obligation) side {
	s.obligations = obligations
	return s
}

var (
	execute     = decided(controlv1.Verdict_VERDICT_ALLOW, core.Execute, "RULE_ALLOW")
	obliged     = decided(controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, core.ExecuteWithObligations, "OBLIGATIONS_ATTACHED")
	obligations = with(obliged, &controlv1.Obligation{Type: "emit_alert"})
	hold        = decided(controlv1.Verdict_VERDICT_REQUIRE_APPROVAL, core.AwaitApproval, "APPROVAL_REQUIRED")
	block       = decided(controlv1.Verdict_VERDICT_DENY, core.Block, "RULE_DENY")
)

// Every ordered pair of the four actions, each with the change written out.
// Holding a call for an approval does not hold it to emit_alert, so the pairs
// between the two move both ways; a block holds every obligation.
func TestClassifyEveryPairOfActions(t *testing.T) {
	sides := map[string]side{"execute": execute, "obligations": obligations, "hold": hold, "block": block}
	want := map[[2]string]Change{
		{"execute", "execute"}: Unchanged, {"execute", "obligations"}: Stricter, {"execute", "hold"}: Stricter, {"execute", "block"}: Stricter,
		{"obligations", "execute"}: Looser, {"obligations", "obligations"}: Unchanged, {"obligations", "hold"}: Other, {"obligations", "block"}: Stricter,
		{"hold", "execute"}: Looser, {"hold", "obligations"}: Other, {"hold", "hold"}: Unchanged, {"hold", "block"}: Stricter,
		{"block", "execute"}: Looser, {"block", "obligations"}: Looser, {"block", "hold"}: Looser, {"block", "block"}: Unchanged,
	}
	if len(want) != 16 {
		t.Fatalf("%d pairs written, want 16", len(want))
	}
	for pair, change := range want {
		if got := classify(sides[pair[0]], sides[pair[1]]); got != change {
			t.Errorf("%s to %s: %s, want %s", pair[0], pair[1], got, change)
		}
	}
}

// The obligations a call must meet order a change with its action; an
// advisory obligation binds nothing.
func TestClassifyObligations(t *testing.T) {
	approver := &controlv1.Obligation{Type: "second_approver"}
	readOnly := &controlv1.Obligation{Type: "read_only"}
	for name, c := range map[string]struct {
		before, after side
		want          Change
	}{
		"second approver dropped":    {with(hold, approver), hold, Looser},
		"second approver added":      {hold, with(hold, approver), Stricter},
		"read_only made advisory":    {with(obliged, readOnly), with(obliged, &controlv1.Obligation{Type: "read_only", Advisory: true}), Looser},
		"advisory made binding":      {with(obliged, &controlv1.Obligation{Type: "read_only", Advisory: true}), with(obliged, readOnly), Stricter},
		"one obligation for another": {obligations, with(obliged, readOnly), Other},
		"an obligation added":        {obligations, with(obliged, obligations.obligations[0], readOnly), Stricter},
		"an obligation dropped":      {with(obliged, obligations.obligations[0], readOnly), obligations, Looser},
		"a cap raised": {with(obliged, &controlv1.Obligation{Type: "cap_amount", Params: map[string]string{"max": "100"}}),
			with(obliged, &controlv1.Obligation{Type: "cap_amount", Params: map[string]string{"max": "1000000"}}), Other},
		"emit_alert run to a bare hold":   {obligations, hold, Other},
		"a bare hold to emit_alert run":   {hold, obligations, Other},
		"run to advisory obligations":     {execute, with(obliged, &controlv1.Obligation{Type: "emit_alert", Advisory: true}), Other},
		"advisory obligations to run":     {with(obliged, &controlv1.Obligation{Type: "emit_alert", Advisory: true}), execute, Other},
		"advisory obligations to a hold":  {with(obliged, &controlv1.Obligation{Type: "emit_alert", Advisory: true}), hold, Stricter},
		"a held approver to a block":      {with(hold, approver), block, Stricter},
		"a block to a held approver":      {block, with(hold, approver), Looser},
		"emit_alert run to a held alert":  {obligations, with(hold, obligations.obligations[0]), Stricter},
		"a held alert to emit_alert run":  {with(hold, obligations.obligations[0]), obligations, Looser},
		"a held alert to a held approver": {with(hold, obligations.obligations[0]), with(hold, approver), Other},
	} {
		if got := classify(c.before, c.after); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

// The same action and the same binding obligations with anything else
// different is other, never unchanged.
func TestClassifySameActionOtherwiseDifferent(t *testing.T) {
	for name, c := range map[string]struct{ before, after side }{
		"another verdict": {block, decided(controlv1.Verdict_VERDICT_INDETERMINATE, core.Block, "RULE_DENY")},
		"another code":    {block, decided(controlv1.Verdict_VERDICT_DENY, core.Block, "NO_MATCHING_RULE")},
		"a code more":     {block, decided(controlv1.Verdict_VERDICT_DENY, core.Block, "RULE_DENY", "RULE_UNDETERMINED")},
		"codes reordered": {decided(controlv1.Verdict_VERDICT_DENY, core.Block, "A", "B"), decided(controlv1.Verdict_VERDICT_DENY, core.Block, "B", "A")},
		"an advisory obligation added": {obligations, with(obliged, obligations.obligations[0],
			&controlv1.Obligation{Type: "read_only", Advisory: true})},
		"another obligation param": {obligations, with(obliged, &controlv1.Obligation{Type: "emit_alert", Params: map[string]string{"to": "x"}})},
	} {
		if got := classify(c.before, c.after); got != Other {
			t.Errorf("%s: %s, want other", name, got)
		}
	}
	same := with(decided(obligations.verdict, obligations.action, "OBLIGATIONS_ATTACHED"), &controlv1.Obligation{Type: "emit_alert"})
	if got := classify(obligations, same); got != Unchanged {
		t.Errorf("equal decisions built apart: %s, want unchanged", got)
	}
}

// A side that was not evaluated makes the case unknown whatever the other
// side decided, and so does an action this build does not name.
func TestClassifyUnevaluatedIsUnknown(t *testing.T) {
	for name, c := range map[string]struct{ before, after side }{
		"before not evaluated": {side{}, block},
		"after not evaluated":  {block, side{}},
		"neither":              {side{}, side{}},
		"an unnamed action":    {block, side{evaluated: true, verdict: block.verdict, action: core.EnforcementAction(9), codes: block.codes}},
	} {
		if got := classify(c.before, c.after); got != Unknown {
			t.Errorf("%s: %s, want unknown", name, got)
		}
	}
}
