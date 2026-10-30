package match_test

import (
	"slices"
	"testing"

	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// TestExplainDecidesAsEvaluateDoes: over documents and calls nobody chose,
// Explain's result is Evaluate's, and it traces every rule once, in document
// order, under its own id and effect.
func TestExplainDecidesAsEvaluateDoes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		spec, fixed := withAnchor(rt, drawDocument(rt))
		env, in := drawEnvelope(rt), drawInputs(rt)
		fixed.set(env)
		program := mustCompile(rt, spec.build())

		want := program.Evaluate(env, in)
		got, traces := program.Explain(env, in)
		assertSame(rt, "Explain against Evaluate", want, got)
		fixed.check(rt, got)
		ids := make([]string, len(traces))
		for i, tr := range traces {
			ids[i] = tr.ID
			if tr.Effect != spec.effects()[tr.ID] {
				rt.Fatalf("rule %s traced as %s, written as %s", tr.ID, tr.Effect, spec.effects()[tr.ID])
			}
		}
		if !slices.Equal(ids, spec.ids()) {
			rt.Fatalf("traced rules %q, the document's are %q", ids, spec.ids())
		}
	})
}

// TestEveryTraceAgreesWithItsValue: a rule is no when a constraint it lists
// does not hold, unknown when none fails and one is unknown, matched when it
// lists none; and the result's lists are the traces read that way.
func TestEveryTraceAgreesWithItsValue(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		spec, fixed := withAnchor(rt, drawDocument(rt))
		env, in := drawEnvelope(rt), drawInputs(rt)
		fixed.set(env)
		result, traces := mustCompile(rt, spec.build()).Explain(env, in)
		var matched, undetermined []string
		var unknownAllows []match.UnknownAllow
		for _, tr := range traces {
			assertTraceAgrees(rt, tr)
			switch {
			case tr.Value == match.ValueYes:
				matched = append(matched, tr.ID)
			case tr.Value == match.ValueUnknown && tr.Effect != allow:
				undetermined = append(undetermined, tr.ID)
			case tr.Value == match.ValueUnknown:
				var needs []string
				for _, u := range tr.Unknown {
					for _, n := range u.Needs {
						if !slices.Contains(needs, n) {
							needs = append(needs, n)
						}
					}
				}
				unknownAllows = append(unknownAllows, match.UnknownAllow{ID: tr.ID, Needs: needs})
			}
		}
		if !slices.Equal(matched, result.RuleIDs) || !slices.Equal(undetermined, result.Indeterminate) ||
			!sameUnknownAllows(unknownAllows, result.UnknownAllows) {
			rt.Fatalf("traces give matched %q, undetermined %q and unknown allows %+v, the result %s",
				matched, undetermined, unknownAllows, summary(result))
		}
	})
}

func assertTraceAgrees(f failer, tr match.RuleTrace) {
	f.Helper()
	var want match.Value
	switch {
	case len(tr.No) > 0:
		want = match.ValueNo
	case len(tr.Unknown) > 0:
		want = match.ValueUnknown
	default:
		want = match.ValueYes
	}
	if tr.Value != want {
		f.Fatalf("rule %s has value %d with no=%q unknown=%v", tr.ID, tr.Value, tr.No, tr.Unknown)
	}
	for _, u := range tr.Unknown {
		if u.Field == "" || len(u.Needs) == 0 || slices.Contains(u.Needs, "") {
			f.Fatalf("rule %s lists an unknown constraint that names nothing: %+v", tr.ID, u)
		}
	}
}

// TestExplainNamesWhatEachConstraintReads: each constraint is named by the
// document's field and, when unknown, by the input it lacked.
func TestExplainNamesWhatEachConstraintReads(t *testing.T) {
	tracked := contract.NewFlowState(true, confidential)
	rows := map[string]struct {
		when    rules.When
		env     *controlv1.ActionEnvelope
		in      match.Inputs
		value   match.Value
		no      []string
		unknown []match.Unread
	}{
		"a field the call leaves out": {
			when:    rules.When{Resource: &rules.ResourceWhen{Environment: list("prod")}, Action: &rules.ActionWhen{Effect: []controlv1.EffectClass{read}}},
			env:     with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "" }),
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: "when.resource.environment", Needs: list("resource.environment")}},
		},
		"a field that does not hold, beside one that is unknown": {
			when: rules.When{
				Principal: &rules.PrincipalWhen{AuthnStrength: list("hardware")},
				Resource:  &rules.ResourceWhen{Environment: list("prod")},
			},
			env:     with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "" }),
			value:   match.ValueNo,
			no:      list("when.principal.authnStrength"),
			unknown: []match.Unread{{Field: "when.resource.environment", Needs: list("resource.environment")}},
		},
		"a map key, quoted so that it cannot close the brackets": {
			when:    rules.When{Resource: &rules.ResourceWhen{Labels: map[string][]string{`a"] b`: list("gold")}}},
			env:     envelope(),
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: `when.resource.labels["a\"] b"]`, Needs: list(`resource.labels["a\"] b"]`)}},
		},
		"a delegated scope without a chain": {
			when:    rules.When{Delegation: &rules.DelegationWhen{Scopes: list("refunds")}},
			env:     envelope(),
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: "when.delegation.scopes", Needs: list("delegation")}},
		},
		"a data floor and a call with no label": {
			when:    rules.When{Data: &rules.DataWhen{SensitivityAtLeast: confidential}},
			env:     with(func(e *controlv1.ActionEnvelope) { e.Data = nil }),
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: "when.data.sensitivityAtLeast", Needs: list("data.sensitivities")}},
		},
		"a toxic flow in a run nobody tracked": {
			when:    rules.When{Flow: &rules.FlowWhen{ToxicAtLeast: confidential}},
			env:     envelope(),
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: "when.flow.toxicAtLeast", Needs: list("flow")}},
		},
		"a toxic flow whose run read nothing known and whose call carries no label": {
			when: rules.When{Flow: &rules.FlowWhen{ToxicAtLeast: confidential}},
			env: with(func(e *controlv1.ActionEnvelope) {
				e.Data = nil
				e.Destination.TrustZone = zoneExternal
			}),
			in:      match.Inputs{Flow: contract.NewFlowState(true, unlabelled)},
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: "when.flow.toxicAtLeast", Needs: list("flow.max_sensitivity_read", "data.sensitivities")}},
		},
		"a toxic flow whose run read something known below the floor": {
			when: rules.When{Flow: &rules.FlowWhen{ToxicAtLeast: restricted}},
			env: with(func(e *controlv1.ActionEnvelope) {
				e.Data = nil
				e.Destination.TrustZone = zoneExternal
			}),
			in:      match.Inputs{Flow: tracked},
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: "when.flow.toxicAtLeast", Needs: list("data.sensitivities")}},
		},
		"no answer from the decision point": {
			when:    rules.When{Action: &rules.ActionWhen{Name: list("refund")}, External: &rules.ExternalWhen{Denies: true}},
			env:     envelope(),
			value:   match.ValueUnknown,
			unknown: []match.Unread{{Field: "when.external.denies", Needs: list("external")}},
		},
		"an answer that does not deny": {
			when:  rules.When{Action: &rules.ActionWhen{Name: list("refund")}, External: &rules.ExternalWhen{Denies: true}},
			env:   envelope(),
			in:    match.Inputs{External: match.ExternalAllows},
			value: match.ValueNo,
			no:    list("when.external.denies"),
		},
		"every field present and holding": {
			when:  rules.When{Principal: &rules.PrincipalWhen{Attributes: map[string][]string{"team": list("payments")}}, Agent: &rules.AgentWhen{Framework: list("langgraph")}},
			env:   envelope(),
			value: match.ValueYes,
		},
	}
	for name, row := range rows {
		t.Run(name, func(t *testing.T) {
			p := compile(t, rules.Rule{ID: "r", Effect: deny, When: row.when})
			_, traces := p.Explain(row.env, row.in)
			if len(traces) != 1 {
				t.Fatalf("traced %d rules, the document has 1", len(traces))
			}
			tr := traces[0]
			if tr.Value != row.value || !slices.Equal(tr.No, row.no) || !sameUnread(tr.Unknown, row.unknown) {
				t.Errorf("traced value %d no=%q unknown=%+v, want value %d no=%q unknown=%+v",
					tr.Value, tr.No, tr.Unknown, row.value, row.no, row.unknown)
			}
		})
	}
}

func sameUnread(a, b []match.Unread) bool {
	return slices.EqualFunc(a, b, func(x, y match.Unread) bool { return x.Field == y.Field && slices.Equal(x.Needs, y.Needs) })
}

// TestExplainOnNoProgramTracesNothing: a program nobody compiled evaluated
// nothing, which the nil traces say, and its result is Evaluate's.
func TestExplainOnNoProgramTracesNothing(t *testing.T) {
	for name, p := range map[string]*match.Program{"nil": nil, "zero": {}} {
		got, traces := p.Explain(envelope(), match.Inputs{})
		if traces != nil {
			t.Errorf("%s program traced %v", name, traces)
		}
		assertSame(t, name+" program", p.Evaluate(envelope(), match.Inputs{}), got)
	}
}

// TestEvaluateAllocatesNoTrace pins what Evaluate allocates on a call a
// three-rule document decides, so that the explanation never reaches the
// request path; Explain on the same call allocates more, which shows the
// count can tell the two apart.
func TestEvaluateAllocatesNoTrace(t *testing.T) {
	p := allocProgram(t)
	env, in := envelope(), match.Inputs{Flow: contract.NewFlowState(false, public)}
	evaluate := testing.AllocsPerRun(100, func() { p.Evaluate(env, in) })
	explain := testing.AllocsPerRun(100, func() { p.Explain(env, in) })
	if evaluate != evaluateAllocs {
		t.Errorf("Evaluate allocates %v times per call, pinned at %v", evaluate, evaluateAllocs)
	}
	if explain <= evaluate {
		t.Errorf("Explain allocates %v times per call and Evaluate %v; the count cannot tell them apart", explain, evaluate)
	}
}

// evaluateAllocs is Evaluate's count on allocProgram's call.
const evaluateAllocs = 5

func allocProgram(t testing.TB) *match.Program {
	return compile(t,
		rules.Rule{ID: "no-prod-deletes", Effect: deny, When: rules.When{
			Action:   &rules.ActionWhen{Effect: []controlv1.EffectClass{remove}},
			Resource: &rules.ResourceWhen{Environment: list("prod")},
		}},
		rules.Rule{ID: "reads", Effect: allow, When: rules.When{Action: &rules.ActionWhen{Effect: []controlv1.EffectClass{read}}}},
		rules.Rule{ID: "teams", Effect: approval, When: rules.When{Principal: &rules.PrincipalWhen{
			Attributes: map[string][]string{"team": list("payments")},
		}}},
	)
}
