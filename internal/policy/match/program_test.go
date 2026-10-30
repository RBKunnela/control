package match_test

import (
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// TestProgramKeepsNothingOfTheDocument changes, after Compile, every part of
// the document a program could hold a reference to, and expects the answer the
// document gave when it was compiled.
func TestProgramKeepsNothingOfTheDocument(t *testing.T) {
	doc := document(rules.Rule{
		ID: "cap", Effect: withObligations,
		Obligations: []rules.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}},
		When: rules.When{
			Action:     &rules.ActionWhen{Name: list("refund"), Effect: []controlv1.EffectClass{read}},
			Principal:  &rules.PrincipalWhen{Attributes: map[string][]string{"team": {"payments"}}},
			Delegation: &rules.DelegationWhen{Scopes: list("admin")},
		},
	})
	p, err := match.Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	r := &doc.Rules[0]
	r.ID = "renamed"
	r.Effect = deny
	r.Obligations[0].Type = "read_only"
	r.Obligations[0].Params["max"] = "999999"
	r.Obligations[0].Params["currency"] = "EUR"
	r.Obligations = append(r.Obligations, rules.Obligation{Type: "emit_alert"})
	r.When.Action.Name[0] = "archive"
	r.When.Action.Effect[0] = write
	r.When.Principal.Attributes["team"][0] = "legal"
	r.When.Principal.Attributes["role"] = list("admin")
	r.When.Delegation.Scopes[0] = "nobody"
	r.When.Resource = &rules.ResourceWhen{Environment: list("staging")}
	doc.Rules = append(doc.Rules, rules.Rule{ID: "deny-all", Effect: deny, When: actionNamed("refund")})

	assertResult(t, p.Evaluate(envelope(), match.Inputs{Delegated: true, Scopes: list("admin")}), want{
		verdict: withObligations, determinate: withObligations,
		ids: list("cap"), codes: list(attached),
		obligations: []*controlv1.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}},
	})
}

// TestResultSharesNothingWithTheProgram: a caller that rewrites what it got
// back changes nothing the next caller gets.
func TestResultSharesNothingWithTheProgram(t *testing.T) {
	p := compile(t,
		rules.Rule{ID: "cap", Effect: withObligations, When: actionNamed("refund"),
			Obligations: []rules.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}}},
		// False for the call that proceeds, unknown for the one that does not.
		rules.Rule{ID: "approve-staging", Effect: approval,
			When: rules.When{Resource: &rules.ResourceWhen{Environment: list("staging")}}},
	)
	proceeding := envelope()
	undecided := with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "" })

	first := p.Evaluate(proceeding, match.Inputs{})
	first.Obligations[0].Type = "read_only"
	first.Obligations[0].Params["max"] = "0"
	scribble(first.RuleIDs)
	scribble(first.ReasonCodes)
	obligations := first.Obligations[:cap(first.Obligations)]
	for i := range obligations {
		obligations[i] = &controlv1.Obligation{Type: "emit_alert"}
	}
	scribble(p.Evaluate(undecided, match.Inputs{}).Indeterminate)

	assertResult(t, p.Evaluate(proceeding, match.Inputs{}), want{
		verdict: withObligations, determinate: withObligations,
		ids: list("cap"), codes: list(attached),
		obligations: []*controlv1.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}},
	})
	assertResult(t, p.Evaluate(undecided, match.Inputs{}), want{
		verdict: indeterminate, determinate: withObligations,
		ids: list("cap"), undetermined: list("approve-staging"), codes: list(attached, ruleUndetermined),
	})
}

// scribble overwrites every slot of the array behind s, spare capacity
// included, so a result sharing an array with the program would carry the
// change into the next one.
func scribble(s []string) {
	full := s[:cap(s)]
	for i := range full {
		full[i] = "tampered"
	}
}

// TestEvaluateLeavesItsArgumentsAlone: neither the envelope nor the caller's
// scopes change.
func TestEvaluateLeavesItsArgumentsAlone(t *testing.T) {
	p := compile(t,
		rules.Rule{ID: "scoped", Effect: approval, When: rules.When{Delegation: &rules.DelegationWhen{Scopes: list("read")}}},
		rules.Rule{ID: "toxic", Effect: deny, When: rules.When{Flow: &rules.FlowWhen{ToxicAtLeast: confidential}}},
		rules.Rule{ID: "labelled", Effect: withObligations, When: rules.When{Data: &rules.DataWhen{SensitivityAtLeast: public}},
			Obligations: []rules.Obligation{{Type: "redact_fields"}}},
	)
	// Every list in the envelope holds two entries or more, out of order, so
	// an evaluator that sorted one in place changes it.
	env := with(func(e *controlv1.ActionEnvelope) {
		e.Data.Sensitivities = []controlv1.Sensitivity{secret, public}
		e.Delegation = []*controlv1.Delegation{
			{From: "alice", To: "agent-7", Scopes: list("write", "read")},
			{From: "agent-7", To: "agent-9", Scopes: list("write", "read")},
		}
	})
	before := proto.Clone(env)
	// Out of order on purpose: an evaluator that sorted them in place shows here.
	scopes := list("write", "read")

	got := p.Evaluate(env, match.Inputs{Flow: contract.NewFlowState(true, secret), Delegated: true, Scopes: scopes})

	assertResult(t, got, want{
		verdict: approval, determinate: approval,
		ids: list("scoped", "labelled"), codes: list(approvalRequired, attached),
		obligations: []*controlv1.Obligation{{Type: "redact_fields"}},
	})
	if !proto.Equal(env, before) {
		t.Error("Evaluate changed the envelope it was given")
	}
	if !slices.Equal(scopes, list("write", "read")) {
		t.Errorf("Evaluate changed the caller's scopes to %q", scopes)
	}
}

// TestConcurrentEvaluation shares one program across goroutines, each of which
// rewrites what it gets back. Run with -race.
func TestConcurrentEvaluation(t *testing.T) {
	p := compile(t,
		rules.Rule{ID: "cap-refunds", Effect: withObligations, When: actionNamed("refund"),
			Obligations: []rules.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}}},
		rules.Rule{ID: "deny-staging", Effect: deny, When: rules.When{Resource: &rules.ResourceWhen{Environment: list("staging")}}},
		rules.Rule{ID: "approve-admin", Effect: approval, When: rules.When{Delegation: &rules.DelegationWhen{Scopes: list("admin")}}},
	)
	capped := []*controlv1.Obligation{{Type: "cap_amount", Params: map[string]string{"max": "100"}}}
	cases := []struct {
		env         *controlv1.ActionEnvelope
		in          match.Inputs
		verdict     controlv1.Verdict
		obligations []*controlv1.Obligation
	}{
		{envelope(), match.Inputs{Delegated: true}, withObligations, capped},
		{with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "staging" }), match.Inputs{Delegated: true}, deny, nil},
		{envelope(), match.Inputs{Delegated: true, Scopes: list("admin")}, approval, capped},
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				c := cases[(g+i)%len(cases)]
				got := p.Evaluate(c.env, c.in)
				if got.Verdict != c.verdict || !sameObligations(got.Obligations, c.obligations) {
					t.Errorf("goroutine %d, call %d: %s, want %s with %s", g, i, summary(got), c.verdict, describe(c.obligations))
					return
				}
				for _, o := range got.Obligations {
					o.Params["max"] = "0"
				}
			}
		})
	}
	wg.Wait()
}

// TestProgramNobodyCompiled: nothing evaluated the call, which is neither a
// match nor "no rule matched".
func TestProgramNobodyCompiled(t *testing.T) {
	var zero match.Program
	for _, c := range []struct {
		name string
		p    *match.Program
	}{{"nil", nil}, {"the zero value", &zero}} {
		t.Run(c.name, func(t *testing.T) {
			assertResult(t, c.p.Evaluate(envelope(), match.Inputs{}), want{
				verdict: indeterminate, determinate: deny, codes: list("POLICY_UNAVAILABLE"),
			})
		})
	}
}

// TestNoEnvelope: every field is absent, so a restrictive rule over any of them
// is indeterminate and an ALLOW over any of them matches nothing and is
// reported unknown.
func TestNoEnvelope(t *testing.T) {
	p := compile(t,
		rules.Rule{ID: "allow-refunds", Effect: allow, When: actionNamed("refund")},
		rules.Rule{ID: "deny-bob", Effect: deny, When: rules.When{Principal: &rules.PrincipalWhen{ID: list("bob")}}},
	)
	assertResult(t, p.Evaluate(nil, match.Inputs{}), want{
		verdict: indeterminate, determinate: deny, undetermined: list("deny-bob"), codes: list(ruleUndetermined),
		unknownAllows: list("allow-refunds"),
	})
}

func TestCompileRefusesNoDocument(t *testing.T) {
	p, err := match.Compile(nil)
	if err == nil || p != nil {
		t.Fatalf("Compile(nil) = %v, %v; want a refusal and no program", p, err)
	}
}

// TestEmptyDocumentDeniesEverything is the refusal above's accepting twin: a
// document with no rules compiles, and there is no implicit allow.
func TestEmptyDocumentDeniesEverything(t *testing.T) {
	p, err := match.Compile(document())
	if err != nil {
		t.Fatalf("Compile refused a document with no rules: %v", err)
	}
	assertResult(t, p.Evaluate(envelope(), match.Inputs{}), want{
		verdict: deny, determinate: deny, codes: list(noMatchingRule),
	})
}
