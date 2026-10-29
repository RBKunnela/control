package contract_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// breaker is one way to break an envelope, and the paths it clears, so a
// draw can tell whether an effect's requirements are still present.
type breaker struct {
	name   string
	clears []string
	mutate func(*controlv1.ActionEnvelope)
}

// breakers are edits each rule of Validate but the effect's refuses, and edits
// no rule refuses, so a draw mixes accepted and refused envelopes.
func breakers() []breaker {
	return []breaker{
		{"schema version of another major", nil, func(e *controlv1.ActionEnvelope) { e.SchemaVersion = "9.0" }},
		{"no schema version", nil, func(e *controlv1.ActionEnvelope) { e.SchemaVersion = "" }},
		{"no request id", nil, func(e *controlv1.ActionEnvelope) { e.RequestId = "" }},
		{"no principal id", nil, func(e *controlv1.ActionEnvelope) { e.Principal.Id = "" }},
		{"an action name past its bound", nil, func(e *controlv1.ActionEnvelope) { e.Action.Name = strings.Repeat("n", contract.MaxStringBytes+1) }},
		{"a zero proposal time", nil, func(e *controlv1.ActionEnvelope) { e.OccurredAt = &timestamppb.Timestamp{} }},
		{"an undeclared trust zone", nil, func(e *controlv1.ActionEnvelope) {
			e.Destination = &controlv1.Destination{TrustZone: controlv1.TrustZone(77)}
		}},
		{"a hop from a stranger", nil, func(e *controlv1.ActionEnvelope) {
			e.Agent = &controlv1.Agent{Id: "agent-1"}
			e.Delegation = []*controlv1.Delegation{expiring("stranger", "agent-1")}
		}},
		{"a host with a port", []string{"destination.trust_zone"}, func(e *controlv1.ActionEnvelope) {
			e.Destination = &controlv1.Destination{Host: "api.example.com:443"}
		}},
		{"a label that says nothing", nil, func(e *controlv1.ActionEnvelope) {
			e.Data = &controlv1.DataLabels{Sensitivities: []controlv1.Sensitivity{controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED}}
		}},
		{"an upper-case hash", nil, func(e *controlv1.ActionEnvelope) {
			e.Arguments = &controlv1.Arguments{CanonicalHash: "sha256:" + strings.Repeat("AB", 32)}
		}},
		{"a preview with no profile", []string{"arguments.canonical_hash"}, func(e *controlv1.ActionEnvelope) {
			e.Arguments = &controlv1.Arguments{RedactedPreview: "raw"}
		}},
		{"no resource", []string{"resource.type", "resource.id", "resource.environment", "resource.tenant_id"}, func(e *controlv1.ActionEnvelope) { e.Resource = nil }},
		{"no principal tenant", []string{"principal.tenant_id"}, func(e *controlv1.ActionEnvelope) { e.Principal.TenantId = "" }},
		{"a known host", nil, func(e *controlv1.ActionEnvelope) {
			e.Destination = &controlv1.Destination{Host: "api.example.com", TrustZone: controlv1.TrustZone_TRUST_ZONE_PARTNER}
		}},
		{"a run context", nil, func(e *controlv1.ActionEnvelope) { e.Context = &controlv1.RunContext{RunId: "run-1"} }},
	}
}

func declaredEffects() []controlv1.EffectClass {
	var out []controlv1.EffectClass
	values := controlv1.EffectClass(0).Descriptor().Values()
	for i := range values.Len() {
		if n := values.Get(i).Number(); n != 0 {
			out = append(out, controlv1.EffectClass(n))
		}
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// TestValidateUnclassifiedAgreesWithValidateOnAClassifiedEnvelope: over
// envelopes with a declared effect and every path the effect requires, the
// two return the same refusal, or both accept.
func TestValidateUnclassifiedAgreesWithValidateOnAClassifiedEnvelope(t *testing.T) {
	all := breakers()
	rapid.Check(t, func(rt *rapid.T) {
		effect := rapid.SampledFrom(declaredEffects()).Draw(rt, "effect")
		required := effectsUnderTest()[effect]
		env := satisfying(effect, required)
		picked := rapid.SliceOfNDistinct(rapid.IntRange(0, len(all)-1), 0, 3, rapid.ID[int]).Draw(rt, "breakers")
		for _, i := range picked {
			b := all[i]
			if slices.ContainsFunc(b.clears, func(p string) bool { return slices.Contains(required, p) }) {
				return
			}
			b.mutate(env)
		}
		want, got := contract.Validate(env), contract.ValidateUnclassified(env)
		if errText(got) != errText(want) {
			rt.Fatalf("on a %s envelope ValidateUnclassified = %v, Validate = %v", effect, got, want)
		}
	})
}

// valueRule is one rule of checkValues, an edit that breaks only that rule,
// and the refusal the rule gives, written out rather than read from the code.
type valueRule struct {
	name   string
	field  string
	want   error
	mutate func(*controlv1.ActionEnvelope)
}

func valueRules() []valueRule {
	chain := func(e *controlv1.ActionEnvelope, hops ...*controlv1.Delegation) {
		e.Agent = &controlv1.Agent{Id: "agent-1"}
		e.Delegation = hops
	}
	issued := time.Date(2026, 9, 9, 11, 0, 0, 0, time.UTC)
	return []valueRule{
		{"a hop with no from", "delegation[0].from", contract.ErrMissingField, func(e *controlv1.ActionEnvelope) { chain(e, expiring("", "agent-1")) }},
		{"a hop with no to", "delegation[0].to", contract.ErrMissingField, func(e *controlv1.ActionEnvelope) { chain(e, expiring("user-1", "")) }},
		{"a hop with no expiry", "delegation[0].expires_at", contract.ErrMissingField, func(e *controlv1.ActionEnvelope) {
			hop := expiring("user-1", "agent-1")
			hop.ExpiresAt = nil
			chain(e, hop)
		}},
		{"a hop that expires before it was issued", "delegation[0].expires_at", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			hop := expiring("user-1", "agent-1")
			hop.ExpiresAt = timestamppb.New(issued.Add(-time.Second))
			chain(e, hop)
		}},
		{"a chain that does not start at the principal", "delegation[0].from", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			chain(e, expiring("stranger", "agent-1"))
		}},
		{"a hop that does not continue the one before", "delegation[1].from", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			chain(e, expiring("user-1", "party-1"), expiring("party-2", "agent-1"))
		}},
		{"a chain that does not end at the agent", "delegation[0].to", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			chain(e, expiring("user-1", "party-1"))
		}},
		{"a host with a port", "destination.host", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			e.Destination = &controlv1.Destination{Host: "api.example.com:443"}
		}},
		{"a label that says nothing", "data.sensitivities[0]", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			e.Data = &controlv1.DataLabels{Sensitivities: []controlv1.Sensitivity{controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED}}
		}},
		{"an upper-case hash", "arguments.canonical_hash", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			e.Arguments = &controlv1.Arguments{CanonicalHash: "sha256:" + strings.Repeat("AB", 32)}
		}},
		{"a preview with no profile", "arguments.redacted_preview", contract.ErrInvalidValue, func(e *controlv1.ActionEnvelope) {
			e.Arguments = &controlv1.Arguments{RedactedPreview: "raw"}
		}},
	}
}

// unclassified is the base envelope with no effect class, which every rule
// but the effect's accepts.
func unclassified() *controlv1.ActionEnvelope {
	env := valid()
	env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	return env
}

// TestValidateUnclassifiedHoldsEveryValueRule: an envelope with no effect
// that breaks one rule of the values Validate checks after the effect is
// refused for that rule, however the rest of it is drawn.
func TestValidateUnclassifiedHoldsEveryValueRule(t *testing.T) {
	if err := contract.ValidateUnclassified(unclassified()); err != nil {
		t.Fatalf("the base envelope with no effect is refused, so no case below proves anything: %v", err)
	}
	var lacks *contract.ValidationError
	if err := contract.Validate(unclassified()); !errors.As(err, &lacks) || lacks.Field != "action.effect" {
		t.Fatalf("Validate of the base envelope with no effect = %v, want the missing effect", err)
	}
	rules := valueRules()
	rapid.Check(t, func(rt *rapid.T) {
		rule := rules[rapid.IntRange(0, len(rules)-1).Draw(rt, "rule")]
		env := unclassified()
		if rapid.Bool().Draw(rt, "with a run context") {
			env.Context = &controlv1.RunContext{RunId: "run-1", Tags: []string{"k=v"}}
		}
		if rapid.Bool().Draw(rt, "without a resource") {
			env.Resource = nil
		}
		if err := contract.ValidateUnclassified(env); err != nil {
			rt.Fatalf("the drawn envelope is refused before %s is applied: %v", rule.name, err)
		}
		rule.mutate(env)
		err := contract.ValidateUnclassified(env)
		var ve *contract.ValidationError
		if !errors.Is(err, rule.want) || !errors.As(err, &ve) || ve.Field != rule.field {
			rt.Fatalf("%s: ValidateUnclassified = %v, want %v naming %q", rule.name, err, rule.want, rule.field)
		}
	})
}

// TestValidateUnclassifiedSkipsOnlyTheEffect: the missing effect and what an
// effect would require are the two rules it does not apply.
func TestValidateUnclassifiedSkipsOnlyTheEffect(t *testing.T) {
	transact := satisfying(controlv1.EffectClass_EFFECT_CLASS_TRANSACT, nil)
	if err := contract.ValidateUnclassified(transact); err != nil {
		t.Errorf("ValidateUnclassified of a TRANSACT lacking what it requires = %v, want nil", err)
	}
	assertRefused(t, contract.Validate(transact), contract.ErrMissingField, "arguments.canonical_hash")
	assertRefused(t, contract.ValidateUnclassified(nil), contract.ErrMissingField, "")
}
