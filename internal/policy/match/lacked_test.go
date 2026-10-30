package match_test

import (
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// TestAnUnknownAllowNamesWhatItLacked: each unknown ALLOW names the inputs
// its unknown constraints lacked, in wire spelling, in the rule's order and
// once each; a constraint that holds is not named.
func TestAnUnknownAllowNamesWhatItLacked(t *testing.T) {
	untrusted := contract.NewFlowState(true, public)
	for _, c := range []struct {
		name  string
		when  rules.When
		env   *controlv1.ActionEnvelope
		in    match.Inputs
		needs []string
	}{
		{"resource id", rules.When{Resource: &rules.ResourceWhen{ID: list("inv-1")}},
			with(func(e *controlv1.ActionEnvelope) { e.Resource.Id = "" }), match.Inputs{}, list("resource.id")},
		{"authentication strength", rules.When{Principal: &rules.PrincipalWhen{AuthnStrength: list("mfa")}},
			with(func(e *controlv1.ActionEnvelope) { e.Principal.AuthnStrength = "" }), match.Inputs{}, list("principal.authn_strength")},
		{"an attribute", rules.When{Principal: &rules.PrincipalWhen{Attributes: map[string][]string{"team": {"payments"}}}},
			with(func(e *controlv1.ActionEnvelope) { e.Principal.Attributes = nil }), match.Inputs{}, list(`principal.attributes["team"]`)},
		{"a label", rules.When{Resource: &rules.ResourceWhen{Labels: map[string][]string{"tier": {"gold"}}}},
			with(func(e *controlv1.ActionEnvelope) { e.Resource.Labels = nil }), match.Inputs{}, list(`resource.labels["tier"]`)},
		{"a host", rules.When{Destination: &rules.DestinationWhen{Host: list("ledger.internal")}},
			with(func(e *controlv1.ActionEnvelope) { e.Destination.Host = "" }), match.Inputs{}, list("destination.host")},
		{"a delegation", rules.When{Delegation: &rules.DelegationWhen{Scopes: list("read")}},
			envelope(), match.Inputs{}, list("delegation")},
		{"data labels", rules.When{Data: &rules.DataWhen{SensitivityAtLeast: internal}},
			with(func(e *controlv1.ActionEnvelope) { e.Data = nil }), match.Inputs{}, list("data.sensitivities")},
		{"a run nobody tracked", rules.When{Flow: &rules.FlowWhen{ToxicAtLeast: confidential}},
			envelope(), match.Inputs{}, list("flow")},
		{"two inputs, in the rule's order, a held one left out",
			rules.When{
				Principal: &rules.PrincipalWhen{ID: list("alice"), AuthnStrength: list("mfa")},
				Resource:  &rules.ResourceWhen{ID: list("inv-1")},
			},
			with(func(e *controlv1.ActionEnvelope) { e.Principal.AuthnStrength, e.Resource.Id = "", "" }), match.Inputs{},
			list("principal.authn_strength", "resource.id")},
		{"one input two constraints lack, once",
			rules.When{Data: &rules.DataWhen{SensitivityAtLeast: confidential}, Flow: &rules.FlowWhen{ToxicAtLeast: confidential}},
			with(func(e *controlv1.ActionEnvelope) { e.Data, e.Destination = nil, nil }), match.Inputs{Flow: untrusted},
			list("data.sensitivities")},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := compile(t, rules.Rule{ID: "under-test", Effect: allow, When: c.when}).Evaluate(c.env, c.in)
			if len(got.UnknownAllows) != 1 || got.UnknownAllows[0].ID != "under-test" || !slices.Equal(got.UnknownAllows[0].Needs, c.needs) {
				t.Errorf("UnknownAllows = %+v, want under-test lacking %q", got.UnknownAllows, c.needs)
			}
		})
	}
}
