package match_test

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// truth is the value ADR-0012 gives a constraint.
type truth int

const (
	holds truth = iota + 1
	fails
	unknown
)

// constraintCase is one constraint against one call. refused records that
// Validate refuses the envelope, which makes the row a defensive one: the
// kernel validates first and never sends it.
type constraintCase struct {
	name    string
	when    rules.When
	env     *controlv1.ActionEnvelope
	in      match.Inputs
	want    truth
	refused bool
}

// checkConstraints reads each constraint's value through the verdicts ADR-0012
// gives it. A lone REQUIRE_APPROVAL rule is REQUIRE_APPROVAL when it holds, no
// match when it fails and INDETERMINATE when it cannot be told; a lone ALLOW
// rule is ALLOW when it holds, no match otherwise, and reported among the
// unknown allows when it cannot be told.
func checkConstraints(t *testing.T, cases []constraintCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := contract.Validate(c.env); (err != nil) != c.refused {
				t.Errorf("Validate = %v, and the row says refused is %t", err, c.refused)
			}
			restrictive := want{verdict: approval, determinate: approval, ids: list("under-test"), codes: list(approvalRequired)}
			permissive := want{verdict: allow, determinate: allow, ids: list("under-test"), codes: list(ruleAllow)}
			nothing := want{verdict: deny, determinate: deny, codes: list(noMatchingRule)}
			switch c.want {
			case holds:
			case fails:
				restrictive, permissive = nothing, nothing
			case unknown:
				restrictive = want{verdict: indeterminate, determinate: deny, undetermined: list("under-test"), codes: list(ruleUndetermined)}
				permissive = want{verdict: deny, determinate: deny, codes: list(noMatchingRule), unknownAllows: list("under-test")}
			default:
				t.Fatal("the row states no value")
			}
			t.Run("as REQUIRE_APPROVAL", func(t *testing.T) {
				p := compile(t, rules.Rule{ID: "under-test", Effect: approval, When: c.when})
				assertResult(t, p.Evaluate(c.env, c.in), restrictive)
			})
			t.Run("as ALLOW", func(t *testing.T) {
				p := compile(t, rules.Rule{ID: "under-test", Effect: allow, When: c.when})
				assertResult(t, p.Evaluate(c.env, c.in), permissive)
			})
		})
	}
}

func TestPrincipalConstraints(t *testing.T) {
	principal := func(w rules.PrincipalWhen) rules.When { return rules.When{Principal: &w} }
	edit := func(f func(*controlv1.Principal)) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) { f(e.Principal) })
	}
	checkConstraints(t, []constraintCase{
		{name: "id holds", when: principal(rules.PrincipalWhen{ID: list("alice")}), env: envelope(), want: holds},
		{name: "id is one of several", when: principal(rules.PrincipalWhen{ID: list("bob", "alice")}), env: envelope(), want: holds},
		{name: "id fails", when: principal(rules.PrincipalWhen{ID: list("bob")}), env: envelope(), want: fails},
		{name: "id differs in case", when: principal(rules.PrincipalWhen{ID: list("Alice")}), env: envelope(), want: fails},
		{name: "id is a prefix of the value", when: principal(rules.PrincipalWhen{ID: list("ali")}), env: envelope(), want: fails},
		{name: "id absent", when: principal(rules.PrincipalWhen{ID: list("alice")}),
			env: edit(func(p *controlv1.Principal) { p.Id = "" }), want: unknown, refused: true},
		{name: "no principal at all", when: principal(rules.PrincipalWhen{ID: list("alice")}),
			env: with(func(e *controlv1.ActionEnvelope) { e.Principal = nil }), want: unknown, refused: true},
		{name: "type holds", when: principal(rules.PrincipalWhen{Type: list("user")}), env: envelope(), want: holds},
		{name: "type fails", when: principal(rules.PrincipalWhen{Type: list("service")}), env: envelope(), want: fails},
		{name: "type absent", when: principal(rules.PrincipalWhen{Type: list("user")}),
			env: edit(func(p *controlv1.Principal) { p.Type = "" }), want: unknown},
		{name: "authnStrength holds", when: principal(rules.PrincipalWhen{AuthnStrength: list("mfa")}), env: envelope(), want: holds},
		{name: "authnStrength fails", when: principal(rules.PrincipalWhen{AuthnStrength: list("aal3")}), env: envelope(), want: fails},
		{name: "authnStrength absent", when: principal(rules.PrincipalWhen{AuthnStrength: list("mfa")}),
			env: edit(func(p *controlv1.Principal) { p.AuthnStrength = "" }), want: unknown},
		{name: "tenantId holds", when: principal(rules.PrincipalWhen{TenantID: list("tenant-a")}), env: envelope(), want: holds},
		{name: "tenantId fails", when: principal(rules.PrincipalWhen{TenantID: list("tenant-b")}), env: envelope(), want: fails},
		{name: "tenantId absent", when: principal(rules.PrincipalWhen{TenantID: list("tenant-a")}),
			env: edit(func(p *controlv1.Principal) { p.TenantId = "" }), want: unknown},
		{name: "attribute holds", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"payments"}}}),
			env: envelope(), want: holds},
		{name: "attribute is one of several", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"legal", "payments"}}}),
			env: envelope(), want: holds},
		{name: "attribute fails", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"legal"}}}),
			env: envelope(), want: fails},
		{name: "attribute key missing", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"payments"}}}),
			env: edit(func(p *controlv1.Principal) { p.Attributes = nil }), want: unknown},
		{name: "attribute value empty", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"payments"}}}),
			env: edit(func(p *controlv1.Principal) { p.Attributes = map[string]string{"team": ""} }), want: unknown},
		// Keys match exactly, so the envelope does not carry this one.
		{name: "a key that differs in case is another key", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"Team": {"payments"}}}),
			env: envelope(), want: unknown},
		{name: "every key holds", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"payments"}, "role": {"admin"}}}),
			env: edit(func(p *controlv1.Principal) { p.Attributes = map[string]string{"team": "payments", "role": "admin"} }), want: holds},
		{name: "a key missing beside one that holds", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"payments"}, "role": {"admin"}}}),
			env: envelope(), want: unknown},
		{name: "a key missing beside one that fails", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"team": {"legal"}, "role": {"admin"}}}),
			env: envelope(), want: fails},
		// An envelope may carry the empty key, and one that does not leaves
		// it missing, as any other key.
		{name: "the empty key holds", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"": {"payments"}}}),
			env: edit(func(p *controlv1.Principal) { p.Attributes = map[string]string{"": "payments"} }), want: holds},
		{name: "the empty key fails", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"": {"payments"}}}),
			env: edit(func(p *controlv1.Principal) { p.Attributes = map[string]string{"": "legal"} }), want: fails},
		{name: "the empty key missing", when: principal(rules.PrincipalWhen{Attributes: map[string][]string{"": {"payments"}}}),
			env: envelope(), want: unknown},
	})
}

func TestAgentConstraints(t *testing.T) {
	agent := func(w rules.AgentWhen) rules.When { return rules.When{Agent: &w} }
	edit := func(f func(*controlv1.Agent)) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) { f(e.Agent) })
	}
	checkConstraints(t, []constraintCase{
		{name: "id holds", when: agent(rules.AgentWhen{ID: list("agent-7")}), env: envelope(), want: holds},
		{name: "id fails", when: agent(rules.AgentWhen{ID: list("agent-8")}), env: envelope(), want: fails},
		{name: "id absent", when: agent(rules.AgentWhen{ID: list("agent-7")}),
			env: edit(func(a *controlv1.Agent) { a.Id = "" }), want: unknown},
		{name: "no agent at all", when: agent(rules.AgentWhen{ID: list("agent-7")}),
			env: with(func(e *controlv1.ActionEnvelope) { e.Agent = nil }), want: unknown},
		{name: "framework holds", when: agent(rules.AgentWhen{Framework: list("langgraph")}), env: envelope(), want: holds},
		{name: "framework fails", when: agent(rules.AgentWhen{Framework: list("autogen")}), env: envelope(), want: fails},
		{name: "framework absent", when: agent(rules.AgentWhen{Framework: list("langgraph")}),
			env: edit(func(a *controlv1.Agent) { a.Framework = "" }), want: unknown},
	})
}

func TestActionConstraints(t *testing.T) {
	action := func(w rules.ActionWhen) rules.When { return rules.When{Action: &w} }
	edit := func(f func(*controlv1.Action)) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) { f(e.Action) })
	}
	effects := func(e ...controlv1.EffectClass) rules.When { return action(rules.ActionWhen{Effect: e}) }
	checkConstraints(t, []constraintCase{
		{name: "name holds", when: action(rules.ActionWhen{Name: list("refund")}), env: envelope(), want: holds},
		{name: "name fails", when: action(rules.ActionWhen{Name: list("archive")}), env: envelope(), want: fails},
		{name: "name differs in case", when: action(rules.ActionWhen{Name: list("REFUND")}), env: envelope(), want: fails},
		{name: "name absent", when: action(rules.ActionWhen{Name: list("refund")}),
			env: edit(func(a *controlv1.Action) { a.Name = "" }), want: unknown, refused: true},
		{name: "provider holds", when: action(rules.ActionWhen{Provider: list("payments")}), env: envelope(), want: holds},
		{name: "provider fails", when: action(rules.ActionWhen{Provider: list("files")}), env: envelope(), want: fails},
		{name: "provider absent", when: action(rules.ActionWhen{Provider: list("payments")}),
			env: edit(func(a *controlv1.Action) { a.Provider = "" }), want: unknown},
		{name: "protocol holds", when: action(rules.ActionWhen{Protocol: list("mcp")}), env: envelope(), want: holds},
		{name: "protocol fails", when: action(rules.ActionWhen{Protocol: list("a2a")}), env: envelope(), want: fails},
		{name: "protocol absent", when: action(rules.ActionWhen{Protocol: list("mcp")}),
			env: edit(func(a *controlv1.Action) { a.Protocol = "" }), want: unknown},
		{name: "kind holds", when: action(rules.ActionWhen{Kind: list("tool_call")}), env: envelope(), want: holds},
		{name: "kind fails", when: action(rules.ActionWhen{Kind: list("resource_read")}), env: envelope(), want: fails},
		{name: "kind absent", when: action(rules.ActionWhen{Kind: list("tool_call")}),
			env: edit(func(a *controlv1.Action) { a.Kind = "" }), want: unknown},
		{name: "effect holds", when: effects(read), env: envelope(), want: holds},
		{name: "effect is one of several", when: effects(write, read), env: envelope(), want: holds},
		{name: "effect fails", when: effects(write, remove), env: envelope(), want: fails},
		{name: "effect unspecified", when: effects(read),
			env: edit(func(a *controlv1.Action) { a.Effect = effectUnset }), want: unknown, refused: true},
		{name: "an effect this build cannot name", when: effects(read),
			env: edit(func(a *controlv1.Action) { a.Effect = controlv1.EffectClass(42) }), want: unknown, refused: true},
	})
}

func TestResourceConstraints(t *testing.T) {
	resource := func(w rules.ResourceWhen) rules.When { return rules.When{Resource: &w} }
	edit := func(f func(*controlv1.Resource)) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) { f(e.Resource) })
	}
	checkConstraints(t, []constraintCase{
		{name: "type holds", when: resource(rules.ResourceWhen{Type: list("invoice")}), env: envelope(), want: holds},
		{name: "type fails", when: resource(rules.ResourceWhen{Type: list("ledger")}), env: envelope(), want: fails},
		// A READ needs a resource type; a COMMUNICATE does not, so this
		// absence is one the kernel can send.
		{name: "type absent", when: resource(rules.ResourceWhen{Type: list("invoice")}),
			env: with(func(e *controlv1.ActionEnvelope) { e.Action.Effect = communicate; e.Resource.Type = "" }), want: unknown},
		{name: "id holds", when: resource(rules.ResourceWhen{ID: list("inv-1")}), env: envelope(), want: holds},
		{name: "id fails", when: resource(rules.ResourceWhen{ID: list("inv-2")}), env: envelope(), want: fails},
		{name: "id absent", when: resource(rules.ResourceWhen{ID: list("inv-1")}),
			env: edit(func(r *controlv1.Resource) { r.Id = "" }), want: unknown},
		{name: "tenantId holds", when: resource(rules.ResourceWhen{TenantID: list("tenant-a")}), env: envelope(), want: holds},
		{name: "tenantId fails", when: resource(rules.ResourceWhen{TenantID: list("tenant-b")}), env: envelope(), want: fails},
		{name: "tenantId absent", when: resource(rules.ResourceWhen{TenantID: list("tenant-a")}),
			env: edit(func(r *controlv1.Resource) { r.TenantId = "" }), want: unknown},
		{name: "environment holds", when: resource(rules.ResourceWhen{Environment: list("prod")}), env: envelope(), want: holds},
		{name: "environment fails", when: resource(rules.ResourceWhen{Environment: list("staging")}), env: envelope(), want: fails},
		{name: "environment absent", when: resource(rules.ResourceWhen{Environment: list("prod")}),
			env: edit(func(r *controlv1.Resource) { r.Environment = "" }), want: unknown},
		{name: "label holds", when: resource(rules.ResourceWhen{Labels: map[string][]string{"tier": {"gold"}}}), env: envelope(), want: holds},
		{name: "label fails", when: resource(rules.ResourceWhen{Labels: map[string][]string{"tier": {"silver"}}}), env: envelope(), want: fails},
		{name: "label key missing", when: resource(rules.ResourceWhen{Labels: map[string][]string{"tier": {"gold"}}}),
			env: edit(func(r *controlv1.Resource) { r.Labels = nil }), want: unknown},
		{name: "label value empty", when: resource(rules.ResourceWhen{Labels: map[string][]string{"tier": {"gold"}}}),
			env: edit(func(r *controlv1.Resource) { r.Labels = map[string]string{"tier": ""} }), want: unknown},
		{name: "the empty key holds", when: resource(rules.ResourceWhen{Labels: map[string][]string{"": {"gold"}}}),
			env: edit(func(r *controlv1.Resource) { r.Labels = map[string]string{"": "gold"} }), want: holds},
		{name: "the empty key missing", when: resource(rules.ResourceWhen{Labels: map[string][]string{"": {"gold"}}}),
			env: envelope(), want: unknown},
	})
}

func TestDestinationConstraints(t *testing.T) {
	destination := func(w rules.DestinationWhen) rules.When { return rules.When{Destination: &w} }
	zones := func(z ...controlv1.TrustZone) rules.When { return destination(rules.DestinationWhen{TrustZone: z}) }
	edit := func(f func(*controlv1.Destination)) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) { f(e.Destination) })
	}
	checkConstraints(t, []constraintCase{
		{name: "trustZone holds", when: zones(zoneInternal), env: envelope(), want: holds},
		{name: "trustZone is one of several", when: zones(zoneExternal, zoneInternal), env: envelope(), want: holds},
		{name: "trustZone fails", when: zones(zoneExternal), env: envelope(), want: fails},
		{name: "trustZone unspecified", when: zones(zoneInternal),
			env: edit(func(d *controlv1.Destination) { d.TrustZone = zoneUnset }), want: unknown},
		{name: "no destination at all", when: zones(zoneInternal),
			env: with(func(e *controlv1.ActionEnvelope) { e.Destination = nil }), want: unknown},
		{name: "a zone this build cannot name", when: zones(zoneInternal),
			env: edit(func(d *controlv1.Destination) { d.TrustZone = controlv1.TrustZone(42) }), want: unknown, refused: true},
		{name: "host holds", when: destination(rules.DestinationWhen{Host: list("ledger.internal")}), env: envelope(), want: holds},
		{name: "host fails", when: destination(rules.DestinationWhen{Host: list("ledger.example")}), env: envelope(), want: fails},
		{name: "host absent", when: destination(rules.DestinationWhen{Host: list("ledger.internal")}),
			env: edit(func(d *controlv1.Destination) { d.Host = "" }), want: unknown},
	})
}

// TestHostIsComparedAsWritten: a host matches only as written, as every string
// does, so a second spelling of a host is another host, and a DENY on one
// spelling does not stop the other beside a broader ALLOW. Giving a host one
// spelling is the job of the boundary, where Validate and Parse read it; the
// matcher does not do it, and this test keeps that in view. It validates no
// envelope: whether Validate refuses the second spelling is the boundary's
// rule, not this package's.
func TestHostIsComparedAsWritten(t *testing.T) {
	p := compile(t,
		rules.Rule{ID: "no-paste", Effect: deny, When: rules.When{Destination: &rules.DestinationWhen{Host: list("paste.example.net")}}},
		rules.Rule{ID: "reads", Effect: allow, When: rules.When{Action: &rules.ActionWhen{Effect: []controlv1.EffectClass{read}}}},
	)
	to := func(host string) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) { e.Destination.Host = host })
	}
	assertResult(t, p.Evaluate(to("paste.example.net"), match.Inputs{}), want{
		verdict: deny, determinate: deny, ids: list("no-paste", "reads"), codes: list(ruleDeny, ruleAllow),
	})
	assertResult(t, p.Evaluate(to("PASTE.EXAMPLE.NET"), match.Inputs{}), want{
		verdict: allow, determinate: allow, ids: list("reads"), codes: list(ruleAllow),
	})
}

// TestDataSensitivityAtLeast is ADR-0012's predicate: true when
// contains_secrets is set or a label is at or above the floor, unknown when
// there is no label and no contains_secrets, false otherwise. It reads the
// envelope's own data and never the run's. contract.SensitivityAtLeast is not
// this predicate: it answers false for "no label", which the rows marked
// unknown refuse.
func TestDataSensitivityAtLeast(t *testing.T) {
	floor := func(s controlv1.Sensitivity) rules.When {
		return rules.When{Data: &rules.DataWhen{SensitivityAtLeast: s}}
	}
	labelled := func(secrets bool, labels ...controlv1.Sensitivity) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) {
			e.Data = &controlv1.DataLabels{Sensitivities: labels, ContainsSecrets: secrets}
		})
	}
	checkConstraints(t, []constraintCase{
		{name: "a label at the floor", when: floor(internal), env: labelled(false, internal), want: holds},
		{name: "a label above the floor", when: floor(internal), env: labelled(false, secret), want: holds},
		{name: "the lowest floor", when: floor(public), env: labelled(false, public), want: holds},
		{name: "a label below the floor", when: floor(confidential), env: labelled(false, internal), want: fails},
		{name: "every label below the floor", when: floor(confidential), env: labelled(false, public, internal), want: fails},
		{name: "any label reaching the floor", when: floor(confidential), env: labelled(false, public, restricted), want: holds},
		{name: "the order of the labels is not read", when: floor(confidential), env: labelled(false, restricted, public), want: holds},
		{name: "no label and no secrets", when: floor(public), env: labelled(false), want: unknown},
		{name: "no data at all", when: floor(public), env: with(func(e *controlv1.ActionEnvelope) { e.Data = nil }), want: unknown},
		{name: "secrets asserted and no label", when: floor(secret), env: labelled(true), want: holds},
		{name: "secrets asserted beside a lower label", when: floor(secret), env: labelled(true, public), want: holds},
		{name: "what the run read is not this constraint's input", when: floor(internal), env: labelled(false),
			in: match.Inputs{Flow: contract.NewFlowState(true, secret)}, want: unknown},
		{name: "a run nobody tracked does not matter here", when: floor(secret), env: labelled(false, secret),
			in: match.Inputs{Flow: contract.FlowState{}}, want: holds},

		{name: "a label that says nothing", when: floor(public), env: labelled(false, unlabelled), want: unknown, refused: true},
		{name: "a label that says nothing beside one that reaches the floor", when: floor(secret),
			env: labelled(false, unlabelled, secret), want: holds, refused: true},
		{name: "a label that says nothing beside one below the floor", when: floor(internal),
			env: labelled(false, public, unlabelled), want: unknown, refused: true},
		// By number this would be above SECRET and meet every floor.
		{name: "a label above the scale", when: floor(public), env: labelled(false, 6), want: unknown, refused: true},
		{name: "a label below the scale", when: floor(public), env: labelled(false, -1), want: unknown, refused: true},
	})
}

// TestFlowToxicAtLeast is contract.ToxicFlow's answer, with its refusal read as
// unknown (ADR-0012).
func TestFlowToxicAtLeast(t *testing.T) {
	toxic := func(s controlv1.Sensitivity) rules.When { return rules.When{Flow: &rules.FlowWhen{ToxicAtLeast: s}} }
	towards := func(zone controlv1.TrustZone, labels ...controlv1.Sensitivity) *controlv1.ActionEnvelope {
		return with(func(e *controlv1.ActionEnvelope) {
			e.Destination = &controlv1.Destination{TrustZone: zone}
			e.Data = &controlv1.DataLabels{Sensitivities: labels}
		})
	}
	flow := func(influenced bool, read controlv1.Sensitivity) match.Inputs {
		return match.Inputs{Flow: contract.NewFlowState(influenced, read)}
	}
	checkConstraints(t, []constraintCase{
		{name: "an influenced run sends out what it read above the floor", when: toxic(confidential),
			env: towards(zoneExternal), in: flow(true, secret), want: holds},
		{name: "no untrusted influence", when: toxic(confidential), env: towards(zoneExternal), in: flow(false, secret), want: fails},
		{name: "a trusted destination", when: toxic(confidential), env: towards(zoneInternal), in: flow(true, secret), want: fails},
		{name: "a partner is trusted", when: toxic(confidential), env: towards(zonePartner), in: flow(true, secret), want: fails},
		{name: "no destination is an untrusted one", when: toxic(confidential),
			env: with(func(e *controlv1.ActionEnvelope) { e.Destination = nil }), in: flow(true, secret), want: holds},
		{name: "every part known and below the floor", when: toxic(confidential),
			env: towards(zoneExternal, public), in: flow(true, internal), want: fails},
		{name: "a label reaching the floor", when: toxic(confidential),
			env: towards(zoneExternal, restricted), in: flow(true, internal), want: holds},
		{name: "a flow nobody computed", when: toxic(confidential), env: towards(zoneExternal, secret), want: unknown},
		{name: "fields set by hand are not a computed flow", when: toxic(confidential), env: towards(zoneExternal, secret),
			in: match.Inputs{Flow: contract.FlowState{UntrustedInfluence: true, MaxSensitivityRead: secret}}, want: unknown},
		{name: "a run whose reading nobody knows, and no label", when: toxic(confidential),
			env: towards(zoneExternal), in: flow(true, unlabelled), want: unknown},
		{name: "an unknown run beside a declared PUBLIC", when: toxic(internal),
			env: towards(zoneExternal, public), in: flow(true, unlabelled), want: unknown},
	})
}

// TestDelegationScopes reads the kernel's Inputs, never the envelope's chain:
// only the kernel knows whether the chain passed its check.
func TestDelegationScopes(t *testing.T) {
	scoped := rules.When{Delegation: &rules.DelegationWhen{Scopes: list("read", "write")}}
	chained := with(func(e *controlv1.ActionEnvelope) {
		e.Delegation = []*controlv1.Delegation{{
			From: "alice", To: "agent-7", Scopes: list("read"),
			ExpiresAt: &timestamppb.Timestamp{Seconds: 1789131600},
		}}
	})
	checkConstraints(t, []constraintCase{
		{name: "no chain", when: scoped, env: envelope(), want: unknown},
		{name: "a chain granting nothing", when: scoped, env: envelope(), in: match.Inputs{Delegated: true}, want: fails},
		{name: "a chain granting one of them", when: scoped, env: envelope(),
			in: match.Inputs{Delegated: true, Scopes: list("write")}, want: holds},
		{name: "a chain granting others only", when: scoped, env: envelope(),
			in: match.Inputs{Delegated: true, Scopes: list("admin")}, want: fails},
		{name: "one of several granted", when: scoped, env: envelope(),
			in: match.Inputs{Delegated: true, Scopes: list("admin", "read")}, want: holds},
		{name: "scopes with no chain behind them", when: scoped, env: envelope(),
			in: match.Inputs{Scopes: list("read")}, want: unknown},
		{name: "a scope that differs in case", when: scoped, env: envelope(),
			in: match.Inputs{Delegated: true, Scopes: list("READ")}, want: fails},
		{name: "the envelope's own chain is not the input", when: scoped, env: chained, want: unknown},
	})
}

// TestConstraintsCombineAsAllOf: a rule is false if any constraint is false,
// else unknown if any is unknown, else true, in whatever order its groups are
// read.
func TestConstraintsCombineAsAllOf(t *testing.T) {
	nameAndPlace := func(env string) rules.When {
		return rules.When{Action: &rules.ActionWhen{Name: list("refund")}, Resource: &rules.ResourceWhen{Environment: list(env)}}
	}
	typeAndPlace := func(typ, env string) rules.When {
		return rules.When{Principal: &rules.PrincipalWhen{Type: list(typ)}, Resource: &rules.ResourceWhen{Environment: list(env)}}
	}
	checkConstraints(t, []constraintCase{
		{name: "both hold", when: nameAndPlace("prod"), env: envelope(), want: holds},
		{name: "one fails", when: nameAndPlace("staging"), env: envelope(), want: fails},
		{name: "one unknown", when: nameAndPlace("prod"),
			env: with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "" }), want: unknown},
		{name: "an unknown read before a failure", when: typeAndPlace("user", "staging"),
			env: with(func(e *controlv1.ActionEnvelope) { e.Principal.Type = "" }), want: fails},
		{name: "a failure read before an unknown", when: typeAndPlace("service", "prod"),
			env: with(func(e *controlv1.ActionEnvelope) { e.Resource.Environment = "" }), want: fails},
	})
}
