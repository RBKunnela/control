package rules

import (
	"fmt"
	"slices"

	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// reasonsFor lists the reason codes a rule of an effect may name, its default
// first. A code the kernel emits about its own checks, TENANT_MISMATCH,
// POLICY_STALE or a delegation code, is on no list: a policy that could name
// one could dress its own denial as the kernel's. The codes are literals
// because nothing that decides imports the registry; a test holds each to it.
func reasonsFor(effect controlv1.Verdict) []string {
	switch effect {
	case controlv1.Verdict_VERDICT_ALLOW:
		return []string{"RULE_ALLOW"}
	case controlv1.Verdict_VERDICT_DENY:
		return []string{"RULE_DENY", "ENVIRONMENT_BOUNDARY", "OUT_OF_SCOPE_ACTION", "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL"}
	case controlv1.Verdict_VERDICT_REQUIRE_APPROVAL:
		return []string{"APPROVAL_REQUIRED"}
	case controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS:
		return []string{"OBLIGATIONS_ATTACHED"}
	}
	return nil
}

// Param is one parameter an obligation type declares.
type Param struct {
	Name     string
	Required bool
	Grammar  Grammar
}

// ObligationSpec is one type of the obligation catalogue: the parameters it
// declares, and the names of which at least one must be present. A type with
// no Params takes no parameters.
type ObligationSpec struct {
	Type   string
	Params []Param
	OneOf  []string
}

// catalogue is the obligation catalogue. The enforcement point applies some of
// these types; a receiver that cannot apply a non-advisory one denies
// (ADR-0011). A type nothing applies declares no parameters, since a value no
// applier reads could only be an instruction nobody follows (ADR-0061).
func catalogue() []ObligationSpec {
	return []ObligationSpec{
		{Type: "redact_fields", Params: []Param{{Name: "fields", Required: true, Grammar: GrammarMemberNames}}},
		{Type: "read_only"},
		{
			Type:   "restrict_resources",
			Params: []Param{{Name: "ids", Grammar: GrammarIdentifiers}, {Name: "prefix", Grammar: GrammarResourcePrefix}},
			OneOf:  []string{"ids", "prefix"},
		},
		{Type: "require_idempotency_key"},
		{Type: "cap_amount", Params: []Param{{Name: "max", Required: true, Grammar: GrammarInteger}, {Name: "field", Grammar: GrammarMemberName}}},
		{Type: "cap_rate"},
		{Type: "require_sandbox"},
		{Type: "second_approver"},
		{Type: "emit_alert"},
		{Type: "shorten_timeout", Params: []Param{{Name: "ms", Required: true, Grammar: GrammarMilliseconds}}},
		{Type: "deny_external_sink"},
	}
}

// Obligations returns the catalogue, in its order. Every call builds a fresh
// copy, so a caller cannot change what the parser reads.
func Obligations() []ObligationSpec { return catalogue() }

func obligationTypes() []string {
	specs := catalogue()
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = s.Type
	}
	return out
}

func obligationSpec(typ string) (ObligationSpec, bool) {
	for _, s := range catalogue() {
		if s.Type == typ {
			return s, true
		}
	}
	return ObligationSpec{}, false
}

// ParamNames returns the parameters typ declares, in the catalogue's order,
// and false for a type outside the catalogue. An applier refuses any other
// parameter by this list; the value it parses itself.
func ParamNames(typ string) ([]string, bool) {
	spec, ok := obligationSpec(typ)
	if !ok {
		return nil, false
	}
	out := make([]string, len(spec.Params))
	for i, p := range spec.Params {
		out[i] = p.Name
	}
	return out, true
}

// KnownObligation reports whether name is an obligation type of the
// catalogue, spelled exactly, for a receiver that must refuse an obligation
// type it could never be handed.
func KnownObligation(name string) bool {
	_, ok := obligationSpec(name)
	return ok
}

// ruleEffect reads a rule's effect. The four are named here rather than
// looked up, so a verdict the contract adds later is no rule effect until
// someone decides it is one.
func ruleEffect(v any, a at) (controlv1.Verdict, error) {
	s, err := text(v, a)
	if err != nil {
		return controlv1.Verdict_VERDICT_UNSPECIFIED, err
	}
	switch s {
	case "ALLOW":
		return controlv1.Verdict_VERDICT_ALLOW, nil
	case "DENY":
		return controlv1.Verdict_VERDICT_DENY, nil
	case "REQUIRE_APPROVAL":
		return controlv1.Verdict_VERDICT_REQUIRE_APPROVAL, nil
	case "ALLOW_WITH_OBLIGATIONS":
		return controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, nil
	}
	return controlv1.Verdict_VERDICT_UNSPECIFIED,
		a.refuse(fmt.Errorf("%w: want ALLOW, DENY, REQUIRE_APPROVAL or ALLOW_WITH_OBLIGATIONS", ErrEnum))
}

// reason reads a rule's reason against its effect. The effect's own default
// reads as "", written out or not, so the model has one spelling of it.
func reason(v any, a at, effect controlv1.Verdict) (string, error) {
	s, err := text(v, a)
	if err != nil {
		return "", err
	}
	allowed := reasonsFor(effect)
	if !slices.Contains(allowed, s) {
		return "", a.refuse(ErrReason)
	}
	if s == allowed[0] {
		return "", nil
	}
	return s, nil
}

func obligationType(v any, a at) (string, error) {
	s, err := text(v, a)
	if err != nil {
		return "", err
	}
	if !KnownObligation(s) {
		return "", a.refuse(ErrObligationType)
	}
	return s, nil
}

// effectClass reads an effect class the way contract.ParseEffect spells it.
func effectClass(v any, a at) (controlv1.EffectClass, error) {
	s, err := text(v, a)
	if err != nil {
		return controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, err
	}
	class, err := contract.ParseEffect(s)
	if err != nil {
		return controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED,
			a.refuse(fmt.Errorf("%w: want an effect class without its prefix", ErrEnum))
	}
	return class, nil
}

// trustZone reads a trust zone by its name without the prefix. The lookup goes
// through the descriptor, as ParseEffect's does, so a zone a later minor adds
// parses once the generated code carries it.
func trustZone(v any, a at) (controlv1.TrustZone, error) {
	s, err := text(v, a)
	if err != nil {
		return controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED, err
	}
	n, ok := enumNumber(controlv1.TrustZone(0).Descriptor(), "TRUST_ZONE_", s)
	if !ok || n == 0 {
		return controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED,
			a.refuse(fmt.Errorf("%w: want a trust zone without its prefix", ErrEnum))
	}
	return controlv1.TrustZone(n), nil
}

// floor reads a sensitivity floor. UNSPECIFIED is a declared name and the
// lookup finds it; ValidSensitivityFloor then refuses it, as it refuses every
// floor nothing can be compared against, because a floor nobody set is not a
// floor of zero.
func floor(v any, a at) (controlv1.Sensitivity, error) {
	s, err := text(v, a)
	if err != nil {
		return controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED, err
	}
	n, ok := enumNumber(controlv1.Sensitivity(0).Descriptor(), "SENSITIVITY_", s)
	if !ok {
		return controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED,
			a.refuse(fmt.Errorf("%w: want a sensitivity without its prefix", ErrEnum))
	}
	if f := controlv1.Sensitivity(n); contract.ValidSensitivityFloor(f) {
		return f, nil
	}
	return controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED, a.refuse(ErrFloor)
}

func enumNumber(d protoreflect.EnumDescriptor, prefix, name string) (protoreflect.EnumNumber, bool) {
	value := d.Values().ByName(protoreflect.Name(prefix + name))
	if value == nil {
		return 0, false
	}
	return value.Number(), true
}
