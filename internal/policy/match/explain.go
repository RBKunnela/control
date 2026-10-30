package match

import (
	"errors"
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// part names a constraint for an explanation: the field as the document spells
// it, and the input it reads in wire spelling. A flow constraint reads several
// inputs, and which of them it lacked is found when it is explained.
type part struct {
	field string
	reads string
	flow  bool
}

// externalField is the external constraint as the document spells it.
const externalField = "when.external.denies"

// Value is a rule's value for one call.
type Value uint8

const (
	// ValueUnknown is a rule an input it reads left undetermined.
	ValueUnknown Value = iota
	// ValueNo is a rule a constraint of which does not hold.
	ValueNo
	// ValueYes is a rule every constraint of which holds.
	ValueYes
)

// RuleTrace is how one rule read one call.
type RuleTrace struct {
	ID     string
	Effect controlv1.Verdict
	// Value is the value the evaluation gave the rule.
	Value Value
	// Unknown are the constraints that read unknown, in the rule's order with
	// the external answer last.
	Unknown []Unread
	// No are the fields of the constraints that do not hold, in the same order.
	No []string
}

// Unread is a constraint that read unknown and the inputs it lacked, in wire
// spelling. Validate refuses an envelope holding a value this build cannot
// read, so on the kernel's path an input is lacking because nobody sent it.
type Unread struct {
	Field string
	Needs []string
}

// Explain evaluates as Evaluate does and also says how each rule read the call,
// in document order. The traces are nil when nothing was evaluated.
func (p *Program) Explain(env *controlv1.ActionEnvelope, in Inputs) (Result, []RuleTrace) {
	if p == nil || !p.compiled {
		return unavailable(), nil
	}
	traces := make([]RuleTrace, 0, len(p.rules))
	result := p.evaluate(env, in, &traces)
	return result, traces
}

// trace reads every constraint of the rule, where holds stops at the first
// false one. The constraints are pure, so a second reading gives the values
// holds saw, and v is the value holds gave.
func (r *rule) trace(env *controlv1.ActionEnvelope, in *Inputs, v truth) RuleTrace {
	t := RuleTrace{ID: r.id, Effect: r.effect, Value: valueOf(v)}
	for i, c := range r.constraints {
		p := r.parts[i]
		switch c(env, in) {
		case yes:
		case no:
			t.No = append(t.No, p.field)
		default:
			t.Unknown = append(t.Unknown, Unread{Field: p.field, Needs: p.needs(env, in)})
		}
	}
	if r.external {
		switch in.External {
		case ExternalDenies:
		case ExternalAllows:
			t.No = append(t.No, externalField)
		default:
			t.Unknown = append(t.Unknown, Unread{Field: externalField, Needs: []string{"external"}})
		}
	}
	return t
}

// lacked is the inputs the rule's unknown constraints lacked, once each in
// the rule's order. An ALLOW rule reads no external answer, so none is named.
func (r *rule) lacked(env *controlv1.ActionEnvelope, in *Inputs) []string {
	var out []string
	for i, c := range r.constraints {
		if v := c(env, in); v == yes || v == no {
			continue
		}
		for _, need := range r.parts[i].needs(env, in) {
			if !slices.Contains(out, need) {
				out = append(out, need)
			}
		}
	}
	return out
}

func valueOf(v truth) Value {
	switch v {
	case yes:
		return ValueYes
	case no:
		return ValueNo
	}
	return ValueUnknown
}

func (p part) needs(env *controlv1.ActionEnvelope, in *Inputs) []string {
	if p.flow {
		return flowNeeds(env, in)
	}
	return []string{p.reads}
}

// flowNeeds names what left a toxic-flow constraint unknown: a run nobody
// tracked, the run's reading, or the call's own labels. Whether the run was
// tracked is asked of contract.ToxicFlow itself, with a call whose data meets
// every floor, so this never second-guesses the predicate's own refusal.
func flowNeeds(env *controlv1.ActionEnvelope, in *Inputs) []string {
	probe := &controlv1.ActionEnvelope{Data: &controlv1.DataLabels{ContainsSecrets: true}}
	_, err := contract.ToxicFlow(in.Flow, probe, controlv1.Sensitivity_SENSITIVITY_PUBLIC)
	if errors.Is(err, contract.ErrMissingField) {
		return []string{"flow"}
	}
	var needs []string
	if err != nil || !contract.ValidSensitivityFloor(in.Flow.MaxSensitivityRead) {
		needs = append(needs, "flow.max_sensitivity_read")
	}
	labels := env.GetData().GetSensitivities()
	if len(labels) == 0 || slices.ContainsFunc(labels, func(s controlv1.Sensitivity) bool { return !contract.ValidSensitivityFloor(s) }) {
		needs = append(needs, "data.sensitivities")
	}
	if len(needs) == 0 {
		needs = []string{"flow"}
	}
	return needs
}
