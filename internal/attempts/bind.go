package attempts

import (
	"fmt"

	"github.com/guardana/control/internal/scenario"
)

// Bind holds every attempt to the scenario it names, read already and keyed
// by the path as the manifest writes it: each step of the scenario labelled
// exactly once, a step that is no call labelled operator, and each effect an
// attack step names a call of the tool that step calls.
func (m *Manifest) Bind(scenarios map[string]*scenario.Scenario) error {
	for i, a := range m.Attempts {
		at := index("attempts", i)
		s, ok := scenarios[a.Scenario]
		if !ok {
			return refuse(ErrLabel, at+".scenario", fmt.Sprintf("%s was not read", a.Scenario))
		}
		for j, st := range a.Steps {
			here := index(at+".steps", j)
			if st.Step >= len(s.Steps) {
				return refuse(ErrLabel, here+".step", fmt.Sprintf("the scenario has %d steps, so there is no step %d", len(s.Steps), st.Step))
			}
			call := s.Steps[st.Step].Call
			if call == nil && st.Label != LabelOperator {
				return refuse(ErrLabel, here+".label", fmt.Sprintf("step %d is an operator's action, so it is labelled operator", st.Step))
			}
			for _, id := range st.Effects {
				if e := m.Effect(id); e.Call != call.Tool {
					return refuse(ErrEffect, here+".effects", fmt.Sprintf("%s is a call of %s, and step %d calls %s", id, e.Call, st.Step, call.Tool))
				}
			}
		}
		if len(a.Steps) != len(s.Steps) {
			return refuse(ErrLabel, at+".steps", fmt.Sprintf("%d of the scenario's %d steps are labelled; label each once", len(a.Steps), len(s.Steps)))
		}
	}
	return nil
}

// LabelOf is the label of step i of the attempt.
func (a Attempt) LabelOf(i int) StepLabel {
	for _, st := range a.Steps {
		if st.Step == i {
			return st
		}
	}
	return StepLabel{Step: i}
}
