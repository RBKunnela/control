package attempts

import (
	"fmt"
	"path"
	"strings"

	"github.com/guardana/control/internal/gatewayconfig"
)

func readPlanes(v *Value) ([]Plane, error) {
	items, err := list(v, "planes", 2, MaxPlanes)
	if err != nil {
		return nil, err
	}
	out := make([]Plane, len(items))
	roles := map[Role]bool{}
	for i, item := range items {
		at := index("planes", i)
		if out[i], err = readPlane(item, at); err != nil {
			return nil, err
		}
		for _, q := range out[:i] {
			if q.ID == out[i].ID {
				return nil, refuse(ErrDuplicate, at+".id", q.ID)
			}
		}
		roles[out[i].Role] = true
	}
	if !roles[RoleMeasured] || !roles[RolePositive] {
		return nil, refuse(ErrValue, "planes", "want at least one measured plane and one positive plane")
	}
	return out, nil
}

func readPlane(item *Value, at string) (Plane, error) {
	var p Plane
	f, err := closed(item, at, "id", "mode", "decision_point", "role")
	if err != nil {
		return p, err
	}
	if p.ID, err = identifier(f["id"], at+".id"); err != nil {
		return p, err
	}
	if p.Mode, err = oneOf(f["mode"], at+".mode", gatewayconfig.ModeNames()...); err != nil {
		return p, err
	}
	if p.DecisionPoint, err = oneOf(f["decision_point"], at+".decision_point", DecisionPointSilent, DecisionPointNone); err != nil {
		return p, err
	}
	role, err := oneOf(f["role"], at+".role", string(RoleMeasured), string(RolePositive))
	if err != nil {
		return p, err
	}
	p.Role = Role(role)
	if p.Role == RolePositive && p.Mode != "OBSERVE" {
		return p, refuse(ErrValue, at+".mode", "a positive plane runs in OBSERVE, which runs the calls other modes block or hold")
	}
	return p, nil
}

func readEffects(v *Value) ([]Effect, error) {
	items, err := list(v, "effects", 1, MaxEffects)
	if err != nil {
		return nil, err
	}
	out := make([]Effect, len(items))
	for i, item := range items {
		at := index("effects", i)
		f, err := closed(item, at, "id", "server", "call", "args")
		if err != nil {
			return nil, err
		}
		e := &out[i]
		if e.ID, err = identifier(f["id"], at+".id"); err != nil {
			return nil, err
		}
		for _, d := range out[:i] {
			if d.ID == e.ID {
				return nil, refuse(ErrDuplicate, at+".id", e.ID)
			}
		}
		if e.Server, err = boundedText(f["server"], at+".server", MaxNameBytes); err != nil {
			return nil, err
		}
		if e.Call, err = boundedText(f["call"], at+".call", MaxNameBytes); err != nil {
			return nil, err
		}
		conds, err := list(f["args"], at+".args", 0, MaxConditions)
		if err != nil {
			return nil, err
		}
		for j, c := range conds {
			cond, err := readCondition(c, index(at+".args", j))
			if err != nil {
				return nil, err
			}
			e.Conditions = append(e.Conditions, cond)
		}
	}
	return out, nil
}

func readCondition(v *Value, at string) (Condition, error) {
	f, err := closed(v, at, "member", "?", "equals", "contains")
	if err != nil {
		return Condition{}, err
	}
	var c Condition
	if c.Member, err = text(f["member"], at+".member"); err != nil {
		return Condition{}, err
	}
	if err := checkPointer(c.Member); err != nil {
		return Condition{}, refuse(ErrValue, at+".member", err.Error())
	}
	equals, hasEquals := f["equals"]
	contains, hasContains := f["contains"]
	switch {
	case hasEquals == hasContains:
		return Condition{}, refuse(ErrValue, at, "want exactly one of equals and contains")
	case hasEquals:
		c.Equals = equals
	default:
		if c.Contains, err = text(contains, at+".contains"); err != nil {
			return Condition{}, err
		}
		if c.Contains == "" || len(c.Contains) > MaxContainsBytes {
			return Condition{}, refuse(ErrBound, at+".contains", fmt.Sprintf("%d bytes, want 1 to %d", len(c.Contains), MaxContainsBytes))
		}
	}
	return c, nil
}

func (m *Manifest) readAttempts(v *Value) ([]Attempt, error) {
	items, err := list(v, "attempts", 1, MaxAttempts)
	if err != nil {
		return nil, err
	}
	out := make([]Attempt, len(items))
	for i, item := range items {
		at := index("attempts", i)
		f, err := closed(item, at, "id", "scenario", "steps")
		if err != nil {
			return nil, err
		}
		a := &out[i]
		if a.ID, err = identifier(f["id"], at+".id"); err != nil {
			return nil, err
		}
		for _, b := range out[:i] {
			if b.ID == a.ID {
				return nil, refuse(ErrDuplicate, at+".id", a.ID)
			}
		}
		if a.Scenario, err = text(f["scenario"], at+".scenario"); err != nil {
			return nil, err
		}
		if err := m.checkPath(a.Scenario, at+".scenario"); err != nil {
			return nil, err
		}
		if a.Steps, err = m.readSteps(f["steps"], at+".steps"); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (m *Manifest) readSteps(v *Value, at string) ([]StepLabel, error) {
	items, err := list(v, at, 1, MaxSteps)
	if err != nil {
		return nil, err
	}
	out := make([]StepLabel, len(items))
	for i, item := range items {
		here := index(at, i)
		f, err := closed(item, here, "step", "label", "?", "effects")
		if err != nil {
			return nil, err
		}
		s := &out[i]
		if s.Step, err = integer(f["step"], here+".step", 0, MaxSteps-1); err != nil {
			return nil, err
		}
		for _, t := range out[:i] {
			if t.Step == s.Step {
				return nil, refuse(ErrLabel, here+".step", fmt.Sprintf("step %d is labelled twice", s.Step))
			}
		}
		label, err := oneOf(f["label"], here+".label", string(LabelAttack), string(LabelLegitimate), string(LabelOperator))
		if err != nil {
			return nil, err
		}
		s.Label = Label(label)
		if s.Effects, err = m.labelEffects(s.Label, f, here+".effects"); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// labelEffects is the effects a step of label names: required on an attack
// step and refused on any other.
func (m *Manifest) labelEffects(label Label, f map[string]*Value, at string) ([]string, error) {
	effects, has := f["effects"]
	switch {
	case label != LabelAttack && has:
		return nil, refuse(ErrEffect, at, "only an attack step names effects")
	case label == LabelAttack && !has:
		return nil, refuse(ErrMissing, at, "an attack step names the effects it aims at")
	case has:
		return m.stepEffects(effects, at)
	}
	return nil, nil
}

func (m *Manifest) stepEffects(v *Value, at string) ([]string, error) {
	items, err := list(v, at, 1, MaxStepEffects)
	if err != nil {
		return nil, err
	}
	var out []string
	for i, item := range items {
		id, err := identifier(item, index(at, i))
		if err != nil {
			return nil, err
		}
		switch {
		case m.Effect(id) == nil:
			return nil, refuse(ErrEffect, index(at, i), fmt.Sprintf("no effect is called %s", id))
		case strings.Contains(" "+strings.Join(out, " ")+" ", " "+id+" "):
			return nil, refuse(ErrDuplicate, index(at, i), id)
		}
		out = append(out, id)
	}
	return out, nil
}

// checkPointer holds a member to a JSON pointer: empty, the whole arguments,
// or "/" segments in which "~" is only "~0" or "~1".
func checkPointer(p string) error {
	if len(p) > MaxMemberBytes {
		return fmt.Errorf("%d bytes, the bound is %d", len(p), MaxMemberBytes)
	}
	if p != "" && p[0] != '/' {
		return fmt.Errorf("%q is not a JSON pointer, which starts with /", clip(p))
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' && (i+1 == len(p) || (p[i+1] != '0' && p[i+1] != '1')) {
			return fmt.Errorf("%q has a ~ that is neither ~0 nor ~1", clip(p))
		}
	}
	return nil
}

// checkDemoPath holds the demo's path to the path rule, climbing at most
// once: the demo sits in the manifest's directory, below it, or in its
// parent.
func checkDemoPath(p string) error {
	if err := lexical(p, "demo"); err != nil {
		return err
	}
	if climbs(p) > 1 {
		return refuse(ErrPath, "demo", fmt.Sprintf("%q climbs more than one directory", clip(p)))
	}
	return nil
}

// checkPath holds a path to the path rule: it lies under the manifest's
// directory, or under the directory that holds the demo.
func (m *Manifest) checkPath(p, at string) error {
	if err := lexical(p, at); err != nil {
		return err
	}
	if climbs(p) == 0 {
		return nil
	}
	demoDir := path.Dir(m.Demo)
	if rest, ok := strings.CutPrefix(p, demoDir+"/"); ok && climbs(demoDir) > 0 && climbs(rest) == 0 {
		return nil
	}
	return refuse(ErrPath, at, fmt.Sprintf("%q leaves the manifest's directory for one that does not hold the demo", clip(p)))
}

// lexical refuses an absolute path, a backslash, an empty or "." segment and
// a ".." anywhere but at the start: what remains is a path written the one
// way path.Clean writes it.
func lexical(p, at string) error {
	switch {
	case p == "" || len(p) > MaxPathBytes:
		return refuse(ErrBound, at, fmt.Sprintf("%d bytes, want 1 to %d", len(p), MaxPathBytes))
	case strings.HasPrefix(p, "/") || strings.ContainsAny(p, `\:`):
		return refuse(ErrPath, at, fmt.Sprintf("%q is absolute or holds a backslash or a colon; a path is relative to the manifest", clip(p)))
	case path.Clean(p) != p || p == "." || p == ".." || strings.HasSuffix(p, "/.."):
		return refuse(ErrPath, at, fmt.Sprintf("%q is not written the one way: no empty or . segment, and .. only at the start", clip(p)))
	}
	return nil
}

// climbs is how many ".." segments a lexical path starts with.
func climbs(p string) int {
	n := 0
	for strings.HasPrefix(p, "../") {
		p, n = p[3:], n+1
	}
	if p == ".." {
		n++
	}
	return n
}
