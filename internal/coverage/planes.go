package coverage

import (
	"fmt"
	"slices"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
)

// modeClass is what a plane in one mode does with a path it classifies. The
// zero value classifies nothing.
type modeClass uint8

const (
	modeRefused modeClass = iota
	modeDecides
	modeEnforces
)

// classOf is the plane's mode table read for coverage. SHADOW and WARN are
// declared but refused when the plane starts, so a plane configured with one
// never runs and classifies nothing.
func classOf(mode controlv1.EnforcementMode) (modeClass, error) {
	switch mode {
	case controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE,
		controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN:
		return modeEnforces, nil
	case controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE:
		return modeDecides, nil
	case controlv1.EnforcementMode_ENFORCEMENT_MODE_SHADOW,
		controlv1.EnforcementMode_ENFORCEMENT_MODE_WARN:
		return modeRefused, nil
	}
	return modeRefused, fmt.Errorf("%w: enforcement mode %d is not one a plane runs in", ErrInput, mode)
}

func modeName(mode controlv1.EnforcementMode) string {
	return strings.TrimPrefix(mode.String(), "ENFORCEMENT_MODE_")
}

// checkPlane refuses a mode, or an effect of an override or a tool, the
// contract does not declare, which no configuration the loader accepts can
// hold.
func checkPlane(p Plane) error {
	if _, err := classOf(p.Mode); err != nil {
		return err
	}
	effects := make([]controlv1.EffectClass, 0, len(p.Overrides)+len(p.Tools))
	for _, o := range p.Overrides {
		effects = append(effects, o.Effect)
	}
	for _, t := range p.Tools {
		effects = append(effects, t.Effect)
	}
	for _, e := range effects {
		v := controlv1.EffectClass(0).Descriptor().Values().ByNumber(e.Number())
		if v == nil || e == controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
			return fmt.Errorf("%w: plane %s: effect %d is not one the contract declares", ErrInput, printable(p.Name), e)
		}
	}
	return nil
}

// planeCoverage is the planes' state for a tool path: enforced only when
// every plane that classifies it enforces it, otherwise the weakest plane's
// state. It returns a line per plane in front of the path, and the planes
// that classify it.
func planeCoverage(planes []Plane, path Path) (State, []PlaneLine, []Plane) {
	state := NotCovered
	var lines []PlaneLine
	var by []Plane
	for _, p := range planes {
		line, classifies, ok := planeLine(p, path)
		if !ok {
			continue
		}
		lines = append(lines, line)
		if classifies {
			if len(by) == 0 || line.State < state {
				state = line.State
			}
			by = append(by, p)
		}
	}
	return state, lines, by
}

// planeLine is one plane's state for path, never more than decided for a
// plane that is not inline.
func planeLine(p Plane, path Path) (PlaneLine, bool, bool) {
	if path.Kind == KindEnforceTool {
		return toolTableLine(p, path)
	}
	line, classifies, inFront := mcpLine(p, path)
	if why := notInline(p.Strength); why != "" && line.State > Decided {
		line.State, line.Basis = Decided, line.Basis+"; "+why
	}
	return line, classifies, inFront
}

// cooperating is why a plane whose adapter hands its decisions to a client
// enforces nothing it decides (ADR-0051).
const cooperating = "a cooperating client enforces the decision, which the plane cannot keep from the effect"

// unheld is why a plane whose strength is none, or one this build does not
// know, enforces nothing it decides.
const unheld = "no enforcement point holds the path"

// notInline is why a plane of strength s enforces nothing it decides, or
// nothing for an inline one.
func notInline(s channel.Strength) string {
	switch s {
	case channel.StrengthInline:
		return ""
	case channel.StrengthCooperative:
		return cooperating
	}
	return unheld
}

// toolTableLine is a plane's state for an enforce_tool path. A plane stands
// in front of it when its tool table names the tool, and decides it in every
// mode it runs in: the client it answers may ignore the answer.
func toolTableLine(p Plane, path Path) (PlaneLine, bool, bool) {
	i := slices.IndexFunc(p.Tools, func(t Tool) bool { return t.Name == path.Tool })
	if i < 0 {
		return PlaneLine{}, false, false
	}
	line := PlaneLine{Plane: p.Name}
	head := modeName(p.Mode)
	class, _ := classOf(p.Mode)
	switch {
	case class == modeRefused:
		line.Basis = head + refusedAtStart
		return line, false, true
	case class == modeEnforces && p.Tools[i].Effect == controlv1.EffectClass_EFFECT_CLASS_READ && failOpenRead(p):
		head += readsUndecided
	}
	line.State = Decided
	line.Basis = head + "; the tool table classifies it by name; " + cooperating + "; no tool definition is checked" + planeUnread
	return line, true, true
}

const (
	refusedAtStart = " is refused at start by the plane, so it classifies nothing"
	readsUndecided = " with fail_open_read: a read runs undecided while the policy is unavailable"
)

// mcpLine is one plane's state for an mcp_tool path. A plane stands in front
// of the path when it lists the path's upstream or has an override for its
// tool, and classifies it when, besides, its mode runs.
func mcpLine(p Plane, path Path) (PlaneLine, bool, bool) {
	fingerprints, readUndecided := overridesFor(p, path)
	if len(fingerprints) == 0 && !slices.Contains(p.Upstreams, path.Upstream) {
		return PlaneLine{}, false, false
	}
	line := PlaneLine{Plane: p.Name}
	class, _ := classOf(p.Mode)
	head := modeName(p.Mode)
	switch {
	case class == modeRefused:
		line.Basis = head + refusedAtStart
		return line, false, true
	case len(fingerprints) == 0:
		return unclassifiedLine(line, class, head), true, true
	case class == modeDecides:
		line.State = Decided
	case readUndecided:
		line.State = Decided
		head += readsUndecided
	default:
		line.State = Enforced
	}
	pins := "override pins fingerprint " + fingerprints[0]
	if len(fingerprints) > 1 {
		pins = "overrides pin fingerprints " + strings.Join(fingerprints, ", ")
	}
	line.Basis = head + "; " + pins + "; the live definition is not checked" + planeUnread
	return line, true, true
}

// overridesFor is the fingerprints p's overrides pin for path's tool, and
// whether one of them is a read the plane lets run undecided.
func overridesFor(p Plane, path Path) ([]string, bool) {
	var fingerprints []string
	readUndecided := false
	for _, o := range p.Overrides {
		if o.Upstream != path.Upstream || o.Tool != path.Tool {
			continue
		}
		fingerprints = append(fingerprints, printable(o.Fingerprint))
		readUndecided = readUndecided || o.Effect == controlv1.EffectClass_EFFECT_CLASS_READ && failOpenRead(p)
	}
	return fingerprints, readUndecided
}

const planeUnread = "; the plane's environment is not read"

// unclassifiedLine is a running plane's state for a tool on one of its
// upstreams that no override names: the plane blocks such a call in every
// mode but OBSERVE, which lets it run.
func unclassifiedLine(line PlaneLine, class modeClass, mode string) PlaneLine {
	const why = "; the plane lists the upstream and no override names the tool" + planeUnread
	if class == modeDecides {
		line.State, line.Basis = Decided, "an unclassified call runs in "+mode+why
		return line
	}
	line.State, line.Basis = Enforced, "an unclassified call is blocked in "+mode+why
	return line
}

// failOpenRead is the plane's effective setting: LOCKDOWN turns fail-open
// reads off whatever the configuration says.
func failOpenRead(p Plane) bool {
	return p.FailOpenRead && p.Mode != controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN
}
