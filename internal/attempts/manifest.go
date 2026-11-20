package attempts

import (
	"errors"
	"fmt"
	"slices"

	"github.com/guardana/control/internal/files"
)

// ManifestKind is the one kind of manifest this build reads. A change to the
// format is a new kind.
const ManifestKind = "attempt-manifest/v1alpha1"

// NoModel is the one model this kind names: the attempts are scripted.
const NoModel = "no model"

// The bounds of a manifest.
const (
	MaxManifestBytes  = 256 << 10
	MaxDepth          = 16
	MaxAboutBytes     = 200
	MaxSelectionBytes = 400
	MaxRepetitions    = 20
	MaxPlanes         = 8
	MaxAttempts       = 64
	MaxSteps          = 256
	MaxEffects        = 64
	MaxStepEffects    = 8
	MaxConditions     = 16
	MaxIDBytes        = 64
	MaxNameBytes      = 128
	MaxPathBytes      = 512
	MaxMemberBytes    = 256
	MaxContainsBytes  = 1024
	MaxObservedLimit  = 999999999
)

// Manifest is one read manifest. Every path is as written, relative to the
// manifest's directory.
type Manifest struct {
	About       string
	Selection   string
	Repetitions int
	Model       string
	Demo        string
	Policy      string
	Planes      []Plane
	Attempts    []Attempt
	Effects     []Effect
	Thresholds  Thresholds
}

// Role is what a plane configuration is for.
type Role string

// The two roles: the plane being measured, and the plane on which every
// attack effect must be observed for an absence elsewhere to count.
const (
	RoleMeasured Role = "measured"
	RolePositive Role = "positive"
)

// The decision points a plane configuration may name.
const (
	DecisionPointSilent = "silent"
	DecisionPointNone   = "none"
)

// Plane is one plane configuration every attempt runs on.
type Plane struct {
	ID            string
	Mode          string
	DecisionPoint string
	Role          Role
}

// Label is what one step of an attempt is.
type Label string

// The three labels.
const (
	LabelAttack     Label = "attack"
	LabelLegitimate Label = "legitimate"
	LabelOperator   Label = "operator"
)

// Attempt is one scenario file with a label for each of its steps.
type Attempt struct {
	ID       string
	Scenario string
	Steps    []StepLabel
}

// StepLabel labels one step of the scenario. Effects, for an attack step
// only, names the effects the step aims at.
type StepLabel struct {
	Step    int
	Label   Label
	Effects []string
}

// Effect is what counts as one named effect at a victim: a call the server
// received whose arguments meet every condition.
type Effect struct {
	ID         string
	Server     string
	Call       string
	Conditions []Condition
}

// Condition holds one member of the arguments, named by a JSON pointer, to a
// value: Equals when it is set, else Contains, a text the member's string
// must hold.
type Condition struct {
	Member   string
	Equals   *Value
	Contains string
}

// Thresholds are what a measured plane must meet: at most AttackObservedMax
// observed effects, and a share of legitimate steps completed of at least
// CompletedMinBasis in ten-thousandths. CompletedMin is the share as written.
type Thresholds struct {
	AttackObservedMax int
	CompletedMin      string
	CompletedMinBasis int
}

// ReadManifestFile reads the manifest at path. It reads at most one byte
// past the bound, and its open never waits on a named pipe.
func ReadManifestFile(path string) (*Manifest, []byte, error) {
	raw, err := files.ReadRegular(path, MaxManifestBytes, 0)
	switch {
	case errors.Is(err, files.ErrTooLarge):
		return nil, nil, fmt.Errorf("%w: over %d bytes", ErrTooLarge, MaxManifestBytes)
	case err != nil:
		return nil, nil, fmt.Errorf("attempts: %w", err)
	}
	m, err := ReadManifest(raw)
	return m, raw, err
}

// ReadManifest reads raw. A document over its bound is refused before it is
// read; then its syntax; then its kind, wherever the member stands; then a
// null, a repeated member, a string that is not UTF-8 or escapes a lone
// surrogate, or anything after the document; then every member.
func ReadManifest(raw []byte) (*Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: %d bytes, the bound is %d", ErrTooLarge, len(raw), MaxManifestBytes)
	}
	root, noted, fatal := parse(raw, MaxDepth)
	if fatal != nil {
		return nil, fatal
	}
	if err := checkKind(root); err != nil {
		return nil, err
	}
	if noted != nil {
		return nil, noted
	}
	return readManifest(root)
}

func checkKind(root *Value) error {
	if root.Kind != Object {
		return refuse(ErrWrongType, "", "want an object")
	}
	var kinds []*Value
	for _, m := range root.Members {
		if m.Name == "kind" {
			kinds = append(kinds, m.Value)
		}
	}
	switch {
	case len(kinds) == 0:
		return refuse(ErrMissing, "kind", "")
	case len(kinds) > 1:
		return refuse(ErrDuplicate, "kind", "")
	case kinds[0].Kind == 0:
		return refuse(ErrNull, "kind", "")
	case kinds[0].Kind != String:
		return refuse(ErrWrongType, "kind", "want a string")
	case kinds[0].Text != ManifestKind:
		return refuse(ErrKind, "kind", fmt.Sprintf("this build reads %s, not %q", ManifestKind, clip(kinds[0].Text)))
	}
	return nil
}

func readManifest(root *Value) (*Manifest, error) {
	f, err := closed(root, "", "kind", "about", "selection", "repetitions", "model", "demo", "policy",
		"planes", "attempts", "effects", "thresholds")
	if err != nil {
		return nil, err
	}
	m := &Manifest{}
	if m.About, err = boundedText(f["about"], "about", MaxAboutBytes); err != nil {
		return nil, err
	}
	if m.Selection, err = boundedText(f["selection"], "selection", MaxSelectionBytes); err != nil {
		return nil, err
	}
	if m.Repetitions, err = integer(f["repetitions"], "repetitions", 1, MaxRepetitions); err != nil {
		return nil, err
	}
	if m.Model, err = text(f["model"], "model"); err != nil {
		return nil, err
	}
	if m.Model != NoModel {
		return nil, refuse(ErrValue, "model", fmt.Sprintf("this kind names no model, so it must be %q", NoModel))
	}
	if err := m.readPaths(f["demo"], f["policy"]); err != nil {
		return nil, err
	}
	if m.Planes, err = readPlanes(f["planes"]); err != nil {
		return nil, err
	}
	if m.Effects, err = readEffects(f["effects"]); err != nil {
		return nil, err
	}
	if m.Attempts, err = m.readAttempts(f["attempts"]); err != nil {
		return nil, err
	}
	if m.Thresholds, err = readThresholds(f["thresholds"]); err != nil {
		return nil, err
	}
	return m, m.checkCoverage()
}

func (m *Manifest) readPaths(demo, policy *Value) error {
	var err error
	if m.Demo, err = text(demo, "demo"); err != nil {
		return err
	}
	if err := checkDemoPath(m.Demo); err != nil {
		return err
	}
	if m.Policy, err = text(policy, "policy"); err != nil {
		return err
	}
	return m.checkPath(m.Policy, "policy")
}

// checkCoverage refuses a manifest that measures nothing: no attack step or
// no legitimate step, an effect no attack step names, or no plane of either
// role.
func (m *Manifest) checkCoverage() error {
	named := map[string]bool{}
	var attack, legitimate bool
	for _, a := range m.Attempts {
		for _, st := range a.Steps {
			attack = attack || st.Label == LabelAttack
			legitimate = legitimate || st.Label == LabelLegitimate
			for _, e := range st.Effects {
				named[e] = true
			}
		}
	}
	switch {
	case !attack:
		return refuse(ErrLabel, "attempts", "no step is labelled attack, so no effect is measured")
	case !legitimate:
		return refuse(ErrLabel, "attempts", "no step is labelled legitimate, so no cost is measured")
	}
	for i, e := range m.Effects {
		if !named[e.ID] {
			return refuse(ErrEffect, fmt.Sprintf("effects[%d]", i), fmt.Sprintf("no attack step names %s", e.ID))
		}
	}
	return nil
}

// measured is whether the plane of configuration id is measured.
func (m *Manifest) measured(id string) bool {
	return slices.ContainsFunc(m.Planes, func(p Plane) bool { return p.ID == id && p.Role == RoleMeasured })
}

// Effect is the effect called id, or nil.
func (m *Manifest) Effect(id string) *Effect {
	for i := range m.Effects {
		if m.Effects[i].ID == id {
			return &m.Effects[i]
		}
	}
	return nil
}

// Files is every file the manifest names, each once, in the order named: the
// demo, the policy and each scenario.
func (m *Manifest) Files() []string {
	out := []string{m.Demo, m.Policy}
	for _, a := range m.Attempts {
		seen := false
		for _, p := range out {
			seen = seen || p == a.Scenario
		}
		if !seen {
			out = append(out, a.Scenario)
		}
	}
	return out
}
