package coverage

import (
	"fmt"
	"strings"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
)

// Exit statuses of the coverage command.
const (
	// ExitCovered: every declared path is at least observed and no
	// observation is a call around the plane.
	ExitCovered = 0
	// ExitGaps: some path is weaker than observed, a call went around the
	// plane, or a walk down a trace was cut at its bound.
	ExitGaps = 1
	// ExitRefused: an input was refused and no map was made.
	ExitRefused = 2
)

// UndeclaredRow is the standing last line: a path nobody declared is unknown.
const UndeclaredRow = "undeclared paths: unknown"

// Plane is one plane's configuration as gatewayconfig.Load reads it with a
// nil environment: the plane's environment is not read, and every plane line
// says so.
type Plane struct {
	// Name is how lines name the plane, such as the configuration's path.
	Name string
	// Mode is the configured enforcement mode.
	Mode controlv1.EnforcementMode
	// FailOpenRead is policy.fail_open_read as configured.
	FailOpenRead bool
	// Upstreams are the names of the configuration's upstreams. A plane
	// that lists a path's upstream and has no override for its tool still
	// counts: it blocks the unclassified call, or in OBSERVE lets it run.
	Upstreams []string
	// Overrides are the configuration's classified tools.
	Overrides []Override
	// Strength is how far the plane's adapter keeps a call from its effect,
	// as the protocol table states it for the listener's protocol. Only an
	// inline plane enforces; a cooperative one hands each decision to a
	// client that enforces it, and the zero value, None, enforces nothing.
	Strength channel.Strength
	// Tools are what an enforcement API listener's tool table classifies.
	Tools []Tool
	// Export is this plane's evidence export for the join; nil when none was
	// given, so no observation can be shown to have gone around this plane.
	Export *Export
}

// Override is one tool classification of a plane: the tool on an upstream,
// the definition fingerprint it pins, and the effect class it assigns.
type Override struct {
	Upstream    string
	Tool        string
	Fingerprint string
	Effect      controlv1.EffectClass
}

// Tool is one tool an enforcement API listener's tool table classifies by
// name, and the effect class it assigns.
type Tool struct {
	Name   string
	Effect controlv1.EffectClass
}

// Source is one observation source whose descriptor was read. A descriptor
// that is absent is not passed: the paths naming its source are then not
// covered by it.
type Source struct {
	// Descriptor is what observe.ReadDescriptor returned.
	Descriptor *observev1.SourceDescriptor
	// Records are the committed records of the source's log, in order; nil
	// when the log directory holds no log yet, which is never heard.
	Records []*observev1.Record
}

// Input is everything one map is made from.
type Input struct {
	Inventory *Inventory
	Planes    []Plane
	Sources   []Source
	// AbsentDescriptors are the descriptors given for sources that do not
	// exist. A source the inventory names and no Source carries may be one
	// of them, or one no descriptor was given for.
	AbsentDescriptors []string
	// Now is the clock read once by the caller; liveness is measured to it.
	Now time.Time
}

// Report is one map: a PathCoverage per declared path, in the inventory's
// order.
type Report struct {
	Paths []PathCoverage
}

// PathCoverage is what covers one declared path, and on what basis.
type PathCoverage struct {
	Path Path
	// State is the strongest of the planes' state and the sources' state.
	State State
	// Basis names what State rests on: the planes or the sources.
	Basis string
	// Trust is the weakest trust among the sources that observed the path;
	// unspecified when none did.
	Trust observev1.Trust
	// Sampled is true when every source that observed the path samples, so
	// a call of it may have gone unseen.
	Sampled bool
	// Planes has a line for each plane in front of the path: one that lists
	// its upstream or has an override for its tool.
	Planes []PlaneLine
	// Sources has a line for each source the inventory names for the path.
	Sources []SourceLine
	// Joins has one check per matching observation, made only beside a path
	// a plane enforces or decides.
	Joins []JoinCheck
}

// PlaneLine is one plane's state for a path.
type PlaneLine struct {
	Plane string
	State State
	Basis string
}

// SourceLine is one source's state for a path: Observed, Unknown or
// NotCovered.
type SourceLine struct {
	SourceID string
	State    State
	Trust    observev1.Trust
	// Sampled is an observing source whose descriptor does not say it
	// samples completely.
	Sampled bool
	Basis   string
}

// JoinCheck is the join of one observation with the evidence.
type JoinCheck struct {
	ObservationID string
	Join          Join
	// Why says why the join was not checked.
	Why string
	// Cut is a join not checked because its walk passed MaxWalkSpans.
	Cut bool
}

// Map states coverage for every declared path. It refuses, with ErrInput, an
// absent inventory or one of no path or of a path twice, a zero Now, a plane
// mode or override effect the contract does not declare, and a source
// without a descriptor or one source twice.
func Map(in Input) (*Report, error) {
	sources, err := in.check()
	if err != nil {
		return nil, err
	}
	r := &Report{Paths: make([]PathCoverage, 0, len(in.Inventory.Paths))}
	walked := families{}
	for _, p := range in.Inventory.Paths {
		r.Paths = append(r.Paths, in.path(p, sources, walked))
	}
	return r, nil
}

func (in Input) check() (map[string]*Source, error) {
	switch {
	case in.Inventory == nil || len(in.Inventory.Paths) == 0:
		return nil, fmt.Errorf("%w: no inventory, or one of no path", ErrInput)
	case in.Now.IsZero():
		return nil, fmt.Errorf("%w: no time to measure liveness to", ErrInput)
	}
	if err := unique(in.Inventory.Paths); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInput, err)
	}
	for _, p := range in.Planes {
		if err := checkPlane(p); err != nil {
			return nil, err
		}
	}
	sources := make(map[string]*Source, len(in.Sources))
	for i := range in.Sources {
		id := in.Sources[i].Descriptor.GetSourceId()
		switch {
		case id == "":
			return nil, fmt.Errorf("%w: source %d has no descriptor", ErrInput, i)
		case sources[id] != nil:
			return nil, fmt.Errorf("%w: source %s given twice", ErrInput, printable(id))
		}
		sources[id] = &in.Sources[i]
	}
	return sources, nil
}

func (in Input) path(p Path, sources map[string]*Source, walked families) PathCoverage {
	pc := PathCoverage{Path: p}
	planeState, counting := NotCovered, []Plane(nil)
	if p.Kind == KindMCPTool || p.Kind == KindEnforceTool {
		planeState, pc.Planes, counting = planeCoverage(in.Planes, p)
	}
	for _, ps := range p.Sources {
		pc.Sources = append(pc.Sources, sourceLine(ps, sources[ps.SourceID], in.Now, in.AbsentDescriptors))
	}
	sourceState, trust, sampled, sourcesBy := sourceCoverage(pc.Sources)
	switch {
	case len(counting) > 0 && planeState >= sourceState:
		pc.State, pc.Basis = planeState, "planes "+planeNames(counting)
	case sourceState > NotCovered:
		pc.State, pc.Basis = sourceState, "sources "+strings.Join(sourcesBy, ", ")
	default:
		pc.Basis = "no plane classifies it and no live source observed it"
	}
	if sourceState == Observed {
		pc.Trust, pc.Sampled = trust, sampled
	}
	if planeState >= Decided {
		pc.Joins = joins(p, pc.State, sources, counting, walked)
	}
	return pc
}

func planeNames(planes []Plane) string {
	names := make([]string, 0, len(planes))
	for _, p := range planes {
		names = append(names, printable(p.Name))
	}
	return strings.Join(names, ", ")
}

// joins checks every observation of the path, from any source the path
// names, live or not, against the exports of the planes in front of it: an
// old call around the plane is still one.
func joins(p Path, state State, sources map[string]*Source, planes []Plane, walked families) []JoinCheck {
	need := modeDecides
	if state == Enforced {
		need = modeEnforces
	}
	var out []JoinCheck
	for _, ps := range p.Sources {
		src := sources[ps.SourceID]
		if src == nil {
			continue
		}
		j := joiner{f: walked.of(src), path: p, need: need, planes: planes, seen: map[int]verdict{}}
		for _, o := range observationsOf(src, ps) {
			out = append(out, j.join(o))
		}
	}
	return out
}

// ExitStatus is the command's exit status for a map and the error that
// stopped it: ExitRefused on an error or a map of no path, ExitCovered when
// every path is at least observed, none went around the plane and no walk was
// cut, ExitGaps otherwise.
func ExitStatus(r *Report, err error) int {
	if err != nil || r == nil || len(r.Paths) == 0 {
		return ExitRefused
	}
	for _, p := range r.Paths {
		if p.State < Observed {
			return ExitGaps
		}
		for _, j := range p.Joins {
			if j.Join == JoinAround || j.Cut {
				return ExitGaps
			}
		}
	}
	return ExitCovered
}
