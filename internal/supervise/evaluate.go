package supervise

import (
	"fmt"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/observe"
)

// RecordSchemaVersion is the version of a 0.1 procedure's report and of each
// finding record that carries no member of 0.2.
const RecordSchemaVersion = "0.1"

// Run is an opened run, as its record says.
type Run struct {
	// ID is "run-" and 32 lowercase hex digits.
	ID     string
	Tenant string
	// Project is the project the run's record names, or empty when no record
	// names one. When given, every event of the run read and every run of the
	// tree must be of it.
	Project string
	Closed  bool
	// Parent is the run this one was opened under, or empty for a root.
	Parent string
}

// MaxTreeRuns bounds the runs one supervision reads as its tree, the
// supervised run included, so the report that lists them fits a findings
// log line with every string it carries at the contract's longest.
const MaxTreeRuns = 400

// Export is one evidence export's events. Whole is true when it holds every
// line of its trail; NotWhole says why it does not.
type Export struct {
	Events   []*controlv1.Event
	Whole    bool
	NotWhole string
}

// Source is one observation source with the observations of its log, read
// under one identity: its descriptor's source id, tenant and project.
// LastHeard and Heard are what observe.LastHeard reads from its import
// reports, and EveryRunDoubted and DoubtedRuns what observe.DoubtedRuns
// reads: a span an import refused, or an observation the log refused for an
// id it held with other content, was never read and may be a call of any
// run, when EveryRunDoubted, or of a run DoubtedRuns names.
type Source struct {
	SourceID         string
	Tenant, Project  string
	HeartbeatSeconds uint32
	LastHeard        time.Time
	Heard            bool
	Observations     []*observev1.Observation
	EveryRunDoubted  bool
	DoubtedRuns      []string
}

// Input is everything one supervision reads. SourcesNotRead names, as the
// caller named them, the sources it was given whose descriptor it did not
// find: each is in doubt as a silent source is.
type Input struct {
	Procedure *Procedure
	// Run is the supervised run.
	Run Run
	// Tree is Run and the runs the procedure's children mode reads beside
	// it, Run first and each other run after its parent. Under inherit Run is
	// a root, Tree its whole tree and every run of it judged; under separate
	// the others are Run's children, listed and not judged. Empty is Run
	// alone, all a 0.1 procedure reads.
	Tree           []Run
	Exports        []Export
	Sources        []Source
	SourcesNotRead []string
}

// StepMatch names one step's instances, the plane requests, and the
// observations of it no plane call joins: those are reported by the runtime
// only, and no rule counts them as the step taken.
type StepMatch struct {
	StepID         string
	RequestIDs     []string
	ObservationIDs []string
}

// Result is one supervision's findings and its report. Report.Read's
// EventsTaken is 0 when no plane event of the run was read, and then no rule
// was checked: that is never a pass.
type Result struct {
	Findings []*findingv1alpha1.FindingRecord
	Report   *findingv1alpha1.SuperviseReport
	Steps    []StepMatch
	// SourcesNotRead is Input's: the named sources whose observations were
	// not read, so every finding that rests on what they did not report is
	// indeterminate.
	SourcesNotRead []string
	// NeverHeard names, in the order given, the sources no import report
	// says were heard, and Silent those whose heartbeat ran out before the
	// run's last plane event with a time. Either is in doubt, as a source not
	// read is.
	NeverHeard, Silent []string
	// PlaneBlocks counts the run's blocks that are no denial: the plane's
	// own, and the kernel's on a verdict other than DENY, by the first reason
	// code of the decision each carries.
	PlaneBlocks map[string]uint64
	// Instances are the calls judged: the run's tool calls in the order
	// first read, then the reports no plane call joins. Rests[i] holds the
	// places in Instances of the calls Findings[i] cites.
	Instances []Instance
	Rests     [][]int
}

// Evaluate checks one run against its procedure. It refuses a run id that is
// not an opened run's with ErrRunID, and a procedure ReadProcedure did not
// make, a run with no tenant, a tree its procedure does not read, a source
// given twice, a run whose events name two projects or another than its
// record, or a source of another tenant or project than the run's with
// ErrInput.
func Evaluate(in Input) (*Result, error) {
	e, err := prepare(in)
	if err != nil {
		return nil, err
	}
	states := e.states()
	var drafts []draft
	for _, id := range RuleIDsOf(e.p.schema) {
		// The waivers of the rules that were checked are written whatever
		// EXCEPTION_TAKEN's own state says of the others.
		if states[id].state == findingv1alpha1.RuleState_RULE_STATE_CHECKED || id == RuleExceptionTaken {
			drafts = append(drafts, e.apply(id)...)
		}
	}
	return e.result(drafts, states), nil
}

// RunProject is the one project the run's events name, as Evaluate reads
// them, or "" when none of them is read. It refuses what Evaluate refuses
// before it reads a source.
func RunProject(in Input) (string, error) {
	if err := checkInput(in); err != nil {
		return "", err
	}
	rd := newRead(judged(in), in.Run.Tenant, in.Run.Project)
	if err := rd.takeEvents(in.Exports); err != nil {
		return "", err
	}
	return rd.project, nil
}

// prepare checks in and reads what belongs to its run, ready for the rules.
func prepare(in Input) (*evaluation, error) {
	if err := checkInput(in); err != nil {
		return nil, err
	}
	rd := newRead(judged(in), in.Run.Tenant, in.Run.Project)
	if err := rd.takeEvents(in.Exports); err != nil {
		return nil, err
	}
	if err := rd.checkSources(in.Sources); err != nil {
		return nil, err
	}
	rd.takeObservations(in.Sources)
	return newEvaluation(in, rd), nil
}

func checkInput(in Input) error {
	if in.Procedure == nil || in.Procedure.digest == "" {
		return ErrInput.with("no procedure ReadProcedure accepted")
	}
	if !observe.ValidRunID(in.Run.ID) {
		return ErrRunID
	}
	if in.Run.Tenant == "" {
		return ErrInput.with("the run names no tenant")
	}
	seen := map[string]bool{}
	for _, s := range in.Sources {
		if seen[s.SourceID] {
			return ErrInput.with("a source is given twice")
		}
		seen[s.SourceID] = true
	}
	return checkTree(in)
}

// treeOf is the input's tree: Run alone when none is given.
func treeOf(in Input) []Run {
	if len(in.Tree) == 0 {
		return []Run{in.Run}
	}
	return in.Tree
}

// checkTree holds the tree to the procedure's children mode: Run first and
// every run of Run's tenant and project, given once. Under inherit Run is a root and
// every other run comes after its parent; under separate every other run is
// Run's child; a 0.1 procedure reads a root run alone.
func checkTree(in Input) error {
	tree, mode := treeOf(in), in.Procedure.children
	switch {
	case len(tree) > MaxTreeRuns:
		return ErrInput.with(fmt.Sprintf("the run tree holds %d runs, bound %d", len(tree), MaxTreeRuns))
	case tree[0] != in.Run:
		return ErrInput.with("the run tree does not start at the supervised run")
	case in.Run.Parent != "" && !observe.ValidRunID(in.Run.Parent):
		return ErrRunID
	case in.Run.Parent != "" && mode != ChildrenSeparate:
		return ErrInput.with("a child run is supervised on its own only when children are separate")
	case len(tree) > 1 && mode == ChildrenUnstated:
		return ErrInput.with("a 0.1 procedure reads one run")
	}
	listed := make(map[string]bool, len(tree))
	listed[in.Run.ID] = true
	for _, r := range tree[1:] {
		if err := checkMember(in.Run, mode, r, listed); err != nil {
			return err
		}
		listed[r.ID] = true
	}
	return nil
}

// checkMember holds one run of the tree after the first to the supervised
// run, given the runs listed before it.
func checkMember(run Run, mode Children, r Run, listed map[string]bool) error {
	switch {
	case !observe.ValidRunID(r.ID):
		return ErrRunID
	case r.Tenant != run.Tenant:
		return ErrInput.with("a run of the tree belongs to another tenant")
	case r.Project != run.Project:
		return ErrInput.with("a run of the tree belongs to another project")
	case listed[r.ID]:
		return ErrInput.with("a run of the tree is given twice")
	case mode == ChildrenSeparate && r.Parent != run.ID:
		return ErrInput.with("a run listed beside a separate run is not its child")
	case !listed[r.Parent]:
		return ErrInput.with("a run of the tree comes before its parent")
	}
	return nil
}

// judged is the runs whose events and observations are read: the whole
// tree under inherit, else the supervised run alone.
func judged(in Input) map[string]bool {
	out := map[string]bool{in.Run.ID: true}
	if in.Procedure.children == ChildrenInherit {
		for _, r := range treeOf(in) {
			out[r.ID] = true
		}
	}
	return out
}
