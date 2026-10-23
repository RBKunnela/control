package supervise

import (
	"cmp"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/observe"
)

// instance is one call of a step: a plane request. An observation no plane
// call joins is the runtime's claim alone and never an instance. at is when
// it was proposed and endAt when its terminal event happened. Two proposals
// of one instant are untold against each other wherever they were read: a
// plane ships several batches at a time, so a place in an export is not the
// plane's order.
type instance struct {
	step            int
	at, endAt       time.Time
	timed, endTimed bool
	failed          bool
	start, end      ref
	request         string
}

// byProposal orders instances by proposal time, then by request id, so a
// list of them reads the same whatever order the evidence was read in. The
// request id says nothing of which came first.
func byProposal(a, b *instance) int {
	return cmp.Or(a.at.Compare(b.at), cmp.Compare(a.request, b.request))
}

// evaluation is one run's inputs as the rules read them.
type evaluation struct {
	in        Input
	p         *Procedure
	ix        index
	rd        *read
	reqs      []*request
	byRequest map[string]*request
	// unjoined are the run's tool observations that no plane call joins, and
	// joinDoubt those of them a join that ran out of steps may have missed.
	unjoined  []*observev1.Observation
	joinDoubt map[string]bool
	inst      []*instance
	ofStep    map[int][]*instance
	// reported are the unjoined observations of each step, by id.
	reported map[int][]string
	// stepIndex maps a step's id to its place in the procedure.
	stepIndex map[string]int
	// first and last are the run's earliest and latest events with a time,
	// and untimed says whether an event of the run has none.
	first, last *controlv1.Event
	untimed     bool
	silent      map[string]bool
	anySilent   bool
	neverHeard  []string
	lapsed      []string
	// refused is what each source's imports refused, and refusedJudged the
	// sources a copy of which may be a call of a run judged.
	refused       map[string]refusals
	refusedJudged map[string]bool
	// firsts holds firstOf's answer by step: the rules ask it per instance,
	// and the instances do not change once read.
	firsts map[int]first
	// retry, places and bound are built once, when a rule first asks.
	retry  *retryIndex
	places map[string][]place
	bound  map[string][]*request
	// parents is each run's parent in the tree, and scopes ownScope's answers.
	parents map[string]string
	scopes  map[[2]string]bool
	// waived is what each exception took away, filled as the rules it waives
	// are applied.
	waived map[waiverKey]*waiver
}

// refusals are the runs a source's imports refused a copy of, or every run.
type refusals struct {
	every bool
	runs  map[string]bool
}

func (r refusals) covers(run string) bool { return r.every || r.runs[run] }

type first struct {
	in   *instance
	told bool
}

func newEvaluation(in Input, rd *read) *evaluation {
	e := &evaluation{in: in, p: in.Procedure, ix: indexOf(in.Procedure), rd: rd,
		byRequest: map[string]*request{}, ofStep: map[int][]*instance{}, stepIndex: map[string]int{},
		joinDoubt: map[string]bool{}, reported: map[int][]string{}, firsts: map[int]first{}, waived: map[waiverKey]*waiver{},
		scopes: map[[2]string]bool{}}
	for i, s := range e.p.steps {
		e.stepIndex[s.ID] = i
	}
	e.reqs = requestsOf(rd.events, rd.doubtful)
	for _, rq := range e.reqs {
		e.byRequest[rq.id] = rq
	}
	e.spanEvents()
	e.hearSources()
	j := newJoiner(e.ix, e.reqs, rd.spans)
	for _, o := range rd.obs {
		joined, doubt := j.joined(o, rd.obsSource[o.GetObservationId()])
		if !joined {
			e.unjoined = append(e.unjoined, o)
			e.joinDoubt[o.GetObservationId()] = doubt
		}
	}
	e.instances()
	return e
}

// spanEvents finds the run's earliest and latest events with a time, the
// first read winning a tie, and whether an event has no time.
func (e *evaluation) spanEvents() {
	for _, ev := range e.rd.events {
		if !ev.GetOccurredAt().IsValid() {
			e.untimed = true
			continue
		}
		t := ev.GetOccurredAt().AsTime()
		if e.first == nil || t.Before(e.first.GetOccurredAt().AsTime()) {
			e.first = ev
		}
		if e.last == nil || t.After(e.last.GetOccurredAt().AsTime()) {
			e.last = ev
		}
	}
}

// hearSources marks a source silent when it was never heard, or when its
// heartbeat ran out before the run's last plane event: what it did not report
// by then may simply not have arrived. A source named and not read reported
// nothing that was read.
func (e *evaluation) hearSources() {
	e.silent, e.refused, e.refusedJudged = map[string]bool{}, map[string]refusals{}, map[string]bool{}
	e.anySilent = len(e.in.SourcesNotRead) > 0
	for _, s := range e.in.Sources {
		silent := !s.Heard
		if e.last != nil {
			// A source heard after the run's last event was live as of it.
			l := observe.LivenessAt(s.LastHeard, s.Heard, s.HeartbeatSeconds, e.last.GetOccurredAt().AsTime())
			silent = l == observe.NeverHeard || l == observe.Lapsed
		}
		switch {
		case !s.Heard:
			e.neverHeard = append(e.neverHeard, s.SourceID)
		case silent:
			e.lapsed = append(e.lapsed, s.SourceID)
		}
		e.silent[s.SourceID] = silent
		e.anySilent = e.anySilent || silent
		r := refusals{every: s.EveryRunDoubted, runs: map[string]bool{}}
		for _, run := range s.DoubtedRuns {
			r.runs[run] = true
		}
		e.refused[s.SourceID] = r
		for run := range e.rd.runs {
			e.refusedJudged[s.SourceID] = e.refusedJudged[s.SourceID] || r.covers(run)
		}
	}
}

func (e *evaluation) instances() {
	for _, rq := range e.reqs {
		tool, ok := rq.tool()
		en, known := e.ix.byTool[tool]
		if !ok || !known || en.step == noStep {
			continue
		}
		at := rq.proposal.GetOccurredAt()
		in := &instance{step: en.step, at: at.AsTime(), timed: at.IsValid(), failed: rq.failed(),
			start: rq.ref(rq.proposal), request: rq.id}
		if rq.terminal != nil {
			end := rq.terminal.GetOccurredAt()
			in.end, in.endAt, in.endTimed = rq.ref(rq.terminal), end.AsTime(), end.IsValid()
		}
		e.add(in)
	}
	for _, o := range e.unjoined {
		if en, known := e.ix.byName[o.GetSubject().GetName()]; known && en.step != noStep {
			e.reported[en.step] = append(e.reported[en.step], o.GetObservationId())
		}
	}
}

func (e *evaluation) add(in *instance) {
	e.inst = append(e.inst, in)
	e.ofStep[in.step] = append(e.ofStep[in.step], in)
}

// firstOf is a step's first instance and whether it is told: its earliest
// instance when every one has a time, or else the one with no time of the
// least request id, which may have come before any timed one. An earliest
// instance another instance of the step ties is untold too. Where evidence
// was read decides neither. The step must have an instance.
func (e *evaluation) firstOf(step int) (*instance, bool) {
	f, ok := e.firsts[step]
	if !ok {
		f.in, f.told = e.findFirst(step)
		e.firsts[step] = f
	}
	return f.in, f.told
}

func (e *evaluation) findFirst(step int) (*instance, bool) {
	var untimed *instance
	for _, in := range e.ofStep[step] {
		if !in.timed && (untimed == nil || in.request < untimed.request) {
			untimed = in
		}
	}
	if untimed != nil {
		return untimed, false
	}
	return e.firstTimed(step)
}

// firstTimed is a step's earliest instance with a time, or nil, and whether
// it is told: whether no other instance of the step has the same time. Of
// tied earliest instances it is the one of the least request id.
func (e *evaluation) firstTimed(step int) (*instance, bool) {
	var earliest *instance
	for _, in := range e.ofStep[step] {
		if in.timed && (earliest == nil || in.at.Before(earliest.at)) {
			earliest = in
		}
	}
	if earliest == nil {
		return nil, true
	}
	var tied []*instance
	for _, in := range e.ofStep[step] {
		if in.timed && in.at.Equal(earliest.at) {
			tied = append(tied, in)
		}
	}
	return leastRequest(tied), len(tied) == 1
}

// leastRequest is the instance of the least request id, so which of untold
// instances a finding cites does not follow the order evidence was read in.
func leastRequest(ins []*instance) *instance {
	var least *instance
	for _, in := range ins {
		if least == nil || in.request < least.request {
			least = in
		}
	}
	return least
}

// obsRef cites an observation: it suggests at most, and nothing when its id
// was read with two contents, its source is silent, its source's imports
// refused a copy that may be a call of its run, or the join may have missed
// it.
func (e *evaluation) obsRef(o *observev1.Observation) ref {
	id := o.GetObservationId()
	return ref{v: e.obsVerdict(o), r: &findingv1alpha1.Reference{Ref: &findingv1alpha1.Reference_Observation{
		Observation: &findingv1alpha1.ObservationRef{SourceId: e.rd.obsSource[id].SourceID, ObservationId: id},
	}}}
}

// obsVerdict is the verdict obsRef cites o at.
func (e *evaluation) obsVerdict(o *observev1.Observation) controlv1.FindingVerdict {
	id := o.GetObservationId()
	src := e.rd.obsSource[id].SourceID
	if e.rd.obsDoubt[id] || e.joinDoubt[id] || e.silent[src] || e.refused[src].covers(o.GetCorrelation().GetRunId()) {
		return indeterminate
	}
	return suspected
}

// apply runs one rule, less what its exceptions waive, its drafts carrying
// the rule's version from the table.
func (e *evaluation) apply(rule string) []draft {
	row, known := ruleOf(rule)
	if !known {
		return nil
	}
	out := e.except(rule, e.drafts(rule))
	for i := range out {
		out[i].version = row.version
	}
	return out
}

func (e *evaluation) drafts(rule string) []draft {
	switch rule {
	case RuleRepeatedDenial:
		return e.repeatedDenial()
	case RuleStepOutsideProcedure:
		return e.outsideProcedure()
	case RuleDeadlineExceeded:
		return e.deadline()
	case RuleRequiredStepSkipped:
		return e.skipped()
	case RuleStepOutOfOrder:
		out, _ := e.outOfOrder()
		return out
	case RuleContinuedAfterFailure:
		return e.continued()
	case RuleResourceOutsideRun:
		return append(e.resourceOutside(), e.unjudged()...)
	case RuleDeniedActionRetriedArguments:
		return e.retriedArguments()
	case RuleDeniedActionRetriedResource:
		return e.retriedResource()
	case RuleDeniedActionRetriedAround:
		return e.retriedAround()
	case RuleExceptionTaken:
		return e.exceptionsTaken()
	}
	return nil
}
