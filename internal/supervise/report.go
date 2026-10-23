package supervise

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/trailchain"
)

// ruleState is what became of one rule, and why when it was not checked.
type ruleState struct {
	state findingv1alpha1.RuleState
	why   string
}

var checked = ruleState{state: findingv1alpha1.RuleState_RULE_STATE_CHECKED}

func notChecked(why string) ruleState {
	return ruleState{state: findingv1alpha1.RuleState_RULE_STATE_NOT_CHECKED, why: why}
}

func off(member string) ruleState {
	return ruleState{state: findingv1alpha1.RuleState_RULE_STATE_OFF, why: "the procedure leaves " + member + " out"}
}

// notApplied is a rule the procedure's schema knows that this build does
// not apply.
var notApplied = notChecked("this build does not apply the rule")

// states says which rules apply. With no event of the run none does. A rule
// that rests on something not seen applies only once nothing more can arrive
// and nothing was left out of what did: on a closed run, from exports that
// are all whole.
func (e *evaluation) states() map[string]ruleState {
	out := make(map[string]ruleState, len(ruleTable))
	for _, id := range RuleIDsOf(e.p.schema) {
		out[id] = notApplied
	}
	base := checked
	if len(e.rd.events) == 0 {
		base = notChecked("no plane event of the run")
	}
	absence := base
	if absence.state == checked.state {
		absence = e.absenceState()
	}
	for _, id := range ruleIDs {
		out[id] = base
	}
	out[RuleRequiredStepSkipped], out[RuleStepOutOfOrder], out[RuleContinuedAfterFailure] = absence, absence, absence
	if base.state == checked.state {
		e.untimedStates(out)
	}
	if e.p.maxDenials == 0 {
		out[RuleRepeatedDenial] = off("max_denials")
	}
	if e.p.deadlineSeconds == 0 {
		out[RuleDeadlineExceeded] = off("deadline_seconds")
	}
	e.states02(out, base)
	return out
}

// untimedStates leaves unchecked what events without a time cannot tell.
// With no event that has a time, no time and no order can be told; with one
// event that has none, the run may have lasted longer than its timed events
// span, so only a breach on that span is told.
func (e *evaluation) untimedStates(out map[string]ruleState) {
	switch {
	case e.first == nil:
		untimed := notChecked("no event of the run has a time")
		out[RuleDeadlineExceeded] = untimed
		for _, id := range []string{RuleStepOutOfOrder, RuleContinuedAfterFailure} {
			if out[id].state == checked.state {
				out[id] = untimed
			}
		}
	case e.untimed && !e.pastDeadline():
		out[RuleDeadlineExceeded] = notChecked("an event of the run has no time")
	}
}

func (e *evaluation) absenceState() ruleState {
	if !e.in.Run.Closed {
		return notChecked("the run is open")
	}
	if e.p.children == ChildrenInherit {
		for _, r := range treeOf(e.in) {
			if !r.Closed {
				return notChecked("run " + r.ID + " of the tree is open")
			}
		}
	}
	for _, x := range e.in.Exports {
		if !x.Whole {
			return notChecked("an export is not whole: " + x.NotWhole)
		}
	}
	return checked
}

func (e *evaluation) result(drafts []draft, states map[string]ruleState) *Result {
	e.doubtCut(states)
	if s, on := states[RuleExceptionTaken]; on && s.state == checked.state {
		states[RuleExceptionTaken] = e.takenState(states, checked)
	}
	s := scope{tenant: e.in.Run.Tenant, project: e.rd.project, run: e.in.Run.ID, proc: e.p}
	res := &Result{PlaneBlocks: map[string]uint64{}, SourcesNotRead: e.in.SourcesNotRead,
		NeverHeard: e.neverHeard, Silent: e.lapsed}
	for _, d := range drafts {
		res.Findings = append(res.Findings, s.record(d))
	}
	res.Report = &findingv1alpha1.SuperviseReport{
		SchemaVersion: RecordSchemaVersion, TenantId: s.tenant, ProjectId: s.project, RunId: s.run,
		Procedure: s.procedureRef(), Read: e.rd.counts, FindingsWritten: uint64(len(res.Findings)),
	}
	for _, r := range ruleTable {
		if slices.Contains(r.schemas, e.p.schema) {
			res.Report.Rules = append(res.Report.Rules, &findingv1alpha1.RuleResult{
				RuleId: r.id, RuleVersion: r.version, State: states[r.id].state, Why: states[r.id].why})
		}
	}
	e.reportTree(res.Report)
	for _, rq := range e.reqs {
		if rq.terminal.GetKind() == blocked && !rq.denied() {
			res.PlaneBlocks[rq.blockCode()]++
		}
	}
	res.Report.Read.PlaneBlocks = maps.Clone(res.PlaneBlocks)
	for i, step := range e.p.steps {
		m := StepMatch{StepID: step.ID, ObservationIDs: e.reported[i]}
		for _, in := range e.ofStep[i] {
			m.RequestIDs = append(m.RequestIDs, in.request)
		}
		res.Steps = append(res.Steps, m)
	}
	res.Instances, res.Rests = e.instancesOf(res.Findings)
	return res
}

// doubtCut leaves not checked every rule that would read as checked while
// a record of the run is in doubt: the left-out copy, the missing link or the
// order its links do not give may hold the failure, denial, tool or time a
// rule looks for. A request in doubt touches every rule; an observation, a
// source whose imports refused a copy that may be a call of a run judged,
// and a span walk cut short only those that read a source's reports. A rule
// already not checked names its own reason first and each doubt after it.
// Findings stand, at the verdict the doubt allows.
func (e *evaluation) doubtCut(states map[string]ruleState) {
	every, reports := e.doubts()
	for id, s := range states {
		causes := every
		if slices.Contains(reportRules, id) {
			causes = append(slices.Clone(every), reports...)
		}
		switch {
		case id == RuleExceptionTaken || len(causes) == 0 || s == notApplied:
		case s.state == checked.state:
			states[id] = notChecked(strings.Join(causes, "; "))
		case s.state == findingv1alpha1.RuleState_RULE_STATE_NOT_CHECKED:
			states[id] = notChecked(s.why + "; " + strings.Join(causes, "; "))
		}
	}
}

// doubts names, in a fixed order, what puts every rule in doubt, and what
// puts in doubt the rules that read a source's reports besides.
func (e *evaluation) doubts() (every, reports []string) {
	var requests, sources []string
	for _, rq := range e.reqs {
		if rq.doubt {
			requests = append(requests, rq.id)
		}
	}
	for id, judged := range e.refusedJudged {
		if judged {
			sources = append(sources, id)
		}
	}
	if why := inDoubt("request", requests); why != "" {
		every = append(every, why)
	}
	if why := inDoubt("observation", slices.Collect(maps.Keys(e.rd.obsDoubt))); why != "" {
		reports = append(reports, why)
	}
	if why := inDoubt("source", sources); why != "" {
		reports = append(reports, why+": an import refused a copy that may be a call of a run judged")
	}
	if slices.Contains(slices.Collect(maps.Values(e.joinDoubt)), true) {
		reports = append(reports, "a span walk ran out of steps, so a source's report may be a plane call")
	}
	return every, reports
}

// inDoubt names the least of ids, quoted and cut as a producer's bytes are,
// and counts the others; "" when there are none.
func inDoubt(kind string, ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	least := kind + " " + trailchain.Quoted(slices.Min(ids), trailchain.MaxQuotedIDBytes)
	if len(ids) == 1 {
		return least + " is in doubt"
	}
	return least + " and " + strconv.Itoa(len(ids)-1) + " more are in doubt"
}

// reportRules are the rules that read a source's reports of calls no plane
// call joins.
var reportRules = []string{RuleStepOutsideProcedure, RuleDeniedActionRetriedAround}

// reportSchema02 is the version of a report that carries the children mode
// and the run tree, which a 0.2 procedure's report always does.
const reportSchema02 = "0.2"

var childrenModes = map[Children]findingv1alpha1.ChildrenMode{
	ChildrenInherit:  findingv1alpha1.ChildrenMode_CHILDREN_MODE_INHERIT,
	ChildrenSeparate: findingv1alpha1.ChildrenMode_CHILDREN_MODE_SEPARATE,
}

// reportTree names the children mode and the tree in a 0.2 procedure's
// report, the supervised run first and each other run after its parent; a
// 0.1 report names neither.
func (e *evaluation) reportTree(r *findingv1alpha1.SuperviseReport) {
	if e.p.schema != ProcedureSchema02 {
		return
	}
	r.SchemaVersion, r.Children = reportSchema02, childrenModes[e.p.children]
	for _, run := range treeOf(e.in) {
		r.RunTree = append(r.RunTree, &findingv1alpha1.RunTreeMember{RunId: run.ID, ParentRunId: run.Parent})
	}
}
