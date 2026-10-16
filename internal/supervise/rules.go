package supervise

import (
	"cmp"
	"slices"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// byTool groups requests that proposed a tool by that tool and upstream, the
// groups in tool order.
func byTool(reqs []*request, keep func(*request) bool) ([][2]string, map[[2]string][]*request) {
	groups := map[[2]string][]*request{}
	var keys [][2]string
	for _, rq := range reqs {
		tool, ok := rq.tool()
		if !ok || !keep(rq) {
			continue
		}
		if _, seen := groups[tool]; !seen {
			keys = append(keys, tool)
		}
		groups[tool] = append(groups[tool], rq)
	}
	slices.SortFunc(keys, func(a, b [2]string) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) })
	return keys, groups
}

// repeatedDenial fires for a tool on an upstream whose calls the policy
// denied max_denials times or more; under 0.2 per run, as repeatedByRun says.
func (e *evaluation) repeatedDenial() []draft {
	keys, groups := byTool(e.reqs, (*request).denied)
	var out []draft
	for _, tool := range keys {
		denials := groups[tool]
		if uint64(len(denials)) < uint64(e.p.maxDenials) {
			continue
		}
		if e.namesRuns() {
			out = append(out, e.repeatedByRun(tool, denials)...)
			continue
		}
		d := draft{rule: RuleRepeatedDenial, anchor: tool[:], cap: confirmed}
		for _, rq := range cited(denials, e.p.maxDenials) {
			d.refs = append(d.refs, rq.ref(rq.terminal))
		}
		out = append(out, d)
	}
	return out
}

// cited is the denials a finding rests on: those whose trails are in no
// doubt when at least n are, so a doubtful copy cannot weaken a count the
// clean ones reach alone; otherwise all of them, and the doubt with them.
func cited(denials []*request, n uint32) []*request {
	clean := slices.DeleteFunc(slices.Clone(denials), func(rq *request) bool { return rq.doubt })
	if uint64(len(clean)) < uint64(n) {
		return denials
	}
	return clean
}

// outsideProcedure fires for each tool the plane saw called that is neither a
// step nor allowed, then for each name a source reported of a call no plane
// call joins and no entry lists.
func (e *evaluation) outsideProcedure() []draft {
	keys, groups := byTool(e.reqs, func(rq *request) bool {
		tool, _ := rq.tool()
		_, known := e.ix.byTool[tool]
		return !known
	})
	var out []draft
	for _, tool := range keys {
		for _, calls := range e.byRun(groups[tool]) {
			d := draft{rule: RuleStepOutsideProcedure, anchor: tool[:], cap: confirmed}
			for _, rq := range calls {
				d.refs = append(d.refs, rq.ref(rq.proposal))
			}
			if e.namesRuns() {
				d.named(calls[0].proposal.GetRunId())
			}
			out = append(out, d)
		}
	}
	named := map[string]*draft{}
	var names []string
	for _, o := range e.unjoined {
		name := o.GetSubject().GetName()
		if _, known := e.ix.byName[name]; known {
			continue
		}
		if named[name] == nil {
			named[name] = &draft{rule: RuleStepOutsideProcedure, anchor: []string{name}, cap: confirmed}
			names = append(names, name)
		}
		named[name].refs = append(named[name].refs, e.obsRef(o))
	}
	slices.Sort(names)
	for _, n := range names {
		out = append(out, *named[n])
	}
	return out
}

// deadline fires when the run's plane events span more than
// deadline_seconds. Events from more than one export may come from planes
// whose clocks differ, so then it only suggests. A 0.1 finding cites the
// first event and the last; under 0.2 deadlineByRun gives each run its own.
func (e *evaluation) deadline() []draft {
	limit := time.Duration(e.p.deadlineSeconds) * time.Second
	if !e.pastDeadline() {
		return nil
	}
	most := confirmed
	if len(e.in.Exports) != 1 {
		most = suspected
	}
	if e.namesRuns() {
		return e.deadlineByRun(limit, most)
	}
	d := draft{rule: RuleDeadlineExceeded, cap: most}
	for _, ev := range []*controlv1.Event{e.first, e.last} {
		d.refs = append(d.refs, e.byRequest[ev.GetRequestId()].ref(ev))
	}
	return []draft{d}
}

// pastDeadline reports whether the run's events with a time span more than
// deadline_seconds.
func (e *evaluation) pastDeadline() bool {
	limit := time.Duration(e.p.deadlineSeconds) * time.Second
	return e.first != nil && e.last.GetOccurredAt().AsTime().Sub(e.first.GetOccurredAt().AsTime()) > limit
}

// absenceCap is the most a finding that rests on something not seen can
// say: it suggests, and while a source is silent past its heartbeat or was
// named and not read it cannot say even that.
func (e *evaluation) absenceCap() controlv1.FindingVerdict {
	if e.anySilent {
		return indeterminate
	}
	return suspected
}

// skipped fires for each required step with no instance.
func (e *evaluation) skipped() []draft {
	var out []draft
	for i, s := range e.p.steps {
		if s.Required && len(e.ofStep[i]) == 0 {
			out = append(out, draft{rule: RuleRequiredStepSkipped, anchor: []string{s.ID}, cap: e.absenceCap()})
		}
	}
	return out
}

// outOfOrder fires for a step that ran before a step it must follow: its
// first instance comes before the first of that step, or that step has no
// instance at all. An order that cannot be told, because an instance of
// either side has no time, or a first instance shares its time with another
// of its step or with the other side's first, is no pass: the finding is
// then indeterminate. It returns the steps found out of order.
func (e *evaluation) outOfOrder() ([]draft, map[int]bool) {
	var out []draft
	fired := map[int]bool{}
	for i, s := range e.p.steps {
		if len(e.ofStep[i]) == 0 {
			continue
		}
		d, broken := e.order(i, s.ID)
		if d != nil {
			out = append(out, *d)
		}
		fired[i] = broken
	}
	return out, fired
}

// order judges step i, named id, against the steps it must follow, and
// reports whether it is out of order.
func (e *evaluation) order(i int, id string) (*draft, bool) {
	first, told := e.firstOf(i)
	d := draft{rule: RuleStepOutOfOrder, anchor: []string{id}, cap: e.absenceCap(), refs: []ref{first.start}}
	broken := false
	var untold []ref
	for _, a := range e.p.after[id] {
		j := e.stepIndex[a]
		if len(e.ofStep[j]) == 0 {
			broken = true
			continue
		}
		before, beforeTold := e.firstOf(j)
		switch {
		case !told || !beforeTold || before.at.Equal(first.at):
			untold = append(untold, before.start)
		case before.at.After(first.at):
			broken = true
			d.refs = append(d.refs, before.start)
		}
	}
	switch {
	case broken:
		return &d, true
	case len(untold) > 0:
		d.cap, d.refs = indeterminate, append(d.refs, untold...)
		return &d, false
	}
	return nil, false
}
