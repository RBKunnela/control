package supervise

import (
	"cmp"
	"maps"
	"slices"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// namesRuns reports whether findings name the run of the plane event they
// rest on, as a 0.2 procedure's do; a 0.1 finding names the supervised run.
func (e *evaluation) namesRuns() bool { return e.p.schema == ProcedureSchema02 }

// named makes d name run and adds run to its anchor, so findings of one
// rule and anchor in two runs of a tree keep two ids.
func (d *draft) named(run string) {
	d.run = run
	d.anchor = append(slices.Clip(d.anchor), run)
}

// byRun splits calls by the run of each one's proposal, in run order, when
// findings name runs; otherwise calls is one group.
func (e *evaluation) byRun(calls []*request) [][]*request {
	if !e.namesRuns() {
		return [][]*request{calls}
	}
	groups := map[string][]*request{}
	for _, rq := range calls {
		run := rq.proposal.GetRunId()
		groups[run] = append(groups[run], rq)
	}
	runs := make([]string, 0, len(groups))
	for run := range groups {
		runs = append(runs, run)
	}
	slices.Sort(runs)
	out := make([][]*request, 0, len(runs))
	for _, run := range runs {
		out = append(out, groups[run])
	}
	return out
}

// eventOrder orders events by time, one with no time after every timed one,
// and events of one time by request and event id, so the order the exports
// were read in decides nothing.
func eventOrder(a, b *controlv1.Event) int {
	at, bt := a.GetOccurredAt(), b.GetOccurredAt()
	switch {
	case at.IsValid() != bt.IsValid() && at.IsValid():
		return -1
	case at.IsValid() != bt.IsValid():
		return 1
	}
	return cmp.Or(at.AsTime().Compare(bt.AsTime()), cmp.Compare(a.GetRequestId(), b.GetRequestId()),
		cmp.Compare(a.GetEventId(), b.GetEventId()))
}

// repeatedByRun is REPEATED_DENIAL under 0.2 for the denials of one tool
// across the tree, which reach max_denials. A run whose own denials reach it
// is confirmed on them alone, on its clean ones as cited says. Otherwise a run
// with a denial at or after the one that brought the tree's count there is
// suspected: its finding needs other runs' denials. When that order is untold,
// it is indeterminate.
func (e *evaluation) repeatedByRun(tool [2]string, denials []*request) []draft {
	n := uint64(e.p.maxDenials)
	own := map[string][]*request{}
	for _, rq := range denials {
		own[rq.terminal.GetRunId()] = append(own[rq.terminal.GetRunId()], rq)
	}
	tree, late := indeterminate, map[string]bool{}
	if e.oneExportHolds(denials) && !slices.ContainsFunc(denials, untimed) {
		c, told := crossing(denials, e.p.maxDenials)
		late = atOrAfter(denials, c)
		if told {
			tree = suspected
		}
	} else {
		// Two exports' clocks are not one, and a denial with no time could
		// stand anywhere, so no run's denial is known to come before the one
		// that crossed the bound.
		for run := range own {
			late[run] = true
		}
	}
	var out []draft
	for _, run := range slices.Sorted(maps.Keys(own)) {
		d := draft{rule: RuleRepeatedDenial, anchor: tool[:], cap: confirmed}
		s := &refSet{}
		for _, rq := range cited(own[run], e.p.maxDenials) {
			s.event(rq, rq.terminal)
		}
		switch {
		case uint64(len(own[run])) >= n:
		case late[run]:
			d.cap = tree
			for _, rq := range denials {
				if rq.terminal.GetRunId() != run {
					s.event(rq, rq.terminal)
				}
			}
		default:
			continue
		}
		s.into(&d)
		d.named(run)
		out = append(out, d)
	}
	return out
}

// untimed reports a denial whose block has no time.
func untimed(rq *request) bool { return !rq.terminal.GetOccurredAt().IsValid() }

// crossing is the denial that brought the count to n, by the order of the
// blocks, every one of which has a time. There are at least n denials. It is
// not told when a block of another run shares its time.
func crossing(denials []*request, n uint32) (*request, bool) {
	sorted := slices.SortedFunc(slices.Values(denials), func(a, b *request) int { return eventOrder(a.terminal, b.terminal) })
	c := sorted[n-1]
	for _, rq := range denials {
		if rq.terminal.GetRunId() != c.terminal.GetRunId() && tied(rq.terminal, c.terminal) {
			return c, false
		}
	}
	return c, true
}

// atOrAfter is the runs with a denial at or after c, one of c's time
// included.
func atOrAfter(denials []*request, c *request) map[string]bool {
	out := map[string]bool{}
	for _, rq := range denials {
		if eventOrder(rq.terminal, c.terminal) >= 0 || tied(rq.terminal, c.terminal) {
			out[rq.terminal.GetRunId()] = true
		}
	}
	return out
}

// oneExportHolds reports whether one export holds every one of the denials'
// blocks: only then do their times share a clock.
func (e *evaluation) oneExportHolds(denials []*request) bool {
	held := map[int]int{}
	for _, rq := range denials {
		for _, p := range e.placesOf()[rq.terminal.GetEventId()] {
			held[p.export]++
		}
	}
	for _, n := range held {
		if n == len(denials) {
			return true
		}
	}
	return false
}

// tied reports two events with a time, the same one.
func tied(a, b *controlv1.Event) bool {
	return a.GetOccurredAt().IsValid() && b.GetOccurredAt().IsValid() &&
		a.GetOccurredAt().AsTime().Equal(b.GetOccurredAt().AsTime())
}

// deadlineByRun gives each run with an event more than limit after the
// tree's first its own finding, citing that first event and the run's own
// earliest past the limit, at most most.
func (e *evaluation) deadlineByRun(limit time.Duration, most controlv1.FindingVerdict) []draft {
	start := e.first.GetOccurredAt().AsTime()
	past := map[string]*controlv1.Event{}
	for _, ev := range e.rd.events {
		run := ev.GetRunId()
		if ev.GetOccurredAt().IsValid() && ev.GetOccurredAt().AsTime().Sub(start) > limit &&
			(past[run] == nil || eventOrder(ev, past[run]) < 0) {
			past[run] = ev
		}
	}
	out := make([]draft, 0, len(past))
	for _, run := range slices.Sorted(maps.Keys(past)) {
		d := draft{rule: RuleDeadlineExceeded, cap: most}
		for _, ev := range []*controlv1.Event{e.first, past[run]} {
			d.refs = append(d.refs, e.byRequest[ev.GetRequestId()].ref(ev))
		}
		d.named(run)
		out = append(out, d)
	}
	return out
}
