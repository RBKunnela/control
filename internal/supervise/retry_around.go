package supervise

import (
	"maps"
	"slices"
	"sort"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// reported is a source's report of a tool no plane call joins, with its
// place among the tool's reports and where its time stands.
type reported struct {
	o   *observev1.Observation
	at  int
	ord ord
}

// aroundGroup is the reports of one tool, under every name its entry lists,
// by the verdict each is cited at: those with a time in time order, those
// without in the order read.
type aroundGroup struct {
	timed, untimed [2][]reported
	n              int
}

func (e *evaluation) aroundGroups() map[[2]string]*aroundGroup {
	byName := map[string][]*observev1.Observation{}
	for _, o := range e.unjoined {
		byName[o.GetSubject().GetName()] = append(byName[o.GetSubject().GetName()], o)
	}
	out := map[[2]string]*aroundGroup{}
	for _, name := range slices.Sorted(maps.Keys(e.ix.byName)) {
		tool := e.ix.byName[name].tool
		g := out[tool]
		if g == nil {
			g = &aroundGroup{}
			out[tool] = g
		}
		for _, o := range byName[name] {
			c, t := rank(e.obsVerdict(o)), o.GetEventTime()
			if !begun(o) {
				c = rank(indeterminate)
			}
			r := reported{o: o, at: g.n, ord: ord{0, 0, int64(g.n)}}
			if t.IsValid() {
				r.ord = ord{t.GetSeconds(), int64(t.GetNanos()), int64(g.n)}
				g.timed[c] = append(g.timed[c], r)
			} else {
				g.untimed[c] = append(g.untimed[c], r)
			}
			g.n++
		}
	}
	for _, g := range out {
		for _, rs := range g.timed {
			slices.SortFunc(rs, func(a, b reported) int { return compareOrd(a.ord, b.ord) })
		}
	}
	return out
}

// begun reports a report whose time is when its call began. Any other is
// timed when the call ended, or at a stage not known, so a time after a
// denial does not say the call began after it.
func begun(o *observev1.Observation) bool {
	s := o.GetStage()
	return s == observev1.Stage_STAGE_PROPOSED || s == observev1.Stage_STAGE_STARTED
}

// aroundPart is reports a denial weighs at one verdict.
type aroundPart struct {
	v  controlv1.FindingVerdict
	rs []reported
}

// parts is g's reports a denial decided at t weighs: a later time suggests,
// the same time or none is untold, an earlier one is no retry. A report in
// doubt, or timed at its call's end, is untold at that time or later.
func (g *aroundGroup) parts(t *timestamppb.Timestamp) []aroundPart {
	out := []aroundPart{{indeterminate, g.untimed[0]}, {indeterminate, g.untimed[1]}}
	if !t.IsValid() {
		return append(out, aroundPart{indeterminate, g.timed[0]}, aroundPart{indeterminate, g.timed[1]})
	}
	at := func(rs []reported, nanos int64) int {
		return sort.Search(len(rs), func(i int) bool {
			return compareOrd(rs[i].ord, ord{t.GetSeconds(), nanos, -1}) >= 0
		})
	}
	told, doubt := g.timed[rank(suspected)], g.timed[rank(indeterminate)]
	lo, hi := at(told, int64(t.GetNanos())), at(told, int64(t.GetNanos())+1)
	return append(out, aroundPart{indeterminate, doubt[at(doubt, int64(t.GetNanos())):]},
		aroundPart{indeterminate, told[lo:hi]}, aroundPart{suspected, told[hi:]})
}

// retriedAround fires for a source's report of the denied tool, under a name
// its entry lists, that no plane call joins and whose time is after the
// denial was decided. A source's clock is not the plane's, so it suggests at
// most, and only a report of when its call began says it began after the
// denial; the finding names the denial's run, since a report's claimed run is
// never named.
func (e *evaluation) retriedAround() []draft {
	x := e.retryIx()
	var out []draft
	for _, d := range x.denials {
		g := x.around[toolOf(d)]
		if g == nil {
			continue
		}
		parts := g.parts(d.decided.GetOccurredAt())
		best, n := -1, uint64(0)
		for _, p := range parts {
			switch r := rank(p.v); {
			case len(p.rs) == 0 || r < best:
			case r > best:
				best, n = r, uint64(len(p.rs))
			default:
				n += uint64(len(p.rs))
			}
		}
		if n == 0 {
			continue
		}
		var offers []offer
		for _, p := range parts {
			if rank(p.v) == best {
				for _, r := range p.rs[:min(len(p.rs), MaxFindingRefs)] {
					offers = append(offers, offer{at: r.at, v: e.obsVerdict(r.o), r: e.obsRef(r.o)})
				}
			}
		}
		out = append(out, cite(RuleDeniedActionRetriedAround, d, d.decided.GetRunId(), verdictOfRank(best), n, offers))
	}
	return out
}
