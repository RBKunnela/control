package supervise

import (
	"cmp"
	"maps"
	"slices"
	"sort"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// ord is where a call stands in a seq: its proposal's time, seconds then
// nanoseconds, then where the proposal was read.
type ord [3]int64

func compareOrd(a, b ord) int {
	return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]), cmp.Compare(a[2], b[2]))
}

// seq is calls in one order. A call's key is what makes it no retry of a
// denial of the same key: its arguments hash, or its tool. next is, for each
// place, the next place of another key, so a walk steps over a run of one
// key at once; byKey is each key's places, so a range is counted without it.
type seq struct {
	calls []*request
	ords  []ord
	keys  []string
	next  []int
	byKey map[string][]int
}

func newSeq(calls []*request, ords []ord, keyOf func(*request) string) *seq {
	s := &seq{calls: calls, ords: ords, keys: make([]string, len(calls)), next: make([]int, len(calls)), byKey: map[string][]int{}}
	for i, rq := range calls {
		s.keys[i] = keyOf(rq)
		s.byKey[s.keys[i]] = append(s.byKey[s.keys[i]], i)
	}
	for i := len(calls) - 1; i >= 0; i-- {
		switch {
		case i == len(calls)-1:
			s.next[i] = len(calls)
		case s.keys[i+1] != s.keys[i]:
			s.next[i] = i + 1
		default:
			s.next[i] = s.next[i+1]
		}
	}
	return s
}

// search is the first place at or past o.
func (s *seq) search(o ord) int {
	return sort.Search(len(s.ords), func(i int) bool { return compareOrd(s.ords[i], o) >= 0 })
}

// count is how many calls of [lo, hi) a denial d of key k is compared with:
// those of another key, or, when k is "", all but d, which stands at self
// or nowhere in s.
func (s *seq) count(lo, hi int, k string, self int) uint64 {
	n := uint64(len(s.calls[lo:hi]))
	switch {
	case k != "":
		at := s.byKey[k]
		n -= uint64(len(at[sort.SearchInts(at, lo):sort.SearchInts(at, hi)]))
	case lo <= self && self < hi:
		n--
	}
	return n
}

// each visits, in order, up to most of the calls count counts.
func (s *seq) each(lo, hi int, k string, d *request, most int, visit func(*request)) {
	for i := lo; i < hi && most > 0; {
		switch {
		case k != "" && s.keys[i] == k:
			i = s.next[i]
			continue
		case s.calls[i] != d:
			visit(s.calls[i])
			most--
		}
		i++
	}
}

// lane is one run's calls of a group that any denial weighs alike: of one
// trail and one class of what the form reads. Those with a time are in time
// order, those without in the order read.
type lane struct {
	trail, attr int
	timed       *seq
	untimed     *seq
}

// retryGroup is the calls one form compares a denial with, those of one tool
// or on one resource, by run and lane.
type retryGroup struct {
	runs  []string
	lanes map[string][]*lane
}

func (e *evaluation) newRetryGroup(calls []*request, f *retryForm, pos map[*controlv1.Event]int) *retryGroup {
	type laneKey struct {
		run         string
		trail, attr int
	}
	members := map[laneKey][]*request{}
	for _, rq := range calls {
		trail, ok := rq.trail()
		if !ok {
			continue
		}
		k := laneKey{run: rq.proposal.GetRunId(), trail: trail, attr: f.attr(rq)}
		members[k] = append(members[k], rq)
	}
	g := &retryGroup{lanes: map[string][]*lane{}}
	for _, k := range slices.SortedFunc(maps.Keys(members), func(a, b laneKey) int {
		return cmp.Or(cmp.Compare(a.run, b.run), cmp.Compare(a.trail, b.trail), cmp.Compare(a.attr, b.attr))
	}) {
		if len(g.lanes[k.run]) == 0 {
			g.runs = append(g.runs, k.run)
		}
		l := &lane{trail: k.trail, attr: k.attr}
		l.timed, l.untimed = splitByTime(members[k], pos, f.key)
		g.lanes[k.run] = append(g.lanes[k.run], l)
	}
	return g
}

// splitByTime orders calls with a valid proposal time by it, and keeps the
// rest in the order read.
func splitByTime(calls []*request, pos map[*controlv1.Event]int, keyOf func(*request) string) (*seq, *seq) {
	var timed, untimed []*request
	for _, rq := range calls {
		if rq.proposal.GetOccurredAt().IsValid() {
			timed = append(timed, rq)
		} else {
			untimed = append(untimed, rq)
		}
	}
	ordOf := func(rq *request) ord { return ordAt(rq.proposal, pos) }
	for _, part := range [][]*request{timed, untimed} {
		slices.SortFunc(part, func(a, b *request) int { return compareOrd(ordOf(a), ordOf(b)) })
	}
	return newSeq(timed, ords(timed, ordOf), keyOf), newSeq(untimed, ords(untimed, ordOf), keyOf)
}

// ordAt is where ev stands: by its time when it has a valid one, then by
// where it was read.
func ordAt(ev *controlv1.Event, pos map[*controlv1.Event]int) ord {
	if t := ev.GetOccurredAt(); t.IsValid() {
		return ord{t.GetSeconds(), int64(t.GetNanos()), int64(pos[ev])}
	}
	return ord{0, 0, int64(pos[ev])}
}

func ords(calls []*request, ordOf func(*request) ord) []ord {
	out := make([]ord, len(calls))
	for i, rq := range calls {
		out[i] = ordOf(rq)
	}
	return out
}

// part is a range of one lane's calls that a denial weighs at one verdict.
type part struct {
	v      controlv1.FindingVerdict
	s      *seq
	lo, hi int
	self   int
}

// parts is what of l denial d of key k compares, at the verdicts their
// times allow, none above v. The plane may land a later batch of an export
// before an earlier one, so an export's sequence orders nothing; the plane's
// times do. A call proposed before the denial was decided is no retry, one at
// that instant or with no time is untold, and a later one weighs at v; the
// rule's row keeps that from confirming, since the two may have been timed by
// two planes' clocks.
func (l *lane) parts(d *request, k string, v controlv1.FindingVerdict, pos map[*controlv1.Event]int, out []part) []part {
	self := func(s *seq) int {
		if k != "" {
			return -1
		}
		if i := s.search(ordAt(d.proposal, pos)); i < len(s.calls) && s.calls[i] == d {
			return i
		}
		return -1
	}
	t := d.decided.GetOccurredAt()
	untold := part{v: indeterminate, s: l.untimed, hi: len(l.untimed.calls), self: self(l.untimed)}
	if !t.IsValid() {
		return append(out, untold, part{v: indeterminate, s: l.timed, hi: len(l.timed.calls), self: self(l.timed)})
	}
	lo := l.timed.search(ord{t.GetSeconds(), int64(t.GetNanos()), -1})
	hi := l.timed.search(ord{t.GetSeconds(), int64(t.GetNanos()) + 1, -1})
	timedSelf := self(l.timed)
	return append(out, untold, part{v: indeterminate, s: l.timed, lo: lo, hi: hi, self: timedSelf},
		part{v: v, s: l.timed, lo: hi, hi: len(l.timed.calls), self: timedSelf})
}
