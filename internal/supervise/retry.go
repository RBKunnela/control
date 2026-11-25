package supervise

import (
	"cmp"
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// resourceKey is a call's resource as its bytes say. No id is normalised:
// "042" and "42" are two resources.
type resourceKey struct{ typ, id, tenant, env string }

func resourceOf(rq *request) resourceKey {
	r := rq.proposal.GetProposed().GetResource()
	return resourceKey{typ: r.GetType(), id: r.GetId(), tenant: r.GetTenantId(), env: r.GetEnvironment()}
}

// retryIndex is what the retry rules compare: the policy's denials of a tool
// call, by request id, the run's tool calls by tool and by resource, its
// reports no plane call joins by tool, and where each event was read.
type retryIndex struct {
	denials    []*request
	byTool     map[[2]string]*retryGroup
	byResource map[resourceKey]*retryGroup
	around     map[[2]string]*aroundGroup
	pos        map[*controlv1.Event]int
}

func (e *evaluation) retryIx() *retryIndex {
	if e.retry != nil {
		return e.retry
	}
	x := &retryIndex{byTool: map[[2]string]*retryGroup{}, byResource: map[resourceKey]*retryGroup{}, pos: map[*controlv1.Event]int{}}
	for i, ev := range e.rd.events {
		x.pos[ev] = i
	}
	tools, resources := map[[2]string][]*request{}, map[resourceKey][]*request{}
	for _, rq := range e.reqs {
		tool, ok := rq.tool()
		if !ok {
			continue
		}
		tools[tool] = append(tools[tool], rq)
		if k := resourceOf(rq); k.id != "" {
			resources[k] = append(resources[k], rq)
		}
		if rq.denied() {
			x.denials = append(x.denials, rq)
		}
	}
	for tool, calls := range tools {
		x.byTool[tool] = e.newRetryGroup(calls, argumentsForm, x.pos)
	}
	for k, calls := range resources {
		x.byResource[k] = e.newRetryGroup(calls, resourceForm, x.pos)
	}
	slices.SortStableFunc(x.denials, func(a, b *request) int { return cmp.Compare(a.id, b.id) })
	x.around = e.aroundGroups()
	e.retry = x
	return x
}

func toolOf(rq *request) [2]string {
	tool, _ := rq.tool()
	return tool
}

// hashOf keys a call by its arguments hash, "" when it carries none.
func hashOf(rq *request) string {
	return rq.proposal.GetProposed().GetArguments().GetCanonicalHash()
}

// toolKey keys a call by its tool and upstream; it is never "".
func toolKey(rq *request) string {
	t := toolOf(rq)
	return t[0] + "\x00" + t[1]
}

// retryForm is one plane form of a retry. A call whose key is the denial's
// is none; a denial with no key skips no call but itself. attr is the one
// thing about a call the form reads beside its key, and allows says what a
// call of attr c may say as a retry of a denial of attr d, false for none.
type retryForm struct {
	rule   string
	key    func(*request) string
	attr   func(*request) int
	allows func(d, c int) (controlv1.FindingVerdict, bool)
}

// argumentsForm is a call of the denied tool and upstream with other
// arguments. A hash not read cannot tell a variant from the call repeated.
var argumentsForm = &retryForm{rule: RuleDeniedActionRetriedArguments, key: hashOf,
	attr: func(rq *request) int {
		if hashOf(rq) == "" {
			return 0
		}
		return 1
	},
	allows: func(d, c int) (controlv1.FindingVerdict, bool) {
		if d == 0 || c == 0 {
			return indeterminate, true
		}
		return confirmed, true
	}}

// What a call's effect class is, as the resource form reads it.
const (
	effectNotRead = iota
	effectUnknown
	effectRead
)

// resourceForm is a call of another tool or upstream on the denied call's
// resource. A read after the denial of anything but a read does not count;
// an effect class not declared, or one this build does not know, might be
// either.
var resourceForm = &retryForm{rule: RuleDeniedActionRetriedResource, key: toolKey, attr: effectOf,
	allows: func(d, c int) (controlv1.FindingVerdict, bool) {
		switch {
		case d == effectRead, c == effectNotRead:
			return confirmed, true
		case d != effectUnknown && c != effectUnknown:
			return indeterminate, false
		}
		return indeterminate, true
	}}

// effectOf is whether rq's effect class is a read, and effectUnknown when
// this build does not declare it or it is none.
func effectOf(rq *request) int {
	c := rq.proposal.GetProposed().GetAction().GetEffect()
	_, declared := controlv1.EffectClass_name[int32(c)]
	switch {
	case c == controlv1.EffectClass_EFFECT_CLASS_READ:
		return effectRead
	case !declared || c == controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED:
		return effectUnknown
	}
	return effectNotRead
}

// How a call's trail bounds what it says as a retry.
const (
	trailDoubt = iota
	trailWaiting
	trailClear
)

// trail is the class of rq's trail: in doubt, still waiting on an approval
// that may yet be granted, or neither. A call the approvals store approved,
// in a trail not in doubt, is no retry.
func (rq *request) trail() (int, bool) {
	switch {
	case rq.doubt:
		return trailDoubt, true
	case rq.approval == controlv1.ApprovalState_APPROVAL_STATE_APPROVED:
		return 0, false
	case rq.waiting:
		return trailWaiting, true
	}
	return trailClear, true
}

func (e *evaluation) retriedArguments() []draft {
	x := e.retryIx()
	return e.retried(argumentsForm, func(d *request) *retryGroup { return x.byTool[toolOf(d)] })
}

func (e *evaluation) retriedResource() []draft {
	x := e.retryIx()
	return e.retried(resourceForm, func(d *request) *retryGroup { return x.byResource[resourceOf(d)] })
}

// retried fires for each denial and each run with a call of the denial's
// group that the form names a retry of it, proposed after the denial was
// decided. Each run is judged on its own calls, so no run's calls change
// what another's say. A run that is neither the denied run nor its
// descendant suggests at most.
func (e *evaluation) retried(f *retryForm, group func(*request) *retryGroup) []draft {
	var out []draft
	var parts []part
	for _, d := range e.retryIx().denials {
		g := group(d)
		if g == nil {
			continue
		}
		for _, run := range g.runs {
			parts = e.weigh(f, g.lanes[run], d, parts[:0])
			if dr, ok := e.citeCalls(f.rule, d, run, f.key(d), parts); ok {
				out = append(out, dr)
			}
		}
	}
	return out
}

// weigh is what of one run's lanes denial d compares, by verdict.
func (e *evaluation) weigh(f *retryForm, lanes []*lane, d *request, out []part) []part {
	k, da := f.key(d), f.attr(d)
	for _, l := range lanes {
		v, ok := f.allows(da, l.attr)
		if !ok {
			continue
		}
		if l.trail != trailClear {
			v = indeterminate
		}
		out = l.parts(d, k, v, e.retryIx().pos, out)
	}
	return out
}

// citeCalls is the finding of rule on denial d naming run, at the strongest
// verdict of parts, citing the retries that carry it, or false when parts
// hold none.
func (e *evaluation) citeCalls(rule string, d *request, run, k string, parts []part) (draft, bool) {
	best, n := -1, uint64(0)
	for i := range parts {
		p := &parts[i]
		c := p.s.count(p.lo, p.hi, k, p.self)
		switch r := rank(p.v); {
		case c == 0 || r < best:
		case r > best:
			best, n = r, c
		default:
			n += c
		}
	}
	if n == 0 {
		return draft{}, false
	}
	var offers []offer
	pos := e.retryIx().pos
	for _, p := range parts {
		if rank(p.v) != best {
			continue
		}
		p.s.each(p.lo, p.hi, k, d, MaxFindingRefs, func(r *request) {
			offers = append(offers, offer{at: pos[r.proposal], v: r.verdict(), r: r.ref(r.proposal)})
		})
	}
	return cite(rule, d, run, verdictOfRank(best), n, offers), true
}

func verdictOfRank(r int) controlv1.FindingVerdict {
	return [...]controlv1.FindingVerdict{indeterminate, suspected, confirmed}[r]
}

// offer is a retry a finding may cite: where it was read, the verdict it is
// cited at, and the reference.
type offer struct {
	at int
	v  controlv1.FindingVerdict
	r  ref
}

// cite is the finding of rule on denial d naming run at v, resting on n
// retries: of those offered, in the order read, each verdict's first
// MaxFindingRefs are cited, and the rest of the n are counted.
func cite(rule string, d *request, run string, v controlv1.FindingVerdict, n uint64, offers []offer) draft {
	slices.SortStableFunc(offers, func(a, b offer) int { return cmp.Compare(a.at, b.at) })
	var s refSet
	for _, o := range offers {
		if s.take(o.v) {
			s.refs = append(s.refs, o.r)
		}
	}
	s.leftOut += n - uint64(len(offers))
	dr := draft{rule: rule, anchor: []string{d.id}, cap: v, refs: []ref{d.ref(d.decided)}}
	s.into(&dr)
	dr.named(run)
	return dr
}
