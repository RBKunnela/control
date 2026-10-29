package coverage

import (
	"fmt"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
)

// joiner checks one path's observations from one source against the exports
// of the planes that count for it. It keeps each group's verdict: every span
// a group reaches is in the trace, tenant and project of any observation
// reaching it, so the verdict holds for each of them.
type joiner struct {
	f      *family
	path   Path
	need   modeClass
	planes []Plane
	seen   map[int]verdict
}

// verdict is what the proposals at and below a group say of the path's call:
// whether one joins it, and the first plane whose record of it at one of
// those spans does not validate, len(planes) when none.
type verdict struct {
	joined  bool
	refused int
}

// join checks o. It joins when a proposal in a whole export, recorded in a
// mode at least as strong as need, carries its trace id and its own or a
// descendant's span id, in its tenant and project, for a call of the path's
// tool on its upstream: an enforced path joins only an enforcing plane's
// proposal, so an observing plane cannot cover a call around an enforcing
// one. Nothing joins on an empty id, and a trace id alone joins nothing. A
// join needs no event time: the time only bounds calling a call one around
// the plane.
func (j *joiner) join(o *observev1.Observation) JoinCheck {
	check := JoinCheck{ObservationID: o.GetObservationId()}
	trace, span := o.GetCorrelation().GetTraceId(), o.GetCorrelation().GetSpanId()
	if trace == "" || span == "" {
		check.Why = "no trace or span id"
		return check
	}
	g := j.f.walk(spanKey{o.GetTenantId(), o.GetProjectId(), trace, span})
	switch n, counted := j.f.count(g); {
	case !counted:
		check.Why = fmt.Sprintf("counting the spans below it passed its source's bound of %d steps", MaxCountSteps)
		check.Cut = true
		return check
	case n > MaxWalkSpans:
		check.Why = fmt.Sprintf("the walk down its trace passed its bound of %d spans", MaxWalkSpans)
		check.Cut = true
		return check
	}
	switch v := j.verdict(o, g); {
	case v.joined:
		check.Join = Joined
	case v.refused < len(j.planes):
		check.Why = "the record of a call at its span in the export of plane " + printable(j.planes[v.refused].Name) + " does not validate"
	default:
		check.Join, check.Why = unjoined(o, j.planes)
	}
	return check
}

// verdict is group g's verdict for o, each group below it judged first and
// once. No group below one within the bound is past it.
func (j *joiner) verdict(o *observev1.Observation, g int) verdict {
	stack := []int{g}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		if _, done := j.seen[top]; done {
			stack = stack[:len(stack)-1]
			continue
		}
		ready := true
		for _, b := range j.f.groups[top].below {
			if _, done := j.seen[b]; !done {
				stack, ready = append(stack, b), false
			}
		}
		if !ready {
			continue
		}
		v := j.at(o, j.f.groups[top].spans)
		for _, b := range j.f.groups[top].below {
			v.joined = v.joined || j.seen[b].joined
			v.refused = min(v.refused, j.seen[b].refused)
		}
		j.seen[top] = v
		stack = stack[:len(stack)-1]
	}
	return j.seen[g]
}

// at is the verdict of the proposals at spans alone.
func (j *joiner) at(o *observev1.Observation, spans []string) verdict {
	v := verdict{refused: len(j.planes)}
	trace := o.GetCorrelation().GetTraceId()
	for _, span := range spans {
		k := proposalKey{trace, span}
		for i, p := range j.planes {
			x := p.Export
			if x == nil {
				continue
			}
			if x.Whole && x.holds(o, k, j.path, j.need) {
				v.joined = true
			}
			if i < v.refused && x.refusedAt(o, k, j.path) {
				v.refused = i
			}
		}
	}
	return v
}

// refusedAt reports a proposal the contract refuses at k that names o's call
// as a valid one would, whatever its mode: the plane saw that call, but its
// record cannot be joined.
func (x *Export) refusedAt(o *observev1.Observation, k proposalKey, path Path) bool {
	for _, ev := range x.refused[k] {
		if names(ev, o, path) {
			return true
		}
	}
	return false
}

// unjoined says whether the planes' exports could have shown a join they do
// not hold: the call may have passed any plane in front of the path, so each
// one's export must be given, whole, and hold the observation's time.
func unjoined(o *observev1.Observation, planes []Plane) (Join, string) {
	for _, p := range planes {
		switch x := p.Export; {
		case x == nil:
			return JoinNotChecked, "no export of plane " + printable(p.Name)
		case !x.Whole:
			return JoinNotChecked, "the export of plane " + printable(p.Name) + " is not whole: " + x.NotWhole
		}
	}
	if !o.GetEventTime().IsValid() {
		return JoinNotChecked, "no event time"
	}
	t := o.GetEventTime().AsTime()
	for _, p := range planes {
		if x := p.Export; !x.window || t.Before(x.earliest) || t.After(x.latest) {
			return JoinNotChecked, "outside the window of the export of plane " + printable(p.Name)
		}
	}
	return JoinAround, ""
}

func (x *Export) holds(o *observev1.Observation, k proposalKey, path Path, need modeClass) bool {
	for _, ev := range x.proposals[k] {
		if proposes(ev, o, path, need) {
			return true
		}
	}
	return false
}

// proposes reports whether ev, a proposal carrying o's ids, is a call of
// path's tool in o's tenant and project, recorded in a mode at least need.
func proposes(ev *controlv1.Event, o *observev1.Observation, path Path, need modeClass) bool {
	class, err := classOf(ev.GetEnforcementMode())
	return err == nil && class >= need && names(ev, o, path)
}

// names reports whether ev, a proposal carrying o's ids, names a call of
// path's tool in o's tenant and project: on its upstream for an mcp_tool, and
// through the enforcement API for an enforce_tool, whose provider is the
// operator's word for it and no upstream. A prompt or a resource read through
// the plane under a tool's name is not the call. An empty tenant or project
// names nothing: a refused envelope may lack both.
func names(ev *controlv1.Event, o *observev1.Observation, path Path) bool {
	action := ev.GetProposed().GetAction()
	if !sameScope(ev, ev.GetProposed(), o) || action.GetKind() != channel.KindTool || action.GetName() != path.Tool {
		return false
	}
	if path.Kind == KindEnforceTool {
		return action.GetProtocol() == channel.ProtocolEnforce
	}
	return action.GetProvider() == path.Upstream
}

func sameScope(ev *controlv1.Event, env *controlv1.ActionEnvelope, o *observev1.Observation) bool {
	return o.GetTenantId() != "" && o.GetProjectId() != "" &&
		ev.GetTenantId() == o.GetTenantId() && env.GetTenantId() == o.GetTenantId() &&
		ev.GetProjectId() == o.GetProjectId() && env.GetProjectId() == o.GetProjectId()
}
