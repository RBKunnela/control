package supervise

import (
	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/reasons"
	"github.com/guardana/control/internal/trailchain"
)

// request is one request's trail within the run: one step instance.
type request struct {
	id     string
	events []*controlv1.Event
	// doubt is true when its trail is not one coherent chain in the order its
	// links give, or an event id in it was read with two contents.
	doubt    bool
	proposal *controlv1.Event
	kernel   *controlv1.Decision
	// decided is the POLICY_DECIDED event kernel was read from.
	decided  *controlv1.Event
	terminal *controlv1.Event
	// waiting is true while an approval the trail requested is neither
	// decided nor expired, and approval is the state of its first
	// APPROVAL_DECIDED.
	waiting  bool
	approval controlv1.ApprovalState
}

// requestsOf groups the run's events by request id, in the order each request
// was first read.
func requestsOf(events []*controlv1.Event, doubtful map[string]bool) []*request {
	var out []*request
	byID := map[string]*request{}
	for _, ev := range events {
		rq := byID[ev.GetRequestId()]
		if rq == nil {
			rq = &request{id: ev.GetRequestId()}
			byID[rq.id] = rq
			out = append(out, rq)
		}
		rq.events = append(rq.events, ev)
	}
	for _, rq := range out {
		var chained bool
		rq.events, chained = linked(rq.events)
		rq.doubt = doubtful[rq.id] || !chained || trailchain.Validate(rq.events) != nil
		for _, ev := range rq.events {
			rq.note(ev)
		}
	}
	return out
}

// linked is events in the order their links give, the event that links to
// nothing first, and true when that order takes each event exactly once. A
// plane ships several batches at a time, so an export can hold a request's
// later batch first. Links that make no one chain, a second head or none, a
// fork, a gap, an id read twice or a cycle, return events as read and false.
func linked(events []*controlv1.Event) ([]*controlv1.Event, bool) {
	next := make(map[string]*controlv1.Event, len(events))
	var head *controlv1.Event
	for _, ev := range events {
		if prev := ev.GetPrevEventId(); prev != "" {
			next[prev] = ev
		} else {
			head = ev
		}
	}
	out := make([]*controlv1.Event, 0, len(events))
	seen := make(map[string]bool, len(events))
	for ev := head; ev != nil; ev = next[ev.GetEventId()] {
		if seen[ev.GetEventId()] {
			return events, false
		}
		seen[ev.GetEventId()] = true
		out = append(out, ev)
	}
	if len(out) != len(events) {
		return events, false
	}
	return out, true
}

func (rq *request) note(ev *controlv1.Event) {
	switch ev.GetKind() {
	case controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED:
		if rq.proposal == nil {
			rq.proposal = ev
		}
	case controlv1.EventKind_EVENT_KIND_POLICY_DECIDED:
		if rq.kernel == nil {
			rq.kernel, rq.decided = ev.GetDecision(), ev
		}
	case controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED:
		rq.waiting = true
	case controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED:
		rq.waiting = false
		if rq.approval == controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED {
			rq.approval = ev.GetApproval().GetState()
		}
	case controlv1.EventKind_EVENT_KIND_APPROVAL_EXPIRED:
		rq.waiting = false
	case controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED, controlv1.EventKind_EVENT_KIND_ACTION_FAILED,
		controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
		rq.terminal = ev
	}
}

// actionKindTool is how an envelope's action kind names a tool call. A prompt
// or a resource read carries a name the agent chose on the upstream the plane
// routed it to, so it is never a step, an allowed tool or a call outside them.
const actionKindTool = "tool"

// tool is the tool and upstream the request proposed; ok is false when its
// proposal was not read or is not a tool call.
func (rq *request) tool() ([2]string, bool) {
	a := rq.proposal.GetProposed().GetAction()
	return [2]string{a.GetName(), a.GetProvider()}, rq.proposal != nil && a.GetKind() == actionKindTool
}

// failed reports a request that ended blocked or failed. One still open, such
// as one held for approval, has not failed.
func (rq *request) failed() bool {
	k := rq.terminal.GetKind()
	return k == controlv1.EventKind_EVENT_KIND_ACTION_FAILED || k == controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
}

// denied reports a block that carries the kernel's own DENY: the decision of
// the request's POLICY_DECIDED, told apart by its id. A block the plane
// decides itself, such as for a pause, an unclassified tool or an approval
// spent or expired, carries an id of its own and is no denial; nor is the
// kernel's block on a verdict other than DENY.
func (rq *request) denied() bool {
	if rq.terminal.GetKind() != controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED || rq.kernel == nil {
		return false
	}
	block := rq.terminal.GetDecision()
	return block.GetDecisionId() != "" && block.GetDecisionId() == rq.kernel.GetDecisionId() &&
		rq.kernel.GetVerdict() == controlv1.Verdict_VERDICT_DENY
}

// blockCode is the first reason code a block that is no denial carries, as
// the registry names it.
func (rq *request) blockCode() string {
	codes := rq.terminal.GetDecision().GetReasonCodes()
	if len(codes) == 0 {
		return "no reason code"
	}
	if _, ok := reasons.Lookup(codes[0]); !ok {
		return "an unregistered reason code"
	}
	return codes[0]
}

// verdict is the strongest verdict the trail supports.
func (rq *request) verdict() controlv1.FindingVerdict {
	if rq.doubt {
		return controlv1.FindingVerdict_FINDING_VERDICT_INDETERMINATE
	}
	return controlv1.FindingVerdict_FINDING_VERDICT_CONFIRMED
}

// ref cites ev of rq at the strongest verdict the trail supports.
func (rq *request) ref(ev *controlv1.Event) ref {
	return ref{v: rq.verdict(), run: ev.GetRunId(), r: &findingv1alpha1.Reference{Ref: &findingv1alpha1.Reference_Event{
		Event: &findingv1alpha1.EventRef{EventId: ev.GetEventId(), RequestId: rq.id},
	}}}
}

const blocked = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
