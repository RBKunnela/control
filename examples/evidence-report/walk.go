package main

import (
	"fmt"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// walker is where a walk along a linked chain has got to.
type walker struct {
	at       stage
	prevKind string
	// mode is the enforcement mode the request's first event names, which
	// every event of the request has to name.
	mode    controlv1.EnforcementMode
	verdict controlv1.Verdict
	// answer is the approval's answer, empty while none was given.
	answer string
	// running is the execution ACTION_STARTED named.
	running   string
	end, note string
}

// walk follows a linked chain through the lifecycle and says how it ended,
// or why it cannot say.
func walk(chain []*controlv1.Event) (string, string) {
	w := walker{prevKind: startOfRequest, mode: chain[0].GetEnforcementMode(), end: endOpen}
	for _, ev := range chain {
		if note := runDefect(ev, chain[0].GetRunId()); note != "" {
			return endUnknown, note
		}
		if note := w.take(ev); note != "" {
			return endUnknown, note
		}
	}
	switch w.at {
	case atEnded:
		return w.end, w.note
	case atStart:
		return endOpen, "no event proposes an action"
	default:
		return endOpen, "no event ends the action"
	}
}

// take walks one event, and names why the request is unknown when it is.
func (w *walker) take(ev *controlv1.Event) string {
	id, kind := safe(ev.GetEventId()), ev.GetKind()
	s, known := steps[kind]
	if !known {
		return fmt.Sprintf("event %s has kind %d, which this reader cannot place", id, int32(kind))
	}
	if !follows(w.at, s.from) {
		return fmt.Sprintf("%s cannot follow %s", kindName(kind), w.prevKind)
	}
	if note := w.modeDefect(id, ev.GetEnforcementMode()); note != "" {
		return note
	}
	if note := payloadDefect(ev, w.running); note != "" {
		return note
	}
	if s.to != unchanged {
		w.at = s.to
	}
	w.prevKind = kindName(kind)
	switch kind {
	case controlv1.EventKind_EVENT_KIND_POLICY_DECIDED:
		w.verdict = ev.GetDecision().GetVerdict()
	case controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED:
		w.answer = answer(ev.GetApproval().GetState())
	case controlv1.EventKind_EVENT_KIND_ACTION_STARTED:
		w.running = ev.GetExecutionId()
		return w.authorized(id)
	case controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED, controlv1.EventKind_EVENT_KIND_ACTION_FAILED:
		end, note := ending(ev)
		if end == endUnknown {
			return note
		}
		w.ended(end, note)
	case controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
		w.end = endBlocked
	}
	return ""
}

// ended records how the action ended, beside any note already taken.
func (w *walker) ended(end, note string) {
	w.end = end
	switch {
	case note == "":
	case w.note == "":
		w.note = note
	default:
		w.note += "; " + note
	}
}

// modeDefect names an event whose mode says nothing is known to have been
// enforced, or another mode than the request's.
func (w *walker) modeDefect(id string, mode controlv1.EnforcementMode) string {
	switch {
	case mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED:
		return fmt.Sprintf("event %s names no enforcement mode", id)
	case !declared(mode):
		return fmt.Sprintf("event %s names enforcement mode %d, which this reader does not declare", id, int32(mode))
	case mode != w.mode:
		return fmt.Sprintf("event %s names enforcement mode %s, and the request's first event %s", id, modeName(mode), modeName(w.mode))
	}
	return ""
}

// runDefect names an event of another run than the request's first event, an
// empty run being none. A plane stamps one run on a whole request, so a
// request naming two cannot say which run did what.
func runDefect(ev *controlv1.Event, run string) string {
	if got := ev.GetRunId(); got != run {
		return fmt.Sprintf("event %s names run %s, and the request's first event %s", safe(ev.GetEventId()), safe(got), safe(run))
	}
	return ""
}

// authorized holds a start to its decision: a verdict that lets the action
// run, or REQUIRE_APPROVAL and an approval answered yes, and never an
// approval answered no. The plane asks for an approval only after
// REQUIRE_APPROVAL or, under APPROVE, an allowed material call, so an
// approval never lifts a DENY or an INDETERMINATE. Only a mode that enforces
// nothing lets a start go against its decision, and the row says so.
func (w *walker) authorized(id string) string {
	verdict := "verdict " + strings.TrimPrefix(w.verdict.String(), "VERDICT_")
	var after string
	switch {
	case w.answer == "rejected":
		after = "its approval was rejected"
	case w.verdict == controlv1.Verdict_VERDICT_ALLOW, w.verdict == controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS:
		return ""
	case w.verdict == controlv1.Verdict_VERDICT_REQUIRE_APPROVAL && w.answer == "approved":
		return ""
	case w.answer == "approved":
		after = verdict + ", which no approval lifts"
	default:
		after = verdict + " and no approval"
	}
	switch w.mode {
	case controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE, controlv1.EnforcementMode_ENFORCEMENT_MODE_WARN:
		w.note = fmt.Sprintf("ran under %s, which enforces nothing, after %s", modeName(w.mode), after)
		return ""
	}
	return fmt.Sprintf("event %s starts the action under %s after %s: it ran against its decision", id, modeName(w.mode), after)
}

// ending reads how a started action ended from its result. Only a success is
// completed and only a result saying nothing was sent is aborted. A failure
// that timed out or whose outcome is unknown is uncertain: the run may have
// had its effect. A result that is missing or at odds with its event leaves
// the lifecycle unknown.
func ending(ev *controlv1.Event) (string, string) {
	id, kind, r := safe(ev.GetEventId()), ev.GetKind(), ev.GetResult()
	if r == nil {
		return endUnknown, fmt.Sprintf("event %s is %s and carries no result: the effect may have happened", id, kindName(kind))
	}
	status, failed := r.GetStatus(), kind == controlv1.EventKind_EVENT_KIND_ACTION_FAILED
	switch {
	case !failed && status == controlv1.ResultStatus_RESULT_STATUS_SUCCESS:
		return endCompleted, ""
	case failed && status == controlv1.ResultStatus_RESULT_STATUS_BLOCKED:
		return endAborted, ""
	case failed && status == controlv1.ResultStatus_RESULT_STATUS_FAILURE:
		return endFailed, ""
	case failed && (status == controlv1.ResultStatus_RESULT_STATUS_TIMEOUT || status == controlv1.ResultStatus_RESULT_STATUS_UNKNOWN):
		return endUncertain, fmt.Sprintf("event %s is %s with result %s: the effect may have happened", id, kindName(kind), status)
	}
	return endUnknown, fmt.Sprintf("event %s is %s with result %s: the effect may have happened", id, kindName(kind), status)
}

// declared reports whether the contract this reader was built from declares
// the enum's number.
func declared(e protoreflect.Enum) bool { return e.Descriptor().Values().ByNumber(e.Number()) != nil }

// payloadDefect names an event that takes its step without what the step
// needs: the action, a verdict, the approval's answer, the execution that ran.
func payloadDefect(ev *controlv1.Event, running string) string {
	id := safe(ev.GetEventId())
	switch ev.GetKind() {
	case controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED:
		if ev.GetProposed().GetAction() == nil {
			return fmt.Sprintf("event %s is ACTION_PROPOSED and names no action", id)
		}
	case controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
		return decisionDefect(id, ev.GetKind(), ev.GetDecision())
	case controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED:
		if answer(ev.GetApproval().GetState()) == "unknown" {
			return fmt.Sprintf("event %s decides the approval as %s", id, ev.GetApproval().GetState())
		}
	case controlv1.EventKind_EVENT_KIND_ACTION_STARTED:
		if ev.GetExecutionId() == "" {
			return fmt.Sprintf("event %s is ACTION_STARTED and names no execution", id)
		}
	case controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED, controlv1.EventKind_EVENT_KIND_ACTION_FAILED:
		if ev.GetExecutionId() != running {
			return fmt.Sprintf("event %s ends execution %s, not %s, which started", id, safe(ev.GetExecutionId()), safe(running))
		}
	}
	return ""
}

// decisionDefect names a decision event, the kernel's POLICY_DECIDED or the
// ACTION_BLOCKED that carries the block's own, without a declared verdict.
func decisionDefect(id string, kind controlv1.EventKind, d *controlv1.Decision) string {
	switch {
	case d == nil:
		return fmt.Sprintf("event %s is %s and carries no decision", id, kindName(kind))
	case d.GetVerdict() == controlv1.Verdict_VERDICT_UNSPECIFIED:
		return fmt.Sprintf("event %s is %s and decides no verdict", id, kindName(kind))
	case !declared(d.GetVerdict()):
		return fmt.Sprintf("event %s decides verdict %d, which this reader does not declare", id, int32(d.GetVerdict()))
	}
	return ""
}
