package evidence

import (
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/trailchain"
)

var (
	// ErrChainBroken reports a definite defect: a link that does not join, an
	// event belonging to another request, project, tenant or run, an identifier or
	// a mode an event has to carry and does not, an identifier longer than the
	// contract lets a string be, or a step the order below does not allow.
	ErrChainBroken = trailchain.ErrBroken

	// ErrChainIndeterminate reports that the sequence carries an event kind
	// this version cannot place, or an enforcement mode it does not declare,
	// so the trail could not be read either way. event.proto states that an
	// undeclared kind is INDETERMINATE to a reader and never an error, which is
	// what lets a later minor version add one, and common.proto states the
	// same of every undeclared enum number; reporting such a sequence as well
	// formed would claim a reading nothing performed, and reporting it as
	// broken would blame a producer for being newer.
	//
	// It is the weaker answer and it never hides the stronger one. Everything
	// that is a defect whatever the unplaceable kind turns out to mean is
	// reported as ErrChainBroken instead, wherever in the sequence it sits: the
	// links, the identifiers, an event that names no kind, a second proposal.
	// What the undetermined reading does cover is the steps that depend on the
	// state the walk lost, and only those.
	ErrChainIndeterminate = trailchain.ErrIndeterminate
)

// ValidateChain reports whether events are one coherent account of one request.
//
// It answers whether the trail is well formed. It says nothing about whether
// the trail is true: prev_event_id is an ordering link, so a gap shows and an
// altered record does not. prev_event_digest, field 31, is declared for the
// digest link that would change that, and nothing here reads it (ADR-0011; the
// hash chain is planned, ADR-0004).
//
// The order it accepts, per request_id, a bracketed group being optional:
//
//	ACTION_PROPOSED -> POLICY_DECIDED
//	  -> [APPROVAL_REQUESTED -> APPROVAL_DECIDED]
//	  -> ( ACTION_STARTED -> (ACTION_COMPLETED | ACTION_FAILED) )
//	   | ACTION_BLOCKED
//
// APPROVAL_EXPIRED closes an approval window that nobody answered. It may be
// followed by ACTION_BLOCKED, or by another APPROVAL_REQUESTED, and not by
// ACTION_STARTED: event.proto keeps it distinct from APPROVAL_DECIDED because
// "nobody answered" and "somebody said no" are different facts about an
// operator's controls, and a grammar that let the action run after either would
// spend that distinction on nothing.
//
// FINDING_RAISED sits outside that sequence and is accepted at any point after
// ACTION_PROPOSED, including after the last one: the detector plane is
// asynchronous and off the decision path, so a finding is caused by a detector
// finishing rather than by this request progressing. It is refused before
// ACTION_PROPOSED, where it would annotate an action the trail has not
// mentioned. POLICY_RELOADED is accepted anywhere within the sequence,
// including as the first event, because a bundle reload is caused by an
// operator and not by this request.
//
// A sequence may end in any state. An in-flight request is a prefix of a trail,
// not a broken one; what it may not do is take a step the order does not allow.
//
// Beside the order, every event carries the trail's scope: the request_id,
// project_id and tenant_id of event 0, none of them empty, because request_id
// is unique only within a project, and event 0's run_id, which is empty on
// every event of an action taken outside a run. Every event names an
// enforcement mode.
// ACTION_STARTED, ACTION_COMPLETED and ACTION_FAILED each name an execution,
// and the event that closes the action names the one that started it. No
// identifier it reads is longer than contract.MaxStringBytes, the contract's
// bound on a string. A mode this version does not declare is read the way a
// kind it cannot place is: undetermined, and never in front of a definite
// defect.
//
// It refuses an empty slice, and a sequence in which nothing proposes an
// action. An empty trail is the shape a dropped read has, a trail of nothing
// but reloads is the shape a read that dropped the request has, and reporting
// either as well formed is the false green this project looks for.
//
// It does not order events by occurred_at, does not read payloads, and does not
// look at schema_version. Not reading payloads has a cost worth stating: an
// approval carries its outcome in its payload, so a trail in which the approver
// said no and the action ran anyway is well formed here. A nil result is
// therefore not a verification and must not be reported as one: not "verified",
// not "intact", not "untampered".
func ValidateChain(events []*controlv1.Event) error {
	return trailchain.Validate(events)
}
