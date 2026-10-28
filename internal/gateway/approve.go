package gateway

import (
	"errors"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/policy"
)

// approve is the branch for a call that awaits an approval: the kernel's
// REQUIRE_APPROVAL, or an allowed material call under APPROVE, which the same
// approval satisfies. A retry that is a held request again resumes it; any
// other call is held anew. A request held under this binding is one the
// pipeline itself holds, unexpired at this call's clock reading: the store says
// which of its records are still there, and the pipeline's own record says what
// was held. Whatever the store cannot answer blocks the call on its own trail.
func (c *call) approve(snap *policy.Snapshot) Disposition {
	if c.runLapsedNow() {
		// A hold under a run that expired is one no retry can reach, since the
		// listener refuses its token.
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock()
	}
	_, binding, err := approval.Bind(c.env, c.args, approval.BundleDigest(snap.Ref().GetDigest()))
	if err != nil {
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock()
	}
	// Memory before the store, the reverse of a resume's consume then take: a
	// hold taken after this read was consumed first, so the store reads it spent.
	holds := c.p.heldUnder(binding, c.now)
	helds, err := c.p.cfg.Approvals.Find(c.ctx, binding, c.now)
	if err != nil && !errors.Is(err, ErrNoApproval) {
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock()
	}
	var matches []*heldRequest
	var unheld []Held
	for _, held := range helds {
		switch own := holds[held.Approval.GetRequestId()]; {
		case own == nil:
			unheld = append(unheld, held)
		case c.p.cfg.Runs != nil && own.ids.RunID != c.flow.runID():
			// Held under another opened run: this call neither resumes it nor
			// learns from it that the approval was spent (ADR-0034).
		case sameHeldRequest(own.envelope, c.in.Envelope):
			matches = append(matches, own)
		}
	}
	if len(matches) == 0 {
		return c.holdAnew(binding, unheld)
	}
	return c.resume(matches, binding)
}

// holdAnew is the branch for a call no hold matched. A pause or a stop
// written while the store searched blocks it, as one written during the ask
// does, and the clock read with them judges its run again.
func (c *call) holdAnew(binding approval.Binding, unheld []Held) Disposition {
	if c.blockIfCovered() {
		return c.freshBlock()
	}
	if c.runLapsed() {
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock()
	}
	return c.holdOrUsed(binding, unheld)
}

// holdOrUsed holds this call anew, unless a record the store keeps for a
// request the pipeline no longer holds resolves as consumed, as Find returned
// it: a resume of that request spent its approval, and this call is the next
// identical one (ADR-0013). Only a plane resuming a request it held consumes,
// so Consumed proves the approval spent once the hold is gone, though not that
// anything ran: a pause or a record the sink refuses after the consume blocks
// the execution. Every other resolution proves nothing spent, and the call is
// held anew and counted. A record the plane does not hold is never consumed:
// that would spend an answer a reconciliation may still resolve, and tell the
// next identical call that its approval was spent (ADR-0016).
func (c *call) holdOrUsed(binding approval.Binding, unheld []Held) Disposition {
	for _, held := range unheld {
		if held.Resolution == ResolutionConsumed {
			c.decide(verdictDeny, codeApprovalAlreadyUsed)
			return c.freshBlock()
		}
	}
	for _, held := range unheld {
		if held.Resolution != ResolutionNotResumed {
			c.p.counts.add(func(s *Stats) *uint64 { return &s.UnheldRecords })
		}
	}
	return c.hold(binding)
}

// sameHeldRequest reports whether env is the held request again: the binding
// already matched, so what is left is every field the digest leaves out that
// an approval was given under, the data labels and the run context without its
// flow tags. The fresh decision already weighs the run as it stands and has to
// equal the held one, so a flow that matters stops the resume there (ADR-0021).
func sameHeldRequest(held, env *controlv1.ActionEnvelope) bool {
	return proto.Equal(orEmpty(held.GetData()), orEmpty(env.GetData())) &&
		proto.Equal(withoutFlowTags(held.GetContext()), withoutFlowTags(env.GetContext()))
}

// orEmpty makes an absent message and an empty one the same thing, which
// they are on the wire.
func orEmpty[M proto.Message](m M) M {
	if !m.ProtoReflect().IsValid() {
		return m.ProtoReflect().Type().New().Interface().(M)
	}
	return m
}

// hold is a new request awaiting approval: its trail is written, the request
// is held and the agent is told to retry. A trail the sink did not take, to
// its request for approval included, is never held, because the retry would
// resume a trail nobody can read.
func (c *call) hold(binding approval.Binding) Disposition {
	if !c.openTrail() {
		return c.refuseOpen()
	}
	if !c.record(c.trail.Proposed(c.in.Envelope)) || !c.record(c.trail.Decided(c.kernel)) || c.unrecorded {
		return c.blockUnrecorded()
	}
	a := &controlv1.Approval{
		SchemaVersion:      approvalSchemaVersion,
		ApprovalId:         c.p.cfg.NewID(),
		RequestId:          c.in.Envelope.GetRequestId(),
		ActionDigest:       c.kernel.GetActionDigest(),
		PolicyBundleDigest: c.kernel.GetPolicyBundleDigest(),
		State:              approvalPending,
		RequestedAt:        timestampOf(c.now),
		ExpiresAt:          timestampOf(c.now.Add(c.p.cfg.ApprovalTTL)),
	}
	if !c.record(c.trail.ApprovalRequested(a)) || c.unrecorded {
		return c.blockUnrecorded()
	}
	c.held = true
	// Held after the event, because the hold names the event it stands at.
	position := c.trail.Position().LastEventID
	own := &heldRequest{
		ids:         c.trailIDs(),
		approval:    proto.CloneOf(a),
		envelope:    proto.CloneOf(c.in.Envelope),
		decision:    proto.CloneOf(c.kernel),
		basis:       c.basis,
		binding:     binding,
		lastEventID: position,
		expires:     a.GetExpiresAt().AsTime(),
		run:         c.flow.openedID(),
	}
	// Journalled before anything is told about the hold and after
	// APPROVAL_REQUESTED is on the trail, so the entry is only ever recorded
	// for a trail that really stands there.
	switch c.p.journalRecord(c.ctx, own) {
	case entryNotFiled:
		return c.refuseHold(a, false)
	case entryMaybeFiled:
		return c.refuseHold(a, true)
	}
	if !c.p.holdOpen(own) {
		return c.refuseHold(a, true)
	}
	held := Held{
		Approval: a, Envelope: c.in.Envelope, Decision: c.kernel,
		Binding: binding, LastEventID: position,
	}
	if err := c.p.cfg.Approvals.Hold(c.ctx, held, c.now); err != nil {
		if !c.p.takeHold(own) {
			return c.lostHold()
		}
		return c.refuseHold(a, true)
	}
	c.requestID = ""
	return c.pending(a, c.decision)
}

// refuseHold closes the approval window a hold the store would not keep had
// opened: nobody can answer it and nothing holds it, so it expired; then the
// call is blocked because the record that would let it resume is not kept.
// journalled says an entry was filed for this trail, or may have been, which
// is flipped out of held before the window is closed and forgotten only once
// ACTION_BLOCKED is on the trail, so an open trail keeps its entry for a
// reconciliation and its request id; a journal that refuses the flip leaves
// the trail where it stands, for a later plane to close from an entry that
// still says so.
func (c *call) refuseHold(a *controlv1.Approval, journalled bool) Disposition {
	requestID := c.requestID
	if journalled && !c.p.journalMark(c.ctx, requestID, HoldClosing) {
		return c.blockUnrecorded()
	}
	expired := proto.CloneOf(a)
	expired.State = approvalExpired
	if !c.record(c.trail.ApprovalExpired(expired)) {
		return c.blockUnrecorded()
	}
	c.decide(verdictIndeterminate, codeEvidenceUnavailable)
	d, closed := c.block()
	if journalled && closed {
		c.p.journalForget(c.ctx, requestID)
	}
	return d
}

// lostHold answers a call whose hold the sweep or a resume took while the
// store was being asked to keep it: that trail is the taker's to close, count
// and release, so this call writes, counts and releases nothing.
func (c *call) lostHold() Disposition {
	c.decide(verdictIndeterminate, codeEvidenceUnavailable)
	c.requestID = ""
	return Disposition{Action: core.Block, Decision: c.decision}
}

// pending answers the agent with what it needs to retry the held request,
// and the decision that request's trail recorded.
func (c *call) pending(a *controlv1.Approval, decision *controlv1.Decision) Disposition {
	c.p.counts.add(func(s *Stats) *uint64 { return &s.Pending })
	return Disposition{
		Action:   core.AwaitApproval,
		Decision: decision,
		Pending: &Pending{
			ApprovalID:   a.GetApprovalId(),
			ActionDigest: a.GetActionDigest(),
			ExpiresAt:    a.GetExpiresAt().AsTime(),
			RetryAfter:   c.p.cfg.RetryAfter,
		},
	}
}

// freshBlock writes a whole trail for a call refused before its trail was
// started: ACTION_PROPOSED, POLICY_DECIDED and ACTION_BLOCKED.
func (c *call) freshBlock() Disposition {
	if !c.openTrail() {
		return c.refuseOpen()
	}
	if !c.record(c.trail.Proposed(c.in.Envelope)) || !c.record(c.trail.Decided(c.kernel)) {
		return c.blockUnrecorded()
	}
	d, _ := c.block()
	return d
}
