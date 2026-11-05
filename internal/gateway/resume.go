package gateway

import (
	"errors"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/policy/strictjson"
)

// resume is a retry of one of matches, oldest first. The fresh decision is a
// gate: a held request resumes only if this call's recorded decision is the
// one on its trail in verdict, rules, obligations and digest, because the
// trail cannot take a second POLICY_DECIDED. The first held request with an
// approval runs; one whose approval expired or was refused is closed on its
// trail; with none approved the agent is told about the oldest still pending.
// found is what the store answered under binding, which the plane judges.
func (c *call) resume(matches []*heldRequest, binding approval.Binding, found []Held) Disposition {
	var r resumption
	for _, own := range matches {
		if !sameDecision(own.decision, c.kernel) {
			continue
		}
		if d, done := c.try(own, binding, found, &r); done {
			return d
		}
	}
	switch {
	case r.waiting != nil:
		return c.pending(r.waiting.approval, r.waiting.decision)
	case r.concluded != nil:
		return *r.concluded
	case r.consumed:
		// The held request's approval was spent and its trail is closed;
		// this retry is a request of its own, refused in full on its own
		// trail.
		c.decide(verdictDeny, codeApprovalAlreadyUsed)
		return c.freshBlock()
	}
	// Every match was held under another decision than this call's, which its
	// trail cannot record, so this call is a request of its own and is held
	// anew, as one no hold matched is: the agent is told to retry that one
	// (ADR-0013).
	return c.holdAnew(binding, nil)
}

// resumption is what a resume found so far among the held requests it tried.
type resumption struct {
	waiting   *heldRequest
	concluded *Disposition
	consumed  bool
}

// try judges the store's answer about the held request and reports the answer
// when it ends the resume: the execution of an approved one, or a block for a
// store or a ledger that cannot answer. Anything else is noted in r and the
// resume goes on.
//
// The answer is the record the store keeps under the request id and the
// approval id the plane minted, so a record some other writer filed under the
// same binding is never the one judged (ADR-0016). Only an answer that passes
// every check is spent, and the ledger's compare-and-swap is what spends it.
func (c *call) try(own *heldRequest, binding approval.Binding, found []Held, r *resumption) (Disposition, bool) {
	if c.refusedBeforeConsume(own) {
		return c.freshBlock(), true
	}
	a, readable := answerOf(own, found)
	var d Disposition
	switch {
	case !readable:
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock(), true
	case a == nil:
		r.waiting = firstOf(r.waiting, own)
		return d, false
	}
	switch standing := approval.Consumable(a, c.now); standing {
	case approval.StandingUsable:
		return c.spend(own, binding, a, r)
	case approval.StandingMultiUse:
		c.p.counts.add(func(s *Stats) *uint64 { return &s.MultiUseRefused })
		r.waiting = firstOf(r.waiting, own)
		return d, false
	case approval.StandingExpired, approval.StandingRejected:
		return c.closeUnlessSpent(own, binding, a, standing, r)
	default:
		r.waiting = firstOf(r.waiting, own)
		return d, false
	}
}

// closeUnlessSpent closes the held trail on an expired or rejected answer,
// unless the ledger marks the approval spent: that is proof of an execution,
// whatever the record reads now, so the retry is told it was already used. A
// ledger that cannot be read blocks the call with nothing closed.
func (c *call) closeUnlessSpent(own *heldRequest, binding approval.Binding, a *controlv1.Approval, standing approval.Standing, r *resumption) (Disposition, bool) {
	spent, readable := c.spentAlready(own, binding)
	var d Disposition
	switch {
	case !readable:
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock(), true
	case spent:
		r.consumed = true
		return d, false
	case standing == approval.StandingExpired:
		d = c.resumeBlocked(own, verdictDeny, codeApprovalExpired, expiredEvent(own.approval))
	default:
		d = c.resumeRejected(own, a)
	}
	if r.concluded == nil {
		r.concluded = &d
	}
	return d, false
}

// spentAlready reports whether the ledger marks own's request spent under
// binding, and whether the ledger could be read at all.
func (c *call) spentAlready(own *heldRequest, binding approval.Binding) (spent, readable bool) {
	marks, err := c.p.cfg.Ledger.Lookup(c.ctx, binding, c.now)
	if err != nil {
		return false, false
	}
	return marks[own.approval.GetRequestId()] == ResolutionConsumed, true
}

// answerOf is the store's record of the approval the plane minted for own:
// nil with none, and not readable where the store returned two, one it cannot
// speak for, or one in a state this build does not name, since none of those
// is an answer the plane can judge.
func answerOf(own *heldRequest, found []Held) (*controlv1.Approval, bool) {
	var answer *controlv1.Approval
	for _, held := range found {
		a := held.Approval
		if a.GetRequestId() != own.approval.GetRequestId() || a.GetApprovalId() != own.approval.GetApprovalId() {
			continue
		}
		_, named := controlv1.ApprovalState_name[int32(a.GetState())]
		if answer != nil || !named || a.GetState() == controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED {
			return nil, false
		}
		answer = a
	}
	return answer, true
}

// spend checks an approved answer, spends it in the ledger and resumes the
// held request. An answer the checks refuse closes the window with the plane's
// own approval, expired, and is never spent. A ledger that says another call
// spent it notes that in r; one that says the plane settled it leaves the hold
// waiting; one that cannot be written blocks the call with nothing run.
func (c *call) spend(own *heldRequest, binding approval.Binding, a *controlv1.Approval, r *resumption) (Disposition, bool) {
	if verdict, code, refused := approvalFields(own.approval, a, own.expires, c.now); refused {
		d := c.resumeBlocked(own, verdict, code, expiredEvent(own.approval))
		if r.concluded == nil {
			r.concluded = &d
		}
		return d, false
	}
	res, err := c.p.cfg.Ledger.Spend(c.ctx, binding,
		own.approval.GetRequestId(), own.approval.GetApprovalId(), a.GetApproverId(), c.now)
	switch {
	case err == nil && res == ResolutionConsumed:
		return c.resumeApproved(own, a), true
	case errors.Is(err, ErrApprovalConsumed) && res == ResolutionConsumed:
		r.consumed = true
		return Disposition{}, false
	case errors.Is(err, ErrNoApproval) && res == ResolutionNotResumed:
		r.waiting = firstOf(r.waiting, own)
		return Disposition{}, false
	}
	c.decide(verdictIndeterminate, codeEvidenceUnavailable)
	return c.freshBlock(), true
}

// refusedBeforeConsume decides the block of a resume that may not consume its
// approval, on this call's own trail: nothing is spent, so the hold stands for
// a retry.
func (c *call) refusedBeforeConsume(own *heldRequest) bool {
	switch requested := own.approval.GetRequestedAt().AsTime(); {
	case c.blockIfCovered():
		// A pause or a stop: the retry comes after it ends.
	case unvouched(c.now, c.floor) || c.now.Before(requested):
		// A clock that cannot vouch for the approval: the retry comes at a
		// reading that can.
		c.decide(verdictDeny, codeApprovalExpired)
	case c.withholdIfStale(own.basis):
		// The retry comes once the bundle is current again; a bundle
		// replaced since never is, and the hold expires.
	case c.agentGone():
		// The agent left; it may still send the retry.
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
	default:
		return false
	}
	return true
}

func firstOf(first, next *heldRequest) *heldRequest {
	if first != nil {
		return first
	}
	return next
}

// sameDecision reports whether fresh is held again in everything an approval
// was given for.
func sameDecision(held, fresh *controlv1.Decision) bool {
	return held != nil && fresh != nil &&
		held.GetVerdict() == fresh.GetVerdict() &&
		held.GetActionDigest() == fresh.GetActionDigest() &&
		slices.Equal(held.GetPolicyRuleIds(), fresh.GetPolicyRuleIds()) &&
		slices.EqualFunc(held.GetObligations(), fresh.GetObligations(), func(a, b *controlv1.Obligation) bool { return proto.Equal(a, b) })
}

// resumeApproved writes APPROVAL_DECIDED and ACTION_STARTED on the held trail
// and executes exactly once, with the decision that trail recorded. It runs
// only after spend checked the answer field by field and the ledger spent it:
// the approval is consumed before the record is written, because two retries
// must not both write it, and a record the sink refuses then blocks with the
// approval spent.
func (c *call) resumeApproved(own *heldRequest, a *controlv1.Approval) Disposition {
	trail, err := c.resumedTrail(own)
	if err != nil {
		return c.blockUnrecorded()
	}
	if !c.p.takeHold(own) {
		// The hold was dropped or resumed between the lookup and here, so its
		// trail is not this call's to write on.
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock()
	}
	if !c.p.journalMark(c.ctx, own.ids.RequestID, HoldResuming) {
		// The entry still says this trail stands at its request for approval,
		// and nothing may be appended to it while it says so.
		c.p.counts.leftOpen()
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.freshBlock()
	}
	c.requestID, c.trail, c.held = own.ids.RequestID, trail, true
	c.approvalExpires = a.GetExpiresAt().AsTime()
	c.kernel, c.decision, c.basis = own.decision, own.decision, own.basis
	if !c.record(trail.ApprovalDecided(a)) {
		return c.blockUnrecorded()
	}
	if len(c.rest) > 0 {
		c.action = core.ExecuteWithObligations
	} else {
		c.action = core.Execute
	}
	// The entry stays until the trail is closed, at Close or Abort: a plane
	// that stops between the action starting and its closing record leaves an
	// entry a reconciliation counts, rather than a trail nothing names.
	return c.start(trail)
}

// resumeRejected closes the held trail on a rejection, checked as an approval
// is: approval.Consumable has already read a as rejected. Only one that passes
// the field checks is written as APPROVAL_DECIDED; any other is one the plane
// cannot stand behind, so the window closes with its own approval, expired.
func (c *call) resumeRejected(own *heldRequest, a *controlv1.Approval) Disposition {
	if verdict, code, refused := approvalFields(own.approval, a, own.expires, c.now); refused {
		return c.resumeBlocked(own, verdict, code, expiredEvent(own.approval))
	}
	return c.resumeBlocked(own, verdictDeny, codeApprovalRejected, decidedEvent(a))
}

// approvalFields compares an answer with the record the plane minted, field
// by field, and is the whole of what the plane trusts about a store: the same
// checks a resume makes are the ones a reconciliation makes about a hold
// nobody is retrying. An answer of a major this build does not read, or
// decided outside the window between the request and now, is not one the
// plane can place on its trail. Nor is one whose approver id is over the
// bound or the claim rule refuses it: a store holds claims only, so no
// approver the plane authenticated is ever taken from one. It leaves the
// answer's state to its caller, because a refusal is an answer where a resume
// needs an approval.
func approvalFields(want, a *controlv1.Approval, expires, now time.Time) (controlv1.Verdict, string, bool) {
	switch {
	case a == nil, !readsApprovalVersion(a.GetSchemaVersion()),
		a.GetApprovalId() != want.GetApprovalId(), a.GetRequestId() != want.GetRequestId(), a.GetMultiUse(),
		!proto.Equal(a.GetRequestedAt(), want.GetRequestedAt()),
		!decidedWithin(a, want.GetRequestedAt().AsTime(), now),
		len(a.GetApproverId()) > approval.MaxApproverIDBytes,
		approval.CheckClaimedApproverID(a.GetApproverId()) != nil:
		return verdictIndeterminate, codeEvidenceUnavailable, true
	case a.GetActionDigest() != want.GetActionDigest():
		return verdictDeny, codeApprovalDigestMismatch, true
	case a.GetPolicyBundleDigest() != want.GetPolicyBundleDigest():
		return verdictDeny, codeApprovalBundleMismatch, true
	case a.GetExpiresAt() == nil || !now.Before(a.GetExpiresAt().AsTime()):
		return verdictDeny, codeApprovalExpired, true
	case a.GetExpiresAt().AsTime().After(expires):
		return verdictIndeterminate, codeEvidenceUnavailable, true
	}
	return 0, "", false
}

// decidedWithin reports whether a was decided at or after requested and not
// after now. Only an answer nobody gave, still pending or expired, carries no
// decision time.
func decidedWithin(a *controlv1.Approval, requested, now time.Time) bool {
	decided := a.GetDecidedAt()
	if decided == nil {
		return a.GetState() == approvalPending || a.GetState() == approvalExpired
	}
	at := decided.AsTime()
	return !at.Before(requested) && !at.After(now)
}

// readsApprovalVersion reports whether v is MAJOR.MINOR under the major this
// build mints.
func readsApprovalVersion(v string) bool {
	want, _, _ := strings.Cut(approvalSchemaVersion, ".")
	return strictjson.IsVersion(v, want)
}

func expiredEvent(a *controlv1.Approval) func(*evidence.Builder) *controlv1.Event {
	expired := proto.CloneOf(a)
	expired.State = approvalExpired
	return func(t *evidence.Builder) *controlv1.Event { return t.ApprovalExpired(expired) }
}

func decidedEvent(a *controlv1.Approval) func(*evidence.Builder) *controlv1.Event {
	return func(t *evidence.Builder) *controlv1.Event { return t.ApprovalDecided(a) }
}

// resumeBlocked closes the held trail: the approval's outcome, then
// ACTION_BLOCKED with the plane's decision about the held request. It leaves
// this call's own state alone, so a resume can close one held request and go
// on to the next.
//
// Nothing runs on a trail being closed, so a read gets no exemption from the
// sink here. The entry is forgotten and the request id released only where
// both records landed: a trail a refused append left open keeps both, for a
// reconciliation to report and so that no later call writes into it. A hold
// the sweep or another call took first is theirs to close.
func (c *call) resumeBlocked(own *heldRequest, verdict controlv1.Verdict, code string, outcome func(*evidence.Builder) *controlv1.Event) Disposition {
	if !c.p.takeHold(own) {
		return Disposition{Action: core.Block, Decision: c.p.mint(own.decision, c.now, verdictIndeterminate, codeEvidenceUnavailable)}
	}
	decision := c.p.mint(own.decision, c.now, verdict, code)
	trail, err := c.resumedTrail(own)
	if err == nil && c.p.journalMark(c.ctx, own.ids.RequestID, HoldClosing) &&
		c.p.append(c.ctx, outcome(trail)) && c.p.append(c.ctx, trail.Blocked(decision)) {
		c.p.counts.blocked(code)
		c.p.journalForget(c.ctx, own.ids.RequestID)
		c.p.release(own.ids.RequestID)
		return Disposition{Action: core.Block, Decision: decision}
	}
	c.p.counts.blocked(codeEvidenceUnavailable)
	c.p.counts.leftOpen()
	return Disposition{Action: core.Block, Decision: c.p.mint(own.decision, c.now, verdictIndeterminate, codeEvidenceUnavailable)}
}

// resumedTrail continues the held request's trail where the hold left it.
func (c *call) resumedTrail(own *heldRequest) (*evidence.Builder, error) {
	return evidence.Resume(
		own.ids, c.p.cfg.Mode, func() time.Time { return c.now }, c.p.cfg.NewID,
		evidence.Position{LastEventID: own.lastEventID},
	)
}
