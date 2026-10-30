package gateway

import (
	"context"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/match"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/pkg/contract"
)

// call is one admission on its way through the pipeline: what the kernel
// said, what the mode made of it, and the trail it writes.
type call struct {
	p   *Pipeline
	ctx context.Context
	// agent is the context the agent's call came with. Once the call is
	// proposed, ctx no longer ends with it; agent says whether the agent is
	// still there to receive what the plane hands out.
	agent context.Context
	in    Admission
	now   time.Time
	// pause is the operator's pause state as this call took it: once at
	// admission and, when the decision point is asked, once more after the
	// ask, at the clock read after it. Every decision after the ask, the
	// second one on the rewrite path included, is made under that one.
	pause pause.Snapshot
	// stops is the stop state as this call took it, each time it took the
	// pause state.
	stops reaction.Snapshot
	// installed is the policy the plane held when the call took its states
	// last, the one its decision is judged against again at hand-out.
	installed *policy.Snapshot
	// staleSeen: OBSERVE found the policy this call's decision stood on no
	// longer current at a hand-out check, and let it through.
	staleSeen bool
	// causes are the plane's own causes to block this call, named once
	// before any ask and, after one, once more. Whatever the mode does is
	// done under these; nothing names them again.
	causes []cause
	// flow is the run's state as this call took it when it started; every
	// decision of the call is made under it, after an ask included.
	flow flow
	// forged: the producer sent a tag under the reserved flow prefix.
	forged bool

	// kernel is the decision POLICY_DECIDED records: the kernel's about the
	// proposed envelope, or about the authorized one when a rewrite changed
	// the arguments. basis is what it stood on, judged again at hand-out.
	kernel *controlv1.Decision
	basis  core.Basis
	// kernelAction is what the kernel's decision about this call asked for,
	// before the mode is applied to action. A resume leaves it as the retry's
	// own; OBSERVE, its one reader, never holds a call to resume.
	kernelAction core.EnforcementAction
	// refusedInput: the kernel's decision stopped on the request itself,
	// whatever the adapter's Admission said of it.
	refusedInput bool
	// unknownAllows and noRuleMatched are the kernel's ALLOW rules it could
	// not tell, with what each lacked, and whether its decision is DENY for
	// no matching rule alone; only a preview reads them.
	unknownAllows []match.UnknownAllow
	noRuleMatched bool
	action        core.EnforcementAction
	decision      *controlv1.Decision
	material      bool
	// external is the decision point's answer about this call, asked at
	// most once; the zero value when it was not asked.
	external core.External
	// args, digest and rest are the authorized arguments, their arguments
	// hash and the obligations left for the adapter; env is the authorized
	// envelope and actionDigest its canonical action digest with args.
	args         []byte
	digest       string
	rest         []*controlv1.Obligation
	env          *controlv1.ActionEnvelope
	actionDigest string

	trail *evidence.Builder
	// requestID is the trail this call writes on and owns while it is open:
	// its own, or the held request's when it resumes one.
	requestID string
	// unrecorded: the sink refused an event of this trail and the read goes
	// on under AllowReadsUnrecorded.
	unrecorded bool
	// held: the trail stands past a request for approval, so none of its
	// records goes unrecorded, and one the sink refuses leaves the trail open
	// with its journal entry and its request id.
	held bool
	// approvalExpires is when the approval a resumed call runs on expires; a
	// resumed call is handed out only before it.
	approvalExpires time.Time
	// floor is the latest instant the call already relied on: each clock
	// reading it took, a decision's, and the time the plane verified for its
	// snapshot. A later reading behind it proves no expiry unmet.
	floor time.Time
}

func (c *call) run() Disposition {
	snap := c.p.cfg.Policy.Current()
	c.takeFlow()
	// A call the plane blocks whatever the answer is not asked about: its
	// question would leave the plane for nothing, during the very incident a
	// pause or a halt stands for (ADR-0019).
	c.causes = planeCauses(c.planeState())
	c.decideProposed(snap, len(c.causes) == 0)

	trail, err := c.newTrail()
	if err != nil {
		// Nothing can be written about this request, so nothing runs: the
		// kernel's own refusal blocks it, and a request the kernel took but
		// the trail cannot name is refused on its identifiers.
		if c.action != core.Block {
			c.decide(verdictIndeterminate, codeInvalidFieldValue)
		}
		c.p.counts.blocked(firstCode(c.decision))
		return Disposition{Action: core.Block, Decision: c.decision}
	}
	c.trail = trail
	// The call is proposed: its records, its hold and its consume are the
	// plane's to finish whatever the agent does, or a cancel would leave a
	// trail cut short, a hold open and an approval spent with nothing on record.
	c.agent, c.ctx = c.ctx, context.WithoutCancel(c.ctx)

	c.applyMode()
	c.refuseFlow()
	if c.action != core.Block {
		c.authorize(snap)
	}
	if c.action == core.AwaitApproval {
		return c.approve(snap)
	}
	if !c.openTrail() {
		return c.refuseOpen()
	}
	if !c.record(c.trail.Proposed(c.in.Envelope)) || !c.record(c.trail.Decided(c.kernel)) {
		return c.blockUnrecorded()
	}
	if c.action == core.Block {
		d, _ := c.block()
		return d
	}
	return c.start(c.trail)
}

// decideProposed asks the kernel about the proposed envelope and bytes. When
// ask is set and the kernel reports that its decision turns on the decision
// point's answer, and that decision is not a DENY no answer can lift, it asks
// the decision point once and decides again with the answer, in every mode.
// After the ask the call takes the pause and stop states and the clock again
// and names the plane's causes once more, since a pause, a stop, a halt or an
// expiry can come while the ask waits.
func (c *call) decideProposed(snap *policy.Snapshot, ask bool) {
	req := core.Request{
		Envelope: c.in.Envelope, Refusal: c.in.Refusal, AuthorizedArgs: c.in.Arguments, Flow: c.flow.state,
	}
	out := c.p.kernel.Decide(c.ctx, req, snap)
	if ask && out.NeedsExternal && out.Decision.GetVerdict() != verdictDeny {
		c.external = c.p.ask(c.ctx, c.in.Envelope)
		c.takeStates()
		c.causes = planeCauses(c.planeState())
		req.External = c.external
		out = c.p.kernel.Decide(c.ctx, req, snap)
	}
	c.kernel, c.decision, c.action, c.basis = out.Decision, out.Decision, out.Action, out.Basis
	c.kernelAction, c.refusedInput = out.Action, out.RefusedInput
	c.unknownAllows, c.noRuleMatched = out.UnknownAllows, out.NoRuleMatched
	c.reliedOnDecision(out.Decision, snap)
	c.material = contract.IsMaterial(c.in.Envelope.GetAction().GetEffect())
}

// applyMode applies the plane's causes and mode to the action and never to
// the kernel's decision (ADR-0013). A call the plane named a cause of its own
// to block is blocked whatever the mode, OBSERVE included, with every such
// cause listed; otherwise OBSERVE lets through every call but a refused one,
// which the kernel blocked, and APPROVE holds an allowed material one.
func (c *call) applyMode() {
	if len(c.causes) > 0 {
		c.blockOnCauses()
		return
	}
	switch c.p.cfg.Mode {
	case modeObserve:
		if c.observable() {
			c.action = core.Execute
		}
	case modeApprove:
		if c.material && (c.action == core.Execute || c.action == core.ExecuteWithObligations) {
			c.action = core.AwaitApproval
		}
	}
}

// blockOnCauses blocks the call with the plane's decision, which lists every
// cause named in order.
func (c *call) blockOnCauses() {
	codes := make([]string, len(c.causes))
	for i, cause := range c.causes {
		codes[i] = cause.code
	}
	c.decide(verdictOf(c.causes), codes...)
}

// decide replaces the action with a block and the decision with the plane's
// own; the kernel's stays what POLICY_DECIDED records.
func (c *call) decide(verdict controlv1.Verdict, codes ...string) {
	c.action = core.Block
	c.decision = c.p.mint(c.kernel, c.now, verdict, codes...)
}

// openTrail opens this call's own trail, or reports that its request id has
// a trail open in this pipeline already: two trails under one id would
// interleave.
func (c *call) openTrail() bool {
	id := c.in.Envelope.GetRequestId()
	if c.requestID == id {
		return true
	}
	if !c.p.reserve(c.ctx, id, c.now) {
		return false
	}
	c.requestID = id
	return true
}

// refuseOpen blocks a call whose request id has an open trail, writing
// nothing: the only trail it could write on is another call's.
func (c *call) refuseOpen() Disposition {
	c.decide(verdictIndeterminate, codeInvalidFieldValue)
	c.p.counts.blocked(codeInvalidFieldValue)
	return Disposition{Action: core.Block, Decision: c.decision}
}

// record appends event and reports whether the call may go on writing. A
// refused append blocks a material call, a call on a held trail and, without
// the risk setting, a read; under AllowReadsUnrecorded any other read goes on
// unrecorded.
func (c *call) record(event *controlv1.Event) bool {
	if c.unrecorded {
		return true
	}
	gen := c.p.counts.generation()
	if err := c.p.sinkAppend(c.ctx, event); err != nil {
		c.p.counts.sinkFailed(false)
		if c.material || c.held || !c.p.cfg.AllowReadsUnrecorded {
			return false
		}
		c.unrecorded = true
		c.p.counts.add(func(s *Stats) *uint64 { return &s.ReadsUnrecorded })
		return true
	}
	c.p.counts.appended(gen)
	return true
}

// blockUnrecorded is the block for a record the sink would not take: the one
// record that could not be written is the record of this block, so none is
// attempted. A held trail it leaves open keeps its request id reserved, and
// its journal entry where it has one, so no later call writes a second trail
// under that id or forgets that entry at its Close.
func (c *call) blockUnrecorded() Disposition {
	c.decide(verdictIndeterminate, codeEvidenceUnavailable)
	c.p.counts.blocked(codeEvidenceUnavailable)
	if c.held {
		c.p.counts.leftOpen()
	} else {
		c.close()
	}
	return Disposition{Action: core.Block, Decision: c.decision}
}

// block writes ACTION_BLOCKED with the decision the block carries, the
// kernel's or the plane's own, answers it, and reports whether the record is
// on the trail. A refused record the call may not go on without leaves the
// trail open, so the answer is blockUnrecorded's.
func (c *call) block() (Disposition, bool) {
	if !c.record(c.trail.Blocked(c.decision)) {
		return c.blockUnrecorded(), false
	}
	c.p.counts.blocked(firstCode(c.decision))
	c.close()
	return Disposition{Action: core.Block, Decision: c.decision}, !c.unrecorded
}

// agentGone reports whether the agent gave up on this call, which then spends
// no approval and is handed out to nobody.
func (c *call) agentGone() bool { return c.agent != nil && c.agent.Err() != nil }

// close ends the trail this call owns.
func (c *call) close() {
	if c.requestID != "" {
		c.p.release(c.requestID)
		c.requestID = ""
	}
}

// start writes ACTION_STARTED on trail with a fresh execution id, keeps the
// execution for Close and hands out what to send. One refusedBeforeStart
// refuses, or one the pipeline cannot name, keep or raise its run's state for,
// is blocked before it is recorded as started; the block closes the trail, so
// a resumed hold's entry is forgotten there, as Close would. One that lapsed
// while ACTION_STARTED was appended is aborted instead of handed out.
func (c *call) start(trail *evidence.Builder) Disposition {
	requestID := c.requestID
	if c.refusedBeforeStart() {
		return c.blockStart(trail, requestID)
	}
	handle, executionID := c.decision.GetDecisionId(), c.p.cfg.NewID()
	ex := &execution{
		trail: trail, requestID: requestID, executionID: executionID,
		envelope: c.env, digest: c.actionDigest, runID: c.flow.openedID(), unrecorded: c.unrecorded,
	}
	if executionID == "" || !c.p.keep(handle, ex) {
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.blockStart(trail, requestID)
	}
	ok, wrote := c.raise()
	if !ok {
		c.p.drop(handle)
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
		return c.blockStart(trail, requestID)
	}
	// A raise can wait on its root's lock; a pause or stop published while it
	// waited covers the call before it is recorded as started.
	if wrote && c.refusedBeforeStart() {
		c.p.drop(handle)
		return c.blockStart(trail, requestID)
	}
	if !c.record(trail.Started(executionID)) {
		c.p.drop(handle)
		return c.blockUnrecorded()
	}
	if verdict, code, lapsed := c.lapsedWhileStarting(); lapsed {
		c.p.drop(handle)
		return c.lapsedAfterStart(trail, ex, verdict, code)
	}
	ex.unrecorded = c.unrecorded
	c.p.took(c.flow, c.in.ResultTrust, c.in.ResultSensitivity)
	c.requestID = ""
	c.p.counts.add(func(s *Stats) *uint64 { return &s.Executed })
	if c.staleSeen {
		c.p.counts.add(func(s *Stats) *uint64 { return &s.StaleHandedOut })
	}
	return Disposition{
		Action:           c.action,
		Decision:         c.decision,
		AuthorizedArgs:   c.args,
		AuthorizedDigest: c.digest,
		ExecutionID:      executionID,
		Obligations:      c.rest,
		Unrecorded:       ex.unrecorded,
		handle:           handle,
	}
}

// blockStart writes the block start decided on trail and forgets the journal
// entry of requestID once the trail is closed.
func (c *call) blockStart(trail *evidence.Builder, requestID string) Disposition {
	c.trail = trail
	d, closed := c.block()
	if closed {
		c.p.journalForget(c.ctx, requestID)
	}
	return d
}

func firstCode(d *controlv1.Decision) string {
	if codes := d.GetReasonCodes(); len(codes) > 0 {
		return codes[0]
	}
	return ""
}
