package gateway

import (
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/policy"
)

// refusedBeforeStart decides the block of an execution that may not start: a
// pause or stop state taken just now covers it or cannot vouch for it, its
// approval expired, its opened run did, the policy its decision stood on is
// no longer current, or the agent of a call that resumes nothing gave up on
// it. A spent approval stays spent: it was consumed, and a spent approval
// is never handed back to be used again.
func (c *call) refusedBeforeStart() bool {
	switch {
	case c.blockedNow():
	case c.held && lapsedBy(c.now, c.floor, c.approvalExpires):
		c.decide(verdictDeny, codeApprovalExpired)
	case c.runLapsed():
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
	case c.policyWithheld(c.basis):
	case !c.held && c.agentGone():
		// A resumed call spent its approval already; it is handed out, and
		// the adapter aborts what it cannot send.
		c.decide(verdictIndeterminate, codeEvidenceUnavailable)
	default:
		return false
	}
	return true
}

// lapsedWhileStarting takes the installed policy and reads the clock once
// more after ACTION_STARTED, whose append can outlast the approval, the run
// or the policy, stale or replaced meanwhile, and names the block of one that
// lapsed.
func (c *call) lapsedWhileStarting() (controlv1.Verdict, string, bool) {
	installed := c.p.cfg.Policy.Current()
	now := c.p.cfg.Clock()
	switch {
	case c.held && lapsedBy(now, c.floor, c.approvalExpires):
		c.now = now
		return verdictDeny, codeApprovalExpired, true
	case c.flow.kind == flowOpened && lapsedBy(now, c.floor, c.flow.opened.Expires):
		c.now = now
		return verdictIndeterminate, codeEvidenceUnavailable, true
	case c.withholds(c.basis, installed, now):
		c.now = now
		return verdictIndeterminate, codePolicyStale, true
	}
	return 0, "", false
}

// policyWithheld blocks the call, INDETERMINATE with POLICY_STALE, when the
// policy its decision stood on, judged again at the call's last reading
// against the policy it took then, no longer stands (ADR-0055), and reports
// so.
func (c *call) policyWithheld(b core.Basis) bool {
	if !c.withholds(b, c.installed, c.now) {
		return false
	}
	c.decide(verdictIndeterminate, codePolicyStale)
	return true
}

// withholds reports whether the kernel finds basis b no longer current at
// now against installed. OBSERVE enforces no policy (ADR-0013), so there it
// only notes a call whose policy let it run when decided and no longer does,
// which start counts if it hands the call out.
func (c *call) withholds(b core.Basis, installed *policy.Snapshot, now time.Time) bool {
	if c.p.kernel.Recheck(b, installed, now, c.floor) == core.StandingCurrent {
		return false
	}
	if c.p.cfg.Mode == modeObserve {
		c.staleSeen = c.staleSeen || b.Stood() && c.kernelLetRun()
		return false
	}
	return true
}

// kernelLetRun reports whether the kernel's decision let the call run as
// decided, as ENFORCE would have: executed, with or without obligations, a
// read the fail-closed table opened among them. A call it blocked or held is
// one ENFORCE never hands out, stale or not.
func (c *call) kernelLetRun() bool {
	return c.kernelAction == core.Execute || c.kernelAction == core.ExecuteWithObligations
}

// lapsedAfterStart closes the trail of an execution whose approval or opened
// run expired, or whose policy stopped standing, while its ACTION_STARTED was
// appended, the way an adapter aborts what it did not send: ACTION_FAILED with
// a BLOCKED result naming code, which is APPROVAL_EXPIRED, EVIDENCE_UNAVAILABLE
// or POLICY_STALE, and no executed digest. The call is blocked with a decision of the plane's own,
// which no record carries, because the chain has no place for a decision
// after ACTION_STARTED. A record the sink refuses leaves the trail open with
// its request id and its journal entry, as blockUnrecorded does.
func (c *call) lapsedAfterStart(trail *evidence.Builder, ex *execution, verdict controlv1.Verdict, code string) Disposition {
	aborted := ex.stamp(nil)
	aborted.Status = resultBlocked
	aborted.ToolProtocolStatus = code
	aborted.EndedAt = timestampOf(c.now)
	if !c.record(trail.Failed(aborted)) {
		return c.blockUnrecorded()
	}
	c.decide(verdict, code)
	c.p.counts.blocked(code)
	requestID := c.requestID
	c.close()
	c.p.journalForget(c.ctx, requestID)
	return Disposition{Action: core.Block, Decision: c.decision}
}

// reliedOn raises the call's floor to at. Every clock reading the call takes
// raises it, one after 9999 included, so a clock that jumps ahead and comes
// back vouches for nothing later in the call.
func (c *call) reliedOn(at time.Time) {
	if at.After(c.floor) {
		c.floor = at
	}
}

// reliedOnDecision raises the call's floor to the decision's reading and to
// the latest time the plane verified for snap.
func (c *call) reliedOnDecision(d *controlv1.Decision, snap *policy.Snapshot) {
	if at := d.GetDecidedAt(); at != nil {
		c.reliedOn(at.AsTime())
	}
	c.reliedOn(snap.NotBefore())
}

// lapsedBy reports whether an expiry is reached at now, or cannot be told
// unreached.
func lapsedBy(now, floor, expires time.Time) bool {
	return unvouched(now, floor) || !now.Before(expires)
}

// unvouched reports whether now proves nothing unexpired: a reading the
// kernel would refuse to decide at, or one behind floor, an instant the call
// already relied on.
func unvouched(now, floor time.Time) bool {
	return !policy.UsableTime(now) || now.Before(floor)
}
