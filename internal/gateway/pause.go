package gateway

import (
	"context"
	"errors"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/pkg/contract"
)

// planeState is what the plane's own causes to block a call are a function
// of: the call, the mode, the pause and stop snapshots the call took, the
// halts, and whether the call's run is one the plane can vouch for.
type planeState struct {
	mode         controlv1.EnforcementMode
	material     bool
	unclassified bool
	paused       bool
	pauseUnknown bool
	// stopped: an active stop names the opened run the plane vouched for,
	// in its tenant (ADR-0046).
	stopped      bool
	stopUnknown  bool
	sinkHalt     bool
	mismatchHalt bool
	// runHalt: a caller reported bytes that were not the authorized ones for
	// an execution of the call's opened run (ADR-0051).
	runHalt bool
	// runRefused: the call needs an opened run the plane cannot vouch for or
	// read, or a local run the id source could not name (ADR-0034).
	runRefused bool
}

// cause is one reason the plane blocks a call whatever the policy decides,
// with the verdict it carries.
type cause struct {
	code    string
	verdict controlv1.Verdict
}

// planeCauses names, in the order a decision lists them, every cause the
// plane has to block a call whatever the policy says: the DENY causes first,
// then the INDETERMINATE ones (ADR-0019, ADR-0046). None means the policy
// decides.
func planeCauses(s planeState) []cause {
	var out []cause
	for _, c := range []struct {
		on bool
		cause
	}{
		{s.paused, cause{codePaused, verdictDeny}},
		{s.stopped, cause{codeRunStopped, verdictDeny}},
		{s.material && (s.mismatchHalt || s.runHalt), cause{codeExecutedArgsMismatch, verdictDeny}},
		{s.material && s.mode == modeLockdown, cause{codeLockdown, verdictDeny}},
		{s.pauseUnknown, cause{codePauseStateUnavailable, verdictIndeterminate}},
		{s.stopUnknown, cause{codeStopStateUnavailable, verdictIndeterminate}},
		{(s.material && s.sinkHalt) || s.runRefused, cause{codeEvidenceUnavailable, verdictIndeterminate}},
		{s.unclassified && s.mode != modeObserve, cause{codeActionUnclassified, verdictIndeterminate}},
	} {
		if c.on {
			out = append(out, c.cause)
		}
	}
	return out
}

// verdictOf is DENY when any cause denies, and INDETERMINATE otherwise.
func verdictOf(causes []cause) controlv1.Verdict {
	for _, c := range causes {
		if c.verdict == verdictDeny {
			return verdictDeny
		}
	}
	return verdictIndeterminate
}

// newCall starts one admission under the pause and stop states and the
// clock as it takes them now.
func (p *Pipeline) newCall(ctx context.Context, a Admission) *call {
	c := &call{p: p, ctx: ctx, in: a}
	c.takeStates()
	return c
}

// takeStates takes the pause and stop states and the installed policy, and
// then reads the clock the call judges their age by. The other order would
// let a poll or a confirmation published between the two date a state ahead
// of the call and block it as unreadable. A disabled stop state served by a
// source other than StopsDisabled is one the plane cannot vouch for.
func (c *call) takeStates() {
	snap := c.p.cfg.Pause.Current()
	stops := c.p.cfg.Stops.Current()
	c.installed = c.p.cfg.Policy.Current()
	c.now = c.p.cfg.Clock()
	c.reliedOn(c.now)
	c.pause = snap.At(c.now)
	if _, disabled := c.p.cfg.Stops.(disabledStops); stops.State() == reaction.Disabled && !disabled {
		stops = reaction.Snapshot{}
	}
	c.stops = stops
}

// blockedNow takes the pause and stop states and the clock again right
// before an irreversible step, a resume consuming its approval or an
// execution handed out, since a store or a sink that syncs can outlast a
// snapshot, and a halt can be raised meanwhile. A state that covers the call
// or cannot be read, or a halt that covers a material one, blocks it there,
// listing every cause the plane names now, and reports so.
func (c *call) blockedNow() bool {
	c.takeStates()
	state := c.planeState()
	halted := state.material && (state.sinkHalt || state.mismatchHalt || state.runHalt)
	if !halted && !state.paused && !state.pauseUnknown && !state.stopped && !state.stopUnknown {
		return false
	}
	c.causes = planeCauses(state)
	c.blockOnCauses()
	return true
}

// planeState is this call's state as the plane sees it now: the halts as
// they stand, the pause and stop states the call took last and the run it
// took when it started. A stop matches the opened run as the listener
// resolved it and the plane checked it against the envelope, never a run id
// the agent sent or a local run the plane minted: a call with no opened run
// asks about the empty run id, which no line of a list can name.
func (c *call) planeState() planeState {
	sink, mismatch, runHalt := c.p.counts.halts(c.flow.openedID())
	action := c.in.Envelope.GetAction()
	state := c.pause.State()
	var runID, tenantID string
	if run := c.flow.opened; run != nil {
		runID, tenantID = run.ID, run.Who.TenantID
	}
	stops, _ := c.stops.ForCall(runID, tenantID, c.now, c.floor)
	return planeState{
		mode:         c.p.cfg.Mode,
		material:     contract.IsMaterial(action.GetEffect()),
		unclassified: errors.Is(c.in.Refusal, ErrUnclassified),
		paused:       state == pause.Paused && c.pause.Covers(action.GetKind(), action.GetProvider(), action.GetName()),
		pauseUnknown: state == pause.Unknown,
		stopped:      stops == reaction.Stopped,
		stopUnknown:  stops == reaction.Unknown,
		sinkHalt:     sink,
		mismatchHalt: mismatch,
		runHalt:      runHalt,
		runRefused:   c.flow.kind == flowUnnamed || c.flow.kind == flowUnavailable,
	}
}
