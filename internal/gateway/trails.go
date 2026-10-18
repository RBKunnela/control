package gateway

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
)

// maxSweep bounds the holds one call closes at their expiry, so the sweep
// costs the call that runs it a fixed amount of work at most.
const maxSweep = 8

// heldRequest is what the pipeline itself keeps about a request it holds for an
// approval: what hold minted, the trail it stands on and the binding it was
// held under. The store answers about it and never defines it, so a retry
// resumes only what this record holds and the store's answer is checked field
// by field against it (ADR-0013).
type heldRequest struct {
	ids      evidence.IDs
	approval *controlv1.Approval
	envelope *controlv1.ActionEnvelope
	decision *controlv1.Decision
	// basis is what decision stood on, judged again before the consume.
	basis       core.Basis
	binding     approval.Binding
	lastEventID string
	expires     time.Time
	// run is the opened run the request is held under, empty when the plane
	// vouched for none.
	run string
}

// keep records an execution under its handle until Close or Abort. It refuses
// an empty handle, one already open, which would close two trails as one, and
// an execution past the bound on open ones.
func (p *Pipeline) keep(handle string, ex *execution) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, taken := p.open[handle]; taken || handle == "" || len(p.open) >= p.cfg.MaxOpen {
		return false
	}
	p.open[handle] = ex
	return true
}

// take removes and returns the execution under handle, or nil, so a trail
// closes once; its request id stops being open.
func (p *Pipeline) take(handle string) *execution {
	p.mu.Lock()
	defer p.mu.Unlock()
	ex := p.open[handle]
	if ex == nil {
		return nil
	}
	delete(p.open, handle)
	delete(p.trails, ex.requestID)
	return ex
}

// drop removes the execution under handle and leaves its request id to the
// call that kept it.
func (p *Pipeline) drop(handle string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.open, handle)
}

// reserve opens the trail of requestID, or reports that one is open already.
func (p *Pipeline) reserve(ctx context.Context, requestID string, now time.Time) bool {
	// The holds swept are other requests', so this caller's cancellation must
	// not leave their trails open.
	p.sweep(context.WithoutCancel(ctx), now)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, open := p.trails[requestID]; open {
		return false
	}
	p.trails[requestID] = openTrail{}
	return true
}

// holdOpen marks the open trail of h's request held until h expires and keeps
// the record a retry resumes from, or reports that MaxHeld requests are held
// already, or MaxHeldPerRun under h's opened run and unexpired when h was
// requested. A hold the sweep has not closed yet still counts against
// MaxHeld, since it keeps its trail and its record until it is closed.
func (p *Pipeline) holdOpen(h *heldRequest) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := h.approval.GetRequestedAt().AsTime()
	held, ofRun := 0, 0
	for _, t := range p.trails {
		if t.held != nil {
			held++
			if h.run != "" && t.held.run == h.run && now.Before(t.held.expires) {
				ofRun++
			}
		}
	}
	if held >= p.cfg.MaxHeld || ofRun >= p.cfg.MaxHeldPerRun {
		return false
	}
	p.trails[h.ids.RequestID] = openTrail{held: h}
	return true
}

// heldUnder returns the pipeline's own records of the requests it holds under
// binding and unexpired at now, by request id, as one read.
func (p *Pipeline) heldUnder(binding approval.Binding, now time.Time) map[string]*heldRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	holds := make(map[string]*heldRequest)
	for id, t := range p.trails {
		if t.held != nil && t.held.binding == binding && now.Before(t.held.expires) {
			holds[id] = t.held
		}
	}
	return holds
}

// takeHold flips the trail of h from held to open and unheld in one step and
// reports whether h was still the hold on it: a trail the sweep or another
// call took in the meantime is theirs to write on and to release.
func (p *Pipeline) takeHold(h *heldRequest) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, open := p.trails[h.ids.RequestID]; !open || t.held != h {
		return false
	}
	p.trails[h.ids.RequestID] = openTrail{}
	return true
}

// release closes the trail of requestID.
func (p *Pipeline) release(requestID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.trails, requestID)
}

// sweep closes the trails of holds that expired at now and frees their request
// ids, at most maxSweep of them. A dropped hold stops being held under the
// lock and its id stays reserved until its records are written, so nothing
// writes under that id in between.
func (p *Pipeline) sweep(ctx context.Context, now time.Time) {
	p.mu.Lock()
	dropped := make([]*heldRequest, 0, maxSweep)
	for id, t := range p.trails {
		if len(dropped) == maxSweep {
			break
		}
		if t.held != nil && !now.Before(t.held.expires) {
			p.trails[id] = openTrail{}
			dropped = append(dropped, t.held)
		}
	}
	p.mu.Unlock()
	for _, h := range dropped {
		if p.closeExpired(ctx, h, now) {
			p.release(h.ids.RequestID)
		} else {
			p.counts.leftOpen()
		}
	}
}

// closeExpired ends the trail of a hold nobody answered: APPROVAL_EXPIRED,
// then the plane's ACTION_BLOCKED about the held request, since the chain lets
// nothing else follow a request for approval. It reports whether both were
// written; a trail that could not be closed keeps its request id reserved,
// rather than letting a later call write a second trail into it. The journal
// entry leaves held before the first append and is forgotten after the last,
// so no plane ever closes this trail twice.
func (p *Pipeline) closeExpired(ctx context.Context, h *heldRequest, now time.Time) bool {
	if !p.journalMark(ctx, h.ids.RequestID, HoldClosing) {
		return false
	}
	trail, err := evidence.Resume(
		h.ids, p.cfg.Mode, func() time.Time { return now }, p.cfg.NewID,
		evidence.Position{LastEventID: h.lastEventID},
	)
	if err != nil {
		return false
	}
	expired := proto.CloneOf(h.approval)
	expired.State = approvalExpired
	if !p.append(ctx, trail.ApprovalExpired(expired)) {
		return false
	}
	if !p.append(ctx, trail.Blocked(p.mint(h.decision, now, verdictDeny, codeApprovalExpired))) {
		return false
	}
	p.counts.blocked(codeApprovalExpired)
	p.journalForget(ctx, h.ids.RequestID)
	return true
}

// append writes event and reports whether the sink took it.
func (p *Pipeline) append(ctx context.Context, event *controlv1.Event) bool {
	gen := p.counts.generation()
	if err := p.sinkAppend(ctx, event); err != nil {
		p.counts.sinkFailed(false)
		return false
	}
	p.counts.appended(gen)
	return true
}

// sinkAppend is the one way an event reaches the sink. Content capture has no
// setting and is off (ADR-0004), so the previews an adapter put on the event,
// and the profiles naming them, are not recorded.
func (p *Pipeline) sinkAppend(ctx context.Context, event *controlv1.Event) error {
	uncapture(event)
	return p.cfg.Sink.Append(ctx, event)
}

// uncapture clears the previews on event in place. Every event reaching it
// was built for this append around the Builder's own copy of its payload, so
// no message an adapter holds changes. Neither preview is a digest input.
func uncapture(event *controlv1.Event) {
	if a := event.GetProposed().GetArguments(); a != nil {
		a.RedactedPreview, a.RedactionProfile = "", ""
	}
	if r := event.GetResult(); r != nil {
		r.RedactedResultPreview, r.RedactionProfile = "", ""
	}
}

// newTrail builds the trail from the envelope's identifiers, timed at this
// call's clock reading.
func (c *call) newTrail() (*evidence.Builder, error) {
	return evidence.NewBuilder(c.trailIDs(), c.p.cfg.Mode, func() time.Time { return c.now }, c.p.cfg.NewID)
}

// trailIDs names this call's trail from the envelope's identifiers and the
// run the pipeline minted, never the run id the producer sent.
func (c *call) trailIDs() evidence.IDs {
	env := c.in.Envelope
	return evidence.IDs{
		RequestID: env.GetRequestId(),
		RunID:     c.flow.runID(),
		ProjectID: env.GetProjectId(),
		TenantID:  env.GetTenantId(),
	}
}
