package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
)

// Held is a request the plane holds for an approval: not the connection, which
// was answered at once with the pending state, but the request itself, so a
// retry can resume it (ADR-0013). The retry is the same request when it
// matches the binding and equals the envelope on every field the digest
// leaves out. The pipeline keeps its own record of what it held and checks
// every answer about it against that record, so what a store returns here
// says which of its records are still there, never what was held.
type Held struct {
	// Approval carries the held request's request_id, the approval_id the
	// agent was given, the two digests, the state and the expiry.
	Approval *controlv1.Approval
	// Envelope is the held request's envelope.
	Envelope *controlv1.ActionEnvelope
	// Decision is the one the held trail's POLICY_DECIDED recorded; a retry
	// resumes the request only while the kernel still decides it so.
	Decision *controlv1.Decision
	// Binding is what the approval is stored and compared against.
	Binding approval.Binding
	// LastEventID is where the held trail stands, so the resumed request
	// continues it rather than starting another.
	LastEventID string
	// Resolution is what the store can prove became of this record's
	// approval. Its zero value is ResolutionUnspecified.
	Resolution Resolution
}

// Resolution is what became of a held request's approval, as far as the store
// that keeps the record can prove it.
//
// The zero value is the store saying it cannot tell, which is why this is not
// a bool: a bool's zero value reads as "not consumed", so a store that cannot
// answer would be indistinguishable from one answering that nothing used the
// record, and the unsafe side would be reached by default rather than on
// purpose (ADR-0016).
type Resolution int

const (
	// ResolutionUnspecified is a store that cannot say what became of the
	// record. It proves nothing, so the plane holds the call anew.
	ResolutionUnspecified Resolution = iota
	// ResolutionPending is a record nothing consumed and nobody gave up on.
	ResolutionPending
	// ResolutionConsumed is a record a plane spent on an execution of the
	// request it was held for. It is the only answer APPROVAL_ALREADY_USED
	// may rest on, and only Consume sets it.
	ResolutionConsumed
	// ResolutionNotResumed is a record a plane gave up on, because the
	// request it was granted for is gone. Nothing spent it and nothing will.
	ResolutionNotResumed
)

// ApprovalStore holds requests awaiting approval and consumes approvals
// exactly once. Every implementation approves nothing it was not told to,
// and its zero value approves nothing at all.
//
// What an implementation owes the plane: Find hands back the records it still
// keeps, each with the Resolution it can prove and ResolutionUnspecified
// wherever it cannot. ResolutionConsumed is set by Consume and by nothing
// else, and whoever answers an approval may not write it by any route the
// store offers: it is the plane's own proof that a record was spent, and it
// alone refuses a later identical call. Approval and Binding are the two
// fields the plane cannot do without; Envelope, Decision and LastEventID may
// come back empty, since the plane compares every answer with its own record
// of what it held and takes the trail's position from there (ADR-0016).
type ApprovalStore interface {
	// Hold records a request awaiting approval under its binding at now. It
	// refuses a zero now with ErrZeroTime, an incomplete Held with
	// ErrInvalidHold and a request id already held under the binding with
	// ErrAlreadyHeld. Held.Resolution is the store's to say, so Hold ignores
	// what the caller put there.
	Hold(ctx context.Context, held Held, now time.Time) error
	// Find returns every request held under binding and not expired at now,
	// oldest first, or ErrNoApproval when there is none. Two requests that
	// differ only in a field the digest leaves out share a binding, and the
	// caller picks the one the retry equals. It refuses a zero now with
	// ErrZeroTime.
	Find(ctx context.Context, binding approval.Binding, now time.Time) ([]Held, error)
	// Consume marks the approval of the held request consumed, as one
	// compare-and-swap, and returns it as decided. approvalID is the approval
	// the plane minted for that request and keeps in its own record of the
	// hold: a record filed under the same binding and request id carrying any
	// other approval id is not the plane's to spend, so it answers
	// ErrNoApproval and leaves that record exactly as it was. An empty
	// approvalID names no approval at all: it is refused, by whatever the
	// implementation calls that, and never read as any approval will do. It
	// answers ErrZeroTime for a zero now, ErrNoApproval when the request is
	// not held under the binding or its approval is not yet approved,
	// ErrApprovalConsumed when an earlier execution used it, ErrMultiUse for
	// a record marked multi-use, ErrApprovalExpired when now is at or past its
	// expiry, and ErrApprovalRejected beside the record it read when an
	// approver refused it. An answer dated before the request or after now is
	// never consumed. An expired or rejected record is dropped. A consumed
	// approval stays consumed when the upstream call then fails. The caller
	// checks what it returns and trusts none of it.
	Consume(ctx context.Context, binding approval.Binding, requestID, approvalID string, now time.Time) (*controlv1.Approval, error)
	// Resolve records that the request held as requestID under binding will
	// not be resumed: nothing spent its approval and nothing will, so a later
	// identical call is held anew rather than told that an action ran. It
	// grants nothing and spends nothing. It takes ResolutionNotResumed and
	// refuses every other resolution with ErrResolution, since only Consume
	// may mark a record spent; a zero now with ErrZeroTime, a request it does
	// not keep with ErrNoApproval, and a record already consumed with
	// ErrApprovalConsumed, because that record is proof of an execution and
	// nothing may write over it.
	Resolve(ctx context.Context, binding approval.Binding, requestID string, resolution Resolution, now time.Time) error
}

// MemoryApprovals is an ApprovalStore in process memory. The zero value is
// ready to use and approves nothing. Answer is how a test, or an approval
// provider in the same process, decides a held approval. Hold and Find drop
// every record whose approval expired, consumed or not, so what it keeps is
// bounded by what is held within one approval lifetime; a consumed record is
// kept until then, so the next identical call finds it used.
type MemoryApprovals struct {
	mu   sync.Mutex
	held map[approval.Binding][]*heldRecord
}

var _ ApprovalStore = (*MemoryApprovals)(nil)

type heldRecord struct {
	held       Held
	resolution Resolution
}

// Hold records held under its binding.
func (m *MemoryApprovals) Hold(ctx context.Context, held Held, now time.Time) error {
	if now.IsZero() {
		return ErrZeroTime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if held.Approval == nil || held.Approval.GetRequestId() == "" || held.Binding == "" || held.Envelope == nil || held.Decision == nil {
		return ErrInvalidHold
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for binding := range m.held {
		m.dropExpired(binding, now)
	}
	if m.find(held.Binding, held.Approval.GetRequestId()) != nil {
		return ErrAlreadyHeld
	}
	if m.held == nil {
		m.held = make(map[approval.Binding][]*heldRecord)
	}
	m.held[held.Binding] = append(m.held[held.Binding], &heldRecord{held: cloneHeld(held), resolution: ResolutionPending})
	return nil
}

// Find returns clones of what Hold recorded under binding, oldest first.
func (m *MemoryApprovals) Find(ctx context.Context, binding approval.Binding, now time.Time) ([]Held, error) {
	if now.IsZero() {
		return nil, ErrZeroTime
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropExpired(binding, now)
	records := m.held[binding]
	if len(records) == 0 {
		return nil, ErrNoApproval
	}
	out := make([]Held, 0, len(records))
	for _, r := range records {
		found := cloneHeld(r.held)
		found.Resolution = r.resolution
		out = append(out, found)
	}
	return out, nil
}

// Consume is the compare-and-swap: under the lock, the approved and unconsumed
// record the plane minted becomes consumed, and nothing else changes it. An
// answer dated outside its window answers ErrNoApproval, as the directory
// store answers one dated after now.
func (m *MemoryApprovals) Consume(ctx context.Context, binding approval.Binding, requestID, approvalID string, now time.Time) (*controlv1.Approval, error) {
	if now.IsZero() {
		return nil, ErrZeroTime
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.minted(binding, requestID, approvalID)
	if r == nil {
		return nil, ErrNoApproval
	}
	a := r.held.Approval
	switch {
	case r.resolution == ResolutionConsumed:
		return nil, ErrApprovalConsumed
	case r.resolution == ResolutionNotResumed:
		// The plane gave this record up, so nothing may still run on it.
		return nil, ErrNoApproval
	case a.GetMultiUse():
		return nil, ErrMultiUse
	case !unexpired(a, now):
		m.drop(binding, requestID)
		return nil, ErrApprovalExpired
	case !decidedWithin(a, a.GetRequestedAt().AsTime(), now):
		return nil, ErrNoApproval
	case a.GetState() == controlv1.ApprovalState_APPROVAL_STATE_REJECTED:
		m.drop(binding, requestID)
		return proto.CloneOf(a), ErrApprovalRejected
	case a.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED || a.GetApproverId() == "":
		return nil, ErrNoApproval
	}
	r.resolution = ResolutionConsumed
	return proto.CloneOf(a), nil
}

// Resolve records that requestID will not be resumed, and spends nothing.
func (m *MemoryApprovals) Resolve(ctx context.Context, binding approval.Binding, requestID string, resolution Resolution, now time.Time) error {
	if resolution != ResolutionNotResumed {
		return fmt.Errorf("%w: %d", ErrResolution, resolution)
	}
	if now.IsZero() {
		return ErrZeroTime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.find(binding, requestID)
	switch {
	case r == nil:
		return ErrNoApproval
	case r.resolution == ResolutionConsumed:
		return ErrApprovalConsumed
	}
	r.resolution = resolution
	return nil
}

// Answer decides the held approval approvalID: APPROVED with an approver, or
// REJECTED, at decidedAt. It refuses an unknown id with ErrNoApproval, any
// other answer or an approver that claims the reserved authn: prefix with
// ErrApprovalAnswer, and an approval answered or consumed already with
// ErrApprovalAnswered.
func (m *MemoryApprovals) Answer(approvalID string, state controlv1.ApprovalState, approverID, reason string, decidedAt time.Time) error {
	approved := state == controlv1.ApprovalState_APPROVAL_STATE_APPROVED && approverID != ""
	rejected := state == controlv1.ApprovalState_APPROVAL_STATE_REJECTED
	if !approved && !rejected {
		return fmt.Errorf("%w: got %s with approver %q", ErrApprovalAnswer, state, approverID)
	}
	if err := approval.CheckClaimedApproverID(approverID); err != nil {
		return fmt.Errorf("%w: %w", ErrApprovalAnswer, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, records := range m.held {
		for _, r := range records {
			if r.held.Approval.GetApprovalId() != approvalID {
				continue
			}
			if r.resolution != ResolutionPending || r.held.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
				return ErrApprovalAnswered
			}
			r.held.Approval.State = state
			r.held.Approval.ApproverId = approverID
			r.held.Approval.Reason = reason
			r.held.Approval.DecidedAt = timestampOf(decidedAt)
			return nil
		}
	}
	return ErrNoApproval
}

// minted returns the record of requestID under binding when approvalID is the
// approval the caller holds for it, and nil otherwise: a record filed under
// another approval id is one the plane never minted, and an empty approvalID
// matches nothing, so neither is ever spent. mu is held.
func (m *MemoryApprovals) minted(binding approval.Binding, requestID, approvalID string) *heldRecord {
	r := m.find(binding, requestID)
	if r == nil || approvalID == "" || r.held.Approval.GetApprovalId() != approvalID {
		return nil
	}
	return r
}

// find returns the record of requestID under binding, or nil. mu is held.
func (m *MemoryApprovals) find(binding approval.Binding, requestID string) *heldRecord {
	for _, r := range m.held[binding] {
		if r.held.Approval.GetRequestId() == requestID {
			return r
		}
	}
	return nil
}

// drop forgets the record of requestID under binding. mu is held.
func (m *MemoryApprovals) drop(binding approval.Binding, requestID string) {
	m.keep(binding, func(r *heldRecord) bool { return r.held.Approval.GetRequestId() != requestID })
}

// dropExpired forgets every record under binding whose approval is expired at
// now. mu is held.
func (m *MemoryApprovals) dropExpired(binding approval.Binding, now time.Time) {
	m.keep(binding, func(r *heldRecord) bool { return unexpired(r.held.Approval, now) })
}

// unexpired reports whether a expires after now. An approval with no expiry
// has expired: a record that never expires is one no bound reaches.
func unexpired(a *controlv1.Approval, now time.Time) bool {
	return a.GetExpiresAt() != nil && now.Before(a.GetExpiresAt().AsTime())
}

// keep leaves the records under binding that want keeps. mu is held.
func (m *MemoryApprovals) keep(binding approval.Binding, want func(*heldRecord) bool) {
	records := m.held[binding]
	kept := records[:0]
	for _, r := range records {
		if want(r) {
			kept = append(kept, r)
		}
	}
	clear(records[len(kept):])
	if len(kept) == 0 {
		delete(m.held, binding)
		return
	}
	m.held[binding] = kept
}

// cloneHeld deep-copies the messages, so neither the caller's later writes nor
// the store's reach the other side.
func cloneHeld(h Held) Held {
	return Held{
		Approval:    proto.CloneOf(h.Approval),
		Envelope:    proto.CloneOf(h.Envelope),
		Decision:    proto.CloneOf(h.Decision),
		Binding:     h.Binding,
		LastEventID: h.LastEventID,
		Resolution:  h.Resolution,
	}
}
