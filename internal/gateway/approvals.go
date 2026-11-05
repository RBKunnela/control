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
}

// ApprovalStore holds requests awaiting approval and the projections an
// approver lists. Answers come from the ApprovalAuthority, never from here.
//
// What an implementation owes the plane: Find hands back the records it still
// keeps, which pair a retry with its hold and show a record of a hold the
// plane no longer keeps; the plane trusts no part of one. A store says
// nothing about what became of a record: whether an approval was
// spent or given up is the plane's Ledger's to say, and no store can write
// it. Approval and Binding are the two fields the plane cannot do without;
// Envelope, Decision and LastEventID may come back empty, since the plane
// compares every answer with its own record of what it held and takes the
// trail's position from there (ADR-0016).
type ApprovalStore interface {
	// Hold records a request awaiting approval under its binding at now. It
	// refuses a zero now with ErrZeroTime, an incomplete Held or one whose
	// approval is not the pending one the plane mints with ErrInvalidHold, and
	// a request id already held under the binding with ErrAlreadyHeld.
	Hold(ctx context.Context, held Held, now time.Time) error
	// Find returns every request held under binding and not expired at now,
	// held or answered, oldest first, or ErrNoApproval when there is none.
	// Two requests that differ only in a field the digest leaves out share a
	// binding, and the caller picks the one the retry equals. A record the
	// store keeps but cannot speak for comes back with only what identifies
	// it and an unspecified state, and refuses no other record. It refuses a
	// zero now with ErrZeroTime.
	Find(ctx context.Context, binding approval.Binding, now time.Time) ([]Held, error)
	// Release forgets the plane's own record of approvalID, held for
	// requestID under binding, once the plane settled it in its ledger, so no
	// approver is offered an answer nothing will read. It answers
	// ErrNoApproval when no such record is kept, and removes nothing filed
	// under another request or binding.
	Release(ctx context.Context, binding approval.Binding, requestID, approvalID string) error
}

// MemoryApprovals is an ApprovalStore in process memory, and the approval
// authority of the directory kind over the same records. The zero value is
// ready to use and approves nothing. Answer is how a test, or an approver in
// the same process, decides a held approval; what it records is a claim.
// Hold and Find drop every record whose approval expired, so what it keeps is
// bounded by what is held within one approval lifetime.
type MemoryApprovals struct {
	mu   sync.Mutex
	held map[approval.Binding][]*heldRecord
}

var (
	_ ApprovalStore     = (*MemoryApprovals)(nil)
	_ ApprovalAuthority = (*MemoryApprovals)(nil)
)

type heldRecord struct {
	held Held
}

// Hold records held under its binding.
func (m *MemoryApprovals) Hold(ctx context.Context, held Held, now time.Time) error {
	if now.IsZero() {
		return ErrZeroTime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !resumable(held) {
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
	m.held[held.Binding] = append(m.held[held.Binding], &heldRecord{held: cloneHeld(held)})
	return nil
}

// resumable reports whether held is a hold the plane could have minted: a
// pending approval with an approval id, a request id, a requested time and an
// expiry and no answer, the binding, the envelope and the decision. An
// approval that already carries an answer is one the plane would be granting
// itself.
func resumable(held Held) bool {
	return mintedPending(held.Approval) && held.Binding != "" && held.Envelope != nil && held.Decision != nil
}

// mintedPending reports whether a is an approval the plane could have
// minted: pending, with an approval id, a request id, a requested time and an
// expiry, and no answer.
func mintedPending(a *controlv1.Approval) bool {
	return a != nil && a.GetApprovalId() != "" && a.GetRequestId() != "" &&
		a.GetRequestedAt() != nil && a.GetExpiresAt() != nil &&
		a.GetState() == controlv1.ApprovalState_APPROVAL_STATE_PENDING && a.GetApproverId() == "" && a.GetDecidedAt() == nil
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
		out = append(out, cloneHeld(r.held))
	}
	return out, nil
}

// Answer decides the held approval approvalID: APPROVED with an approver, or
// REJECTED, at decidedAt. It refuses an unknown id with ErrNoApproval, any
// other answer or an approver that claims the reserved authn: prefix with
// ErrApprovalAnswer, and an approval answered already with
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
			if r.held.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
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

// Answers returns, as claims, a clone of every record kept under approvalID,
// expired ones included: the plane judges the window itself.
func (m *MemoryApprovals) Answers(ctx context.Context, approvalID string) AnswerBatch {
	if ctx.Err() != nil {
		return AnswerBatch{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := AnswerBatch{State: BatchComplete}
	for _, records := range m.held {
		for _, r := range records {
			if r.held.Approval.GetApprovalId() == approvalID {
				out.Claimed = append(out.Claimed, proto.CloneOf(r.held.Approval))
			}
		}
	}
	return out
}

// Status says the records are claims kept in this process, always readable.
func (m *MemoryApprovals) Status(context.Context) AuthorityStatus {
	return AuthorityStatus{Kind: AuthorityDirectory, Health: AuthorityUsable}
}

// Release drops the record of approvalID held for requestID under binding.
func (m *MemoryApprovals) Release(ctx context.Context, binding approval.Binding, requestID, approvalID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.find(binding, requestID); r == nil || approvalID == "" || r.held.Approval.GetApprovalId() != approvalID {
		return ErrNoApproval
	}
	m.keep(binding, func(r *heldRecord) bool { return r.held.Approval.GetRequestId() != requestID })
	return nil
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

// dropExpired forgets every record under binding whose approval is expired at
// now. mu is held.
func (m *MemoryApprovals) dropExpired(binding approval.Binding, now time.Time) {
	m.keep(binding, func(r *heldRecord) bool { return !approval.Expired(r.held.Approval, now) })
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
	}
}
