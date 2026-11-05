package approvals

import (
	"context"
	"errors"
	"io/fs"
)

// Claim returns the record filed under approvalID as it stands, held or
// answered, expired or not: the plane judges the window and every field
// itself, and an approver id on it is a claim. A record whose approver id the
// claim rule refuses comes back as Find returns it, in no state, and any
// other record that will not decode refuses the call. It answers
// ErrNoApproval when no record is filed under approvalID.
func (p *Plane) Claim(ctx context.Context, approvalID string) (Record, error) {
	if err := checkApprovalID(approvalID); err != nil {
		return Record{}, err
	}
	if err := p.begin(ctx); err != nil {
		return Record{}, err
	}
	defer p.s.mu.Unlock()
	rec, _, err := p.s.readRecord(approvalID, stateAnswered)
	if own, refused := refusedOnlyItself(err); refused {
		return unknownRecord(own), nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return Record{}, ErrNoApproval
	}
	return rec, err
}
