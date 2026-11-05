package approvals

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
)

// Find returns every record under binding that has not expired at now, held
// or answered, oldest first, or ErrNoApproval when there is none. A record is
// a claim: the plane judges every answer itself, and what became of one after
// it was answered is kept in the plane's own ledger, never here.
//
// A record that will not decode, and a directory past its bound, refuse the
// whole call. What the caller loses is a resume; what it is spared is an
// answer about a directory it did not read. A record whose approver id the
// claim rule refuses is the exception: Find names no approval, so it returns
// such a record as one the store cannot speak for, with what identifies it and
// state APPROVAL_STATE_UNSPECIFIED, which a plane closes as unknown.
func (p *Plane) Find(ctx context.Context, binding approval.Binding, now time.Time) ([]Record, error) {
	if err := p.beginAt(ctx, now); err != nil {
		return nil, err
	}
	defer p.s.mu.Unlock()
	all, err := p.matching(binding)
	if err != nil {
		return nil, err
	}
	var found []Record
	for _, rec := range all {
		if !approval.Expired(rec.Approval, now) {
			found = append(found, rec)
		}
	}
	if len(found) == 0 {
		return nil, ErrNoApproval
	}
	slices.SortFunc(found, func(a, b Record) int {
		if c := a.Approval.GetRequestedAt().AsTime().Compare(b.Approval.GetRequestedAt().AsTime()); c != 0 {
			return c
		}
		return strings.Compare(a.ApprovalID, b.ApprovalID)
	})
	return found, nil
}

// matching returns the records filed under binding, expired ones included:
// expiry is the caller's to apply. A record whose approver id the claim rule
// refuses comes back as unknownRecord makes it, so it blocks no lookup of
// another request or another approval. mu is held.
func (p *Plane) matching(binding approval.Binding) ([]Record, error) {
	l, err := p.s.scan()
	if err != nil {
		return nil, err
	}
	if !l.complete {
		return nil, fmt.Errorf("%w: limit %d", ErrTooManyRecords, p.s.opts.maxRecords)
	}
	var found []Record
	for _, id := range l.ids {
		rec, _, refusal, err := p.s.readListed(id, l.state[id])
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		switch {
		case rec.Binding != binding:
		case refusal == nil:
			found = append(found, rec)
		default:
			found = append(found, unknownRecord(rec))
		}
	}
	return found, nil
}

// unknownRecord is a record whose approver id the claim rule refuses, as Find
// returns it: what identifies it and its window, and nothing it says about
// its answer. The store proves nothing from a record it refuses, so its
// approval is unspecified.
func unknownRecord(rec Record) Record {
	a := rec.Approval
	return Record{
		SchemaVersion: rec.SchemaVersion,
		ApprovalID:    rec.ApprovalID,
		RequestID:     rec.RequestID,
		Binding:       rec.Binding,
		Approval: &controlv1.Approval{
			ApprovalId:         a.GetApprovalId(),
			RequestId:          a.GetRequestId(),
			ActionDigest:       a.GetActionDigest(),
			PolicyBundleDigest: a.GetPolicyBundleDigest(),
			State:              controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED,
			RequestedAt:        proto.CloneOf(a.GetRequestedAt()),
			ExpiresAt:          proto.CloneOf(a.GetExpiresAt()),
		},
	}
}
