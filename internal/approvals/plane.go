package approvals

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
)

// Plane is the plane's handle on an approvals directory. It has no method
// that answers an approval: an approval this process could grant itself would
// make the directory decoration. It holds the directory's exclusive lock from
// OpenPlane to Close, so two planes cannot serve one directory.
//
// The zero value is not a store. Every method on it answers ErrClosed, which
// is what a composite literal of this type from another package is worth.
type Plane struct {
	s *store
}

// OpenPlane opens dir for the plane and takes its exclusive lock. It refuses a
// directory another plane holds with ErrLocked, a group- or world-writable one
// with ErrPermissions, one another account owns with ErrOwner, and one that is
// not an approvals store with ErrNotAStore rather than reading it as an empty
// one. An empty directory becomes a store.
//
// A directory held for an instant is waited for rather than refused: asking
// whether a plane holds the lock means taking it, so anything that asks holds
// it briefly. A plane that is genuinely running holds it for its whole life,
// and the refusal it earns is only delayed.
func OpenPlane(dir string, opts ...Option) (*Plane, error) {
	s, err := openStore(dir, true, opts)
	if err != nil {
		return nil, err
	}
	return &Plane{s: s}, nil
}

// Close releases the directory's lock. A later call answers ErrClosed.
func (p *Plane) Close() error {
	if p == nil {
		return ErrClosed
	}
	return p.s.close()
}

// Hold is one request the plane holds for an approval. The record it becomes
// carries the approval, the binding and the request id, and nothing else: the
// envelope and the decision are read for the projection beside the record and
// are not stored, so a writer of the directory can neither choose what the
// plane records nor name a trail to write it into.
type Hold struct {
	// Approval is the pending approval the plane minted: its own id, the held
	// request's id, the two digests and the expiry.
	Approval *controlv1.Approval
	// Binding is what the approval is stored and compared against. It has to
	// be the binding the approval's two digests make.
	Binding approval.Binding
	// Envelope and Decision are rendered into the projection and are not part
	// of the record.
	Envelope *controlv1.ActionEnvelope
	Decision *controlv1.Decision
}

// Hold records a request awaiting approval under its binding at now. It
// refuses a zero now with ErrZeroTime, an incomplete or self-contradictory
// hold with ErrInvalidHold, a request already held under the binding or an
// approval id already used with ErrAlreadyHeld, and a directory at its bound
// with ErrTooManyRecords: a hold that cannot be recorded is refused, never
// taken and forgotten.
func (p *Plane) Hold(ctx context.Context, h Hold, now time.Time) error {
	if err := p.beginAt(ctx, now); err != nil {
		return err
	}
	defer p.s.mu.Unlock()
	rec, err := heldRecord(h, p.s.opts.maxApprovalWindow)
	if err != nil {
		return err
	}
	body, err := encodeRecord(rec, p.s.opts.maxRecordBytes, p.s.opts.maxApprovalWindow)
	if err != nil {
		return err
	}
	view, err := encodeView(ViewOf(h.Approval, h.Envelope, h.Decision))
	if err != nil {
		return err
	}
	if err := p.roomFor(rec, now); err != nil {
		return err
	}
	// A projection already there is left alone. It is not truth, and refusing
	// the hold over one would turn a crash between these two writes into a
	// request that can never be held again.
	if err := p.s.commit(rec.ApprovalID+viewSuffix, view); err != nil && !errors.Is(err, errExists) {
		return err
	}
	if err := p.s.commit(rec.ApprovalID+stateHeld.suffix(), body); err != nil {
		if errors.Is(err, errExists) {
			return fmt.Errorf("%w: approval %q", ErrAlreadyHeld, cause(rec.ApprovalID))
		}
		return errors.Join(err, p.s.remove(rec.ApprovalID+viewSuffix))
	}
	return nil
}

// heldRecord turns a hold into the record it is written as, and refuses a hold
// that is not the plane's own freshly minted one: an approval that already
// carries an answer is one the plane would be granting itself.
func heldRecord(h Hold, maxWindow time.Duration) (Record, error) {
	a := h.Approval
	switch {
	case a == nil:
		return Record{}, fmt.Errorf("%w: no approval", ErrInvalidHold)
	case h.Envelope == nil || h.Decision == nil:
		return Record{}, fmt.Errorf("%w: no envelope or no decision", ErrInvalidHold)
	case a.GetExpiresAt() == nil:
		return Record{}, fmt.Errorf("%w: an approval with no expiry is expired", ErrInvalidHold)
	case a.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING:
		return Record{}, fmt.Errorf("%w: a held approval is pending, not %s", ErrInvalidHold, a.GetState())
	case a.GetApproverId() != "" || a.GetDecidedAt() != nil:
		return Record{}, fmt.Errorf("%w: a held approval carries no answer", ErrInvalidHold)
	}
	rec := Record{
		SchemaVersion: SchemaVersion,
		ApprovalID:    a.GetApprovalId(),
		RequestID:     a.GetRequestId(),
		Binding:       h.Binding,
		Resolution:    ResolutionPending,
		Approval:      proto.CloneOf(a),
	}
	if err := rec.check(maxWindow); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// roomFor refuses a hold the directory has no room for, and one whose request
// or approval id is there already. The scan reads every record, so a record
// that will not decode refuses the hold rather than leaving it to be found by
// the retry that matters. A record whose approver id the claim rule refuses
// still says which request it holds, and is judged by that.
func (p *Plane) roomFor(rec Record, now time.Time) error {
	l, err := p.s.scan()
	if err != nil {
		return err
	}
	if !l.complete || len(l.ids) >= p.s.opts.maxRecords {
		return fmt.Errorf("%w: %d records, limit %d", ErrTooManyRecords, len(l.ids), p.s.opts.maxRecords)
	}
	for _, id := range l.ids {
		if id == rec.ApprovalID {
			return fmt.Errorf("%w: approval %q", ErrAlreadyHeld, cause(id))
		}
		other, _, err := p.s.readRecord(id, l.state[id])
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if own, refused := refusedOnlyItself(err); refused {
			other, err = own, nil
		}
		if err != nil {
			return err
		}
		if other.Binding == rec.Binding && other.RequestID == rec.RequestID && !expired(other.Approval, now) {
			return fmt.Errorf("%w: request %q", ErrAlreadyHeld, cause(rec.RequestID))
		}
	}
	return nil
}

// beginAt is begin for an operation that reads a clock. A zero reading would
// pass every expiry, so it is refused before anything is read.
func (p *Plane) beginAt(ctx context.Context, now time.Time) error {
	if p == nil {
		return ErrClosed
	}
	if err := p.s.usable(); err != nil {
		return err
	}
	if now.IsZero() {
		return ErrZeroTime
	}
	return p.begin(ctx)
}

// begin holds the store's lock for one operation. It refuses a closed handle,
// a cancelled context and a directory that is no longer the one opened before
// anything is read, and the caller unlocks.
func (p *Plane) begin(ctx context.Context) error {
	if p == nil {
		return ErrClosed
	}
	if err := p.s.usable(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.s.mu.Lock()
	if err := p.s.usable(); err != nil {
		p.s.mu.Unlock()
		return err
	}
	if err := p.s.judge(); err != nil {
		p.s.mu.Unlock()
		return err
	}
	return nil
}

// expired reports whether a is past its expiry at now. An approval with no
// expiry is expired: a record that never expires is one a bound cannot reach.
func expired(a *controlv1.Approval, now time.Time) bool {
	return a.GetExpiresAt() == nil || !now.Before(a.GetExpiresAt().AsTime())
}

// Prune forgets every record whose approval has expired at now, and its
// projection, and reports how many it forgot. Nothing else removes a record
// the plane did not consume: a directory left to grow refuses holds at its
// bound, which is a refusal an operator can see.
//
// A directory past its bound is read only as far as the bound. What that pass
// read is pruned, and ErrTooManyRecords beside the count says the sweep did
// not reach the rest.
//
// A record whose approver id the claim rule refuses is pruned like any other
// once it expires; every other record that will not decode stops the sweep.
func (p *Plane) Prune(ctx context.Context, now time.Time) (int, error) {
	if err := p.beginAt(ctx, now); err != nil {
		return 0, err
	}
	defer p.s.mu.Unlock()
	l, err := p.s.scan()
	if err != nil {
		return 0, err
	}
	pruned := 0
	for _, id := range l.ids {
		rec, _, err := p.s.readRecord(id, l.state[id])
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if own, refused := refusedOnlyItself(err); refused {
			rec, err = own, nil
		}
		if err != nil {
			return pruned, err
		}
		if !expired(rec.Approval, now) {
			continue
		}
		if err := p.s.drop(id); err != nil {
			return pruned, err
		}
		pruned++
	}
	if !l.complete {
		return pruned, fmt.Errorf("%w: limit %d, so the sweep read only the first %d records",
			ErrTooManyRecords, p.s.opts.maxRecords, len(l.ids))
	}
	return pruned, nil
}
