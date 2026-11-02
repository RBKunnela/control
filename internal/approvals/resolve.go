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

// Find returns every record under binding that has not expired at now, oldest
// first, or ErrNoApproval when there is none. Each carries the Resolution the
// store can prove.
//
// A consumed record comes back, with ResolutionConsumed, until it expires. It
// is the plane's own proof that an execution spent that approval, and the
// only way a caller can tell the next identical call from a first one; a
// caller that never saw it would hold the call anew and could never say that
// the action already ran.
//
// A record the plane resolved as not resumed does not come back. Nothing
// spent it and nothing will, so it proves nothing about an execution and the
// call is held anew — which is what a caller does with it anyway.
// MemoryApprovals returns such a record and its caller skips it; the two
// stores therefore decide alike, and differ only in a count of records the
// plane no longer holds.
//
// A record that will not decode, and a directory past its bound, refuse the
// whole call. What the caller loses is a resume; what it is spared is an
// answer about a directory it did not read. A record whose approver id the
// claim rule refuses is the exception: it refuses only a call about its own
// approval, which a plane closes as unknown. Find names no approval, so it
// returns such a record as one the store cannot speak for: what identifies
// it, state APPROVAL_STATE_UNSPECIFIED and ResolutionUnspecified.
func (p *Plane) Find(ctx context.Context, binding approval.Binding, now time.Time) ([]Record, error) {
	if err := p.beginAt(ctx, now); err != nil {
		return nil, err
	}
	defer p.s.mu.Unlock()
	all, err := p.matching(binding, "", "", forFind)
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

// forFind selects the states Find returns: everything but the records the
// plane gave up on.
func forFind(st state) bool { return st != stateNotResumed }

// unresolved selects the states nothing has resolved, which is what Consume
// may spend and Resolve may close.
func unresolved(st state) bool { return st <= stateAnswered }

// resolvedState selects the states a plane resolved a record into.
func resolvedState(st state) bool { return st > stateAnswered }

// matching returns the records under binding whose state want accepts,
// optionally narrowed to one request id and one approval id. Expiry is the
// caller's to apply: Find hides an expired record and Consume refuses it by
// name, and a store that hid it from both would answer "no approval" where an
// approval expired. mu is held.
//
// A record whose approver id the claim rule refuses refuses the call that
// names its approval id. With no approval id named it comes back as
// unknownRecord makes it, so it blocks no lookup of another request or
// another approval.
func (p *Plane) matching(binding approval.Binding, requestID, approvalID string, want func(state) bool) ([]Record, error) {
	l, err := p.s.scan()
	if err != nil {
		return nil, err
	}
	if !l.complete {
		return nil, fmt.Errorf("%w: limit %d", ErrTooManyRecords, p.s.opts.maxRecords)
	}
	var found []Record
	for _, id := range l.ids {
		rec, st, refusal, err := p.s.readListed(id, l.state[id])
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !listedUnder(rec, st, binding, requestID, approvalID, want) {
			continue
		}
		switch {
		case refusal == nil:
			found = append(found, rec)
		case approvalID == "":
			found = append(found, unknownRecord(rec))
		default:
			return nil, refusal
		}
	}
	return found, nil
}

// listedUnder reports whether a record in state st is one matching returns:
// filed under binding, for requestID and approvalID where each is named, in a
// state want accepts.
func listedUnder(rec Record, st state, binding approval.Binding, requestID, approvalID string, want func(state) bool) bool {
	return want(st) && rec.Binding == binding &&
		(requestID == "" || rec.RequestID == requestID) && (approvalID == "" || rec.ApprovalID == approvalID)
}

// unknownRecord is a record whose approver id the claim rule refuses, as Find
// returns it: what identifies it and its window, and nothing it says about
// its answer or what became of it. The store proves nothing from a record it
// refuses, so its approval is unspecified and so is its resolution.
func unknownRecord(rec Record) Record {
	a := rec.Approval
	return Record{
		SchemaVersion: rec.SchemaVersion,
		ApprovalID:    rec.ApprovalID,
		RequestID:     rec.RequestID,
		Binding:       rec.Binding,
		Resolution:    ResolutionUnspecified,
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

// Consume marks the approval of the held request consumed, as one
// compare-and-swap by link, and returns it as decided. It answers ErrZeroTime
// for a zero now and ErrNoApproval when the request is not held under the
// binding; ErrApprovalConsumed when an execution used it; and otherwise what
// approval.Consumable says of the record: ErrMultiUse for a record marked
// multi-use, ErrApprovalExpired at or past its expiry, ErrNoApproval for an
// answer dated outside the window between the request and now or no approval
// given, and ErrApprovalRejected beside the record it read when an approver
// refused it. An expired or rejected record is dropped. The caller checks
// what it returns and trusts none of it.
//
// approvalID is the approval the plane minted and holds in its own record, and
// it is part of the compare-and-swap: a record filed under this binding and
// this request id carrying any other approval id is not the plane's, and is
// never answered from, spent or dropped. Where no unresolved record of
// approvalID is left, though, a consumed record of the request under the
// binding answers ErrApprovalConsumed whichever approval id it carries,
// because it proves the request ran. An approvalID that cannot name a file,
// the empty one included, is refused with ErrRecordName rather than read as
// any record at all.
func (p *Plane) Consume(ctx context.Context, binding approval.Binding, requestID, approvalID string, now time.Time) (*controlv1.Approval, error) {
	if err := checkApprovalID(approvalID); err != nil {
		return nil, err
	}
	if err := p.beginAt(ctx, now); err != nil {
		return nil, err
	}
	defer p.s.mu.Unlock()
	found, err := p.one(binding, requestID, approvalID, now)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, ErrNoApproval
	}
	rec := found[0]
	a := rec.Approval
	switch approval.Consumable(a, now) {
	case approval.StandingUsable:
	case approval.StandingMultiUse:
		return nil, ErrMultiUse
	case approval.StandingExpired:
		errs := []error{ErrApprovalExpired}
		for _, stale := range found {
			errs = append(errs, p.s.drop(stale.ApprovalID))
		}
		return nil, errors.Join(errs...)
	case approval.StandingRejected:
		return proto.CloneOf(a), errors.Join(ErrApprovalRejected, p.s.drop(rec.ApprovalID))
	default:
		return nil, ErrNoApproval
	}
	if err := p.resolve(rec, ResolutionConsumed); err != nil {
		return nil, err
	}
	return proto.CloneOf(a), nil
}

// one returns the single unresolved record of approvalID, held for requestID
// under binding, that has not expired, or, where only expired ones are left,
// every one of them, for Consume to answer from the first. Two live records
// is a directory that disagrees with itself, which is refused rather than
// answered from whichever came first.
//
// An unresolved record under another approval id is passed over, expired, or
// refused for its approver id, or not: it is not the record the plane minted,
// so the plane neither answers from it nor drops it. Resolved records are
// spentOrNot's, which reads them whatever their approval id.
func (p *Plane) one(binding approval.Binding, requestID, approvalID string, now time.Time) ([]Record, error) {
	found, err := p.matching(binding, requestID, approvalID, unresolved)
	if err != nil {
		return nil, err
	}
	var live, stale []Record
	for _, rec := range found {
		if approval.Expired(rec.Approval, now) {
			stale = append(stale, rec)
			continue
		}
		live = append(live, rec)
	}
	switch {
	case len(live) == 1:
		return live, nil
	case len(live) > 1:
		return nil, fmt.Errorf("%w: %d live records for request %q", ErrRecordMismatch, len(live), cause(requestID))
	case len(stale) > 0:
		return stale, nil
	}
	return nil, p.spentOrNot(binding, requestID, approvalID)
}

// resolvedAs finds the records of requestID under binding among the ones a
// plane has resolved, whatever their approval id, and says the furthest state
// one stands in. A record whose approver id the claim rule refuses refuses the
// call when it is approvalID's, and is passed over when it is another
// approval's.
//
// Expiry is not consulted. A consumed record is the plane's proof that an
// execution happened, and it says so until it is dropped, whether or not the
// approval it spent would still be honoured. mu is held.
func (p *Plane) resolvedAs(binding approval.Binding, requestID, approvalID string) (state, bool, error) {
	l, err := p.s.scan()
	if err != nil {
		return stateHeld, false, err
	}
	furthest, found := stateHeld, false
	for _, id := range l.ids {
		rec, st, refusal, err := p.s.readListed(id, l.state[id])
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return stateHeld, false, err
		}
		if !listedUnder(rec, st, binding, requestID, "", resolvedState) {
			continue
		}
		switch {
		case refusal != nil && rec.ApprovalID == approvalID:
			return stateHeld, false, refusal
		case refusal != nil:
			continue
		}
		if !found || st > furthest {
			furthest, found = st, true
		}
	}
	return furthest, found, nil
}

// Resolve records that the request held as requestID under binding, with the
// approval approvalID the plane minted for it, will not be resumed: nothing
// spent its approval and nothing will, so a later identical call is held anew
// rather than told that an action ran. It grants nothing and spends nothing.
// A record of any other approval id is never written, and is read only where
// no unresolved record of approvalID is left, as for Consume. An
// approvalID that cannot name a file, the empty one included, is refused with
// ErrRecordName.
//
// It takes ResolutionNotResumed and refuses every other resolution with
// ErrResolution, since only Consume may mark a record spent; a zero now with
// ErrZeroTime, a request it does not keep with ErrNoApproval, and a record
// already consumed with ErrApprovalConsumed, because that record is proof of
// an execution and nothing may write over it. A record this call already
// resolved is not an error: the outcome asked for is the outcome on disk. Nor
// is an approvalID with no record of its own beside a record of the request
// another approval id left not resumed.
//
// An expired record is resolved rather than dropped, so a plane that comes
// back long after it lost the hold still closes it.
func (p *Plane) Resolve(ctx context.Context, binding approval.Binding, requestID, approvalID string, resolution Resolution, now time.Time) error {
	if resolution != ResolutionNotResumed {
		return fmt.Errorf("%w: %v", ErrResolution, resolution)
	}
	if err := checkApprovalID(approvalID); err != nil {
		return err
	}
	if err := p.beginAt(ctx, now); err != nil {
		return err
	}
	defer p.s.mu.Unlock()
	found, err := p.matching(binding, requestID, approvalID, unresolved)
	if err != nil {
		return err
	}
	switch len(found) {
	case 0:
		return p.alreadyResolved(binding, requestID, approvalID)
	case 1:
	default:
		return fmt.Errorf("%w: %d records for request %q", ErrRecordMismatch, len(found), cause(requestID))
	}
	// A pass that lost the link asked for the outcome that is now on disk.
	if err := p.resolve(found[0], ResolutionNotResumed); err != nil && !errors.Is(err, ErrResolved) {
		return err
	}
	return nil
}

// alreadyResolved answers a Resolve that found nothing unresolved: the record
// was spent, the plane resolved it already, or it never kept one.
func (p *Plane) alreadyResolved(binding approval.Binding, requestID, approvalID string) error {
	st, resolved, err := p.resolvedAs(binding, requestID, approvalID)
	switch {
	case err != nil:
		return err
	case !resolved:
		return ErrNoApproval
	case st == stateConsumed:
		return ErrApprovalConsumed
	}
	return nil
}

// spentOrNot says why there is no unresolved record for Consume: a record an
// execution already spent answers ErrApprovalConsumed, and everything else, a
// record the plane gave up on included, answers ErrNoApproval, so the caller
// holds the request anew rather than being told that an action ran.
func (p *Plane) spentOrNot(binding approval.Binding, requestID, approvalID string) error {
	st, found, err := p.resolvedAs(binding, requestID, approvalID)
	switch {
	case err != nil:
		return err
	case found && st == stateConsumed:
		return ErrApprovalConsumed
	}
	return ErrNoApproval
}

// resolve links the record's next name and unlinks the names behind it. The
// link is the compare-and-swap; the re-read after it is what keeps the total
// order when the two terminal names race, because a record read as consumed
// refuses a later execution and a record read as not-resumed does not.
func (p *Plane) resolve(rec Record, to Resolution) error {
	next := stateConsumed
	lost := ErrApprovalConsumed
	if to == ResolutionNotResumed {
		next, lost = stateNotResumed, ErrResolved
	}
	rec.Resolution = to
	body, err := encodeRecord(rec, p.s.opts.maxRecordBytes, p.s.opts.maxApprovalWindow)
	if err != nil {
		return err
	}
	if err := p.s.commit(rec.ApprovalID+next.suffix(), body); err != nil {
		if errors.Is(err, errExists) {
			return lost
		}
		return err
	}
	if next == stateNotResumed {
		err := p.s.present(rec.ApprovalID + stateConsumed.suffix())
		switch {
		case err == nil:
			return errors.Join(ErrApprovalConsumed, p.s.remove(rec.ApprovalID+stateNotResumed.suffix()))
		case !errors.Is(err, fs.ErrNotExist):
			return errors.Join(err, p.s.remove(rec.ApprovalID+stateNotResumed.suffix()))
		}
	}
	return errors.Join(
		p.s.remove(rec.ApprovalID+stateHeld.suffix()),
		p.s.remove(rec.ApprovalID+stateAnswered.suffix()),
	)
}
