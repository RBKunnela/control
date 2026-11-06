package approvals

import (
	"context"
	"errors"
	"io/fs"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// Reader is a read-only handle on an approvals directory, for an operator
// under the signed authority: such an operator answers in the plane's inbox
// and never writes this directory, so the directory may be another
// account's. It takes no lock and writes nothing. A directory a group or the
// world may write is refused as either other handle refuses it.
//
// The zero value is not a store. Every method on it answers ErrClosed.
type Reader struct {
	s *store
}

// OpenReader opens dir for reading. It refuses a group- or world-writable
// directory with ErrPermissions, a directory that is not an approvals store
// with ErrNotAStore, and a platform with no file lock with ErrNoLock, where
// it could not tell whether anything would read an answer.
func OpenReader(dir string, opts ...Option) (*Reader, error) {
	s, err := openStore(dir, openReader, opts)
	if err != nil {
		return nil, err
	}
	if _, err := planeHoldsLock(s.root, dir); err != nil {
		return nil, errors.Join(err, s.close())
	}
	return &Reader{s: s}, nil
}

// Close releases the handle. A later call answers ErrClosed.
func (r *Reader) Close() error {
	if r == nil {
		return ErrClosed
	}
	return r.s.close()
}

// List reads every record under the directory, as Approver.List does.
func (r *Reader) List(ctx context.Context) (Listing, error) {
	if r == nil {
		return Listing{}, ErrClosed
	}
	return r.s.list(ctx)
}

// PlaneAccount reports whether this process runs as the account that owns
// the directory. That account is the plane's: OpenPlane refuses a directory
// another account owns.
func (r *Reader) PlaneAccount() bool {
	if r == nil || r.s == nil {
		return false
	}
	euid := effectiveUID()
	return euid >= 0 && int64(r.s.opened.uid) == int64(euid)
}

// Held returns the plane's record of approvalID while it is held and still
// pending. It refuses an id that cannot name a file with ErrRecordName, an
// unknown id with ErrNoApproval, and a record an approver answered with
// ErrApprovalAnswered.
func (r *Reader) Held(ctx context.Context, approvalID string) (Record, error) {
	if r == nil {
		return Record{}, ErrClosed
	}
	if err := checkApprovalID(approvalID); err != nil {
		return Record{}, err
	}
	if err := r.s.usable(); err != nil {
		return Record{}, err
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := r.s.judge(); err != nil {
		return Record{}, err
	}
	rec, st, err := r.s.readRecord(approvalID, stateHeld)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Record{}, ErrNoApproval
	case err != nil:
		return Record{}, err
	case st == stateAnswered, rec.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING:
		return Record{}, ErrApprovalAnswered
	}
	return rec, nil
}
