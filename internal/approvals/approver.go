package approvals

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// Approver is an approver process's handle on an approvals directory. It has
// Answer and takes no lock, so it never keeps a plane out of its own
// directory. An answer filed while the plane lock is free is filed all the
// same and reported through Answered.PlaneRunning: nobody will resume that
// call, since a hold does not survive a restart, but a plane that keeps a
// hold journal closes the trail with the answer on disk when it comes back.
//
// The zero value is not a store. Every method on it answers ErrClosed.
type Approver struct {
	s *store
}

// OpenApprover opens dir for an approver. It refuses a group- or
// world-writable directory with ErrPermissions, one another account owns with
// ErrOwner, a directory that is not an approvals store with ErrNotAStore
// rather than reading it as an empty one, and a platform with no file lock
// with ErrNoLock, where it could not tell whether anything would consume an
// answer.
//
// It opens whether or not a plane holds the directory: a listing is worth
// having either way, and Listing.PlaneRunning says which it was.
func OpenApprover(dir string, opts ...Option) (*Approver, error) {
	s, err := openStore(dir, false, opts)
	if err != nil {
		return nil, err
	}
	if _, err := planeHoldsLock(s.root, dir); err != nil {
		return nil, errors.Join(err, s.close())
	}
	return &Approver{s: s}, nil
}

// Close releases the handle. A later call answers ErrClosed.
func (a *Approver) Close() error {
	if a == nil {
		return ErrClosed
	}
	return a.s.close()
}

// Entry is one record as an approver sees it: the record itself, and the
// projection beside it when there is one to read.
type Entry struct {
	Record Record
	// View is nil when the projection is missing or will not decode. The
	// record still answers; the readable fields are what is lost, and
	// Listing.Problems says so.
	View *View
}

// Problem is one name a listing could not read, and why.
type Problem struct {
	Name string
	Err  error
}

// Listing is what an approver sees. It is never an empty listing standing in
// for a listing that could not be made: Complete says whether every record was
// read, and Problems names each one that was not.
type Listing struct {
	Entries []Entry
	// Complete is false when the bound stopped the pass or a record would not
	// decode. Such a listing is unmeasured: it is neither the whole directory
	// nor an empty one.
	Complete bool
	// PlaneRunning is whether a plane held the directory's lock when the
	// listing was made. False means nothing will consume an answer.
	PlaneRunning bool
	Problems     []Problem
}

// List reads every record under the directory, newest name first by approval
// id, with its projection.
func (a *Approver) List(ctx context.Context) (Listing, error) {
	if a == nil {
		return Listing{}, ErrClosed
	}
	if err := a.s.usable(); err != nil {
		return Listing{}, err
	}
	if err := ctx.Err(); err != nil {
		return Listing{}, err
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	if err := a.s.usable(); err != nil {
		return Listing{}, err
	}
	if err := a.s.judge(); err != nil {
		return Listing{}, err
	}
	held, err := planeHoldsLock(a.s.root, a.s.dir)
	if err != nil {
		return Listing{}, err
	}
	l, err := a.s.scan()
	if err != nil {
		return Listing{}, err
	}
	out := Listing{Complete: l.complete, PlaneRunning: held}
	for _, id := range l.ids {
		rec, st, err := a.s.readRecord(id, l.state[id])
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			out.Problems = append(out.Problems, Problem{Name: id + st.suffix(), Err: err})
			out.Complete = false
			continue
		}
		out.Entries = append(out.Entries, Entry{Record: rec, View: a.view(id, &out)})
	}
	return out, nil
}

// view reads the projection of id, or reports it as a problem and returns nil.
// A projection is not truth and a listing does not fail over one.
func (a *Approver) view(id string, out *Listing) *View {
	raw, err := a.s.readBounded(id+viewSuffix, a.s.opts.maxRecordBytes)
	if err != nil {
		out.Problems = append(out.Problems, Problem{Name: id + viewSuffix, Err: err})
		return nil
	}
	v, err := decodeView(raw)
	if err != nil {
		out.Problems = append(out.Problems, Problem{Name: id + viewSuffix, Err: err})
		return nil
	}
	return &v
}

// Answered is what came of an answer that was filed. It is returned beside a
// nil error, because a written answer succeeded whatever else was true.
type Answered struct {
	// PlaneRunning is whether a plane held the directory just before the
	// answer was written. False means no plane will resume the held call: the
	// hold did not survive the restart. A plane that keeps a hold journal
	// closes that trail when it comes back, recording that a person answered
	// and that the call still did not run.
	//
	// The zero value is the cautious reading, and the flag can only
	// understate: a plane that starts after the probe finds the answer on
	// disk like any other. See Answer.
	PlaneRunning bool
}

// Answer decides the record of approvalID: APPROVED with an approver, or
// REJECTED, at decidedAt. It changes the state, the approver, the reason and
// the decided time, and nothing else: every other field is the plane's, read
// back from the record and written out again, so this call cannot move an
// expiry, a digest or a request id.
//
// It writes the answer whether or not a plane holds the directory, and says
// which it was in Answered.PlaneRunning. The call the hold was taken for does
// not run either way — a hold does not survive a restart — but the evidence
// differs: when a plane that keeps a hold journal comes back, an answer on
// disk closes that trail with the approver's decision and a refusal to
// resume, while no answer at all closes it as one nobody answered, which
// would be false about a person who did decide. Refusing to write would
// destroy that.
//
// The probe is therefore allowed to be approximate. A plane that starts an
// instant after it reads the answer like any other, so the flag understates
// and never overstates, and nothing about the record depends on it.
//
// It refuses, writing nothing at all: any other answer with ErrApprovalAnswer,
// an approver id or a reason outside its bound with ErrApproverID or
// ErrReason, a zero decidedAt with ErrZeroTime, an id that cannot name a file
// with ErrRecordName, an unknown id with ErrNoApproval, an approval answered
// or resolved already with ErrApprovalAnswered, ErrApprovalConsumed or
// ErrResolved, an approval past its expiry at decidedAt with
// ErrApprovalExpired, and a directory that is no longer the one opened with
// ErrDirectoryChanged.
//
// A failure after the answer was linked takes it back, and is no such
// refusal: a running plane may read the answer before it is taken back. A
// consumed record carrying it by the time the failure is seen makes the call
// succeed, an answer already gone adds ErrOutcomeUnknown, and an unlink racing
// a plane that has read the answer but not yet recorded spending it is
// reported as the failure alone.
func (a *Approver) Answer(ctx context.Context, approvalID string, answer controlv1.ApprovalState, approverID, reason string, decidedAt time.Time) (Answered, error) {
	if a == nil {
		return Answered{}, ErrClosed
	}
	if err := a.s.usable(); err != nil {
		return Answered{}, err
	}
	if err := checkAnswer(approvalID, answer, approverID, reason, decidedAt); err != nil {
		return Answered{}, err
	}
	if err := ctx.Err(); err != nil {
		return Answered{}, err
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	if err := a.s.usable(); err != nil {
		return Answered{}, err
	}
	if err := a.s.judge(); err != nil {
		return Answered{}, err
	}
	// Read before the write, so a probe that cannot be made refuses while
	// nothing has been written.
	running, err := planeHoldsLock(a.s.root, a.s.dir)
	if err != nil {
		return Answered{}, err
	}
	rec, err := a.pending(approvalID, decidedAt)
	if err != nil {
		return Answered{}, err
	}
	if err := a.file(rec, answer, approverID, reason, decidedAt); err != nil {
		return Answered{}, err
	}
	return Answered{PlaneRunning: running}, nil
}

// checkAnswer holds an answer's own fields before any of them reaches an
// Approval. APPROVED with no approver is not an answer: it is a grant nobody
// claimed.
func checkAnswer(approvalID string, answer controlv1.ApprovalState, approverID, reason string, decidedAt time.Time) error {
	if err := checkApprovalID(approvalID); err != nil {
		return err
	}
	switch answer {
	case controlv1.ApprovalState_APPROVAL_STATE_APPROVED:
		if err := CheckApproverID(approverID); err != nil {
			return err
		}
	case controlv1.ApprovalState_APPROVAL_STATE_REJECTED:
		if approverID != "" {
			if err := CheckApproverID(approverID); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%w: got %s", ErrApprovalAnswer, answer)
	}
	if err := checkReason(reason); err != nil {
		return err
	}
	if decidedAt.IsZero() {
		return ErrZeroTime
	}
	return nil
}

// pending returns the record of approvalID while it is still the plane's own
// pending one, and says which way it is not. mu is held.
func (a *Approver) pending(approvalID string, decidedAt time.Time) (Record, error) {
	rec, st, err := a.s.readRecord(approvalID, stateHeld)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Record{}, ErrNoApproval
	case err != nil:
		return Record{}, err
	case st == stateConsumed:
		return Record{}, ErrApprovalConsumed
	case st == stateNotResumed:
		return Record{}, ErrResolved
	case st == stateAnswered:
		return Record{}, ErrApprovalAnswered
	case rec.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING:
		return Record{}, fmt.Errorf("%w: the record reads %s", ErrApprovalAnswered, rec.Approval.GetState())
	case expired(rec.Approval, decidedAt):
		return Record{}, ErrApprovalExpired
	}
	return rec, nil
}

// file writes the answered record and takes the held name away behind it. The
// link is the compare-and-swap; the re-read after it is what stops an answer
// standing beside a record the plane already resolved, which only a crash
// between a plane's link and its unlink can leave, or a plane that spent this
// very answer in between.
func (a *Approver) file(rec Record, answer controlv1.ApprovalState, approverID, reason string, decidedAt time.Time) error {
	answered := rec.clone()
	answered.Approval.State = answer
	answered.Approval.ApproverId = approverID
	answered.Approval.Reason = reason
	answered.Approval.DecidedAt = timestamppb.New(decidedAt)
	body, err := encodeRecord(answered, a.s.opts.maxRecordBytes, a.s.opts.maxApprovalWindow)
	if err != nil {
		return err
	}
	if err := a.s.commit(rec.ApprovalID+stateAnswered.suffix(), body); err != nil {
		if errors.Is(err, errExists) {
			return ErrApprovalAnswered
		}
		return a.unfiled(answered, err)
	}
	// A resolved name that is there as anything but a record is not an absent
	// one: the answer is taken back unless each name is known to be missing.
	for _, resolved := range []state{stateConsumed, stateNotResumed} {
		err := a.s.present(rec.ApprovalID + resolved.suffix())
		switch {
		case err == nil && resolved == stateConsumed:
			return a.spent(answered)
		case err == nil:
			return errors.Join(ErrResolved, a.s.remove(rec.ApprovalID+stateAnswered.suffix()))
		case !errors.Is(err, fs.ErrNotExist):
			return errors.Join(err, a.s.remove(rec.ApprovalID+stateAnswered.suffix()))
		}
	}
	return a.s.remove(rec.ApprovalID + stateHeld.suffix())
}

// unfiled answers a commit of answered that failed. A plane can read the
// answer, spend it and unlink it between the link and the failure, so a
// consumed record of the approval decides the outcome as it does after a
// successful link.
func (a *Approver) unfiled(answered Record, failed error) error {
	err := a.s.present(answered.ApprovalID + stateConsumed.suffix())
	switch {
	case err == nil:
		return a.spent(answered)
	case errors.Is(err, fs.ErrNotExist):
		return failed
	}
	return errors.Join(failed, err)
}

// spent answers an answer linked while a consumed record of its approval is
// there. A plane holds no lock the approver shares, so it can read the answer,
// spend it and unlink the answered and held names before the re-read. Only a
// consumed record carrying this answer means it was filed; any other refuses it
// and takes it back. The names behind it are removed either way, and one the
// plane unlinked first is no failure.
func (a *Approver) spent(answered Record) error {
	id := answered.ApprovalID
	raw, err := a.s.readBounded(id+stateConsumed.suffix(), headerBytes+a.s.opts.maxRecordBytes)
	var consumed Record
	if err == nil {
		consumed, err = a.s.decodeAt(id, stateConsumed, raw)
	}
	if err != nil || !sameAnswer(consumed.Approval, answered.Approval) {
		return errors.Join(ErrApprovalConsumed, err, a.s.remove(id+stateAnswered.suffix()))
	}
	return errors.Join(a.s.remove(id+stateAnswered.suffix()), a.s.remove(id+stateHeld.suffix()))
}

// sameAnswer reports whether two approvals carry the same answer.
func sameAnswer(x, y *controlv1.Approval) bool {
	return x.GetState() == y.GetState() &&
		x.GetApproverId() == y.GetApproverId() &&
		x.GetReason() == y.GetReason() &&
		proto.Equal(x.GetDecidedAt(), y.GetDecidedAt())
}
