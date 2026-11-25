package policywatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/guardana/control/internal/policy"
)

// The inputs a refused start or check names: the floor, which the store
// could not read or raise; the bundle, which did not load or which the floor
// refused; and the statement, missing or not one that confirms the bundle.
const (
	InputFloor     = "floor"
	InputBundle    = "bundle"
	InputStatement = "statement"
)

// StartError is a refused start or check and the input that refused it.
type StartError struct {
	Input string
	Err   error
	// BundleKeyID is the key id the bundle file names, read before anything
	// verified it, or "" where the file is not a bundle.
	BundleKeyID string
}

func (e *StartError) Error() string { return e.Err.Error() }

func (e *StartError) Unwrap() error { return e.Err }

func refused(input string, err error) error { return &StartError{Input: input, Err: err} }

// refusedBundle is a refusal of the bundle j read.
func (j judged) refusedBundle(err error) error {
	keyID := ""
	if j.disk != nil {
		keyID = j.disk.keyID
	}
	return &StartError{Input: InputBundle, Err: err, BundleKeyID: keyID}
}

// refusedVerdict is the refusal the start rule's verdict makes: the
// statement's when the statement was missing or refused, the bundle's
// otherwise.
func (j judged) refusedVerdict() error {
	if j.statementCaused {
		return refused(InputStatement, j.verdict.Cause)
	}
	return j.refusedBundle(j.verdict.Cause)
}

// StartResult is what Start installed and why.
type StartResult struct {
	// Action is policy.StartUnconfirmed or policy.StartConfirmed.
	Action policy.StartAction
	// Unconfirmed is why the bundle started unconfirmed, nil when it was
	// confirmed.
	Unconfirmed error
	// Floor is the floor the start read.
	Floor policy.Floor
}

// judged is the bundle on disk, the statement read beside it and the floor,
// with policy.StartRule's verdict on them at now.
type judged struct {
	disk    *diskBundle
	read    *diskStatement
	st      *policy.Statement
	floor   policy.Floor
	verdict policy.StartVerdict
	now     time.Time
	// statementCaused says the verdict turned on a statement that was
	// missing or refused, which the verdict's cause names.
	statementCaused bool
}

// judge reads the floor, the bundle and the statement and applies the start
// rule at the wall clock's reading taken once they are read, writing
// nothing. A statement that cannot be read or verified is no statement, and
// the verdict's cause says why.
func judge(ctx context.Context, o Options) (judged, error) {
	var j judged
	f, err := o.Floor.Floor(ctx, o.BundleID)
	if err != nil {
		return j, refused(InputFloor, err)
	}
	j.floor = f
	if j.disk = readBundle(o, nil); j.disk.err != nil {
		return j, j.refusedBundle(j.disk.err)
	}
	if err := outlastsPoll(j.disk.snap, o); err != nil {
		return j, j.refusedBundle(err)
	}
	j.read = readStatement(o, nil)
	j.now = o.Wall()
	if j.read.err == nil && expired(j.read.st, j.disk.snap, o.MaxStale, j.now) {
		j.read = &diskStatement{cause: CauseStatementExpired, err: expiry(j.read.st, j.disk.snap, o.MaxStale)}
	}
	if j.read.err == nil {
		j.st = &j.read.st
	}
	j.verdict = policy.StartRule(f, j.disk.snap, j.st, j.now)
	j.statementCaused = j.verdict.Cause != nil && !errors.Is(j.verdict.Cause, policy.ErrClockBehindFloor) && !floorRefuses(f, j.disk.snap)
	if j.read.err != nil && errors.Is(j.verdict.Cause, policy.ErrStatementMissing) {
		// The rule saw no statement; the read says why, once.
		j.verdict.Cause = j.read.err
		if j.verdict.Action == policy.StartRefused {
			j.verdict.Cause = fmt.Errorf("%w: %w: bundle serial %d, floor serial %d",
				policy.ErrAboveFloorUnbound, j.read.err, j.verdict.BundleSerial, j.verdict.FloorSerial)
		}
	}
	return j, nil
}

// unexpiredAt is the reading a raise to st for snap is judged at, taken once
// the store holds its lock: a statement whose budget ran out while the raise
// waited on that lock raises nothing.
func unexpiredAt(st policy.Statement, snap *policy.Snapshot, o Options) policy.Reading {
	return func() (time.Time, error) {
		now := o.Wall()
		if expired(st, snap, o.MaxStale, now) {
			return now, expiry(st, snap, o.MaxStale)
		}
		return now, nil
	}
}

// floorRefuses reports whether f refuses snap whatever statement comes with
// it: a serial below the floor's, or the floor's serial with another digest.
func floorRefuses(f policy.Floor, snap *policy.Snapshot) bool {
	return f.HasSerial() && (snap.Serial() < f.Serial() || snap.Serial() == f.Serial() && snap.Ref().GetDigest() != f.Digest())
}

// Start installs in the holder what the files and the floor allow at start,
// by policy.StartRule at the wall clock's reading, a statement whose budget
// has run out counting as none. A refusal is a
// *StartError and installs nothing: one by the rule names the bundle's serial
// and the floor's. A floor the store cannot read or raise, a bundle that does
// not load or is not the pinned id's, and a bundle whose budget is not longer
// than the poll interval are refused too. A statement that cannot be read or
// verified is no statement: the bundle starts unconfirmed, or is refused if it
// is above the floor, and the result says why. A statement whose budget runs
// out while the floor's raise waits on the store's lock refuses the start,
// and the floor stays as it was.
func Start(ctx context.Context, o Options) (StartResult, error) {
	if err := o.check(); err != nil {
		return StartResult{}, err
	}
	j, err := judge(ctx, o)
	if err != nil {
		return StartResult{Floor: j.floor}, err
	}
	res := StartResult{Action: j.verdict.Action, Unconfirmed: j.verdict.Cause, Floor: j.floor}
	switch j.verdict.Action {
	case policy.StartConfirmed:
		err = o.Holder.InstallConfirmedAt(ctx, j.disk.msg, o.BundleKeys, *j.st, unexpiredAt(*j.st, j.disk.snap, o))
	case policy.StartUnconfirmed:
		err = o.Holder.InstallUnconfirmed(ctx, j.disk.msg, o.BundleKeys)
	default:
		return StartResult{Floor: j.floor}, j.refusedVerdict()
	}
	switch {
	case errors.Is(err, ErrStatementExpired):
		return StartResult{Floor: j.floor}, refused(InputStatement, err)
	case errors.Is(err, policy.ErrFloorRaise), errors.Is(err, policy.ErrFloorRead):
		return StartResult{Floor: j.floor}, refused(InputFloor, err)
	case err != nil:
		return StartResult{Floor: j.floor}, j.refusedBundle(err)
	}
	return res, nil
}

// Report is what Check found: the bundle on disk, the statement that
// confirms it, the floor, and when that confirmation expires.
type Report struct {
	Bundle    *policy.Snapshot
	Statement policy.Statement
	Floor     policy.Floor
	Expires   time.Time
}

// Check judges the files and the floor as a start would, and writes nothing:
// the floor is read and never raised. Beside every refusal of Start, it
// refuses, as a *StartError naming the bundle, a bundle the start would
// install unconfirmed: no statement, one that does not verify, one bound to
// another bundle, one dated after the clock or at or below the floor, one
// whose budget has run out, and a clock behind the floor.
func Check(ctx context.Context, o Options) (Report, error) {
	if err := o.checkReading(); err != nil {
		return Report{}, err
	}
	j, err := judge(ctx, o)
	if err != nil {
		return Report{Floor: j.floor}, err
	}
	rep := Report{Bundle: j.disk.snap, Floor: j.floor}
	if j.verdict.Action != policy.StartConfirmed {
		return rep, j.refusedVerdict()
	}
	rep.Statement = *j.st
	rep.Expires = ExpiresAt(j.st.IssuedAt(), j.disk.snap, o.MaxStale)
	return rep, nil
}
