package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/guardana/control/internal/canon"
)

// Floor is the newest accepted freshness statement for one bundle id, and the
// latest issuedAt any accepted statement carried (ADR-0038). A floor made by
// EmptyFloor holds no serial yet; the zero Floor is no floor at all and takes
// nothing.
type Floor struct {
	bundleID       string
	hasSerial      bool
	serial         int64
	digest         string
	issuedAt       time.Time
	latestIssuedAt time.Time
}

// EmptyFloor is the floor of bundleID before any statement was accepted.
func EmptyFloor(bundleID string) (Floor, error) {
	if !ValidID(bundleID) {
		return Floor{}, fmt.Errorf("%w: the bundle id", ErrFloorInvalid)
	}
	return Floor{bundleID: bundleID}, nil
}

// NewFloor is a floor holding a serial, as a store reads it back. It refuses,
// with ErrFloorInvalid, values no accepted statement could have left.
func NewFloor(bundleID string, serial int64, digest string, issuedAt, latestIssuedAt time.Time) (Floor, error) {
	switch {
	case !ValidID(bundleID):
		return Floor{}, fmt.Errorf("%w: the bundle id", ErrFloorInvalid)
	case serial < 1 || serial > MaxSerial:
		return Floor{}, fmt.Errorf("%w: the serial", ErrFloorInvalid)
	case !canon.ValidDigest(digest):
		return Floor{}, fmt.Errorf("%w: the digest", ErrFloorInvalid)
	case !isIssuedAt(issuedAt):
		return Floor{}, fmt.Errorf("%w: issuedAt", ErrFloorInvalid)
	case !isIssuedAt(latestIssuedAt) || latestIssuedAt.Before(issuedAt):
		return Floor{}, fmt.Errorf("%w: the latest issuedAt", ErrFloorInvalid)
	}
	return Floor{
		bundleID:       bundleID,
		hasSerial:      true,
		serial:         serial,
		digest:         digest,
		issuedAt:       issuedAt.UTC(),
		latestIssuedAt: latestIssuedAt.UTC(),
	}, nil
}

// isIssuedAt reports whether t is a time issuedAt's spelling can carry.
func isIssuedAt(t time.Time) bool {
	_, err := ParseIssuedAt(FormatIssuedAt(t))
	return err == nil && t.Nanosecond() == 0
}

// BundleID is the bundle id the floor is for.
func (f Floor) BundleID() string { return f.bundleID }

// HasSerial reports whether a statement was ever accepted into the floor.
func (f Floor) HasSerial() bool { return f.hasSerial }

// Serial is the newest accepted statement's serial, 0 while HasSerial is
// false.
func (f Floor) Serial() int64 { return f.serial }

// Digest is the newest accepted statement's digest.
func (f Floor) Digest() string { return f.digest }

// IssuedAt is the newest accepted statement's issuedAt.
func (f Floor) IssuedAt() time.Time { return f.issuedAt }

// LatestIssuedAt is the latest issuedAt any accepted statement carried.
func (f Floor) LatestIssuedAt() time.Time { return f.latestIssuedAt }

// Raise returns the floor once st is accepted at the clock reading now, or
// refuses st. In order: the zero Floor takes nothing (ErrFloorInvalid); st
// names the floor's bundle id (ErrFloorBundle); st is dated no later than now
// (ErrStatementFuture); now is not earlier than the latest issuedAt the floor
// holds (ErrClockBehindFloor). A floor with no serial yet then takes st. A
// floor with one takes its own statement again unchanged, refuses its serial
// with another digest (ErrFloorSerialReused), refuses a statement at or below
// its serial and issuedAt (ErrBelowFloor), and moves to any other, keeping the
// later of the two latest issuedAt.
func (f Floor) Raise(st Statement, now time.Time) (Floor, error) {
	if err := f.admits(st, now); err != nil {
		return Floor{}, err
	}
	next := Floor{bundleID: f.bundleID, hasSerial: true, serial: st.serial, digest: st.digest, issuedAt: st.issuedAt, latestIssuedAt: st.issuedAt}
	if !f.hasSerial {
		return next, nil
	}
	switch {
	case st.serial == f.serial && st.digest != f.digest:
		return Floor{}, fmt.Errorf("%w: serial %d", ErrFloorSerialReused, st.serial)
	case st.serial == f.serial && st.issuedAt.Equal(f.issuedAt):
		return f, nil
	case st.serial < f.serial || (st.serial == f.serial && st.issuedAt.Before(f.issuedAt)):
		return Floor{}, fmt.Errorf("%w: serial %d issued %s, floor serial %d issued %s",
			ErrBelowFloor, st.serial, FormatIssuedAt(st.issuedAt), f.serial, FormatIssuedAt(f.issuedAt))
	}
	if f.latestIssuedAt.After(next.latestIssuedAt) {
		next.latestIssuedAt = f.latestIssuedAt
	}
	return next, nil
}

// Takes is Raise's judgement of st at now without the floor Raise returns: nil
// where Raise would take st, and Raise's own refusal otherwise.
func (f Floor) Takes(st Statement, now time.Time) error {
	_, err := f.Raise(st, now)
	return err
}

// admits runs Raise's checks that do not order st against the floor.
func (f Floor) admits(st Statement, now time.Time) error {
	switch {
	case f.bundleID == "":
		return ErrFloorInvalid
	case st.bundleID != f.bundleID:
		return ErrFloorBundle
	case st.issuedAt.After(now):
		return fmt.Errorf("%w: issued %s", ErrStatementFuture, FormatIssuedAt(st.issuedAt))
	case f.hasSerial && now.Before(f.latestIssuedAt):
		return fmt.Errorf("%w: %s", ErrClockBehindFloor, FormatIssuedAt(f.latestIssuedAt))
	}
	return nil
}

// holds reports whether st is f's newest statement. A floor's latest
// issuedAt is never earlier than its issuedAt, which every constructor holds,
// so that needs no check here.
func (f Floor) holds(st Statement) bool {
	return f.hasSerial && f.bundleID == st.bundleID && f.serial == st.serial && f.digest == st.digest && f.issuedAt.Equal(st.issuedAt)
}

// Equal reports whether f and o are the same floor, the times compared as
// instants.
func (f Floor) Equal(o Floor) bool {
	return f.bundleID == o.bundleID && f.hasSerial == o.hasSerial && f.serial == o.serial && f.digest == o.digest &&
		f.issuedAt.Equal(o.issuedAt) && f.latestIssuedAt.Equal(o.latestIssuedAt)
}

// FloorStore keeps the floor where it outlives the process. A store outside
// the guarded trees implements it; the policy package only calls it.
type FloorStore interface {
	// Floor returns the floor stored for bundleID, read from the store and
	// never from memory. A bundle id the store holds no floor for is an
	// error, never an empty floor.
	Floor(ctx context.Context, bundleID string) (Floor, error)
	// RaiseAt holds the store's exclusive lock while it reads the floor
	// stored for st's bundle id, takes the reading now gives, computes
	// stored.Raise(st, reading), writes the result durably when it differs
	// from what is stored, and returns it. When now, stored.Raise or the read
	// refuses or fails, RaiseAt returns that error and the stored floor is
	// unchanged. When the write fails, RaiseAt returns that error and the
	// stored floor may be the raised one: a failed raise never lowers a floor
	// and may have raised it, so a caller publishes nothing on an error.
	RaiseAt(ctx context.Context, st Statement, now Reading) (Floor, error)
}

// Reading is the clock reading a raise is judged at, taken once the store
// holds its lock, so a wait on that lock comes before it. An error refuses
// the raise.
type Reading func() (time.Time, error)

// At is the reading of a time read already.
func At(now time.Time) Reading {
	return func() (time.Time, error) { return now, nil }
}

// StartAction is what a plane does with the bundle on disk at start. The zero
// value refuses the start.
type StartAction uint8

const (
	// StartRefused refuses to start.
	StartRefused StartAction = iota
	// StartUnconfirmed installs the bundle with no confirmation, so every
	// call that reaches the kernel's freshness check is POLICY_STALE.
	StartUnconfirmed
	// StartConfirmed installs the bundle confirmed by the statement bound to
	// it, raising the floor first.
	StartConfirmed
)

// StartVerdict is the start rule's answer. Cause is nil only for
// StartConfirmed; for a refusal it names both serials.
type StartVerdict struct {
	Action       StartAction
	BundleSerial int64
	// FloorSerial is 0 while the floor holds no serial yet.
	FloorSerial int64
	Cause       error
}

// StartRule is ADR-0038's start: what a plane does with the bundle snap holds,
// given the floor read from the store, the verified statement read from disk
// (nil when there is none) and the clock.
//
// A floor with no serial yet starts the bundle confirmed by its statement, or
// unconfirmed. With a serial: a lower bundle, or the floor's serial with
// another digest, refuses; the floor's own bundle starts confirmed by a
// statement the floor takes, or unconfirmed, a clock behind the floor's
// latest issuedAt among the causes; a higher bundle starts only confirmed,
// and refuses without a statement bound to it that the floor takes now, a
// statement dated ahead or a clock behind the latest issuedAt included, since
// the bundle file alone may not choose the policy.
func StartRule(f Floor, snap *Snapshot, st *Statement, now time.Time) StartVerdict {
	v := StartVerdict{BundleSerial: snap.Serial(), FloorSerial: f.serial}
	if err := floorAdmits(f, snap); err != nil {
		return v.refuse(err)
	}
	cause := confirmable(f, snap, st, now)
	switch {
	case cause == nil:
		v.Action = StartConfirmed
	case f.hasSerial && snap.serial > f.serial:
		return v.refuse(fmt.Errorf("%w: %w", ErrAboveFloorUnbound, cause))
	default:
		v.Action, v.Cause = StartUnconfirmed, cause
	}
	return v
}

// floorAdmits refuses a bundle f refuses whatever statement comes with it.
func floorAdmits(f Floor, snap *Snapshot) error {
	switch {
	case snap == nil:
		return ErrNoBundle
	case f.bundleID == "":
		return ErrFloorInvalid
	case snap.ref.GetBundleId() != f.bundleID:
		return ErrFloorBundle
	case f.hasSerial && snap.serial < f.serial:
		return ErrBelowFloor
	case f.hasSerial && snap.serial == f.serial && snap.ref.GetDigest() != f.digest:
		return ErrFloorSerialReused
	}
	return nil
}

// confirmable is why st cannot confirm snap against f at now, or nil. A clock
// behind the floor's latest issuedAt is named first, statement or none.
func confirmable(f Floor, snap *Snapshot, st *Statement, now time.Time) error {
	if f.hasSerial && now.Before(f.latestIssuedAt) {
		return fmt.Errorf("%w: %s", ErrClockBehindFloor, FormatIssuedAt(f.latestIssuedAt))
	}
	if st == nil {
		return ErrStatementMissing
	}
	if err := bound(*st, snap); err != nil {
		return err
	}
	return f.Takes(*st, now)
}

// bound refuses a statement that does not name snap's bundle id, serial and
// digest.
func bound(st Statement, snap *Snapshot) error {
	if st.bundleID != snap.ref.GetBundleId() || st.serial != snap.serial || st.digest != snap.ref.GetDigest() {
		return ErrStatementUnbound
	}
	return nil
}

func (v StartVerdict) refuse(cause error) StartVerdict {
	v.Action = StartRefused
	v.Cause = fmt.Errorf("%w: bundle serial %d, floor serial %d", cause, v.BundleSerial, v.FloorSerial)
	return v
}
