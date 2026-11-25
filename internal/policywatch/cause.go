package policywatch

import (
	"errors"

	"github.com/guardana/control/internal/policy"
)

// Cause is why a poll moved nothing: the replacement or the statement it
// read was refused, and the last good snapshot stays with its confirmation.
type Cause string

// The causes a refusal is counted under.
const (
	// CauseBundleUnreadable is a bundle file that could not be read: missing,
	// not a regular file, or over its bound.
	CauseBundleUnreadable Cause = "bundle_unreadable"
	// CauseBundleInvalid is a bundle that does not load: torn, not a bundle,
	// unsigned, signed under another key, or not a policy the kernel runs.
	CauseBundleInvalid Cause = "bundle_invalid"
	// CauseBundleID is a bundle of another id than the pinned one.
	CauseBundleID Cause = "bundle_id"
	// CauseBundleBudget is a bundle whose budget, with the operator's, is not
	// longer than the poll interval, so no statement could keep it fresh.
	CauseBundleBudget Cause = "bundle_budget"
	// CauseRollback is a bundle below the current serial or below the floor.
	CauseRollback Cause = "rollback"
	// CauseSerialReused is a bundle of the current or the floor's serial with
	// another digest.
	CauseSerialReused Cause = "serial_reused"
	// CauseStatementMissing is no statement file at its path.
	CauseStatementMissing Cause = "statement_missing"
	// CauseStatementUnreadable is a statement file that could not be read.
	CauseStatementUnreadable Cause = "statement_unreadable"
	// CauseStatementInvalid is a statement that does not verify: torn, not an
	// envelope, signed under another key, or a body that is not a statement.
	CauseStatementInvalid Cause = "statement_invalid"
	// CauseStatementUnbound is a statement that names neither the bundle on
	// disk, nor the current one, nor a later serial, or names another id.
	CauseStatementUnbound Cause = "statement_unbound"
	// CauseStatementFuture is a statement dated after the plane's clock.
	CauseStatementFuture Cause = "statement_future"
	// CauseStatementExpired is a statement whose budget had run out before
	// it was read.
	CauseStatementExpired Cause = "statement_expired"
	// CauseBelowFloor is a statement at or below the floor, other than the
	// floor's own.
	CauseBelowFloor Cause = "below_floor"
	// CauseClockBehindFloor is a clock earlier than the latest issuedAt the
	// floor holds.
	CauseClockBehindFloor Cause = "clock_behind_floor"
	// CauseClockBack is a wall clock more than a second below the mark.
	CauseClockBack Cause = "clock_back"
	// CauseWithdrawn is a statement no newer than a confirmation the clock
	// rule withdrew.
	CauseWithdrawn Cause = "withdrawn"
	// CauseFloor is a floor that could not be read or raised, or one read
	// back below the statement the plane confirmed.
	CauseFloor Cause = "floor"
	// CauseUnknown is a refusal of the holder this build cannot name.
	CauseUnknown Cause = "unknown"
)

// Causes is every cause, in a fixed order.
func Causes() []Cause {
	return []Cause{
		CauseBundleUnreadable, CauseBundleInvalid, CauseBundleID, CauseBundleBudget, CauseRollback,
		CauseSerialReused, CauseStatementMissing, CauseStatementUnreadable, CauseStatementInvalid,
		CauseStatementUnbound, CauseStatementFuture, CauseStatementExpired, CauseBelowFloor,
		CauseClockBehindFloor, CauseClockBack, CauseWithdrawn, CauseFloor, CauseUnknown,
	}
}

// causeOf names the cause of a holder's refusal. A floor's own refusal is
// named before ErrFloorRaise and ErrFloorRead, which wrap it and whatever else
// the store's raise or read returned, its deadline included; a refusal no row
// names is unknown, never the floor's.
func causeOf(err error) Cause {
	for _, c := range []struct {
		err   error
		cause Cause
	}{
		{ErrStatementExpired, CauseStatementExpired},
		{policy.ErrConfirmationWithdrawn, CauseWithdrawn},
		{policy.ErrStatementFuture, CauseStatementFuture},
		{policy.ErrClockBehindFloor, CauseClockBehindFloor},
		{policy.ErrFloorSerialReused, CauseSerialReused},
		{policy.ErrSerialReused, CauseSerialReused},
		{policy.ErrRollback, CauseRollback},
		{policy.ErrBelowFloor, CauseBelowFloor},
		{policy.ErrBundlePin, CauseBundleID},
		{policy.ErrFloorBundle, CauseBundleID},
		{policy.ErrStatementUnbound, CauseStatementUnbound},
		{policy.ErrFloorInvalid, CauseFloor},
		{policy.ErrFloorRaise, CauseFloor},
		{policy.ErrFloorRead, CauseFloor},
		{policy.ErrNoFloorStore, CauseFloor},
		{ErrFloorBehind, CauseFloor},
		{policy.ErrTooLarge, CauseBundleInvalid},
		{policy.ErrUnknownField, CauseBundleInvalid},
		{policy.ErrSignatureAlg, CauseBundleInvalid},
		{policy.ErrKey, CauseBundleInvalid},
		{policy.ErrSignature, CauseBundleInvalid},
		{policy.ErrDocument, CauseBundleInvalid},
		{policy.ErrNotCanonical, CauseBundleInvalid},
		{policy.ErrDigest, CauseBundleInvalid},
		{policy.ErrMismatch, CauseBundleInvalid},
		{policy.ErrCreatedAt, CauseBundleInvalid},
	} {
		if errors.Is(err, c.err) {
			return c.cause
		}
	}
	return CauseUnknown
}
