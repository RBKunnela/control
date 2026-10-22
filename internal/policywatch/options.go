package policywatch

import (
	"log/slog"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
)

// Error is a refusal of this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The refusals no other package names.
const (
	// ErrOptions is Options missing what Start, Check or a refresher needs.
	ErrOptions Error = "policywatch: the options name no bundle id, file, key, holder, floor or clock, or an interval or budget that is not positive"
	// ErrClockBack is a wall clock more than a second below the mark.
	ErrClockBack Error = "policywatch: the wall clock stands more than a second below the highest it has read, so no statement is taken"
	// ErrStatementExpired is a statement whose budget ran out before it was
	// read; it confirms nothing, at start as at a poll.
	ErrStatementExpired Error = "policywatch: the statement's budget has run out"
	// ErrNoSnapshot is a refresher over a holder Start installed nothing in.
	ErrNoSnapshot Error = "policywatch: the holder serves no snapshot; Start installs the first"
	// ErrFloorBehind is a floor read back below the statement this plane
	// confirmed and raised it to: a copy restored from before that raise.
	ErrFloorBehind Error = "policywatch: the floor was read back below the statement this plane confirmed"
)

// Options configure Start, Check and a Refresher.
type Options struct {
	// BundleID is the one bundle id the plane serves.
	BundleID string
	// BundlePath and StatementPath are the two files read at every poll.
	BundlePath, StatementPath string
	// BundleKeys verify a bundle and FreshnessKeys a statement.
	BundleKeys, FreshnessKeys bundle.Keyring
	// Holder is the plane's holder, made by policy.NewFloorHolder over Floor.
	Holder *policy.Holder
	// Floor is the store the holder raises; Start and every poll read it.
	Floor policy.FloorStore
	// Interval is the poll interval and MaxStale the operator's budget.
	Interval, MaxStale time.Duration
	// Wall reads the wall clock and Mono the monotonic one, as a duration
	// since any fixed origin.
	Wall func() time.Time
	Mono func() time.Duration
	// Logger takes each refusal when its cause changes, each install and
	// each confirmation; nil logs nothing.
	Logger *slog.Logger
}

// check refuses options a refresher or Start cannot run on.
func (o Options) check() error {
	if err := o.checkReading(); err != nil {
		return err
	}
	if o.Holder == nil || o.Mono == nil {
		return ErrOptions
	}
	return nil
}

// checkReading refuses options Check cannot judge the files by.
func (o Options) checkReading() error {
	if o.BundleID == "" || o.BundlePath == "" || o.StatementPath == "" || len(o.BundleKeys) == 0 ||
		len(o.FreshnessKeys) == 0 || o.Floor == nil || o.Wall == nil || o.Interval <= 0 || o.MaxStale <= 0 {
		return ErrOptions
	}
	return nil
}

// Stats is what a Refresher counted since New.
type Stats struct {
	// Polls counts the polls made.
	Polls uint64
	// Refused counts the polls that moved nothing because something was
	// refused, by cause.
	Refused map[Cause]uint64
	// AwaitingStatement counts the polls that found a new bundle whose
	// statement still names another, and AwaitingBundle those that found a
	// statement naming a bundle not yet on disk.
	AwaitingStatement uint64
	AwaitingBundle    uint64
	// Confirmations counts the statements accepted, renewals and installs
	// alike, and Installs the bundles that replaced the current one.
	Confirmations uint64
	Installs      uint64
	// Withdrawals counts the confirmations the clock rule took back.
	Withdrawals uint64
}
