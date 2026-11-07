package stoplist

import (
	"errors"

	"github.com/guardana/control/internal/reaction"
)

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The refusals of the reader. Each is returned wrapped, beside what it refers
// to, and each maps to one Cause.
const (
	ErrMissing          Error = "stoplist: the stop list does not exist"
	ErrLink             Error = "stoplist: the stop list is a symbolic link"
	ErrDirLink          Error = "stoplist: the stop list's directory is a symbolic link"
	ErrNotRegular       Error = "stoplist: the stop list is not a regular file"
	ErrFileMode         Error = "stoplist: the group or others may write the stop list"
	ErrDirMode          Error = "stoplist: the group or others may write the stop list's directory"
	ErrFileOwner        Error = "stoplist: the stop list is owned by another account"
	ErrDirOwner         Error = "stoplist: the stop list's directory is owned by another account"
	ErrDirChanged       Error = "stoplist: the stop list's directory changed while it was opened"
	ErrFileChanged      Error = "stoplist: the stop list changed while it was opened"
	ErrTooLarge         Error = "stoplist: the stop list is over its bound of bytes"
	ErrNoPermissionBits Error = "stoplist: this platform keeps no permission bits to check"
	// ErrPlaneOwned is a list or its directory owned by the plane's own
	// account under the signed authority, which that account could rewrite.
	ErrPlaneOwned Error = "stoplist: under the signed authority the plane's own account owns it"
)

// The refusals of a signed list against the plane's stop list floor, which
// the floor's taker wraps.
const (
	ErrBelowFloor Error = "stoplist: the signed list's serial is below the plane's stop list floor"
	ErrForked     Error = "stoplist: the signed list's serial is the floor's and its head is another"
	ErrChain      Error = "stoplist: the signed list does not follow the floor: it rises above it naming another previous list, or cuts or changes lines the floor holds"
	ErrFloor      Error = "stoplist: the stop list floor cannot be read or raised"
)

// The refusals of the poller.
const (
	// ErrOptions is a poller asked for with no directory, no route, no clock
	// or an interval that is not positive.
	ErrOptions Error = "stoplist: a poller needs a directory, a route, a clock and a positive interval"
	// ErrNotServable is a stop list a poller refuses to start on: whatever
	// made its first read unknown.
	ErrNotServable Error = "stoplist: the stop list cannot be served"
)

// The causes of an unknown state a read of the file names, beside the ones
// the judge of its content names.
const (
	CauseMissing    reaction.Cause = "missing"
	CauseUnreadable reaction.Cause = "unreadable"
	CauseLink       reaction.Cause = "a link"
	CauseMode       reaction.Cause = "writable by others"
	CauseOwner      reaction.Cause = "owned by another account"
	CausePlaneOwned reaction.Cause = "owned by the plane's account"
	CauseBelowFloor reaction.Cause = "below its floor"
	CauseForked     reaction.Cause = "forked at its floor"
	CauseChain      reaction.Cause = "a broken chain"
	CauseFloor      reaction.Cause = "floor unusable"
)

// Causes is every cause a poller's snapshot can report: the file's, then the
// judge's. The slice is a copy.
func Causes() []reaction.Cause {
	return append([]reaction.Cause{
		CauseMissing, CauseUnreadable, CauseLink, CauseMode, CauseOwner,
		CausePlaneOwned, CauseBelowFloor, CauseForked, CauseChain, CauseFloor,
	}, reaction.Causes()...)
}

// CauseOf names the cause of a read that failed with err. A refusal it does
// not know is CauseUnreadable.
func CauseOf(err error) reaction.Cause {
	for _, c := range []struct {
		err   Error
		cause reaction.Cause
	}{
		{ErrMissing, CauseMissing},
		{ErrLink, CauseLink}, {ErrDirLink, CauseLink},
		{ErrFileMode, CauseMode}, {ErrDirMode, CauseMode},
		{ErrFileOwner, CauseOwner}, {ErrDirOwner, CauseOwner},
		{ErrTooLarge, reaction.CauseTooLarge},
		{ErrPlaneOwned, CausePlaneOwned}, {ErrBelowFloor, CauseBelowFloor}, {ErrForked, CauseForked},
		{ErrChain, CauseChain}, {ErrFloor, CauseFloor},
	} {
		if errors.Is(err, c.err) {
			return c.cause
		}
	}
	return CauseUnreadable
}
