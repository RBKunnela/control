package runs

import (
	"fmt"
	"time"
)

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The vocabulary of the directory and of a file in it.
const (
	// ErrClosed is an operation on a handle nobody opened, or one closed. The
	// zero value of either handle answers it.
	ErrClosed Error = "runs: the directory is not open"
	// ErrNoLock is a platform with no file lock. Neither handle opens there,
	// since two writers of one root's state could not be kept apart.
	ErrNoLock Error = "runs: this platform has no file lock"
	// ErrPermissions is a directory a group or the world may write.
	ErrPermissions Error = "runs: the directory is group- or world-writable"
	// ErrOwner is a directory this user does not own: its records would be
	// another account's word on which runs exist.
	ErrOwner Error = "runs: the directory is not owned by this user"
	// ErrLockChanged is a root's lock file replaced while a raise held it, so
	// another writer may hold the lock at the new file.
	ErrLockChanged Error = "runs: a root's lock file was replaced"
	// ErrDirectoryChanged is a directory that is no longer the one a handle
	// opened: another directory at its name, another owner, or a mode a group
	// or the world may write. Every call judges it first.
	ErrDirectoryChanged Error = "runs: the directory changed since it was opened"
	// ErrNotRunsDir is a directory that holds no marker and is not empty, or
	// whose marker this build cannot read.
	ErrNotRunsDir Error = "runs: the directory is not a runs directory"
	// ErrForeignFile is a name under the directory this package does not
	// write, any entry that is not a regular file whatever it is called, and
	// a file read that another user owns or a group or the world may write.
	ErrForeignFile Error = "runs: a file under the directory is not the directory's"
	// ErrTooLarge is a file over the bound a read holds it to.
	ErrTooLarge Error = "runs: the file is larger than the bound allows"
	// ErrMalformed is a file that is not one JSON object, or one whose field
	// holds a value of the wrong type or shape.
	ErrMalformed Error = "runs: the file is malformed"
	// ErrEncoding is a string that is not valid UTF-8 or escapes an unpaired
	// surrogate. Decoded, either reads as U+FFFD, so two files would read as
	// one.
	ErrEncoding Error = "runs: a string is not valid UTF-8 or escapes an unpaired surrogate"
	// ErrUnknownField is a key this build cannot name.
	ErrUnknownField Error = "runs: the file carries an unknown field"
	// ErrMissingField is a key the format requires that the file lacks. No
	// field has a default.
	ErrMissingField Error = "runs: the file lacks a required field"
	// ErrDuplicateField is a key given twice, which a reader could take
	// either way.
	ErrDuplicateField Error = "runs: the file gives a field twice"
	// ErrSchemaVersion is a schema version whose major this build does not
	// read.
	ErrSchemaVersion Error = "runs: the schema version is not one this build reads"
	// ErrNameMismatch is a file whose run id or root disagrees with its name.
	ErrNameMismatch Error = "runs: the file's name disagrees with what it holds"
)

// The vocabulary of the operator's side.
const (
	// ErrRunID is a run id that is not "run-" and 32 lower-case hex digits.
	ErrRunID Error = "runs: not a run id"
	// ErrZeroTime is a clock reading of zero, which would leave nothing
	// expired.
	ErrZeroTime Error = "runs: the clock reads zero"
	// ErrTTL is a lifetime outside MinTTL and MaxTTL.
	ErrTTL Error = "runs: the lifetime is outside its bounds"
	// ErrIdentity is an identity with an empty, over-long or refused field.
	ErrIdentity Error = "runs: the identity has an empty, too long or refused field"
	// ErrParentUnknown is a parent no record names.
	ErrParentUnknown Error = "runs: the parent run does not exist"
	// ErrParentClosed is a parent the operator closed.
	ErrParentClosed Error = "runs: the parent run is closed"
	// ErrParentExpired is a parent expired at the clock reading given.
	ErrParentExpired Error = "runs: the parent run has expired"
	// ErrParentTenant is a parent opened for another tenant.
	ErrParentTenant Error = "runs: the parent run belongs to another tenant"
	// ErrParentProject is a parent opened for another project.
	ErrParentProject Error = "runs: the parent run belongs to another project"
	// ErrParentOutlived is a run whose expiry would pass its parent's. An
	// *OutlivesParentError carries it.
	ErrParentOutlived Error = "runs: the run would outlive its parent"
	// ErrNoRun is a close or a lookup of a run no record names.
	ErrNoRun Error = "runs: no such run"
	// ErrAlreadyClosed is a close of a run closed already.
	ErrAlreadyClosed Error = "runs: the run is closed already"
	// ErrExists is a fresh run id whose files are there already.
	ErrExists Error = "runs: the run's files exist already"
	// ErrBound is a listing bound that is not positive.
	ErrBound Error = "runs: the listing bound is not positive"
	// ErrNotRoot is a tree asked for by a run opened under another.
	ErrNotRoot Error = "runs: the run is not a root"
	// ErrTreeBound is a tree, or a run's children, past the bound asked for.
	ErrTreeBound Error = "runs: the tree holds more runs than its bound"
	// ErrTreeTenant is a run of a tree opened for another tenant than its
	// root, which only a writer of the directory can make.
	ErrTreeTenant Error = "runs: a run of the tree belongs to another tenant"
	// ErrTreeProject is a run of a tree opened for another project than its
	// root, which only a writer of the directory can make.
	ErrTreeProject Error = "runs: a run of the tree belongs to another project"
	// ErrTreeBroken is a run whose chain of parents does not reach its
	// tree's root within the tree.
	ErrTreeBroken Error = "runs: a run's parents do not reach its root"
	// ErrState is a state this build cannot write: a sensitivity it cannot
	// name.
	ErrState Error = "runs: the state cannot be written"
)

// OutlivesParentError is an opening refused because the run would expire after
// its parent. It matches ErrParentOutlived.
type OutlivesParentError struct {
	Parent                     string
	ExpiresAt, ParentExpiresAt time.Time
}

// Error names both expiries.
func (e *OutlivesParentError) Error() string {
	return fmt.Sprintf("%s: it would expire at %s, its parent %s at %s",
		ErrParentOutlived, formatTime(e.ExpiresAt), e.Parent, formatTime(e.ParentExpiresAt))
}

// Unwrap returns ErrParentOutlived.
func (e *OutlivesParentError) Unwrap() error { return ErrParentOutlived }

// Cause is why a token was refused. The values are a fixed label set, so
// none ever names a run.
type Cause string

// The causes, in the order Resolve judges them.
const (
	// CauseMissing is an empty token.
	CauseMissing Cause = "missing"
	// CauseMalformed is a token that is not a run id and a secret.
	CauseMalformed Cause = "malformed"
	// CauseUnknown is a run id no record holds, or a secret that does not
	// match the record's. The two are one cause, so a caller without the
	// secret learns nothing about which ids exist.
	CauseUnknown Cause = "unknown"
	// CauseIdentity is a record for another project, tenant, principal or
	// agent.
	CauseIdentity Cause = "identity"
	// CauseClosed is a run the operator closed.
	CauseClosed Cause = "closed"
	// CauseExpired is a run expired at the reading, or a zero reading.
	CauseExpired Cause = "expired"
	// CauseUnreadable is a record or a directory that could not be read.
	CauseUnreadable Cause = "unreadable"
)

// Causes returns every cause, in the order Resolve judges them.
func Causes() []Cause {
	return []Cause{CauseMissing, CauseMalformed, CauseUnknown, CauseIdentity, CauseClosed, CauseExpired, CauseUnreadable}
}

// Refusal is a token Resolve refused, and why.
type Refusal struct {
	Cause Cause
	Err   error
}

// Error names the cause and what caused it.
func (r *Refusal) Error() string {
	if r.Err == nil {
		return "runs: token refused: " + string(r.Cause)
	}
	return fmt.Sprintf("runs: token refused: %s: %v", r.Cause, r.Err)
}

// Unwrap returns what caused the refusal.
func (r *Refusal) Unwrap() error { return r.Err }

func refuse(c Cause, err error) *Refusal { return &Refusal{Cause: c, Err: err} }
