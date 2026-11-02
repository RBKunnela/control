package segmentlog

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

const (
	// ErrKind is a kind this build does not know.
	ErrKind Error = "segmentlog: unknown kind"
	// ErrConfig is a configuration no log opens with.
	ErrConfig Error = "segmentlog: the configuration is refused"
	// ErrNoPermissionBits is a platform that keeps no permission bits, so
	// the directory cannot be checked.
	ErrNoPermissionBits Error = "segmentlog: this platform keeps no permission bits to check"
	// ErrNoLock is a platform with no file lock, so the directory cannot be
	// held by one writer.
	ErrNoLock Error = "segmentlog: this platform has no file lock, so the directory cannot be held"
	// ErrDirectory is a directory the group or others may write, another
	// account owns, or that holds a name no writer of this package leaves.
	ErrDirectory Error = "segmentlog: the directory is not one only this account writes, or holds a foreign name"
	// ErrLocked is a directory another writer holds.
	ErrLocked Error = "segmentlog: the directory is held by another writer"
	// ErrManifest is a manifest that does not decode as this package writes
	// it, or that disagrees with the files it names.
	ErrManifest Error = "segmentlog: the manifest is refused"
	// ErrVersion is a manifest of a format or version this build does not
	// read.
	ErrVersion Error = "segmentlog: the manifest's format or version is not one this build reads"
	// ErrBinding is a log bound to another tenant or project.
	ErrBinding Error = "segmentlog: the log is bound to another tenant or project"
	// ErrBudget is an append the log's byte bound refuses, or any append to a
	// log opened with no bound.
	ErrBudget Error = "segmentlog: the log is at its byte bound; an operator prunes sealed segments"
	// ErrFull is a seal past the most segments a manifest names.
	ErrFull Error = "segmentlog: the manifest names the most segments it may"
	// ErrLines is an append that is not whole lines.
	ErrLines Error = "segmentlog: an append is whole lines, each ending in a newline"
	// ErrPrune is a prune that names no sealed segment, or the live one.
	ErrPrune Error = "segmentlog: a prune names sealed segments only"
	// ErrClock is a prune whose clock stands before the seal of a segment it
	// would prune, a date the manifest cannot hold.
	ErrClock Error = "segmentlog: the clock stands before a segment's seal"
	// ErrClosed is a call on a log that is closed.
	ErrClosed Error = "segmentlog: the log is closed"
	// ErrFailed is a call on a log a seal or a prune left part way, or whose
	// live file changed under it: the next open completes the step or counts
	// the file again, and until then the log takes nothing more.
	ErrFailed Error = "segmentlog: a seal or a prune stopped part way, or the live file changed; open the log again"
	// ErrLiveChanged is a failed append after which the live file no longer
	// holds what the log counted, so the log fails.
	ErrLiveChanged Error = "segmentlog: the live file no longer holds what the log counted"
	// ErrMoved is a segment that a seal or a prune moved between reading the
	// manifest and opening the file.
	ErrMoved Error = "segmentlog: the segment moved while it was opened"
)
