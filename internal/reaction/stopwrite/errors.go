package stopwrite

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The writer's refusals. A refusal of the list's file itself is the reader's
// sentinel, from internal/reaction/stoplist, since the writer judges the
// file as a plane does.
const (
	// ErrExists is an Init or a Carry over a stop list that exists already.
	ErrExists Error = "stopwrite: a stop list exists already"
	// ErrLocked is a writer that could not take the lock before its context
	// ended.
	ErrLocked Error = "stopwrite: another writer holds the stop list's lock"
	// ErrNoLock is a platform with no file lock, where two writers could
	// each judge the list without the other's line.
	ErrNoLock Error = "stopwrite: this platform has no file lock for the stop list"
	// ErrRefused is a write the plane's judge would refuse the list for,
	// wrapping the judge's refusal, or one under a route naming a rule that
	// may not stop a run, which a plane refuses to start on; nothing is
	// written.
	ErrRefused Error = "stopwrite: the plane's judge would refuse the list this write makes"
	// ErrNamed is a finding AppendFinding was given that the list names
	// already, by another writer since its caller read the list; nothing is
	// written.
	ErrNamed Error = "stopwrite: the stop list names the finding already"
	// ErrCarried is a write to a list its owner may not write, as a signed
	// carry leaves the list it carried from: a line appended to it after the
	// carry would be one a plane still serving it takes and the carried list
	// lacks; nothing is written.
	ErrCarried Error = "stopwrite: the stop list is read-only, as a carry leaves the list it carried from"
	// ErrNothingLifted is a lift that ends no stop of its run, agent or
	// principal through its line in the list as it stands under the lock,
	// such as one read from the list before another lift ended that stop;
	// nothing is written.
	ErrNothingLifted Error = "stopwrite: the lift ends no stop the list holds"
	// ErrFull is a write that would take the list past its bound of bytes or
	// of lines, wrapping the judge's refusal; nothing is written.
	ErrFull Error = "stopwrite: the write would take the stop list past its bounds"
)
