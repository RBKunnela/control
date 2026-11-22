package policystate

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The vocabulary of the directory.
const (
	// ErrClosed is a call on a store nobody opened, or one closed. The zero
	// Store answers it.
	ErrClosed Error = "policystate: the directory is not open"
	// ErrNoLock is a platform with no file lock. Nothing opens a directory
	// there, since two writers of one floor could not be kept apart.
	ErrNoLock Error = "policystate: this platform has no file lock"
	// ErrKind is a kind Open, Init or Reset does not take: neither KindPlane
	// nor KindSigner. KindRoute has functions of its own.
	ErrKind Error = "policystate: not a kind of floor directory"
	// ErrWrongKind is a directory of another kind: a plane's floors are not a
	// signer's, neither is a route floor directory, and the reverse.
	ErrWrongKind Error = "policystate: the directory is another kind's"
	// ErrNotStateDir is a path that is not a floor directory: missing, not a
	// directory, a link, holding no marker, or one this build cannot read.
	ErrNotStateDir Error = "policystate: not a floor directory"
	// ErrPermissions is a directory or a file whose mode gives its group or
	// the world any access.
	ErrPermissions Error = "policystate: the mode gives the group or the world access"
	// ErrOwner is a directory or a file this user does not own: its floor
	// would be another account's word.
	ErrOwner Error = "policystate: not owned by this user"
	// ErrDirectoryChanged is a directory that is no longer the one the store
	// opened: another directory at its name, another owner, or a mode that
	// gives the group or the world access. Every call judges it first.
	ErrDirectoryChanged Error = "policystate: the directory changed since it was opened"
	// ErrForeignFile is a name under the directory this package does not
	// write, and any entry that is not a regular file whatever its name.
	ErrForeignFile Error = "policystate: a file under the directory is not the directory's"
	// ErrTooLarge is a file over the bound every read holds it to.
	ErrTooLarge Error = "policystate: the file is larger than the bound allows"
)

// The vocabulary of a floor file.
const (
	// ErrNoFloor is a bundle id or a route id the directory holds no floor
	// file for. It is never read as a floor with no serial: a removed file is
	// not a first start.
	ErrNoFloor Error = "policystate: no floor file for the id"
	// ErrMalformed is a file that is not one strict JSON object, or one whose
	// member holds a value of the wrong type or form.
	ErrMalformed Error = "policystate: the file is malformed"
	// ErrUnknownField is a member the format does not have.
	ErrUnknownField Error = "policystate: the file holds a member the format does not have"
	// ErrMissingField is a member the format requires that the file lacks.
	// No member has a default.
	ErrMissingField Error = "policystate: the file lacks a member the format requires"
	// ErrDuplicateField is a member named twice, which a reader could take
	// either way.
	ErrDuplicateField Error = "policystate: the file names a member twice"
	// ErrSchemaVersion is a schema version whose major this build does not
	// read.
	ErrSchemaVersion Error = "policystate: the schema version is not one this build reads"
	// ErrUnwritable is a record or a marker the writer would write as bytes
	// the reader refuses or reads otherwise; nothing is written.
	ErrUnwritable Error = "policystate: the record would not read back as itself"
	// ErrNameMismatch is a floor file whose bundle_id or route_id is not the
	// id its name is the hash of.
	ErrNameMismatch Error = "policystate: the file's name is not the hash of the id it holds"
)

// The vocabulary of the operator's side.
const (
	// ErrExists is Init or InitRoute for an id that has a floor file already.
	// Neither replaces one, so neither is a second way to lower a floor.
	ErrExists Error = "policystate: the id has a floor file already"
	// ErrTooManyBundleIDs is Init of an id past MaxBundleIDs, or a marker
	// listing more.
	ErrTooManyBundleIDs Error = "policystate: the directory lists as many bundle ids as it may"
	// ErrTooManyRouteIDs is InitRoute of an id past MaxRouteIDs, or a route
	// marker listing more.
	ErrTooManyRouteIDs Error = "policystate: the directory lists as many route ids as it may"
	// ErrFloorRemoved is Init or InitRoute of an id the marker lists whose
	// file is gone: making it again would lower the floor with no record, so
	// only Reset gives a bundle id a floor again, and nothing a route id.
	ErrFloorRemoved Error = "policystate: the id's floor file was removed; Init does not make it again"
	// ErrReason is a reset with an empty reason, one over MaxReasonBytes, or
	// one holding a character a log line should not carry.
	ErrReason Error = "policystate: the reset reason is empty, too long or refused"
)

// The vocabulary of a route floor.
const (
	// ErrRouteInvalid is a route id, serial or digest no route can carry.
	ErrRouteInvalid Error = "policystate: not a route id, serial or digest a route can carry"
	// ErrRouteBelowFloor is a route whose serial is below its floor's.
	ErrRouteBelowFloor Error = "policystate: the route's serial is below the floor's"
	// ErrRouteForked is a route at its floor's serial with another digest:
	// two routes signed under one serial.
	ErrRouteForked Error = "policystate: the route's serial is the floor's but its digest is another"
	// ErrStagingTaken is a staging name where something stands that no
	// build of a floor directory left: a build never removes it.
	ErrStagingTaken Error = "policystate: the name a floor directory is built under holds what no build left there"
)
