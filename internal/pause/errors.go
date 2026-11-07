package pause

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The refusals of the reader. Each is returned wrapped, beside what it
// refers to, and each maps to one Cause.
const (
	// ErrMissing is a pause file that does not exist.
	ErrMissing Error = "pause: the pause file does not exist"
	// ErrLink is a pause file that is a symbolic link.
	ErrLink Error = "pause: the pause file is a symbolic link"
	// ErrNotRegular is a pause file that is not a regular file.
	ErrNotRegular Error = "pause: the pause file is not a regular file"
	// ErrFileMode is a pause file the group or others may write.
	ErrFileMode Error = "pause: the group or others may write the pause file"
	// ErrDirMode is a directory holding the pause file that the group or
	// others may write, and so replace the file in.
	ErrDirMode Error = "pause: the group or others may write the pause file's directory"
	// ErrFileOwner is a pause file another account than this process's
	// effective user owns, and so may rewrite whatever its mode says.
	ErrFileOwner Error = "pause: the pause file is owned by another account"
	// ErrDirOwner is a directory holding the pause file that another account
	// owns, and so may replace the file in.
	ErrDirOwner Error = "pause: the pause file's directory is owned by another account"
	// ErrDirLink is a directory holding the pause file whose own name is a
	// symbolic link, which a writer of its parent could point anywhere.
	ErrDirLink Error = "pause: the pause file's directory is a symbolic link"
	// ErrDirChanged is a directory holding the pause file that another took
	// the place of while it was being opened.
	ErrDirChanged Error = "pause: the pause file's directory changed while it was opened"
	// ErrFileChanged is a pause file that another took the place of between
	// the check that its name is no link and the open, which follows one.
	ErrFileChanged Error = "pause: the pause file changed while it was opened"
	// ErrTooLarge is a pause file over MaxFileBytes.
	ErrTooLarge Error = "pause: the pause file is over its size bound"
	// ErrMalformed is a document this build refuses: not strict JSON, an
	// unknown or repeated member, a missing one, a value out of its bound or
	// its set, or two entries under one id.
	ErrMalformed Error = "pause: the pause file is malformed"
	// ErrVersion is a document of a schema version this build does not read.
	ErrVersion Error = "pause: the pause file is of a schema version this build does not read"
	// ErrNoPermissionBits is a platform that keeps no permission bits, so
	// nothing can say who may write the file.
	ErrNoPermissionBits Error = "pause: this platform keeps no permission bits to check"
)

// The refusals of a signed file, and of a plane under the signed authority.
const (
	// ErrUnsigned is a version 1 or 2 file under the signed authority, which
	// takes a pause only from an operator's signature.
	ErrUnsigned Error = "pause: the pause file is not signed, and the authority is signed"
	// ErrSignedFile is a signed file under another authority, which holds no
	// roster to check the signature with.
	ErrSignedFile Error = "pause: the pause file is signed, and only a plane under the signed authority checks a signature"
	// ErrUnauthenticated is a signature no operator key of the roster made.
	ErrUnauthenticated Error = "pause: no operator key of the roster signed the pause file"
	// ErrOtherScope is a signed document for another tenant or project than
	// the plane's.
	ErrOtherScope Error = "pause: the signed pause names another tenant or project than the plane's"
	// ErrOtherFile is a signed document for another pause file than the one
	// it was read from: a copy of another plane's.
	ErrOtherFile Error = "pause: the signed pause names another pause file than the one it was read from"
	// ErrNotVouched is a signed file a writer starts from that the roster
	// does not vouch for: a writer that signed it again would sign entries
	// someone without a roster key put there.
	ErrNotVouched Error = "pause: the signed pause file the write starts from is not one the roster vouches for"
	// ErrPlaneOwned is a pause file or its directory owned by the account of
	// a plane under the signed authority, which could then rewrite it.
	ErrPlaneOwned Error = "pause: under the signed authority the plane's own account owns it"
	// ErrUnauthorized is a signer the roster grants no operate over the
	// plane's tenant and project.
	ErrUnauthorized Error = "pause: the signer may not operate in the plane's tenant and project"
	// ErrAuthority is a roster, authenticator or authorizer that gave no
	// answer.
	ErrAuthority Error = "pause: the operator authority gave no answer"
	// ErrBelowFloor is a signed document of a serial below the floor's: an
	// older document replayed.
	ErrBelowFloor Error = "pause: the signed pause's serial is below the floor's"
	// ErrForked is a signed document at the floor's serial with another
	// digest.
	ErrForked Error = "pause: the signed pause's serial is the floor's and its digest is another"
	// ErrFloor is a pause floor that could not be read or raised.
	ErrFloor Error = "pause: the pause floor cannot be read or raised"
	// ErrSigner is a write with no signer or one whose key is not the one the
	// header names, or a signature that could not be made.
	ErrSigner Error = "pause: the document cannot be signed"
	// ErrSigned is an unsigned write to a signed file: dropping the
	// signature would make a file the plane refuses.
	ErrSigned Error = "pause: the pause file is signed, and the write is not"
	// ErrChanged is a pause file that another writer replaced while this one
	// held the lock, which that writer did not take.
	ErrChanged Error = "pause: the pause file changed while it was written"
	// ErrSerial is a signed document at the highest serial there is, which
	// no later one can follow.
	ErrSerial Error = "pause: the signed pause is at the highest serial"
)

// The refusals of the writer.
const (
	// ErrExists is an Init over a pause file that exists already.
	ErrExists Error = "pause: a pause file exists already"
	// ErrLocked is a writer that could not take the lock before its context
	// ended.
	ErrLocked Error = "pause: another writer holds the pause file's lock"
	// ErrNoLock is a platform with no file lock, where two writers could
	// lose each other's entries.
	ErrNoLock Error = "pause: this platform has no file lock for the pause file"
	// ErrDuplicateID is an entry added under an id the document holds.
	ErrDuplicateID Error = "pause: an entry with this id exists already"
	// ErrNoEntry is a removal of an id the document does not hold.
	ErrNoEntry Error = "pause: no entry with this id"
	// ErrOptions is a poller asked for with no path, no clock or an interval
	// that is not positive, a signed read with no judge, or a judge missing a
	// port or a field.
	ErrOptions Error = "pause: a poller needs a path, a clock and a positive interval, and a signed read a judge with every port"
	// ErrNotServable is a pause file a poller refuses to start on: whatever
	// made its first read unknown.
	ErrNotServable Error = "pause: the pause file cannot be served"
)
