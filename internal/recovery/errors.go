package recovery

// Error is a refusal by this package, matched with errors.Is.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The refusals.
const (
	// ErrManifest is a backup.json this build cannot read exactly.
	ErrManifest Error = "recovery: the manifest is malformed"
	// ErrVersion is a manifest of a major this build does not read.
	ErrVersion Error = "recovery: the manifest's schema version is not one this build reads"
	// ErrMemory is a backup or a restore under the memory authority, which
	// keeps nothing a restore could take back.
	ErrMemory Error = "recovery: the memory authority keeps no state to back up or restore"
	// ErrOtherPlane is a backup of another tenant, project or authority than
	// the configuration's.
	ErrOtherPlane Error = "recovery: the backup is another tenant's, project's or authority's"
	// ErrSource is an entry whose source or path is not where the
	// configuration puts that file.
	ErrSource Error = "recovery: a file of the backup does not come from where the configuration puts it"
	// ErrTampered is a file whose size or SHA-256 is not the manifest's.
	ErrTampered Error = "recovery: a file of the backup is not the one the manifest names"
	// ErrUnlisted is a file in the backup the manifest does not name, or an
	// entry that is not a regular file.
	ErrUnlisted Error = "recovery: the backup holds a file the manifest does not name"
	// ErrStopHistories is a stop list that survived and neither begins with
	// the backup's list nor carries it: two histories of the plane's stops.
	ErrStopHistories Error = "recovery: the stop list and the backup's are two histories"
	// ErrPlaneRunning is a backup or a restore while a plane holds the
	// spool's or the hold journal's directory.
	ErrPlaneRunning Error = "recovery: a plane holds its directories; stop it first"
	// ErrNoLock is a platform without the file lock a plane takes, where
	// nothing would keep one from starting halfway through.
	ErrNoLock Error = "recovery: this platform has no file lock to keep a plane out"
	// ErrExists is a backup into a directory that exists.
	ErrExists Error = "recovery: the backup directory exists"
	// ErrNotRegular is a file or directory of the state a backup copies that
	// is neither: a link, a pipe, a device.
	ErrNotRegular Error = "recovery: the state holds an entry that is neither a regular file nor a directory"
)
