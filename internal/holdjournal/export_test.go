package holdjournal

import (
	"io/fs"
	"os"
)

// SetOwnerWanted makes uid name the account each file or directory the
// journal judges has to belong to, until the returned function restores the
// real one.
func SetOwnerWanted(uid func(fs.FileInfo) int) (restore func()) {
	saved := ownerWanted
	ownerWanted = uid
	return func() { ownerWanted = saved }
}

// SetDirSync makes sync what forces the journal's directory to disk, until the
// returned function restores the real one.
func SetDirSync(sync func(*os.File) error) (restore func()) {
	saved := dirSync
	dirSync = sync
	return func() { dirSync = saved }
}
