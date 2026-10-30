//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package spool

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// lockFile is the file that holds the directory on a platform without flock.
const lockFile = "spool.lock"

// lockDir creates the lock file exclusively in the directory root holds, named
// dir in errors, naming the process that holds it, and returns what removes
// it. One a dead process left behind is refused by name: whether its holder is
// gone is the operator's call, not the spool's.
func lockDir(root *os.Root, dir string) (func() error, error) {
	f, err := root.OpenFile(lockFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("%w: %s exists; remove it once no process holds the spool", ErrLocked, filepath.Join(dir, lockFile))
	}
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return nil, errors.Join(fmt.Errorf("spool: %w", err), root.Remove(lockFile))
	}
	return func() error { return root.Remove(lockFile) }, nil
}

// shareDir reports whether a spool holds the directory root holds, named dir
// in errors, by its lock file. It takes nothing, since a lock here is a file
// it would have to create, so a spool may open the directory meanwhile.
func shareDir(root *os.Root, dir string) (release func() error, held bool, err error) {
	_, err = root.Lstat(lockFile)
	switch {
	case err == nil:
		return nil, true, nil
	case errors.Is(err, fs.ErrNotExist):
		return func() error { return nil }, false, nil
	}
	return nil, false, fmt.Errorf("spool: asking whether a spool holds %q: %w", dir, err)
}
