package holdjournal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// dirFiles is one directory's files, reached through root and written by the
// rules below; the journal and its ledger each have one.
type dirFiles struct {
	root *os.Root
}

// errExists is a name that was there already. Each caller translates it into
// the refusal its own operation documents, so no caller has to read a file
// system error to learn what happened.
const errExists Error = "holdjournal: the name exists already"

// writeSynced writes body to name in the directory, where no name
// points at yet, and forces it to disk. A file this fails on is removed: a
// temporary name nobody linked or renamed is not an entry, and the next open
// would only have to sweep it.
func (d dirFiles) writeSynced(name string, body []byte) error {
	f, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return errors.Join(err, d.root.Remove(name))
	}
	return nil
}

// tmpName is a name no entry can take.
func tmpName() string {
	return tmpPrefix + rand.Text() + tmpSuffix
}

// create writes body under name, which must not be there: the link fails with
// EEXIST rather than replacing an entry that exists already. The file is
// forced to disk before the link and the directory after it, so a name that
// was reported written survives a power loss. A failure after the link wraps
// ErrMaybeRecorded and leaves the name in place: whether it survives a power
// loss is unknown, and an unlink could not be forced to disk either, so the
// caller moves the entry out of held and forgets it as it would a filed one.
func (d dirFiles) create(name string, body []byte) error {
	tmp := tmpName()
	if err := d.writeSynced(tmp, body); err != nil {
		return err
	}
	err := d.root.Link(tmp, name)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.Join(errExists, d.root.Remove(tmp))
		}
		return errors.Join(err, d.root.Remove(tmp))
	}
	if err := errors.Join(d.root.Remove(tmp), d.syncDir()); err != nil {
		return fmt.Errorf("%w: %w", ErrMaybeRecorded, err)
	}
	return nil
}

// replace puts body under name, over whatever is there. The rename is atomic,
// so a crash leaves the old state or the new one and never a torn file, and
// the directory is forced to disk before the write is reported durable.
func (d dirFiles) replace(name string, body []byte) error {
	tmp := tmpName()
	if err := d.writeSynced(tmp, body); err != nil {
		return err
	}
	if err := d.root.Rename(tmp, name); err != nil {
		return errors.Join(err, d.root.Remove(tmp))
	}
	return d.syncDir()
}

// remove unlinks one name and reports whether it was there. A name that is
// already gone is not a failure: forgetting a request the journal holds no
// entry for is what the caller does after every execution it closes.
func (d dirFiles) remove(name string) (bool, error) {
	err := d.root.Remove(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, d.syncDir()
}

// dirSync forces an open directory to disk; a test replaces it to make that
// fail.
var dirSync = (*os.File).Sync

// syncDir forces the directory's entries to disk, so a name that was linked,
// renamed or unlinked before a power loss is in that state after it.
func (d dirFiles) syncDir() error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dirSync(f), f.Close())
}

// openRegular opens name to read it, and refuses anything but a regular file
// this account owns, and no group or other account may write, that stood at
// name when it looked. A handle on the directory follows a symbolic link that
// stays inside it, so a link is refused by its directory entry before the
// open; the open does not block, so a named pipe swapped in after the look is
// refused by the descriptor rather than waited on under the journal's mutex.
func (d dirFiles) openRegular(name string) (*os.File, error) {
	before, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, cause(name))
	}
	f, err := d.root.OpenFile(name, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.Join(fmt.Errorf("%w: %q changed while it was opened", ErrForeignFile, cause(name)), f.Close())
	}
	if after.Mode().Perm()&0o022 != 0 {
		return nil, errors.Join(fmt.Errorf("%w: %q has mode %04o", ErrForeignFile, cause(name), after.Mode().Perm()), f.Close())
	}
	if err := checkOwner(after); err != nil {
		return nil, errors.Join(fmt.Errorf("%q: %w", cause(name), err), f.Close())
	}
	return f, nil
}

// readBounded reads one file and refuses one larger than limit rather than
// holding what it claims to be. A file that is exactly limit bytes is read;
// one byte more is refused.
func (d dirFiles) readBounded(name string, limit int) ([]byte, error) {
	f, err := d.openRegular(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("%w: over %d bytes", ErrEntryTooLarge, limit)
	}
	return raw, nil
}
