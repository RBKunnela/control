package holdjournal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// errExists is a name that was there already. Each caller translates it into
// the refusal its own operation documents, so no caller has to read a file
// system error to learn what happened.
const errExists Error = "holdjournal: the name exists already"

// writeSynced writes body to name in the journal's directory, where no name
// points at yet, and forces it to disk. A file this fails on is removed: a
// temporary name nobody linked or renamed is not an entry, and the next open
// would only have to sweep it.
func (j *Journal) writeSynced(name string, body []byte) error {
	f, err := j.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return errors.Join(err, j.root.Remove(name))
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
func (j *Journal) create(name string, body []byte) error {
	tmp := tmpName()
	if err := j.writeSynced(tmp, body); err != nil {
		return err
	}
	err := j.root.Link(tmp, name)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.Join(errExists, j.root.Remove(tmp))
		}
		return errors.Join(err, j.root.Remove(tmp))
	}
	if err := errors.Join(j.root.Remove(tmp), j.syncDir()); err != nil {
		return fmt.Errorf("%w: %w", ErrMaybeRecorded, err)
	}
	return nil
}

// replace puts body under name, over whatever is there. The rename is atomic,
// so a crash leaves the old state or the new one and never a torn file, and
// the directory is forced to disk before the write is reported durable.
func (j *Journal) replace(name string, body []byte) error {
	tmp := tmpName()
	if err := j.writeSynced(tmp, body); err != nil {
		return err
	}
	if err := j.root.Rename(tmp, name); err != nil {
		return errors.Join(err, j.root.Remove(tmp))
	}
	return j.syncDir()
}

// remove unlinks one name and reports whether it was there. A name that is
// already gone is not a failure: forgetting a request the journal holds no
// entry for is what the caller does after every execution it closes.
func (j *Journal) remove(name string) (bool, error) {
	err := j.root.Remove(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, j.syncDir()
}

// dirSync forces an open directory to disk; a test replaces it to make that
// fail.
var dirSync = (*os.File).Sync

// syncDir forces the directory's entries to disk, so a name that was linked,
// renamed or unlinked before a power loss is in that state after it.
func (j *Journal) syncDir() error {
	d, err := j.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dirSync(d), d.Close())
}

// openRegular opens name to read it, and refuses anything but a regular file
// this account owns, and no group or other account may write, that stood at
// name when it looked. A handle on the directory follows a symbolic link that
// stays inside it, so a link is refused by its directory entry before the
// open; the open does not block, so a named pipe swapped in after the look is
// refused by the descriptor rather than waited on under the journal's mutex.
func (j *Journal) openRegular(name string) (*os.File, error) {
	before, err := j.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, cause(name))
	}
	f, err := j.root.OpenFile(name, os.O_RDONLY|nonBlocking, 0)
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
func (j *Journal) readBounded(name string, limit int) ([]byte, error) {
	f, err := j.openRegular(name)
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
