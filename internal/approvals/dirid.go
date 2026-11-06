package approvals

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// effectiveUID is the account an approvals directory has to belong to.
var effectiveUID = os.Geteuid

// The steps a test can act at: the directory judged at open, the plane's
// lock taken, a call's judge passed, and a name linked before anything reads
// the directory again.
const (
	stepOpened = "opened"
	stepLocked = "locked"
	stepJudged = "judged"
	stepLinked = "linked"
)

// withSteps runs f at each step, so a test can swap the directory under its
// name in between.
func withSteps(f func(step string)) Option {
	return func(o *options) error {
		o.steps = f
		return nil
	}
}

func (s *store) step(name string) {
	if s.opts.steps != nil {
		s.opts.steps(name)
	}
}

// writableByOthers is the mode bits that make a directory's approvals a
// group's or the world's.
const writableByOthers fs.FileMode = 0o022

// dirID is what a directory is judged by: which directory it is, who owns it,
// and its permission bits.
type dirID struct {
	dev, ino uint64
	uid      uint32
	perm     fs.FileMode
}

// still refuses now unless it is the directory o describes, under the same
// owner, and writable by nobody else.
func (o dirID) still(now dirID) error {
	switch {
	case now.dev != o.dev || now.ino != o.ino:
		return fmt.Errorf("%w: another directory stands at its name", ErrDirectoryChanged)
	case now.uid != o.uid:
		return fmt.Errorf("%w: owned by uid %d, opened owned by uid %d", ErrDirectoryChanged, now.uid, o.uid)
	case now.perm&writableByOthers != 0:
		return fmt.Errorf("%w: %w: mode %04o", ErrDirectoryChanged, ErrPermissions, now.perm)
	}
	return nil
}

// sameDirectory refuses now unless it is the directory o describes. It is
// how a name is judged: what matters there is only whether it still names
// the directory the handle opened.
func (o dirID) sameDirectory(now dirID) error {
	if now.dev != o.dev || now.ino != o.ino {
		return fmt.Errorf("%w: another directory stands at its name", ErrDirectoryChanged)
	}
	return nil
}

// openRoot opens dir as a root, and judges the directory the root holds: a
// directory a group or the world may write, or another account owns, would
// make every approval theirs. anyOwner lets another account own it, for a
// handle that writes nothing there.
// Every file this store reads or writes after this is named through the root,
// so a directory put at dir later is never read or written through it.
func openRoot(dir string, anyOwner bool) (*os.Root, dirID, error) {
	// The trailing "." fails on anything but a directory rather than wait on
	// a named pipe put at dir.
	root, err := os.OpenRoot(dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, dirID{}, fmt.Errorf("%w: %w", ErrNotAStore, err)
	}
	info, err := root.Stat(".")
	if err != nil {
		return nil, dirID{}, errors.Join(fmt.Errorf("%w: %w", ErrNotAStore, err), root.Close())
	}
	if info.Mode().Perm()&writableByOthers != 0 {
		return nil, dirID{}, errors.Join(fmt.Errorf("%w: mode %04o", ErrPermissions, info.Mode().Perm()), root.Close())
	}
	id, err := identify(info)
	if err != nil {
		return nil, dirID{}, errors.Join(err, root.Close())
	}
	if euid := effectiveUID(); !anyOwner && (euid < 0 || int64(id.uid) != int64(euid)) {
		return nil, dirID{}, errors.Join(fmt.Errorf("%w: owned by uid %d", ErrOwner, id.uid), root.Close())
	}
	return root, id, nil
}

// judge holds the directory the root holds to what it was when the handle
// opened it: the same owner, and writable by nobody else. It also refuses a
// name that no longer names that directory, though no file is reached through
// the name: a handle serving a directory the operator can no longer find
// under the name they gave would answer for a store nobody is looking at.
func (s *store) judge() error {
	info, err := s.root.Stat(".")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDirectoryChanged, err)
	}
	if err := s.stillIs(info); err != nil {
		return err
	}
	named, err := os.Stat(s.dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDirectoryChanged, err)
	}
	now, err := identify(named)
	if err != nil {
		return err
	}
	if err := s.opened.sameDirectory(now); err != nil {
		return err
	}
	s.step(stepJudged)
	return nil
}

func (s *store) stillIs(info fs.FileInfo) error {
	now, err := identify(info)
	if err != nil {
		return err
	}
	return s.opened.still(now)
}
