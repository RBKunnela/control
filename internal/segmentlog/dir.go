package segmentlog

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/guardana/control/internal/files"
)

// forbidden is the permission bits a file in the directory may not have:
// whoever may write one can write evidence into the log. The directory may
// give the group and others nothing, as its names and sizes say what the
// plane did and when.
const (
	forbidden    fs.FileMode = 0o022
	forbiddenDir fs.FileMode = 0o077
)

// ownerWanted is the account the directory and its files belong to.
var ownerWanted = func(fs.FileInfo) int { return os.Geteuid() }

// openDir opens dir in its parent, creating it mode 0700 when absent, and
// refuses it unless the parent is one where no account but this one or root
// can replace a name, and dir a directory, not a link, of this account that
// the group and others cannot reach. dir is named by its absolute, cleaned
// path, and opened through the parent judged, so a name holding a link and
// ".." reaches no other directory. The parent is synced, so a directory made
// here is still named in it after a crash.
func openDir(dir string, sync func(*os.Root) error) (*os.Root, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: no directory", ErrConfig)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	parent, err := openParent(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	name := filepath.Base(abs)
	if err := parent.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if err := sync(parent); err != nil {
		return nil, err
	}
	return openChild(parent, name, abs)
}

// openChild opens the directory name in parent, abs by its path, and judges
// it. A root follows a link that stays inside it, so a link is refused by its
// directory entry, and the directory opened has to be the one it named.
func openChild(parent *os.Root, name, abs string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	switch {
	case err != nil:
		return nil, err
	case !before.IsDir():
		return nil, fmt.Errorf("%w: %s is a link or not a directory", ErrDirectory, strconv.Quote(abs))
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	switch {
	case err != nil:
	case !os.SameFile(before, info):
		err = fmt.Errorf("%w: another directory stood at %s when it was opened", ErrMoved, strconv.Quote(abs))
	default:
		err = judge(info, true)
	}
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

// openParent opens the directory parent and judges it.
func openParent(parent string) (*os.Root, error) {
	// The trailing "." fails on anything but a directory rather than wait on
	// a named pipe put at parent.
	root, err := os.OpenRoot(parent + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err == nil {
		err = judgeParent(info, parent)
	}
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

// judgeParent refuses a parent directory in which another account than this
// one or root could replace the log's directory: one another account owns,
// or one the group or others may write that is not sticky, as only the owner
// of a name in a sticky directory may remove or rename it.
func judgeParent(info fs.FileInfo, parent string) error {
	perm := info.Mode().Perm()
	if perm&forbidden != 0 && info.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%w: the parent %s: %w: mode %04o and not sticky", ErrDirectory, strconv.Quote(parent), files.ErrMode, perm)
	}
	owned := files.CheckOwnedBy(info, ownerWanted(info))
	if owned != nil && files.CheckOwnedBy(info, 0) != nil {
		return fmt.Errorf("%w: the parent %s: %w", ErrDirectory, strconv.Quote(parent), owned)
	}
	return nil
}

// judge refuses what a writer of this package does not leave: anything but a
// directory the group and others cannot reach or a regular file they cannot
// write, as wanted, of this account.
func judge(info fs.FileInfo, dir bool) error {
	mask := forbidden
	if dir {
		mask = forbiddenDir
	}
	switch {
	case dir && !info.IsDir():
		return fmt.Errorf("%w: not a directory", ErrDirectory)
	case !dir && !info.Mode().IsRegular():
		return fmt.Errorf("%w: %s is not a regular file", ErrDirectory, info.Name())
	case info.Mode().Perm()&mask != 0:
		return fmt.Errorf("%w: %s: %w: mode %04o", ErrDirectory, info.Name(), files.ErrMode, info.Mode().Perm())
	}
	if err := files.CheckOwnedBy(info, ownerWanted(info)); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrDirectory, info.Name(), err)
	}
	return nil
}

// openJudged opens name in root with flag, and refuses a file judge refuses,
// judged by its descriptor. A root follows a link that stays inside the
// directory whatever the flags say, so a link is refused by its directory
// entry before the open, and the descriptor has to be the file that entry
// named.
func openJudged(root *os.Root, name string, flag int) (*os.File, error) {
	before, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist) && flag&os.O_CREATE != 0:
		before, flag = nil, flag|os.O_EXCL
	case err != nil:
		return nil, err
	case !before.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrDirectory, name)
	}
	f, err := root.OpenFile(name, flag|openFlags, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	switch {
	case err != nil:
	case before != nil && !os.SameFile(before, info):
		err = fmt.Errorf("%w: another file stood at %s when it was opened", ErrMoved, name)
	default:
		err = judge(info, false)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// names is every name in the directory root holds.
func names(root *os.Root) ([]string, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	out, err := d.Readdirnames(-1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return out, errors.Join(err, d.Close())
}

// readManifest reads the manifest in root, or reports it absent. A root
// follows a link that stays inside the directory, so the manifest is judged
// by its directory entry, and the descriptor has to be the file it named.
func readManifest(root *os.Root) ([]byte, bool, error) {
	before, err := root.Lstat(ManifestName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	case !before.Mode().IsRegular():
		return nil, false, fmt.Errorf("%w: %s is not a regular file", ErrManifest, ManifestName)
	}
	f, err := root.OpenFile(ManifestName, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	switch {
	case err != nil:
		return nil, false, err
	case !os.SameFile(before, info):
		return nil, false, fmt.Errorf("%w: another file stood at %s when it was opened", ErrMoved, ManifestName)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}
