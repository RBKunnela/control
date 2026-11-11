package gatewayconfig

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/guardana/control/internal/files"
)

// othersWrite is the permission bits that let an account other than the
// owner replace or rewrite the configuration, which names the mode, the
// policy keys, the pause file and the credentials the plane sends. The
// group's bit is refused too: which accounts a group holds cannot be read
// from the files on every system, and under an access control list the group
// bits are the mask that lets a named account write.
const othersWrite fs.FileMode = 0o022

// othersMayWrite refuses an entry whose mode lets an account other than its
// owner write it.
func othersMayWrite(info fs.FileInfo) error {
	if perm := info.Mode().Perm(); perm&othersWrite != 0 {
		return fmt.Errorf("%w: mode %04o; the group or others may write it", files.ErrMode, perm)
	}
	return nil
}

// ownerWanted is the plane's account, which may own the configuration and
// every directory and link on its path beside root.
var ownerWanted = func(fs.FileInfo) int { return os.Geteuid() }

// ownerOf reads the account that owns info's file, where the platform names
// one.
var ownerOf = statOwner

// onReadOnlyMount reports whether an opened directory sits on a read-only
// mount.
var onReadOnlyMount = readOnlyMount

// The steps a test can act at: a directory others may write looked up on the
// walk, the path walked, the directory opened and judged, and the file's name
// judged no link.
const (
	stepDirLooked = "directory looked up"
	stepWalked    = "path walked"
	stepDirOpened = "directory opened"
	stepFileNamed = "file named"
)

// configSteps, when a test sets it, runs at each step, so the test can swap
// the directory or the file under the path in between.
var configSteps func(step string)

func configStep(s string) {
	if configSteps != nil {
		configSteps(s)
	}
}

// errChanged is a directory or file that is not, by identity, the one judged.
var errChanged = errors.New("changed while it was read")

// errSecondName is a configuration file with another name, or one whose
// names the platform does not count: whoever reaches the other name reaches
// the file, wherever that name lies.
var errSecondName = errors.New("the file has a name besides the one read, or its names cannot be counted")

// errTooManyLinks is a path that passes more links than maxLinks, as a loop
// of links does.
var errTooManyLinks = errors.New("too many links")

// readJudged reads the configuration at path once every entry on the path is
// judged, as resolveJudged judges it. The file it reaches has to be regular,
// closed to writes by others, owned by the plane's account or root, and
// without another name, and its directory is judged as every other. The file
// and its directory are judged again on the descriptors the read goes
// through, so nothing swapped in after a check is read, and the file read is
// returned as that descriptor states it. A refusal names what was judged and
// why, never what the file holds.
func readJudged(path string) ([]byte, fs.FileInfo, error) {
	if !files.PermissionBits {
		return nil, nil, files.ErrNoPermissionBits
	}
	resolved, err := resolveJudged(path)
	if err != nil {
		return nil, nil, err
	}
	configStep(stepWalked)
	dir, name := filepath.Dir(resolved), filepath.Base(resolved)
	root, err := openJudgedDir(dir)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	named, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	configStep(stepFileNamed)
	// A root follows a link at the name whatever the flags say, so the file
	// opened is held to be the entry named above, which a link never is.
	f, err := root.OpenFile(name, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(named, info) {
		return nil, nil, fmt.Errorf("%s %w", resolved, errChanged)
	}
	if err := judgeFile(info); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", resolved, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maxConfigBytes {
		return nil, nil, fmt.Errorf("%w: limit %d", files.ErrTooLarge, maxConfigBytes)
	}
	return raw, info, nil
}

// openJudgedDir opens dir, judges it on the opened descriptor, and returns a
// root proven to be that same directory.
func openJudgedDir(dir string) (*os.Root, error) {
	d, err := files.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	// Held open until the root is proven the same directory, so its identity
	// cannot pass to another directory in between.
	defer func() { _ = d.Close() }()
	judged, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if err := errors.Join(judgeDirMode(d, judged), checkConfigOwner(judged)); err != nil {
		return nil, fmt.Errorf("its directory %s: %w", dir, err)
	}
	configStep(stepDirOpened)
	// The trailing "." fails on anything but a directory rather than wait on
	// a pipe.
	root, err := os.OpenRoot(dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, err
	}
	rooted, err := root.Stat(".")
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	if !os.SameFile(judged, rooted) {
		return nil, errors.Join(fmt.Errorf("its directory %s %w", dir, errChanged), root.Close())
	}
	return root, nil
}

// judgeFile refuses the configuration file unless it is regular, closed to
// writes by any account but its owner, with no name but the one read, and
// owned by the plane's account or root.
func judgeFile(info fs.FileInfo) error {
	mode := info.Mode()
	if !mode.IsRegular() {
		return fmt.Errorf("%w: %s", files.ErrNotRegular, mode.Type())
	}
	if err := othersMayWrite(info); err != nil {
		return err
	}
	if !singleName(info) {
		return errSecondName
	}
	return checkConfigOwner(info)
}

// checkConfigOwner refuses a file or directory owned by an account other
// than the plane's or root: its owner may rewrite it whatever its mode says.
// Root is taken because a container mounts the configuration read-only as
// root's.
func checkConfigOwner(info fs.FileInfo) error {
	want := ownerWanted(info)
	owner, named := ownerOf(info)
	switch {
	case want < 0 || !named:
		return fmt.Errorf("%w; it has to be owned by the plane's account or root", files.ErrOwnerUnknown)
	case owner != want && owner != 0:
		return fmt.Errorf("%w: uid %d; it has to be owned by the plane's account or root", files.ErrOwner, owner)
	}
	return nil
}
