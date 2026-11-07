package stoplist

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/reaction"
)

// FileName is the stop list's name in its directory.
const FileName = "stops.jsonl"

// forbidden is the permission bits neither the list nor its directory may
// carry: whoever may write either may rewrite the stops.
const forbidden fs.FileMode = 0o022

// The steps a test can act at: the directory opened and judged, the root on
// it established, and the list's name judged no link.
const (
	stepOpened    = "opened"
	stepRooted    = "rooted"
	stepFileNamed = "file named"
)

// steps, when a test sets it, runs at each step, so the test can swap the
// directory or the file under the path in between.
var steps func(step string)

func step(s string) {
	if steps != nil {
		steps(s)
	}
}

// effectiveUID is the account the list and its directory have to be owned
// by: another owner may rewrite either whatever its mode says.
var effectiveUID = os.Geteuid

// Owner is whose account the list and its directory have to be owned by. A
// writer, and a plane under any authority but signed, needs them its own. A
// plane under the signed authority reads a list its operators write and
// refuses one its own account owns, which it could rewrite; AnyOwner is for a
// plane whose one account is the operators' too, which only a test or a dev
// plane is.
type Owner uint8

// The owners.
const (
	OwnedByThisUser Owner = iota
	OwnedByAnother
	AnyOwner
)

// judge refuses, with mine, an entry this process's effective user does not
// own under OwnedByThisUser, with ErrPlaneOwned one it owns under
// OwnedByAnother, and nothing under AnyOwner.
func (o Owner) judge(info fs.FileInfo, mine Error) error {
	if o == AnyOwner {
		return nil
	}
	err := files.CheckOwnedBy(info, effectiveUID())
	switch {
	case o == OwnedByThisUser && err != nil:
		return fmt.Errorf("%w: %w", mine, err)
	case o == OwnedByAnother && err == nil:
		return ErrPlaneOwned
	case o == OwnedByAnother && !errors.Is(err, files.ErrOwner):
		return fmt.Errorf("%w: %w", mine, err)
	}
	return nil
}

// OpenDir opens the directory holding the stop list and returns a root on it.
// The open refuses a link at dir and never waits on a named pipe; the mode
// and the owner are judged on the opened descriptor; and the root is proven
// to be that same directory, so a directory swapped in under the path after
// the check is never read or written.
func OpenDir(dir string) (*os.Root, error) { return openDirAs(dir, OwnedByThisUser) }

func openDirAs(dir string, owner Owner) (*os.Root, error) {
	if !files.PermissionBits {
		return nil, ErrNoPermissionBits
	}
	d, err := files.OpenDir(dir)
	if err != nil {
		if info, lerr := os.Lstat(dir); lerr == nil && info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrDirLink, dir)
		}
		return nil, missing(err)
	}
	// Held open until the root is proven the same directory, so its identity
	// cannot pass to another directory in between.
	defer func() { _ = d.Close() }()
	judged, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if judged.Mode().Perm()&forbidden != 0 {
		return nil, fmt.Errorf("%w: mode %04o", ErrDirMode, judged.Mode().Perm())
	}
	if err := owner.judge(judged, ErrDirOwner); err != nil {
		return nil, err
	}
	step(stepOpened)
	// The trailing "." fails on anything but a directory rather than wait on
	// a pipe, and the identity check refuses whatever took the judged
	// directory's place in between.
	root, err := os.OpenRoot(dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, missing(err)
	}
	rooted, err := root.Stat(".")
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	if !os.SameFile(judged, rooted) {
		return nil, errors.Join(fmt.Errorf("%w: %s", ErrDirChanged, dir), root.Close())
	}
	step(stepRooted)
	return root, nil
}

// Named judges the list's name in root before it is opened: it exists and is
// no link. The root follows a link at the name whatever the open's flags say,
// so CheckOpened then holds the opened file to the one judged here.
func Named(root *os.Root) (fs.FileInfo, error) {
	named, err := root.Lstat(FileName)
	if err != nil {
		return nil, missing(err)
	}
	if named.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrLink, FileName)
	}
	step(stepFileNamed)
	return named, nil
}

// CheckOpened judges f, opened at the list's name after Named judged it as
// named: the same file, regular, writable by no one but its owner, and owned
// by this process's effective user. Every check reads the opened descriptor.
func CheckOpened(named fs.FileInfo, f *os.File) error {
	return checkOpenedAs(named, f, OwnedByThisUser)
}

func checkOpenedAs(named fs.FileInfo, f *os.File, owner Owner) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	switch {
	case !os.SameFile(named, info):
		return fmt.Errorf("%w: %s", ErrFileChanged, FileName)
	case !info.Mode().IsRegular():
		return fmt.Errorf("%w: %s", ErrNotRegular, info.Mode().Type())
	case info.Mode().Perm()&forbidden != 0:
		return fmt.Errorf("%w: mode %04o", ErrFileMode, info.Mode().Perm())
	}
	return owner.judge(info, ErrFileOwner)
}

// Read reads the stop list in dir with every check OpenDir, Named and
// CheckOpened make, and refuses one over reaction.MaxListBytes without
// reading past it. Nothing is locked: the writer only appends, and the judge
// leaves out a line being written.
func Read(dir string) ([]byte, error) { return ReadAs(dir, OwnedByThisUser) }

// ReadAs is Read with the list and its directory owned as owner says.
func ReadAs(dir string, owner Owner) ([]byte, error) {
	root, err := openDirAs(dir, owner)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	named, err := Named(root)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(FileName, os.O_RDONLY|OpenFlags, 0)
	if err != nil {
		return nil, missing(err)
	}
	defer func() { _ = f.Close() }()
	if err := checkOpenedAs(named, f, owner); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, reaction.MaxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > reaction.MaxListBytes {
		return nil, fmt.Errorf("%w: limit %d", ErrTooLarge, reaction.MaxListBytes)
	}
	return raw, nil
}

func missing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrMissing, err)
	}
	return err
}
