package files

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// One sentinel per refusal. Each is returned wrapped, beside what it refers to.
const (
	// ErrExists is a name CreateNoReplaceIn found taken.
	ErrExists Error = "files: the name exists already"
	// ErrNotRegular is a path that is not a regular file: a directory, a named
	// pipe, a device or a socket.
	ErrNotRegular Error = "files: not a regular file"
	// ErrNotDirectory is a path CheckDir was handed that is not a directory.
	ErrNotDirectory Error = "files: not a directory"
	// ErrMode is a file or directory whose permission bits include one the
	// caller forbade.
	ErrMode Error = "files: the mode gives access the caller forbids"
	// ErrTooLarge is a file over the caller's bound.
	ErrTooLarge Error = "files: over the size bound"
	// ErrNoPermissionBits is a mode check asked for on a platform that keeps
	// no permission bits to check.
	ErrNoPermissionBits Error = "files: this platform keeps no permission bits to check"
	// ErrOwner is a file ReadOwned found owned by another account.
	ErrOwner Error = "files: owned by another account"
	// ErrOwnerUnknown is an owner check the platform gives nothing to make.
	ErrOwnerUnknown Error = "files: this platform names no owner to check"
	// ErrNoDirOpen is OpenDir on a platform that cannot open a directory
	// without following a link.
	ErrNoDirOpen Error = "files: this platform cannot open a directory without following a link"
)

// tmpPrefix starts every temporary name this package makes. The random rest,
// rand.Text's 26 characters of the standard base32 alphabet, keeps two
// writers in one directory apart.
const (
	tmpPrefix  = ".tmp-"
	tmpRandLen = 26
)

// IsTemp reports whether name has the shape of a temporary file this
// package's writers make, which a crash before the file was named or removed
// leaves behind.
func IsTemp(name string) bool {
	r, ok := strings.CutPrefix(name, tmpPrefix)
	if !ok || len(r) != tmpRandLen {
		return false
	}
	for i := range len(r) {
		if c := r[i]; (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// CreateNoReplaceIn writes body under name in the directory root holds, with
// mode perm, and refuses with ErrExists when the name is taken. The body goes
// to a temporary file that is forced to disk before link(2) gives it the name,
// and link never replaces, so a crash leaves either no name or the whole body
// under it. Every step goes through root, so a path swapped for a link once
// root is open changes nothing it writes. The temporary file is removed
// either way. A failure after the link unlinks the name again, and only a
// failure of that unlink too, which the error carries, leaves the name in
// place. Nothing forces that unlink to disk, since forcing the directory is
// what failed, so a power loss can bring the name back, and another process
// may read the name before it is unlinked.
func CreateNoReplaceIn(root *os.Root, name string, body []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(root, body, perm)
	if err != nil {
		return err
	}
	if err := root.Link(tmp, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errors.Join(fmt.Errorf("%w: %q", ErrExists, name), root.Remove(tmp))
		}
		return errors.Join(err, root.Remove(tmp))
	}
	if err := errors.Join(root.Remove(tmp), syncRoot(root)); err != nil {
		return errors.Join(err, root.Remove(name))
	}
	return nil
}

// Replace puts body under dir/name with mode perm, over whatever is there. It
// is ReplaceIn through a handle to dir.
func Replace(dir, name string, body []byte, perm fs.FileMode) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	return errors.Join(ReplaceIn(root, name, body, perm), root.Close())
}

// ReplaceIn puts body under name in the directory root holds, with mode perm,
// over whatever is there. The rename is atomic, so a crash leaves the old
// content or the new and never a torn file; a symbolic link at the name is
// replaced, never followed. Every step goes through root, so a path swapped
// once root is open changes nothing it writes.
func ReplaceIn(root *os.Root, name string, body []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(root, body, perm)
	if err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		return errors.Join(err, root.Remove(tmp))
	}
	return syncRoot(root)
}

// writeTemp writes body to a fresh temporary file in root and forces it to
// disk. The mode is set on the descriptor, so the process umask cannot narrow
// or widen it. A file this fails on is removed.
func writeTemp(root *os.Root, body []byte, perm fs.FileMode) (string, error) {
	tmp := tmpPrefix + rand.Text()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(body)
	}
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return "", errors.Join(err, root.Remove(tmp))
	}
	return tmp, nil
}

// SyncDir forces a directory's entries to disk, so a name linked, renamed or
// unlinked before a power loss is in that state after it.
func SyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the caller's own directory
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

func syncRoot(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// ReadRegular reads the file at path, which must be a regular file of at most
// limit bytes whose permission bits include none of forbidden. Every check
// reads the opened descriptor, so the file judged is the file read, and the
// open does not block, so a named pipe is refused rather than waited on. A
// file of exactly limit bytes is read; one byte more is refused.
func ReadRegular(path string, limit int64, forbidden fs.FileMode) ([]byte, error) {
	return read(path, limit, forbidden, anyOwner)
}

// ReadOwned is ReadRegular that also refuses, with ErrOwner, a file uid does
// not own, judged from the same descriptor. A negative uid, which is what
// os.Geteuid reports where there is none, refuses with ErrOwnerUnknown.
func ReadOwned(path string, limit int64, forbidden fs.FileMode, uid int) ([]byte, error) {
	if uid < 0 {
		return nil, ErrOwnerUnknown
	}
	return read(path, limit, forbidden, uid)
}

// anyOwner is the owner read is given when it checks none.
const anyOwner = -1

func read(path string, limit int64, forbidden fs.FileMode, owner int) ([]byte, error) {
	if forbidden != 0 && !PermissionBits {
		return nil, ErrNoPermissionBits
	}
	f, err := os.OpenFile(path, os.O_RDONLY|nonBlocking, 0) //nolint:gosec // G304: the path is the caller's to name, and the descriptor is checked before any byte is read
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, describe(info.Mode()))
	}
	if owner != anyOwner {
		if err := checkOwner(info, owner); err != nil {
			return nil, err
		}
	}
	if perm := info.Mode().Perm(); perm&forbidden != 0 {
		return nil, fmt.Errorf("%w: mode %04o", ErrMode, perm)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w: limit %d", ErrTooLarge, limit)
	}
	return raw, nil
}

// CheckOwnedBy refuses, with ErrOwner, the file info describes when uid does
// not own it. A negative uid, or a platform that names no owner, refuses with
// ErrOwnerUnknown.
func CheckOwnedBy(info fs.FileInfo, uid int) error {
	if uid < 0 {
		return ErrOwnerUnknown
	}
	return checkOwner(info, uid)
}

// OpenDir opens the directory at path for reading. The open itself refuses a
// symbolic link at path, even one naming a directory, and anything else that
// is not a directory, and it never waits, as an open of a named pipe with no
// writer would.
func OpenDir(path string) (*os.File, error) {
	return openDir(path)
}

// checkOwner refuses info unless the platform names its owner and that owner
// is uid.
func checkOwner(info fs.FileInfo, uid int) error {
	got, ok := ownerOf(info)
	switch {
	case !ok:
		return ErrOwnerUnknown
	case got != uid:
		return fmt.Errorf("%w: uid %d", ErrOwner, got)
	}
	return nil
}

// CheckDir refuses a path that is not a directory, following a symbolic link,
// or one whose permission bits include any of forbidden.
func CheckDir(dir string, forbidden fs.FileMode) error {
	if forbidden != 0 && !PermissionBits {
		return ErrNoPermissionBits
	}
	info, err := os.Stat(dir)
	switch {
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%w: %q", ErrNotDirectory, dir)
	case info.Mode().Perm()&forbidden != 0:
		return fmt.Errorf("%w: mode %04o", ErrMode, info.Mode().Perm())
	}
	return nil
}

// describe names what a non-regular file is.
func describe(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "a directory"
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0:
		return "a device"
	default:
		return "type " + m.Type().String()
	}
}
