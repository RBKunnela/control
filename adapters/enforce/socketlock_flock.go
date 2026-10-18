//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package enforce

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// lockSocket takes the lock a receiver holds beside its socket for as long
// as it listens, and returns what releases it. The kernel drops the lock when
// the process dies, so a free lock proves no receiver lives on the socket,
// which a refused connection does not prove on macOS. The file stays after a
// release: removing it would let a second receiver lock a new file while a
// third still holds the old one.
func lockSocket(socket string) (func() error, error) {
	path := socket + ".lock"
	f, err := openLock(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketInUse, err)
	}
	if err := ownLock(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return nil, errors.Join(fmt.Errorf("%w: another receiver holds %s", ErrSocketInUse, path), f.Close())
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: locking %s: %w", ErrSocketInUse, path, err), f.Close())
	}
	return f.Close, nil
}

// openLock creates the lock with mode 0600, whatever the umask leaves of it,
// or opens the one a receiver before this one created. Neither follows a
// link.
func openLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: the configured socket's own lock, in a directory ownDir checked
	if errors.Is(err, fs.ErrExist) {
		return os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: as above
	}
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// checkLock refuses, taking no lock, a file at the lock's path that
// lockSocket would refuse. No file there is no refusal: Listen creates one.
func checkLock(socket string) error {
	f, err := os.OpenFile(socket+".lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the configured socket's own lock, in a directory ownDir checked
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSocketInUse, err)
	}
	return errors.Join(ownLock(f), f.Close())
}

// ownLock refuses an opened lock that is not a regular file of one name that
// this user owns with mode 0600.
func ownLock(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSocketInUse, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ownedByMe(info) || info.Mode().Perm() != 0o600 || !ok || st.Nlink != 1 {
		return fmt.Errorf("%w: %s is not a file of this user with one name and mode 0600: %v", ErrSocketInUse, f.Name(), info.Mode())
	}
	return nil
}
