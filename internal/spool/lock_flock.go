//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package spool

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockFile is the name a lock takes under the directory; flock needs none.
const lockFile = ""

// lockDir takes an exclusive lock on the directory root holds, named dir in
// errors, and returns what releases it. The kernel drops the lock when the
// process dies, so a crash leaves nothing behind that refuses the next Open.
func lockDir(root *os.Root, dir string) (func() error, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.Join(fmt.Errorf("%w: %q", ErrLocked, dir), d.Close())
		}
		return nil, errors.Join(fmt.Errorf("spool: locking %q: %w", dir, err), d.Close())
	}
	return d.Close, nil
}

// shareDir takes a shared lock on the directory root holds, named dir in
// errors, so that no spool opens it while the lock is held, and returns what
// releases it. held is true, with nothing taken, when a spool holds it already.
func shareDir(root *os.Root, dir string) (release func() error, held bool, err error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, false, fmt.Errorf("spool: %w", err)
	}
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, d.Close()
		}
		return nil, false, errors.Join(fmt.Errorf("spool: asking whether a spool holds %q: %w", dir, err), d.Close())
	}
	return d.Close, false, nil
}
