//go:build linux || darwin

package files

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// lockRetry is how often a writer tries a lock again while another open of
// the file holds one.
const lockRetry = 10 * time.Millisecond

// openJudged opens the entry at name in the directory root holds for
// reading, without following a link or waiting on a pipe; a link at the
// name is errLink.
func openJudged(root *os.Root, name string) (*os.File, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	closed := d.Close()
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, errors.Join(errLink, closed)
	case err != nil:
		return nil, errors.Join(&os.PathError{Op: "openat", Path: name, Err: err}, closed)
	}
	f := os.NewFile(uintptr(fd), name)
	if closed != nil {
		return nil, errors.Join(closed, f.Close())
	}
	return f, nil
}

// lockFile takes an exclusive flock of f, trying again while another open of
// the file holds one, and answers ErrLockHeld once ctx ends first; closing f
// lets the lock go.
func lockFile(ctx context.Context, f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case !errors.Is(err, unix.EWOULDBLOCK):
			return err
		}
		select {
		case <-ctx.Done():
			return ErrLockHeld
		case <-time.After(lockRetry):
		}
	}
}
