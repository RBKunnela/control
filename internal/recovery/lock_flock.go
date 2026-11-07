//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package recovery

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// holdDir takes the exclusive flock the spool and the hold journal each take
// on their own directory while a plane serves, and returns what releases it.
// It is taken here rather than through those packages so this binary links
// neither the spool nor evidence; a test holds the two to the same lock.
func holdDir(dir string) (func() error, error) {
	// The trailing "." fails on anything but a directory rather than wait on
	// a named pipe put at dir.
	d, err := os.Open(dir + string(os.PathSeparator) + ".") //nolint:gosec // G304: a directory the plane's configuration names
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.Join(fmt.Errorf("%w: %q", ErrPlaneRunning, dir), d.Close())
		}
		return nil, errors.Join(fmt.Errorf("recovery: locking %q: %w", dir, err), d.Close())
	}
	return d.Close, nil
}
