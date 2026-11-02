//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package segmentlog

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockTries and lockPause bound how long a writer waits for its lock: a
// reader asking whether a writer holds a file takes a shared lock for an
// instant, and a writer starting then must not take that for another writer.
const (
	lockTries = 50
	lockPause = 5 * time.Millisecond
)

// Lock takes an exclusive lock on the open file, waiting up to lockTries
// times lockPause for one held by anyone else to go, and is ErrLocked past
// that. Closing the file releases it, and the kernel drops it when the
// process dies, so a writer that crashed leaves nothing behind that refuses
// the next one.
func Lock(f *os.File) error {
	for try := 1; ; try++ {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case !errors.Is(err, syscall.EWOULDBLOCK):
			return fmt.Errorf("taking the lock: %w", err)
		case try == lockTries:
			return ErrLocked
		}
		time.Sleep(lockPause)
	}
}

// HeldByWriter reports whether a writer holds the open file's lock, by
// taking a shared lock without waiting and letting it go at once.
func HeldByWriter(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	switch {
	case errors.Is(err, syscall.EWOULDBLOCK):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("asking whether a writer holds the lock: %w", err)
	}
	return false, syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
