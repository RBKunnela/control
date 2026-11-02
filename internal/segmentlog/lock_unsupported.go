//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package segmentlog

import "os"

// Lock is ErrNoLock: without a file lock two writers could write one file or
// directory at once, so a writer refuses to open.
func Lock(*os.File) error { return ErrNoLock }

// HeldByWriter is false: no writer that takes Lock opens a file here.
func HeldByWriter(*os.File) (bool, error) { return false, nil }
