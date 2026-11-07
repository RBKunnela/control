//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package recovery

import "fmt"

// holdDir refuses where the hold journal takes no file lock: nothing would
// keep a plane from starting halfway through a restore.
func holdDir(dir string) (func() error, error) {
	return nil, fmt.Errorf("%w: %q", ErrNoLock, dir)
}
