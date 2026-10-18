//go:build unix && !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package enforce

// Without a file lock nothing proves a receiver dead before its socket is
// replaced, so Listen refuses instead.
func lockSocket(string) (func() error, error) { return nil, ErrPlatform }

func checkLock(string) error { return ErrPlatform }
