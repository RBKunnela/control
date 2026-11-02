//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// rosterLockRetry is how often a signer tries the lock again while another
// holds it.
const rosterLockRetry = 10 * time.Millisecond

// lockContended runs each time lockRoot finds the lock held. A test learns
// from it that a second signer waits.
var lockContended = func() {}

// lockRoot takes an exclusive lock on the directory root holds, trying until
// ctx ends, and returns what releases it. The kernel drops the lock when the
// process dies, so a signer that crashed leaves nothing that refuses the next.
func lockRoot(ctx context.Context, root *os.Root) (func() error, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return d.Close, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.Join(err, d.Close())
		}
		lockContended()
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), d.Close())
		case <-time.After(rosterLockRetry):
		}
	}
}
