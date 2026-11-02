//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package main

import (
	"context"
	"errors"
	"os"
)

// lockRoot refuses on a platform with no advisory lock: two signers could
// both write one serial, so roster sign writes nothing there.
func lockRoot(context.Context, *os.Root) (func() error, error) {
	return nil, errors.New("this platform has no lock that keeps two signers of one roster apart")
}

// lockContended never runs here; it stands so the tests build on every
// platform.
var lockContended = func() {}
