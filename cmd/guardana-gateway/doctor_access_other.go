//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package main

import "errors"

// mayWrite cannot ask here without writing, so it never answers yes.
func mayWrite(string) error {
	return errors.New("this platform cannot be asked whether a directory takes a file without writing one")
}
