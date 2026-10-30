//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import "syscall"

// writeAccess is access(2)'s W_OK, the same on every platform this file
// builds for.
const writeAccess = 0x2

// mayWrite asks the kernel whether dir takes a new name. access(2) judges the
// real user, which is the plane's own account unless the binary runs
// set-user-ID, and answers for a read-only file system too.
func mayWrite(dir string) error { return syscall.Access(dir, writeAccess) }
