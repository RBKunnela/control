//go:build unix

package hookbridge

import "syscall"

// nonBlocking makes an open of a named pipe return instead of waiting for a
// writer, so the regular-file check runs at all.
const nonBlocking = syscall.O_NONBLOCK
