//go:build unix

package inbox

import "syscall"

// nonBlocking makes an open of a named pipe or a device return instead of
// waiting for the other end, so one planted file cannot stall a read.
const nonBlocking = syscall.O_NONBLOCK
