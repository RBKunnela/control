package peercred

import (
	"fmt"
	"net"
)

// Error is a peer credential that could not be read.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

const (
	// ErrUnsupported is a platform this package reads no peer credential on.
	ErrUnsupported Error = "peercred: this platform cannot name a socket peer's account"
	// ErrNotUnix is a connection that is not a Unix socket's.
	ErrNotUnix Error = "peercred: the connection is not a Unix socket's"
	// ErrUnreadable is a peer credential the kernel did not hand over.
	ErrUnreadable Error = "peercred: the peer's credential cannot be read"
)

// UID returns the effective user id of the process on the other end of conn,
// as it stood when that process connected or accepted. It fails with
// ErrNotUnix for any other connection, ErrUnsupported where Supported is
// false, and ErrUnreadable when the kernel's answer cannot be read.
func UID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, ErrNotUnix
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	var uid uint32
	var readErr error
	if err := raw.Control(func(fd uintptr) { uid, readErr = peerUID(int(fd)) }); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if readErr != nil {
		return 0, readErr
	}
	return uid, nil
}
