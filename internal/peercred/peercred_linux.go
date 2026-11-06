package peercred

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Supported says this platform names a socket peer's account.
const Supported = true

// peerUID reads SO_PEERCRED, which the kernel fills at connect and listen.
func peerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	return cred.Uid, nil
}
