package peercred

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Supported says this platform names a socket peer's account.
const Supported = true

// xucredVersion is XUCRED_VERSION of sys/ucred.h, which x/sys does not name.
const xucredVersion = 0

// peerUID reads LOCAL_PEERCRED, the credential getpeereid reads. A structure
// of another version is laid out otherwise, so its uid is not taken.
func peerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if cred.Version != xucredVersion {
		return 0, fmt.Errorf("%w: xucred version %d", ErrUnreadable, cred.Version)
	}
	return cred.Uid, nil
}
