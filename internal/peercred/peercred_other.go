//go:build !linux && !darwin

package peercred

// Supported says this platform names a socket peer's account.
const Supported = false

func peerUID(int) (uint32, error) { return 0, ErrUnsupported }
