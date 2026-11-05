//go:build unix

package gatewayconfig

import (
	"errors"
	"syscall"
)

// writeOK is access(2)'s W_OK, which every unix spells 2.
const writeOK = 0x2

// planeIDs reads the plane's real and effective uids and gids.
var planeIDs = func() (uid, euid, gid, egid int) {
	return syscall.Getuid(), syscall.Geteuid(), syscall.Getgid(), syscall.Getegid()
}

// accessWrite asks the kernel whether the plane's account may write path,
// which the kernel answers for the real uid and gid with no capability. A
// plane whose real and effective ids differ, or that holds a capability
// that overrides the answer, is not the account the kernel answers for.
func accessWrite(path string) (bool, error) {
	uid, euid, gid, egid := planeIDs()
	switch {
	case uid != euid:
		return false, errors.New("the plane's real and effective uids differ, and access(2) answers for the real one")
	case gid != egid:
		return false, errors.New("the plane's real and effective gids differ, and access(2) answers for the real one")
	}
	if err := judgeCapabilities(); err != nil {
		return false, err
	}
	switch err := syscall.Access(path, writeOK); {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EROFS):
		return false, nil
	default:
		return false, err
	}
}
