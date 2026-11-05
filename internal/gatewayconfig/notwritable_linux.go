package gatewayconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// procStatus reads the plane's own status, which names the capabilities it
// holds.
var procStatus = func() ([]byte, error) { return os.ReadFile("/proc/self/status") }

// judgeCapabilities refuses a plane holding a capability that writes, chowns
// or chmods past what access(2) answers, or whose status cannot be read.
func judgeCapabilities() error {
	status, err := procStatus()
	if err != nil {
		return fmt.Errorf("the plane's capabilities cannot be read: %w", err)
	}
	return capabilityRefusal(string(status))
}

// aclPresent reports whether the entry at path carries a POSIX access
// control list, or a directory a default one. Linux keeps none on a link.
func aclPresent(path string, info fs.FileInfo) (bool, error) {
	if info.Mode()&fs.ModeSymlink != 0 {
		return false, nil
	}
	names := []string{"system.posix_acl_access"}
	if info.IsDir() {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		_, err := syscall.Getxattr(path, name, nil)
		switch {
		case err == nil:
			return true, nil
		case !errors.Is(err, syscall.ENODATA):
			return false, err
		}
	}
	return false, nil
}
