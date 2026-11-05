//go:build !unix

package gatewayconfig

import (
	"errors"
	"io/fs"
)

// accessWrite cannot ask this platform whether the plane may write a path,
// so no path is shown closed to it.
func accessWrite(string) (bool, error) {
	return false, errors.New("this platform cannot say whether the plane's account may write a path")
}

// aclPresent is never reached here: CheckNotPlaneWritable refuses first, as
// the platform keeps no permission bits.
func aclPresent(string, fs.FileInfo) (bool, error) {
	return false, errors.New("this platform cannot say whether an entry carries an access control list")
}
