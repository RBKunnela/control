//go:build unix && !linux && !darwin

package gatewayconfig

import "io/fs"

// judgeCapabilities is not asked here: only Linux capabilities are read, and
// CheckNotPlaneWritable states the limit.
func judgeCapabilities() error { return nil }

// aclPresent is not asked here: only the access control lists of Linux and
// Darwin are read, and CheckNotPlaneWritable states the limit.
func aclPresent(string, fs.FileInfo) (bool, error) { return false, nil }
