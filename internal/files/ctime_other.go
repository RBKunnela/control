//go:build !linux && !darwin

package files

import (
	"io/fs"
	"time"
)

// changeTime reports no change time where this package reads none.
func changeTime(fs.FileInfo) (time.Time, bool) { return time.Time{}, false }
