//go:build darwin

package files

import (
	"io/fs"
	"syscall"
	"time"
)

// changeTime is info's inode change time, when its system data holds one.
func changeTime(info fs.FileInfo) (time.Time, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec), true
}
