//go:build unix

package main

import (
	"os"
	"strconv"
	"syscall"
)

// ownerText names the account that owns the file at path, as a refusal
// says it.
func ownerText(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return "a file whose owner could not be read"
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "a file whose owner could not be read"
	}
	return "owned by uid " + strconv.FormatUint(uint64(st.Uid), 10)
}
