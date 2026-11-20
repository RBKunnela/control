//go:build unix

package attempts

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readJournalFile opens path without following a link at its name and
// without waiting on a named pipe, and judges the opened file itself, so the
// file judged is the file read.
func readJournalFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: a journal in a directory this run made
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return nil, errors.New("it is not a regular file")
	case !ok || st == nil:
		return nil, errors.New("this platform does not say who owns it")
	case st.Nlink != 1:
		return nil, fmt.Errorf("it has %d names", st.Nlink)
	case int(st.Uid) != os.Geteuid():
		return nil, errors.New("another account owns it")
	case info.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("its mode %v lets another account reach it", info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxJournalBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxJournalBytes {
		return nil, fmt.Errorf("over %d bytes", MaxJournalBytes)
	}
	return raw, nil
}
