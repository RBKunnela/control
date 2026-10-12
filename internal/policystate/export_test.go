package policystate

import (
	"io/fs"
	"os"
)

// SetEffectiveUID makes uid the user a directory and its files have to belong
// to until the returned function restores the real one.
func SetEffectiveUID(uid func() int) (restore func()) {
	saved := effectiveUID
	effectiveUID = uid
	return func() { effectiveUID = saved }
}

// SetReplace makes replace the way a file is replaced whole until the
// returned function restores the real one, so a test can stop a write where a
// crash would.
func SetReplace(replace func(root *os.Root, name string, body []byte, perm fs.FileMode) error) (restore func()) {
	saved := replaceIn
	replaceIn = replace
	return func() { replaceIn = saved }
}

// WritersWaiting is how many writers of this process wait for or hold the
// lock of the directory at path.
func WritersWaiting(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	id, err := identify(info)
	if err != nil {
		return 0, err
	}
	t := turnOf(id)
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writers, nil
}
