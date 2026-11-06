package approvals

import (
	"errors"
	"fmt"
)

// JudgeDirectory refuses dir where a plane's or an approver's open would
// refuse it for the directory itself: anything but a directory, a mode a
// group or the world may write, and an owner other than this process's
// account. It takes no lock, reads no record and creates nothing, so a
// command that only inspects may call it while a plane serves.
func JudgeDirectory(dir string) error {
	root, _, err := openRoot(dir, false)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if err := root.Close(); err != nil {
		return errors.Join(fmt.Errorf("%s: %w", dir, ErrNotAStore), err)
	}
	return nil
}
