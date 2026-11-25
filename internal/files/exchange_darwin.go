//go:build darwin

package files

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// exchange swaps the entries a and b of the directory d with renameatx_np's
// RENAME_SWAP.
func exchange(d *os.File, a, b string) error {
	fd := int(d.Fd())
	err := unix.RenameatxNp(fd, a, fd, b, unix.RENAME_SWAP)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOTSUP):
		return fmt.Errorf("%w: %w", ErrNoExchange, err)
	}
	return &os.LinkError{Op: "renameatx_np", Old: a, New: b, Err: err}
}
