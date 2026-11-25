//go:build linux

package files

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// exchange swaps the entries a and b of the directory d with renameat2's
// RENAME_EXCHANGE.
func exchange(d *os.File, a, b string) error {
	fd := int(d.Fd())
	err := unix.Renameat2(fd, a, fd, b, unix.RENAME_EXCHANGE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP):
		return fmt.Errorf("%w: %w", ErrNoExchange, err)
	}
	return &os.LinkError{Op: "renameat2", Old: a, New: b, Err: err}
}
