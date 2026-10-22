package spool

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/guardana/control/internal/files"
)

// Options configure a spool once, at Open.
type Options struct {
	// Dir holds the segments; it has to exist.
	Dir string
	// MaxBytes bounds the bytes on disk, the quarantine's included, plus the
	// reservations for closing records; it has to be positive. A quarantine
	// append is the one write that can put the bytes past it, by records that
	// already sit in a segment the acknowledgement after it releases.
	MaxBytes int64
	// SegmentBytes is the size at which a segment rolls; it has to be positive
	// and at most MaxBytes. One record larger than it gets a segment of its own.
	SegmentBytes int64
	// Fsync is when a record is forced to disk.
	Fsync FsyncPolicy
	// Interval is the timer of FsyncInterval; it has to be positive under that
	// policy and is refused under the other.
	Interval time.Duration
	// MaxOpenTrails bounds the trails holding a reservation at once, so a plane
	// that never closes a trail cannot lock the budget away without end. Zero
	// means DefaultMaxOpenTrails; it has to be positive or zero.
	MaxOpenTrails int
	// ClosingReserve is the allowance kept per open trail for its closing
	// record, so a closing record no larger than it is never refused on the
	// budget. Zero means DefaultClosingReserve; it has to be at most MaxBytes.
	ClosingReserve int64

	// openFile, openRead and syncDir are the seams a test observes the writes,
	// the reads and the directory syncs through; nil means the operating
	// system's.
	openFile func(root *os.Root, name string, flag int) (segmentFile, error)
	openRead func(root *os.Root, name string, flag int) (*os.File, error)
	syncDir  func(root *os.Root) error
}

func (o Options) check() error {
	if err := o.checkBounds(); err != nil {
		return err
	}
	return o.checkFsync()
}

// openSpoolDir opens dir as a root and refuses it unless it is a directory of
// this process's account that no other account may write. The checks read the
// opened directory, so the one judged is the one every file is reached through.
func openSpoolDir(dir string) (*os.Root, error) {
	// The trailing "." fails on anything but a directory rather than wait on a
	// named pipe put at dir.
	root, err := os.OpenRoot(dir + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, fmt.Errorf("%w: dir: %w", ErrInvalidOptions, err)
	}
	info, err := root.Stat(".")
	if err == nil {
		err = checkSpoolDir(info)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: dir: %w", ErrInvalidOptions, err), root.Close())
	}
	return root, nil
}

func checkSpoolDir(info fs.FileInfo) error {
	switch {
	case !info.IsDir():
		return files.ErrNotDirectory
	case !files.PermissionBits:
		return files.ErrNoPermissionBits
	case info.Mode().Perm()&writableByOthers != 0:
		return fmt.Errorf("%w: mode %04o", files.ErrMode, info.Mode().Perm())
	}
	return files.CheckOwnedBy(info, effectiveUID())
}

func (o Options) checkBounds() error {
	switch {
	case o.MaxBytes <= 0:
		return fmt.Errorf("%w: MaxBytes %d is not positive", ErrInvalidOptions, o.MaxBytes)
	case o.SegmentBytes <= 0 || o.SegmentBytes > o.MaxBytes:
		return fmt.Errorf("%w: SegmentBytes %d is not in 1..MaxBytes", ErrInvalidOptions, o.SegmentBytes)
	case o.ClosingReserve < 0 || o.ClosingReserve > o.MaxBytes:
		return fmt.Errorf("%w: ClosingReserve %d is not in 0..MaxBytes", ErrInvalidOptions, o.ClosingReserve)
	case o.MaxOpenTrails < 0:
		return fmt.Errorf("%w: MaxOpenTrails %d is negative", ErrInvalidOptions, o.MaxOpenTrails)
	}
	return nil
}

func (o Options) checkFsync() error {
	switch {
	case o.Fsync == FsyncEveryRecord && o.Interval != 0:
		return fmt.Errorf("%w: Interval is set under FsyncEveryRecord", ErrInvalidOptions)
	case o.Fsync == FsyncInterval && o.Interval <= 0:
		return fmt.Errorf("%w: Interval %v is not positive under FsyncInterval", ErrInvalidOptions, o.Interval)
	case o.Fsync > FsyncInterval:
		return fmt.Errorf("%w: unknown fsync policy %d", ErrInvalidOptions, o.Fsync)
	}
	return nil
}
