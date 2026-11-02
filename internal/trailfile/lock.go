package trailfile

import (
	"errors"
	"os"

	"github.com/guardana/control/internal/segmentlog"
)

// lock takes the writer's exclusive lock on the open file as a log's writer
// takes its directory's, refusing a file another writer holds as ErrLocked
// and a platform with no file lock as ErrNoLock.
func lock(f *os.File) error {
	err := segmentlog.Lock(f)
	switch {
	case errors.Is(err, segmentlog.ErrLocked):
		return ErrLocked
	case errors.Is(err, segmentlog.ErrNoLock):
		return ErrNoLock
	}
	return err
}

// heldByWriter reports whether a writer holds the file.
func heldByWriter(f *os.File) (bool, error) { return segmentlog.HeldByWriter(f) }
