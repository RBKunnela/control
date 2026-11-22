package policystate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// StagingPath is the temporary sibling name a restore builds the floor
// directory live under before it renames it into place. A build removes
// only what a stopped build left there, a directory holding stagingMark;
// anything else at the name refuses it with ErrStagingTaken.
func StagingPath(live string) string {
	return filepath.Join(filepath.Dir(live), "."+filepath.Base(live)+".restoring")
}

// buildFloors makes live from the backup's floors under a temporary sibling
// name, which a stopped build leaves for the next to remove, and renames it
// into place, so the name holds either nothing or every floor.
func buildFloors[V any](k floorKind[V], live string, ids []string, held map[string]*V, step Step) (Restored, error) {
	var keep []string
	for _, id := range ids {
		if (held[id] != nil && k.hasSerial(*held[id])) || k.listEmpty {
			keep = append(keep, id)
		}
	}
	if len(keep) == 0 {
		return Restored{}, nil
	}
	tmp := StagingPath(live)
	if err := step("build " + live); err != nil {
		return Restored{}, err
	}
	d, err := freshDir(tmp)
	if err != nil {
		return Restored{}, err
	}
	written, err := fillFloors(k, d, keep, held)
	if err = errors.Join(err, d.close()); err != nil {
		return Restored{}, err
	}
	out := Restored{Built: true, Listed: keep, Written: written}
	if err := step("rename " + live); err != nil {
		return Restored{}, err
	}
	if err := unmark(tmp); err != nil {
		return Restored{}, err
	}
	if err := os.Rename(tmp, live); err != nil {
		return Restored{}, err
	}
	return out, syncParent(live)
}

// fillFloors writes into d, a directory just made, the marker listing keep
// and the floor of every id of keep held holds a serial for.
func fillFloors[V any](k floorKind[V], d *dir, keep []string, held map[string]*V) ([]string, error) {
	if err := k.writeMarker(d, keep, true); err != nil {
		return nil, err
	}
	var written []string
	for _, id := range keep {
		if held[id] == nil || !k.hasSerial(*held[id]) {
			continue
		}
		next, _, err := k.restored(nil, *held[id])
		if err == nil {
			err = k.write(d, next)
		}
		if err != nil {
			return written, err
		}
		written = append(written, id)
	}
	return written, nil
}

// stagingMark is the file a build makes first in its staging directory and
// removes just before the rename: a directory at the staging name holding it
// is one a stopped build left, and the only thing a build removes there.
const stagingMark = ".restoring"

// freshDir removes what a stopped build left at tmp and makes it again,
// owner-only and holding stagingMark alone.
func freshDir(tmp string) (*dir, error) {
	if err := removeLeftover(tmp); err != nil {
		return nil, err
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	d, err := openDir(tmp)
	if err != nil {
		return nil, err
	}
	if err := mark(d, tmp); err != nil {
		return nil, errors.Join(err, d.close())
	}
	return d, nil
}

// removeLeftover removes the directory at tmp when a stopped build left it,
// and refuses anything else standing there: an empty directory too, since a
// build marks its directory before it writes a floor into it.
func removeLeftover(tmp string) error {
	switch info, err := os.Lstat(tmp); {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%w: %s is %s", ErrStagingTaken, tmp, info.Mode().Type())
	}
	marked, err := os.Lstat(filepath.Join(tmp, stagingMark))
	if err != nil || !marked.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrStagingTaken, tmp)
	}
	return os.RemoveAll(tmp)
}

// mark makes stagingMark in d, the directory at tmp, and forces it to disk.
func mark(d *dir, tmp string) error {
	f, err := d.root.OpenFile(stagingMark, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	return syncDir(tmp)
}

// unmark removes stagingMark from the directory at tmp before it becomes a
// floor directory, which holds nothing else, and forces that to disk.
func unmark(tmp string) error {
	if err := os.Remove(filepath.Join(tmp, stagingMark)); err != nil {
		return err
	}
	return syncDir(tmp)
}

func syncDir(path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: a floor directory or its parent, named by the operator's configuration
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func syncParent(path string) error { return syncDir(filepath.Dir(path)) }
