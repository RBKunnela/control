package policystate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/guardana/control/internal/files"
)

// readDir lists the directory, sorted by name.
func (d *dir) readDir() ([]os.DirEntry, error) {
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(-1)
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

// judgeContents reads the marker, which has to name kind, and refuses a
// directory holding anything this package does not write, a floor file of an
// id the marker does not list among them: guessing what else is there is how
// a planted name gets read. It returns the ids the marker lists.
func (d *dir) judgeContents(entries []os.DirEntry, kind Kind) ([]string, error) {
	if !holds(entries, markerFile) {
		if holds(entries, routeMarkerFile) {
			return nil, fmt.Errorf("%w: it holds route floors, not a %s's", ErrWrongKind, kind)
		}
		return nil, fmt.Errorf("%w: it holds no %s", ErrNotStateDir, markerFile)
	}
	ids, err := d.readMarker(kind)
	if err != nil {
		return nil, err
	}
	if err := judgeEntries(entries, markerFile, ids, floorName); err != nil {
		return nil, err
	}
	return ids, nil
}

// holds reports whether entries hold an entry called name.
func holds(entries []os.DirEntry, name string) bool {
	return slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() == name })
}

// judgeEntries refuses an entry that is not a regular file, and any name but
// the marker, the file name gives a listed id, and what a crash left.
func judgeEntries(entries []os.DirEntry, marker string, ids []string, name func(string) string) error {
	listed := make(map[string]bool, len(ids))
	for _, id := range ids {
		listed[name(id)] = true
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, clip(e.Name()))
		}
		if n := e.Name(); n != marker && !listed[n] && !files.IsTemp(n) {
			return fmt.Errorf("%w: %q", ErrForeignFile, clip(n))
		}
	}
	return nil
}

// openRegular opens name read-only and refuses anything but the regular file
// that stood at name when it looked, owned by this user and closed to the
// group and the world: a link, a pipe, a device, or a file swapped in between
// the look and the open.
func (d *dir) openRegular(name string) (*os.File, error) {
	before, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrForeignFile, clip(name))
	}
	f, err := d.root.OpenFile(name, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.Join(fmt.Errorf("%w: %q changed while it was opened", ErrForeignFile, clip(name)), f.Close())
	}
	id, err := identify(after)
	if err == nil {
		err = judgeOwned(id)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%q: %w", clip(name), err), f.Close())
	}
	return f, nil
}

// readFile reads one regular file of at most limit bytes. A file of exactly
// the bound is read; one byte more is refused.
func (d *dir) readFile(name string, limit int64) ([]byte, error) {
	f, err := d.openRegular(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w: %q is over %d bytes", ErrTooLarge, clip(name), limit)
	}
	return raw, nil
}
