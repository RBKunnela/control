package policystate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/guardana/control/internal/files"
)

// KindRoute is the floors of the reaction routes a plane loads. Its
// directory has a marker and file names of its own, and only InitRoute,
// ReadRoute and RaiseRoute open it: Open, Init and Reset refuse the kind.
const KindRoute Kind = "route"

// MaxRouteIDs bounds how many route ids one directory lists.
const MaxRouteIDs = 32

// RouteFloor is a route id's floor: the highest serial taken and the digest
// of the route at it. Serial is 0 and Digest empty while the floor holds no
// serial yet.
type RouteFloor struct {
	RouteID string
	Serial  int64
	Digest  string
}

// HasSerial reports whether a route was ever taken into the floor.
func (f RouteFloor) HasSerial() bool { return f.Serial != 0 }

// InitRoute gives routeID a floor file holding no serial yet in dir, a route
// floor directory, and lists routeID in its marker. It makes dir, mode 0700,
// when nothing stands at the name, and makes an empty directory, or one
// holding only what a crash left, a route floor directory. It refuses an id
// whose file exists with ErrExists and an id listed once whose file is gone
// with ErrFloorRemoved, so it never lowers a floor; an id past MaxRouteIDs
// with ErrTooManyRouteIDs; a plane's or a signer's directory with
// ErrWrongKind; and every directory ReadRoute refuses.
func InitRoute(ctx context.Context, dir, routeID string) (err error) {
	body, err := encodeRouteFile(RouteFloor{RouteID: routeID})
	if err != nil {
		return err
	}
	// The mode is only ever narrowed by the umask, as in Init.
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	d, err := openDir(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	unlock, err := d.lockToWrite(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := d.claimRoute(routeID); err != nil {
		return err
	}
	name := routeName(routeID)
	if err := files.CreateNoReplaceIn(d.root, name, body, 0o600); err != nil {
		if errors.Is(err, files.ErrExists) {
			return fmt.Errorf("%w: %s", ErrExists, name)
		}
		return err
	}
	return nil
}

// claimRoute lists routeID in the route marker before its file is made, as
// claim does, and refuses an id already listed before anything is written.
func (d *dir) claimRoute(routeID string) error {
	entries, err := d.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	if onlyLeftovers(entries) {
		return d.writeRouteMarker([]string{routeID}, true)
	}
	ids, err := d.judgeRouteContents(entries)
	if err != nil {
		return err
	}
	if slices.Contains(ids, routeID) {
		name := routeName(routeID)
		_, err := d.root.Lstat(name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%w: %s; a route floor is made again only in a new directory", ErrFloorRemoved, name)
		case err != nil:
			return err
		}
		return fmt.Errorf("%w: %s", ErrExists, name)
	}
	if len(ids) >= MaxRouteIDs {
		return fmt.Errorf("%w: %d listed", ErrTooManyRouteIDs, len(ids))
	}
	ids = append(ids, routeID)
	slices.Sort(ids)
	return d.writeRouteMarker(ids, false)
}

func (d *dir) writeRouteMarker(ids []string, create bool) error {
	body, err := encodeRouteMarker(ids)
	if err != nil {
		return err
	}
	if create {
		err = files.CreateNoReplaceIn(d.root, routeMarkerFile, body, 0o600)
	} else {
		err = replaceIn(d.root, routeMarkerFile, body, 0o600)
	}
	if err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	return nil
}

// ReadRoute reads routeID's floor from dir, a route floor directory, and
// writes nothing. It takes no lock, so it never waits on a raise: a file is
// only ever replaced whole, and the read sees the floor before the raise or
// after it. It judges the directory as RaiseRoute does and refuses what
// RaiseRoute refuses before it compares: an id checkRouteID refuses with
// ErrRouteInvalid; a missing directory or marker with ErrNotStateDir; a
// plane's or a signer's directory with ErrWrongKind; anything this package
// does not write with ErrForeignFile; another owner, or access for the group
// or the world, with ErrOwner or ErrPermissions; and an id the marker does
// not list, or whose file is gone, with ErrNoFloor.
func ReadRoute(dir, routeID string) (_ RouteFloor, err error) {
	if err := checkRouteID(routeID); err != nil {
		return RouteFloor{}, err
	}
	d, err := openDir(dir)
	if err != nil {
		return RouteFloor{}, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	return d.readRouteFloor(routeID)
}

// RaiseRoute holds the directory's exclusive lock while it reads routeID's
// floor, and takes a route at serial with digest: one above the floor's
// serial, or any when the floor holds none, replaces the file whole; one at
// it with its digest leaves the file as it was. It refuses a serial below
// the floor's with ErrRouteBelowFloor, the floor's serial with another digest
// with ErrRouteForked, and a serial or digest no route carries with
// ErrRouteInvalid, each leaving the file as it was, and every refusal
// ReadRoute makes. It never creates a directory, a marker or a floor file.
// It returns the floor it leaves, and waits for the lock until ctx ends.
func RaiseRoute(ctx context.Context, dir, routeID string, serial int64, digest string) (_ RouteFloor, err error) {
	next := RouteFloor{RouteID: routeID, Serial: serial, Digest: digest}
	if err := next.check(); err != nil {
		return RouteFloor{}, err
	}
	if !next.HasSerial() {
		return RouteFloor{}, fmt.Errorf("%w: serial 0", ErrRouteInvalid)
	}
	d, err := openDir(dir)
	if err != nil {
		return RouteFloor{}, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	unlock, err := d.lockToWrite(ctx)
	if err != nil {
		return RouteFloor{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	stored, err := d.readRouteFloor(routeID)
	if err != nil {
		return RouteFloor{}, err
	}
	raise, err := stored.takes(next)
	switch {
	case err != nil:
		return RouteFloor{}, err
	case !raise:
		return stored, nil
	}
	if err := d.writeRouteFloor(next); err != nil {
		return RouteFloor{}, err
	}
	return next, nil
}

// writeRouteFloor replaces the route floor file f names, whole.
func (d *dir) writeRouteFloor(f RouteFloor) error {
	body, err := encodeRouteFile(f)
	if err != nil {
		return err
	}
	return replaceIn(d.root, routeName(f.RouteID), body, 0o600)
}

// takes reports whether the floor takes next by raising itself to it. A
// floor with no serial holds 0, below every route's; one at next's serial and
// digest takes it as it is; a lower serial, or the same with another digest,
// is refused.
func (f RouteFloor) takes(next RouteFloor) (raise bool, err error) {
	switch {
	case next.Serial > f.Serial:
		return true, nil
	case next.Serial < f.Serial:
		return false, fmt.Errorf("%w: serial %d, the floor's %d", ErrRouteBelowFloor, next.Serial, f.Serial)
	case next.Digest != f.Digest:
		return false, fmt.Errorf("%w: serial %d", ErrRouteForked, next.Serial)
	}
	return false, nil
}

// readRouteFloor judges what the directory holds and reads routeID's floor
// file.
func (d *dir) readRouteFloor(routeID string) (RouteFloor, error) {
	entries, err := d.readDir()
	if err != nil {
		return RouteFloor{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	if _, err := d.judgeRouteContents(entries); err != nil {
		return RouteFloor{}, err
	}
	// judgeRouteContents refuses a file the marker does not list, so a file
	// read here is a listed id's, and an id never listed has no file.
	name := routeName(routeID)
	raw, err := d.readFile(name, maxFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return RouteFloor{}, fmt.Errorf("%w: %s", ErrNoFloor, name)
	case err != nil:
		return RouteFloor{}, err
	}
	f, err := decodeRouteFile(raw)
	switch {
	case err != nil:
		return RouteFloor{}, fmt.Errorf("%s: %w", name, err)
	case f.RouteID != routeID:
		return RouteFloor{}, fmt.Errorf("%w: %s", ErrNameMismatch, name)
	}
	return f, nil
}

// judgeRouteContents is judgeContents for a route floor directory: a plane's
// or a signer's marker is the other kind's, and the route marker names the
// files the directory may hold.
func (d *dir) judgeRouteContents(entries []os.DirEntry) ([]string, error) {
	if holds(entries, markerFile) {
		return nil, fmt.Errorf("%w: it holds a plane's or a signer's floors, not route floors", ErrWrongKind)
	}
	if !holds(entries, routeMarkerFile) {
		return nil, fmt.Errorf("%w: it holds no %s", ErrNotStateDir, routeMarkerFile)
	}
	raw, err := d.readFile(routeMarkerFile, maxMarkerBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	ids, err := decodeRouteMarker(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	if err := judgeEntries(entries, routeMarkerFile, ids, routeName); err != nil {
		return nil, err
	}
	return ids, nil
}
