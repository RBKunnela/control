package policystate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
)

// KindStops is the floor of the signed stop lists one plane takes: the
// highest header serial it took for its tenant and project, the list head's
// digest at it, and the length and SHA-256 of the part of that list it
// accepted. Its directory holds that one floor, and only
// InitStops, ReadStops and RaiseStops open it.
const KindStops Kind = "stops"

// The vocabulary of a stop list floor.
const (
	// ErrStopsInvalid is a tenant, project, serial or digest no signed stop
	// list header can carry.
	ErrStopsInvalid Error = "policystate: not a tenant, project, serial or digest a signed stop list header can carry"
	// ErrStopsBelowFloor is a stop list whose header serial is below the
	// floor's: an older list put back.
	ErrStopsBelowFloor Error = "policystate: the stop list's serial is below the floor's"
	// ErrStopsForked is a stop list at its floor's serial with another head
	// digest: two lists signed under one serial.
	ErrStopsForked Error = "policystate: the stop list's serial is the floor's but its head digest is another"
	// ErrStopsRewritten is a stop list at its floor's serial and head whose
	// accepted part is shorter than the floor's, or of its length with other
	// bytes: lines the plane accepted were cut or changed.
	ErrStopsRewritten Error = "policystate: the stop list's accepted part is shorter than the floor's or other bytes"
	// ErrStopsScope is a stop list floor directory kept for another tenant
	// or project than the one asked for.
	ErrStopsScope Error = "policystate: the stop list floor is another tenant's or project's"
)

// The names a stop list floor directory holds besides what a crash leaves.
const (
	stopsMarkerFile = "stops.meta"
	stopsFloorFile  = "stops.floor.json"
)

var (
	stopsMarkerMembers = []string{"schema_version", "kind", "tenant", "project"}
	stopsFileMembers   = []string{"schema_version", "tenant", "project", "serial", "digest", "length", "prefix"}
)

// StopsFloor is a plane's stop list floor: its tenant and project, the
// highest header serial taken with the head digest of the list at it, and
// the Length in bytes and the SHA-256 Prefix of that list's part the plane
// accepted. Serial and Length are 0 and the digests empty while the floor
// holds no serial yet.
type StopsFloor struct {
	Tenant, Project string
	Serial          int64
	Digest          string
	Length          int64
	Prefix          string
}

// HasSerial reports whether a signed stop list was ever taken into the floor.
func (f StopsFloor) HasSerial() bool { return f.Serial != 0 }

// InitStops makes dir the stop list floor directory of tenant and project, its
// floor holding no serial yet. It makes dir, mode 0700, when nothing stands
// at the name. It refuses a directory that holds a stop list floor already with
// ErrExists, one whose floor file is gone with ErrFloorRemoved, so it never
// lowers a floor; another kind's directory with ErrWrongKind; and anything
// else than what a crash leaves with ErrForeignFile.
func InitStops(ctx context.Context, dir, tenant, project string) (err error) {
	f := StopsFloor{Tenant: tenant, Project: project}
	body, err := encodeStopsFile(f)
	if err != nil {
		return err
	}
	marker, err := encodeStopsMarker(tenant, project)
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
	if err := d.refuseStopsInitOver(); err != nil {
		return err
	}
	if err := files.CreateNoReplaceIn(d.root, stopsMarkerFile, marker, 0o600); err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	if err := files.CreateNoReplaceIn(d.root, stopsFloorFile, body, 0o600); err != nil {
		if errors.Is(err, files.ErrExists) {
			return fmt.Errorf("%w: %s", ErrExists, stopsFloorFile)
		}
		return err
	}
	return nil
}

// refuseStopsInitOver refuses a directory holding anything but what a crash
// leaves: another kind's, or a stop list floor made already, whose file is there
// or gone.
func (d *dir) refuseStopsInitOver() error {
	entries, err := d.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	if onlyLeftovers(entries) {
		return nil
	}
	if _, err := d.judgeStopsContents(entries); err != nil {
		return err
	}
	if holds(entries, stopsFloorFile) {
		return fmt.Errorf("%w: %s", ErrExists, stopsFloorFile)
	}
	return fmt.Errorf("%w: %s; a stop list floor is made again only in a new directory", ErrFloorRemoved, stopsFloorFile)
}

// ReadStops reads the stop list floor of tenant and project from dir and writes
// nothing. It takes no lock: a file is only ever replaced whole. It refuses
// what RaiseStops refuses before it compares, a directory kept for another
// tenant or project with ErrStopsScope among them.
func ReadStops(dir, tenant, project string) (_ StopsFloor, err error) {
	if err := checkStopsScope(tenant, project); err != nil {
		return StopsFloor{}, err
	}
	d, err := openDir(dir)
	if err != nil {
		return StopsFloor{}, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	return d.readStopsFloor(tenant, project)
}

// RaiseStops holds the directory's exclusive lock while it reads the stop list
// floor of next's tenant and project, and takes next: a serial above the
// floor's, or a longer accepted part at its serial and head, replaces the file
// whole, and the floor's own serial, head and part leave it as they were. It
// refuses a lower serial with ErrStopsBelowFloor, the floor's serial with
// another head with ErrStopsForked, a shorter part or one of the floor's
// length with another SHA-256 with ErrStopsRewritten, and a serial, digest or
// length no stop list carries with ErrStopsInvalid, each leaving the file as
// it was, and every refusal ReadStops makes. Whether a longer part begins with
// the floor's is the caller's to check before. It never creates a directory, a
// marker or a floor file, and waits for the lock until ctx ends.
func RaiseStops(ctx context.Context, dir string, next StopsFloor) (StopsFloor, error) {
	return raiseSerial(ctx, dir, next)
}

var stopsRefusals = serialRefusals{invalid: ErrStopsInvalid, below: ErrStopsBelowFloor, forked: ErrStopsForked, rewritten: ErrStopsRewritten}

func (f StopsFloor) at() serialAt {
	return serialAt{serial: f.Serial, digest: f.Digest, length: f.Length, prefix: f.Prefix}
}
func (StopsFloor) refusals() serialRefusals { return stopsRefusals }
func (f StopsFloor) readFrom(d *dir) (StopsFloor, error) {
	return d.readStopsFloor(f.Tenant, f.Project)
}

// writeTo replaces the stop list floor file whole.
func (f StopsFloor) writeTo(d *dir) error {
	body, err := encodeStopsFile(f)
	if err != nil {
		return err
	}
	return replaceIn(d.root, stopsFloorFile, body, 0o600)
}

func (d *dir) readStopsFloor(tenant, project string) (StopsFloor, error) {
	entries, err := d.readDir()
	if err != nil {
		return StopsFloor{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	scope, err := d.judgeStopsContents(entries)
	if err != nil {
		return StopsFloor{}, err
	}
	if scope != [2]string{tenant, project} {
		return StopsFloor{}, ErrStopsScope
	}
	raw, err := d.readFile(stopsFloorFile, maxFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return StopsFloor{}, fmt.Errorf("%w: %s", ErrNoFloor, stopsFloorFile)
	case err != nil:
		return StopsFloor{}, err
	}
	f, err := decodeStopsFile(raw)
	switch {
	case err != nil:
		return StopsFloor{}, fmt.Errorf("%s: %w", stopsFloorFile, err)
	case f.Tenant != tenant || f.Project != project:
		return StopsFloor{}, fmt.Errorf("%w: %s", ErrNameMismatch, stopsFloorFile)
	}
	return f, nil
}

// judgeStopsContents refuses a directory holding another kind's marker, one
// holding no stop list marker, and any name but the marker, the floor file and
// what a crash leaves. It returns the tenant and the project the marker
// names.
func (d *dir) judgeStopsContents(entries []os.DirEntry) ([2]string, error) {
	for _, other := range []string{markerFile, routeMarkerFile, authorityMarkerFile, pauseMarkerFile} {
		if holds(entries, other) {
			return [2]string{}, fmt.Errorf("%w: it holds a plane's, a signer's, route, authority or pause floors, not a stop list floor", ErrWrongKind)
		}
	}
	if !holds(entries, stopsMarkerFile) {
		return [2]string{}, fmt.Errorf("%w: it holds no %s", ErrNotStateDir, stopsMarkerFile)
	}
	raw, err := d.readFile(stopsMarkerFile, maxMarkerBytes)
	if err != nil {
		return [2]string{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	tenant, project, err := decodeStopsMarker(raw)
	if err != nil {
		return [2]string{}, fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	if err := judgeEntries(entries, stopsMarkerFile, []string{stopsFloorFile}, func(name string) string { return name }); err != nil {
		return [2]string{}, err
	}
	return [2]string{tenant, project}, nil
}

func checkStopsScope(tenant, project string) error {
	if !policy.ValidID(tenant) || !policy.ValidID(project) {
		return fmt.Errorf("%w: the tenant or the project", ErrStopsInvalid)
	}
	return nil
}

func (f StopsFloor) check() error {
	if err := checkStopsScope(f.Tenant, f.Project); err != nil {
		return err
	}
	switch {
	case f.Serial == 0 && f.Digest == "" && f.Length == 0 && f.Prefix == "":
		return nil
	case f.Serial < 1 || f.Serial > policy.MaxSerial:
		return fmt.Errorf("%w: serial %d", ErrStopsInvalid, f.Serial)
	case !canon.ValidDigest(f.Digest):
		return fmt.Errorf("%w: the digest", ErrStopsInvalid)
	case f.Length < 1:
		return fmt.Errorf("%w: length %d", ErrStopsInvalid, f.Length)
	case !canon.ValidDigest(f.Prefix):
		return fmt.Errorf("%w: the prefix", ErrStopsInvalid)
	}
	return nil
}
