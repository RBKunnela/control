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

// KindPause is the floor of the signed pause documents one plane takes: the
// highest serial it took for its tenant and project and the document's digest
// at it. Its directory holds that one floor, and only InitPause, ReadPause and
// RaisePause open it.
const KindPause Kind = "pause"

// The vocabulary of a pause floor.
const (
	// ErrPauseInvalid is a tenant, project, serial or digest no signed pause
	// document can carry.
	ErrPauseInvalid Error = "policystate: not a tenant, project, serial or digest a signed pause can carry"
	// ErrPauseBelowFloor is a pause document whose serial is below the
	// floor's: an older document replayed.
	ErrPauseBelowFloor Error = "policystate: the pause document's serial is below the floor's"
	// ErrPauseForked is a pause document at its floor's serial with another
	// digest: two documents signed under one serial.
	ErrPauseForked Error = "policystate: the pause document's serial is the floor's but its digest is another"
	// ErrPauseScope is a pause floor directory kept for another tenant or
	// project than the one asked for.
	ErrPauseScope Error = "policystate: the pause floor is another tenant's or project's"
)

// The names a pause floor directory holds besides what a crash leaves.
const (
	pauseMarkerFile = "pause.meta"
	pauseFloorFile  = "pause.floor.json"
)

var (
	pauseMarkerMembers = []string{"schema_version", "kind", "tenant", "project"}
	pauseFileMembers   = []string{"schema_version", "tenant", "project", "serial", "digest"}
)

// PauseFloor is a plane's pause floor: its tenant and project, and the
// highest serial taken with the digest of the document at it. Serial is 0 and
// Digest empty while the floor holds no serial yet.
type PauseFloor struct {
	Tenant, Project string
	Serial          int64
	Digest          string
}

// HasSerial reports whether a signed pause was ever taken into the floor.
func (f PauseFloor) HasSerial() bool { return f.Serial != 0 }

// InitPause makes dir the pause floor directory of tenant and project, its
// floor holding no serial yet. It makes dir, mode 0700, when nothing stands
// at the name. It refuses a directory that holds a pause floor already with
// ErrExists, one whose floor file is gone with ErrFloorRemoved, so it never
// lowers a floor; another kind's directory with ErrWrongKind; and anything
// else than what a crash leaves with ErrForeignFile.
func InitPause(ctx context.Context, dir, tenant, project string) (err error) {
	f := PauseFloor{Tenant: tenant, Project: project}
	body, err := encodePauseFile(f)
	if err != nil {
		return err
	}
	marker, err := encodePauseMarker(tenant, project)
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
	if err := d.refuseInitOver(); err != nil {
		return err
	}
	if err := files.CreateNoReplaceIn(d.root, pauseMarkerFile, marker, 0o600); err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	if err := files.CreateNoReplaceIn(d.root, pauseFloorFile, body, 0o600); err != nil {
		if errors.Is(err, files.ErrExists) {
			return fmt.Errorf("%w: %s", ErrExists, pauseFloorFile)
		}
		return err
	}
	return nil
}

// refuseInitOver refuses a directory holding anything but what a crash
// leaves: another kind's, or a pause floor made already, whose file is there
// or gone.
func (d *dir) refuseInitOver() error {
	entries, err := d.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	if onlyLeftovers(entries) {
		return nil
	}
	if _, err := d.judgePauseContents(entries); err != nil {
		return err
	}
	if holds(entries, pauseFloorFile) {
		return fmt.Errorf("%w: %s", ErrExists, pauseFloorFile)
	}
	return fmt.Errorf("%w: %s; a pause floor is made again only in a new directory", ErrFloorRemoved, pauseFloorFile)
}

// ReadPause reads the pause floor of tenant and project from dir and writes
// nothing. It takes no lock: a file is only ever replaced whole. It refuses
// what RaisePause refuses before it compares, a directory kept for another
// tenant or project with ErrPauseScope among them.
func ReadPause(dir, tenant, project string) (_ PauseFloor, err error) {
	if err := checkPauseScope(tenant, project); err != nil {
		return PauseFloor{}, err
	}
	d, err := openDir(dir)
	if err != nil {
		return PauseFloor{}, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	return d.readPauseFloor(tenant, project)
}

// RaisePause holds the directory's exclusive lock while it reads the pause
// floor, and takes a document of tenant and project at serial with digest:
// one above the floor's serial replaces the file whole, and one at it with its
// digest leaves the file as it was. It refuses a lower serial with
// ErrPauseBelowFloor, the floor's serial with another digest with
// ErrPauseForked, and a serial or digest no document carries with
// ErrPauseInvalid, each leaving the file as it was, and every refusal
// ReadPause makes. It never creates a directory, a marker or a floor file,
// and waits for the lock until ctx ends.
func RaisePause(ctx context.Context, dir, tenant, project string, serial int64, digest string) (PauseFloor, error) {
	return raiseSerial(ctx, dir, PauseFloor{Tenant: tenant, Project: project, Serial: serial, Digest: digest})
}

var pauseRefusals = serialRefusals{invalid: ErrPauseInvalid, below: ErrPauseBelowFloor, forked: ErrPauseForked}

func (f PauseFloor) at() serialAt           { return serialAt{serial: f.Serial, digest: f.Digest} }
func (PauseFloor) refusals() serialRefusals { return pauseRefusals }
func (f PauseFloor) readFrom(d *dir) (PauseFloor, error) {
	return d.readPauseFloor(f.Tenant, f.Project)
}

// writeTo replaces the pause floor file whole.
func (f PauseFloor) writeTo(d *dir) error {
	body, err := encodePauseFile(f)
	if err != nil {
		return err
	}
	return replaceIn(d.root, pauseFloorFile, body, 0o600)
}

func (d *dir) readPauseFloor(tenant, project string) (PauseFloor, error) {
	entries, err := d.readDir()
	if err != nil {
		return PauseFloor{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	scope, err := d.judgePauseContents(entries)
	if err != nil {
		return PauseFloor{}, err
	}
	if scope != [2]string{tenant, project} {
		return PauseFloor{}, ErrPauseScope
	}
	raw, err := d.readFile(pauseFloorFile, maxFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return PauseFloor{}, fmt.Errorf("%w: %s", ErrNoFloor, pauseFloorFile)
	case err != nil:
		return PauseFloor{}, err
	}
	f, err := decodePauseFile(raw)
	switch {
	case err != nil:
		return PauseFloor{}, fmt.Errorf("%s: %w", pauseFloorFile, err)
	case f.Tenant != tenant || f.Project != project:
		return PauseFloor{}, fmt.Errorf("%w: %s", ErrNameMismatch, pauseFloorFile)
	}
	return f, nil
}

// judgePauseContents refuses a directory holding another kind's marker, one
// holding no pause marker, and any name but the marker, the floor file and
// what a crash leaves. It returns the tenant and the project the marker
// names.
func (d *dir) judgePauseContents(entries []os.DirEntry) ([2]string, error) {
	for _, other := range []string{markerFile, routeMarkerFile, authorityMarkerFile} {
		if holds(entries, other) {
			return [2]string{}, fmt.Errorf("%w: it holds a plane's, a signer's, route or authority floors, not a pause floor", ErrWrongKind)
		}
	}
	if !holds(entries, pauseMarkerFile) {
		return [2]string{}, fmt.Errorf("%w: it holds no %s", ErrNotStateDir, pauseMarkerFile)
	}
	raw, err := d.readFile(pauseMarkerFile, maxMarkerBytes)
	if err != nil {
		return [2]string{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	tenant, project, err := decodePauseMarker(raw)
	if err != nil {
		return [2]string{}, fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	if err := judgeEntries(entries, pauseMarkerFile, []string{pauseFloorFile}, func(name string) string { return name }); err != nil {
		return [2]string{}, err
	}
	return [2]string{tenant, project}, nil
}

func checkPauseScope(tenant, project string) error {
	if !policy.ValidID(tenant) || !policy.ValidID(project) {
		return fmt.Errorf("%w: the tenant or the project", ErrPauseInvalid)
	}
	return nil
}

func (f PauseFloor) check() error {
	if err := checkPauseScope(f.Tenant, f.Project); err != nil {
		return err
	}
	switch {
	case f.Serial == 0 && f.Digest == "":
		return nil
	case f.Serial < 1 || f.Serial > policy.MaxSerial:
		return fmt.Errorf("%w: serial %d", ErrPauseInvalid, f.Serial)
	case !canon.ValidDigest(f.Digest):
		return fmt.Errorf("%w: the digest", ErrPauseInvalid)
	}
	return nil
}
