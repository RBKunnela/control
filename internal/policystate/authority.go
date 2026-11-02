package policystate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
)

// KindAuthority is the floors of the trust rosters a plane takes. Its
// directory has a marker and file names of its own, and only InitAuthority,
// ReadAuthority and RaiseAuthority open it.
const KindAuthority Kind = "authority"

// MaxRosterIDs bounds how many roster ids one directory lists.
const MaxRosterIDs = 32

// The vocabulary of an authority floor.
const (
	// ErrAuthorityInvalid is a roster id, serial or digest no roster can
	// carry.
	ErrAuthorityInvalid Error = "policystate: not a roster id, serial or digest a roster can carry"
	// ErrAuthorityBelowFloor is a roster whose serial is below its floor's.
	ErrAuthorityBelowFloor Error = "policystate: the roster's serial is below the floor's"
	// ErrAuthorityForked is a roster at its floor's serial with another
	// digest: two rosters signed under one serial.
	ErrAuthorityForked Error = "policystate: the roster's serial is the floor's but its digest is another"
	// ErrTooManyRosterIDs is InitAuthority of an id past MaxRosterIDs, or a
	// marker listing more.
	ErrTooManyRosterIDs Error = "policystate: the directory lists as many roster ids as it may"
)

// The names an authority floor directory holds besides what a crash leaves.
const (
	authorityMarkerFile = "authority.meta"
	authoritySuffix     = ".authority.json"
)

// authorityNameDomain is hashed ahead of a roster id to name its file, so a
// roster id never names the file a bundle or a route id of the same text
// names.
const authorityNameDomain = "agent-authority-floor-name/v1\n"

var (
	authorityMarkerMembers = []string{"schema_version", "kind", "roster_ids"}
	authorityFileMembers   = []string{"schema_version", "roster_id", "serial", "digest"}
)

// AuthorityFloor is a roster id's floor: the highest serial a plane took and
// the digest of the roster at it. Serial is 0 and Digest empty while the
// floor holds no serial yet.
type AuthorityFloor struct {
	RosterID string
	Serial   int64
	Digest   string
}

// HasSerial reports whether a roster was ever taken into the floor.
func (f AuthorityFloor) HasSerial() bool { return f.Serial != 0 }

// InitAuthority gives rosterID a floor file holding no serial yet in dir, an
// authority floor directory, and lists it in the marker. It makes dir, mode
// 0700, when nothing stands at the name. It refuses an id whose file exists
// with ErrExists, an id listed once whose file is gone with ErrFloorRemoved,
// an id past MaxRosterIDs with ErrTooManyRosterIDs, another kind's directory
// with ErrWrongKind, and every directory ReadAuthority refuses. It never
// lowers a floor.
func InitAuthority(ctx context.Context, dir, rosterID string) (err error) {
	body, err := encodeAuthorityFile(AuthorityFloor{RosterID: rosterID})
	if err != nil {
		return err
	}
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
	if err := d.claimAuthority(rosterID); err != nil {
		return err
	}
	name := authorityName(rosterID)
	if err := files.CreateNoReplaceIn(d.root, name, body, 0o600); err != nil {
		if errors.Is(err, files.ErrExists) {
			return fmt.Errorf("%w: %s", ErrExists, name)
		}
		return err
	}
	return nil
}

// claimAuthority lists rosterID in the marker before its file is made, as
// claim does.
func (d *dir) claimAuthority(rosterID string) error {
	entries, err := d.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	if onlyLeftovers(entries) {
		return d.writeAuthorityMarker([]string{rosterID}, true)
	}
	ids, err := d.judgeAuthorityContents(entries)
	if err != nil {
		return err
	}
	if slices.Contains(ids, rosterID) {
		name := authorityName(rosterID)
		_, err := d.root.Lstat(name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%w: %s; an authority floor is made again only in a new directory", ErrFloorRemoved, name)
		case err != nil:
			return err
		}
		return fmt.Errorf("%w: %s", ErrExists, name)
	}
	if len(ids) >= MaxRosterIDs {
		return fmt.Errorf("%w: %d listed", ErrTooManyRosterIDs, len(ids))
	}
	ids = append(ids, rosterID)
	slices.Sort(ids)
	return d.writeAuthorityMarker(ids, false)
}

func (d *dir) writeAuthorityMarker(ids []string, create bool) error {
	body, err := encodeAuthorityMarker(ids)
	if err != nil {
		return err
	}
	if create {
		err = files.CreateNoReplaceIn(d.root, authorityMarkerFile, body, 0o600)
	} else {
		err = replaceIn(d.root, authorityMarkerFile, body, 0o600)
	}
	if err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	return nil
}

// ReadAuthority reads rosterID's floor from dir and writes nothing. It takes
// no lock: a file is only ever replaced whole. It refuses what RaiseAuthority
// refuses before it compares.
func ReadAuthority(dir, rosterID string) (_ AuthorityFloor, err error) {
	if err := checkRosterID(rosterID); err != nil {
		return AuthorityFloor{}, err
	}
	d, err := openDir(dir)
	if err != nil {
		return AuthorityFloor{}, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	return d.readAuthorityFloor(rosterID)
}

// RaiseAuthority holds the directory's exclusive lock while it reads
// rosterID's floor, and takes a roster at serial with digest: one above the
// floor's serial replaces the file whole, and one at it with its digest
// leaves the file as it was. It refuses a lower serial with
// ErrAuthorityBelowFloor, the floor's serial with another digest with
// ErrAuthorityForked, and a serial or digest no roster carries with
// ErrAuthorityInvalid, each leaving the file as it was. It never creates a
// directory, a marker or a floor file, and waits for the lock until ctx ends.
func RaiseAuthority(ctx context.Context, dir, rosterID string, serial int64, digest string) (AuthorityFloor, error) {
	return raiseSerial(ctx, dir, AuthorityFloor{RosterID: rosterID, Serial: serial, Digest: digest})
}

var authorityRefusals = serialRefusals{invalid: ErrAuthorityInvalid, below: ErrAuthorityBelowFloor, forked: ErrAuthorityForked}

func (f AuthorityFloor) at() serialAt           { return serialAt{serial: f.Serial, digest: f.Digest} }
func (AuthorityFloor) refusals() serialRefusals { return authorityRefusals }
func (f AuthorityFloor) readFrom(d *dir) (AuthorityFloor, error) {
	return d.readAuthorityFloor(f.RosterID)
}

// writeTo replaces the authority floor file f names, whole.
func (f AuthorityFloor) writeTo(d *dir) error {
	body, err := encodeAuthorityFile(f)
	if err != nil {
		return err
	}
	return replaceIn(d.root, authorityName(f.RosterID), body, 0o600)
}

func (d *dir) readAuthorityFloor(rosterID string) (AuthorityFloor, error) {
	entries, err := d.readDir()
	if err != nil {
		return AuthorityFloor{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	if _, err := d.judgeAuthorityContents(entries); err != nil {
		return AuthorityFloor{}, err
	}
	name := authorityName(rosterID)
	raw, err := d.readFile(name, maxFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return AuthorityFloor{}, fmt.Errorf("%w: %s", ErrNoFloor, name)
	case err != nil:
		return AuthorityFloor{}, err
	}
	f, err := decodeAuthorityFile(raw)
	switch {
	case err != nil:
		return AuthorityFloor{}, fmt.Errorf("%s: %w", name, err)
	case f.RosterID != rosterID:
		return AuthorityFloor{}, fmt.Errorf("%w: %s", ErrNameMismatch, name)
	}
	return f, nil
}

// judgeAuthorityContents refuses a directory holding another kind's marker,
// one holding no authority marker, and any name the marker does not account
// for.
func (d *dir) judgeAuthorityContents(entries []os.DirEntry) ([]string, error) {
	if holds(entries, markerFile) || holds(entries, routeMarkerFile) {
		return nil, fmt.Errorf("%w: it holds a plane's, a signer's or route floors, not authority floors", ErrWrongKind)
	}
	if !holds(entries, authorityMarkerFile) {
		return nil, fmt.Errorf("%w: it holds no %s", ErrNotStateDir, authorityMarkerFile)
	}
	raw, err := d.readFile(authorityMarkerFile, maxMarkerBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	ids, err := decodeAuthorityMarker(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	if err := judgeEntries(entries, authorityMarkerFile, ids, authorityName); err != nil {
		return nil, err
	}
	return ids, nil
}

func authorityName(rosterID string) string {
	sum := sha256.Sum256([]byte(authorityNameDomain + rosterID))
	return hex.EncodeToString(sum[:]) + authoritySuffix
}

func checkRosterID(id string) error {
	if !policy.ValidID(id) {
		return fmt.Errorf("%w: the roster id", ErrAuthorityInvalid)
	}
	return nil
}

func (f AuthorityFloor) check() error {
	if err := checkRosterID(f.RosterID); err != nil {
		return err
	}
	switch {
	case f.Serial == 0 && f.Digest == "":
		return nil
	case f.Serial < 1 || f.Serial > policy.MaxSerial:
		return fmt.Errorf("%w: serial %d", ErrAuthorityInvalid, f.Serial)
	case !canon.ValidDigest(f.Digest):
		return fmt.Errorf("%w: the digest", ErrAuthorityInvalid)
	}
	return nil
}
