package policystate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/policy"
)

// Init gives bundleID a floor file holding no serial yet in dir, a floor
// directory of kind, and lists bundleID in the marker. It makes dir, mode
// 0700, when nothing stands at the name, and makes an empty directory, or
// one holding only what a crash left, a floor directory of kind. It is never
// a second way to lower a floor: it refuses an id whose file exists with
// ErrExists, never replacing one, and an id listed once whose file is gone
// with ErrFloorRemoved, since only Reset may give that id a floor again. It
// refuses an id past MaxBundleIDs with ErrTooManyBundleIDs. Every refusal
// Open makes, it makes too.
func Init(ctx context.Context, dir string, kind Kind, bundleID string) (err error) {
	if err := checkKind(kind); err != nil {
		return err
	}
	empty, err := policy.EmptyFloor(bundleID)
	if err != nil {
		return err
	}
	body, err := encodeFloorFile(Record{Floor: empty})
	if err != nil {
		return err
	}
	// The mode is only ever narrowed by the umask, and an owner without
	// access cannot open the directory, so no mode wider than 0700 results.
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
	if err := d.claim(kind, bundleID); err != nil {
		return err
	}
	name := floorName(bundleID)
	if err := files.CreateNoReplaceIn(d.root, name, body, 0o600); err != nil {
		if errors.Is(err, files.ErrExists) {
			return fmt.Errorf("%w: %s", ErrExists, name)
		}
		return err
	}
	return nil
}

// claim lists bundleID in the marker before its file is made, so a crash in
// between leaves an id whose file is missing, which Reset can mend, and never
// a file the marker does not list. An empty directory, or one holding only
// what a crash left, becomes a floor directory of kind; any other is judged
// as Open judges it.
func (d *dir) claim(kind Kind, bundleID string) error {
	entries, err := d.readDir()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	if onlyLeftovers(entries) {
		return d.writeMarker(kind, []string{bundleID}, true)
	}
	ids, err := d.judgeContents(entries, kind)
	if err != nil {
		return err
	}
	if slices.Contains(ids, bundleID) {
		_, err := d.root.Lstat(floorName(bundleID))
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrFloorRemoved, floorName(bundleID))
		}
		return nil
	}
	if len(ids) >= MaxBundleIDs {
		return fmt.Errorf("%w: %d listed", ErrTooManyBundleIDs, len(ids))
	}
	ids = append(ids, bundleID)
	slices.Sort(ids)
	return d.writeMarker(kind, ids, false)
}

// onlyLeftovers reports whether entries hold nothing but regular files under
// a temporary name of internal/files, none at all included.
func onlyLeftovers(entries []os.DirEntry) bool {
	for _, e := range entries {
		if !e.Type().IsRegular() || !files.IsTemp(e.Name()) {
			return false
		}
	}
	return true
}

// writeMarker writes the marker naming kind and ids: created where none
// stands, or replaced whole.
func (d *dir) writeMarker(kind Kind, ids []string, create bool) error {
	body, err := encodeMarker(kind, ids)
	if err != nil {
		return err
	}
	if create {
		err = files.CreateNoReplaceIn(d.root, markerFile, body, 0o600)
	} else {
		err = replaceIn(d.root, markerFile, body, 0o600)
	}
	if err != nil {
		return fmt.Errorf("%w: the marker: %w", ErrNotStateDir, err)
	}
	return nil
}

// Reset sets the floor of to's bundle id in dir, a floor directory of kind,
// to to, whatever it held, and records reason and the floor it replaced in
// the file. It returns the floor it replaced. A listed id whose file is gone
// gets its file again, recorded as found missing, the floor it replaced
// returned as one with no serial. A Reset that finds its own floor and
// reason already written, as a retry after a write that failed past its
// rename does, writes nothing and returns the floor the first one replaced.
// It refuses the zero Floor with policy.ErrFloorInvalid, a reason checkReason
// refuses with ErrReason, and an id the marker does not list with ErrNoFloor:
// Init alone lists one. Every refusal Open makes, it makes too, and it holds
// the directory's lock, so no raise runs inside it.
func Reset(ctx context.Context, dir string, kind Kind, to policy.Floor, reason string) (_ policy.Floor, err error) {
	if err := checkKind(kind); err != nil {
		return policy.Floor{}, err
	}
	if to.BundleID() == "" {
		return policy.Floor{}, policy.ErrFloorInvalid
	}
	if err := checkReason(reason); err != nil {
		return policy.Floor{}, err
	}
	d, err := openDir(dir)
	if err != nil {
		return policy.Floor{}, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	unlock, err := d.lockToWrite(ctx)
	if err != nil {
		return policy.Floor{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	entries, err := d.readDir()
	if err != nil {
		return policy.Floor{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	ids, err := d.judgeContents(entries, kind)
	if err != nil {
		return policy.Floor{}, err
	}
	if !slices.Contains(ids, to.BundleID()) {
		return policy.Floor{}, fmt.Errorf("%w: %s, an id this directory never initialised", ErrNoFloor, floorName(to.BundleID()))
	}
	note, done, err := d.resetNote(to, reason)
	if err != nil || done {
		return note.From, err
	}
	if err := d.writeRecord(Record{Floor: to, Reset: &note}); err != nil {
		return policy.Floor{}, err
	}
	return note.From, nil
}

// resetNote is what a reset of to's file records: the floor the file holds,
// or a floor with no serial when the file is gone. done is true when the file
// already holds to with this reason's note, which is then returned.
func (d *dir) resetNote(to policy.Floor, reason string) (note ResetNote, done bool, err error) {
	stored, err := d.readRecord(to.BundleID())
	switch {
	case errors.Is(err, ErrNoFloor):
		empty, err := policy.EmptyFloor(to.BundleID())
		return ResetNote{Reason: reason, From: empty, FileMissing: true}, false, err
	case err != nil:
		return ResetNote{}, false, err
	case stored.Floor.Equal(to) && stored.Reset != nil && stored.Reset.Reason == reason:
		return *stored.Reset, true, nil
	}
	return ResetNote{Reason: reason, From: stored.Floor}, false, nil
}
