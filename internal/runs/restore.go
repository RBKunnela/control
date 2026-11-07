package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// ErrTwoHistories is one run id two directories hold as two runs: another
// identity, lineage, lifetime or secret.
const ErrTwoHistories Error = "runs: one run id names two runs"

// lostState stands for a root's state a directory lost while it kept the
// root's record: everything taken in, nothing known of the reads.
var lostState = State{Untrusted: true, MaxRead: controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED}

// JoinStates is what a restore keeps of two states of one root: untrusted
// where either is, and the higher read, unknown where either is unknown.
func JoinStates(a, b State) State {
	read := max(a.MaxRead, b.MaxRead)
	if !contract.ValidSensitivityFloor(a.MaxRead) || !contract.ValidSensitivityFloor(b.MaxRead) {
		read = controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED
	}
	return State{Untrusted: a.Untrusted || b.Untrusted, MaxRead: read}
}

// Restored is what a restore of a runs directory wrote.
type Restored struct {
	// Closed counts the records written closed, States the states written
	// and Carried the closes carried into a signed layout's state/.
	Closed, States, Carried int
}

// RestoreUnsigned rewrites live, an unsigned runs directory, from backup, a
// copy of one, and closes every run at now: each run either holds is written
// closed, a close already recorded kept, and each root's state is the join
// of the two, a state lost beside its record joined as lostState. Each
// state is written under the root's lock, the one Plane.Raise takes, and
// joined with what it holds then, so a plane that raises the root meanwhile
// is never lowered. It refuses one id held as two runs with ErrTwoHistories
// and a signed layout on either side with ErrLayout, and makes a missing
// live a runs directory. An empty backup is none: live's runs are closed all
// the same. It holds live's lock, and step is called before each write.
func RestoreUnsigned(ctx context.Context, live, backup string, now time.Time, step func(string) error) (_ Restored, err error) {
	if now.IsZero() {
		return Restored{}, ErrZeroTime
	}
	if step == nil {
		step = func(string) error { return nil }
	}
	var from flatRuns
	if backup != "" {
		if from, err = readFlat(backup); err != nil {
			return Restored{}, fmt.Errorf("the backup's runs: %w", err)
		}
	}
	if err := os.Mkdir(live, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return Restored{}, fmt.Errorf("%w: %w", ErrNotRunsDir, err)
	}
	a, err := InitAdmin(ctx, live)
	if err != nil {
		return Restored{}, err
	}
	defer func() { err = errors.Join(err, a.Close()) }()
	if a.Signed() {
		return Restored{}, fmt.Errorf("%w: %s is a signed layout", ErrLayout, clip(live))
	}
	end, err := a.begin(ctx)
	if err != nil {
		return Restored{}, err
	}
	defer func() { err = errors.Join(err, end()) }()
	cur, err := a.d.flat()
	if err != nil {
		return Restored{}, err
	}
	merged, err := mergeRuns(cur, from, now)
	if err != nil {
		return Restored{}, err
	}
	return a.writeMerged(ctx, cur, merged, step)
}

// CheckRestoreUnsigned refuses what RestoreUnsigned would refuse of live
// and backup, ErrTwoHistories and ErrLayout among them, and writes nothing.
func CheckRestoreUnsigned(live, backup string, now time.Time) error {
	if now.IsZero() {
		return ErrZeroTime
	}
	var from flatRuns
	if backup != "" {
		var err error
		if from, err = readFlat(backup); err != nil {
			return fmt.Errorf("the backup's runs: %w", err)
		}
	}
	cur, err := liveFlat(live)
	if err != nil {
		return err
	}
	_, err = mergeRuns(cur, from, now)
	return err
}

// liveFlat is what live holds as RestoreUnsigned finds it: no run where no
// directory, or one holding only what a crash left, stands.
func liveFlat(live string) (flatRuns, error) {
	if _, err := os.Lstat(live); errors.Is(err, fs.ErrNotExist) {
		return flatRuns{}, nil
	}
	if signed, err := signedLayout(live); err != nil || signed {
		return flatRuns{}, errors.Join(err, fmt.Errorf("%w: %s is a signed layout", ErrLayout, clip(live)))
	}
	d, err := openDir(live, roleFlat, ownedByThisUser)
	if err != nil {
		return flatRuns{}, err
	}
	defer func() { _ = d.close() }()
	entries, err := d.readDir()
	if err != nil {
		return flatRuns{}, fmt.Errorf("%w: %w", ErrNotRunsDir, err)
	}
	if onlyLeftovers(entries) {
		return flatRuns{}, nil
	}
	if err := d.judgeContents(entries); err != nil {
		return flatRuns{}, err
	}
	return d.flat()
}

// flatRuns is what an unsigned directory holds: its records, and the state
// of each root whose state file is there.
type flatRuns struct {
	records map[string]Record
	states  map[string]State
}

func readFlat(path string) (flatRuns, error) {
	if signed, err := signedLayout(path); err != nil || signed {
		return flatRuns{}, errors.Join(err, fmt.Errorf("%w: a signed layout", ErrLayout))
	}
	d, err := openDir(path, roleFlat, ownedByThisUser)
	if err != nil {
		return flatRuns{}, err
	}
	defer func() { _ = d.close() }()
	if err := d.checkContents(); err != nil {
		return flatRuns{}, err
	}
	return d.flat()
}

func (d *dir) flat() (flatRuns, error) {
	entries, err := d.readDir()
	if err != nil {
		return flatRuns{}, err
	}
	ids, err := d.scan(entries)
	if err != nil {
		return flatRuns{}, err
	}
	out := flatRuns{records: map[string]Record{}, states: map[string]State{}}
	for _, id := range ids {
		rec, err := d.readRecord(id)
		if err != nil {
			return flatRuns{}, err
		}
		out.records[id] = rec
		if rec.Root != id {
			continue
		}
		switch s, err := d.readState(id); {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return flatRuns{}, err
		default:
			out.states[id] = s
		}
	}
	return out, nil
}

// mergeRuns is every run either side holds, closed at now unless a side
// closed it already, with each root's joined state.
func mergeRuns(cur, from flatRuns, now time.Time) (flatRuns, error) {
	out := flatRuns{records: map[string]Record{}, states: map[string]State{}}
	for _, side := range []flatRuns{from, cur} {
		for id, rec := range side.records {
			have, ok := out.records[id]
			if ok && !sameRun(have, rec) {
				return flatRuns{}, fmt.Errorf("%w: %s", ErrTwoHistories, id)
			}
			if !rec.Closed() && ok {
				rec.ClosedAt = have.ClosedAt
			}
			out.records[id] = rec
		}
	}
	for id, rec := range out.records {
		if !rec.Closed() {
			rec.ClosedAt = canonTime(now)
			out.records[id] = rec
		}
		if rec.Root == id {
			out.states[id] = joinedState(id, cur, from)
		}
	}
	return out, nil
}

// joinedState is the join of root's state on each side that holds its
// record, a state lost beside its record counting as lostState.
func joinedState(root string, cur, from flatRuns) State {
	var joined *State
	for _, side := range []flatRuns{cur, from} {
		if _, held := side.records[root]; !held {
			continue
		}
		s, ok := side.states[root]
		if !ok {
			s = lostState
		}
		if joined != nil {
			s = JoinStates(*joined, s)
		}
		joined = &s
	}
	return *joined
}

// sameRun reports whether a and b are one run, whether or not either is
// closed.
func sameRun(a, b Record) bool {
	a.ClosedAt, b.ClosedAt = time.Time{}, time.Time{}
	return a.ID == b.ID && a.Who == b.Who && a.Root == b.Root && a.Parent == b.Parent &&
		a.OpenedAt.Equal(b.OpenedAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.SecretSHA256 == b.SecretSHA256
}

// writeMerged writes each root's lock and state, then each record, wherever
// it differs from what cur holds, so a root never has a record without them.
func (a *Admin) writeMerged(ctx context.Context, cur, merged flatRuns, step func(string) error) (Restored, error) {
	var out Restored
	for _, root := range sortedKeys(merged.states) {
		s := merged.states[root]
		if have, ok := cur.states[root]; ok && have == s {
			continue
		}
		wrote, err := a.d.writeState(ctx, root, s, step)
		if err != nil {
			return out, err
		}
		if wrote {
			out.States++
		}
	}
	for _, id := range sortedKeys(merged.records) {
		rec := merged.records[id]
		if have, ok := cur.records[id]; ok && have.ClosedAt.Equal(rec.ClosedAt) {
			continue
		}
		if err := step("record " + id); err != nil {
			return out, err
		}
		body, err := a.encodeRecord(rec)
		if err != nil {
			return out, err
		}
		if err := a.d.replace(id+recordTemp, id+recordSuffix, body); err != nil {
			return out, err
		}
		out.Closed++
	}
	return out, nil
}

// writeState writes root's lock file where it is missing, then joins s into
// its state under that lock. A state missing there takes s as it is.
func (d *dir) writeState(ctx context.Context, root string, s State, step func(string) error) (bool, error) {
	switch _, err := d.root.Lstat(root + lockSuffix); {
	case errors.Is(err, fs.ErrNotExist):
		if err := step("lock " + root); err != nil {
			return false, err
		}
		if err := d.createEmpty(root + lockSuffix); err != nil {
			return false, err
		}
	case err != nil:
		return false, err
	}
	return d.joinLocked(ctx, root, s, initialState, step)
}

// joinLocked joins s into root's state under the root's lock, the one
// Plane.Raise takes, reading the state under it, so a raise another writer
// makes lands wholly before or after the join and is never lowered. A
// missing state joins s from missing and is written whatever the join; the
// result is whether the state was written.
func (d *dir) joinLocked(ctx context.Context, root string, s, missing State, step func(string) error) (_ bool, err error) {
	lock, err := d.openRegular(root+lockSuffix, os.O_RDWR)
	if err != nil {
		return false, fmt.Errorf("the lock of %s: %w", root, err)
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := lockWaiting(ctx, lock); err != nil {
		return false, err
	}
	have, err := d.readState(root)
	gone := errors.Is(err, fs.ErrNotExist)
	switch {
	case gone:
		have = missing
	case err != nil:
		return false, err
	}
	next := JoinStates(have, s)
	if next == have && !gone {
		return false, nil
	}
	body, err := encodeState(root, next)
	if err != nil {
		return false, err
	}
	if err := step("state " + root); err != nil {
		return false, err
	}
	if err := d.stillLocked(lock, root); err != nil {
		return false, err
	}
	return true, d.replace(root+stateTemp, root+stateSuffix, body)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
