package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/guardana/control/internal/files"
)

// RestoreSigned carries into live's state/ the close of every run whose
// record live's or backup's records/ names, or whose close backup's state/
// holds, and joins each state backup's state/ holds into live's under the
// root's lock, the one Plane.Raise takes, so a plane sharing the directory
// that raises the root meanwhile is never lowered. A state live's state/
// lacks is a root's first only while live holds neither its lock file nor a
// record of its id; with either, it was lost, and joins as lostState. It
// reads the records' names and judges no record: a close carried is the safe
// side. It writes nothing to records/, and step is called before each write.
// An empty backup is none: live's runs are closed all the same.
func RestoreSigned(ctx context.Context, live, backup string, step func(string) error) (out Restored, err error) {
	if err := ctx.Err(); err != nil {
		return Restored{}, err
	}
	if step == nil {
		step = func(string) error { return nil }
	}
	ids, states, err := signedBackup(backup)
	if err != nil {
		return Restored{}, fmt.Errorf("the backup's runs: %w", err)
	}
	more, err := signedIDs(live)
	if err != nil {
		return Restored{}, err
	}
	recorded := make(map[string]bool, len(more))
	for _, id := range more {
		recorded[id] = true
	}
	ids = append(ids, more...)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if err := step("carry"); err != nil {
		return Restored{}, err
	}
	if err := CarryClosed(live, ids); err != nil {
		return Restored{}, err
	}
	out.Carried = len(ids)
	out.States, err = joinSigned(ctx, live, states, recorded, step)
	return out, err
}

// CheckRestoreSigned refuses what RestoreSigned would refuse of live and
// backup, a live that is no signed layout among them, and writes nothing.
func CheckRestoreSigned(live, backup string) (err error) {
	_, states, err := signedBackup(backup)
	if err != nil {
		return fmt.Errorf("the backup's runs: %w", err)
	}
	if _, err := signedIDs(live); err != nil {
		return err
	}
	st, err := openState(live)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, st.close()) }()
	for _, root := range sortedKeys(states) {
		_, err := st.readState(root)
		if errors.Is(err, fs.ErrNotExist) {
			_, err = missingState(st, root, false)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// joinSigned joins each of states into the state/ of live and returns how
// many it wrote. A missing one counts as lostState where its lock file
// stands or recorded holds its id, and as a root's first otherwise, and is
// written whatever the join.
func joinSigned(ctx context.Context, live string, states map[string]State, recorded map[string]bool, step func(string) error) (n int, err error) {
	st, err := openState(live)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, st.close()) }()
	for _, root := range sortedKeys(states) {
		wrote, err := st.startSigned(root, states[root], recorded[root], step)
		if err == nil && !wrote {
			wrote, err = st.joinLocked(ctx, root, states[root], lostState, step)
		}
		if err != nil {
			return n, err
		}
		if wrote {
			n++
		}
	}
	return n, nil
}

// startSigned makes root's state, joined from s, and then its lock file,
// where state/ holds neither: the order and the no-replace write startRoot
// uses, so a plane starting the root at the same time keeps the state one of
// the two made, and the other's join takes the lock. Where only the lock file
// is missing it makes that, and it returns false whenever it made no state.
func (d *dir) startSigned(root string, s State, recorded bool, step func(string) error) (bool, error) {
	switch _, err := d.root.Lstat(root + lockSuffix); {
	case err == nil:
		return false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	switch _, err := d.root.Lstat(root + stateSuffix); {
	case err == nil:
		if err := step("lock " + root); err != nil {
			return false, err
		}
		return false, d.createEmpty(root + lockSuffix)
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	base, err := missingState(d, root, recorded)
	if err != nil {
		return false, err
	}
	body, err := encodeState(root, JoinStates(base, s))
	if err != nil {
		return false, err
	}
	if err := step("state " + root); err != nil {
		return false, err
	}
	err = files.CreateNoReplaceIn(d.root, root+stateSuffix, body, d.mode)
	made := err == nil
	if err != nil && !errors.Is(err, files.ErrExists) {
		return false, err
	}
	return made, d.createEmpty(root + lockSuffix)
}

// missingState is what a root whose state file st lacks starts a join from:
// lostState where its lock file stands or recorded, as the plane refuses
// such a state rather than read it clean, and the initial state otherwise.
func missingState(st *dir, root string, recorded bool) (State, error) {
	_, err := st.root.Lstat(root + lockSuffix)
	switch {
	case err == nil || recorded:
		return lostState, nil
	case errors.Is(err, fs.ErrNotExist):
		return initialState, nil
	}
	return State{}, err
}

// signedBackup is the run ids backup's records/ names or its state/ holds
// a close of, and the states its state/ holds; an empty backup is none.
func signedBackup(backup string) ([]string, map[string]State, error) {
	if backup == "" {
		return nil, map[string]State{}, nil
	}
	ids, err := signedIDs(backup)
	if err != nil {
		return nil, nil, err
	}
	states, closed, err := signedStates(backup)
	if err != nil {
		return nil, nil, err
	}
	return append(ids, closed...), states, nil
}

// CarryClosed writes into the state/ of dir, a signed layout, the close of
// each run of ids, so an open record of one of them is refused whatever
// records/ holds later. It refuses an id CheckRunID refuses before it
// writes any, leaves a close carried already as it is, and judges nothing
// else: closing is the safe side.
func CarryClosed(dir string, ids []string) (err error) {
	for _, id := range ids {
		if err := checkRunID(id); err != nil {
			return err
		}
	}
	st, err := openState(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, st.close()) }()
	for _, id := range ids {
		if err := st.createEmpty(id + closedSuffix); err != nil {
			return err
		}
	}
	return nil
}

func openState(dir string) (*dir, error) {
	if signed, err := signedLayout(dir); err != nil || !signed {
		return nil, errors.Join(err, fmt.Errorf("%w: %s is not a signed layout", ErrLayout, clip(dir)))
	}
	if err := judgeTop(dir, true); err != nil {
		return nil, err
	}
	st, err := openDir(filepath.Join(dir, StateDir), roleState, ownedByThisUser)
	if err != nil {
		return nil, fmt.Errorf("%s/: %w", StateDir, err)
	}
	if err := st.checkContents(); err != nil {
		return nil, errors.Join(err, st.close())
	}
	return st, nil
}

// signedIDs is every run id a record's name under dir's records/ holds.
func signedIDs(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, RecordsDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotRunsDir, err)
	}
	var ids []string
	for _, e := range entries {
		switch k, id := classify(e.Name(), roleRecords); {
		case !e.Type().IsRegular() || k == kindForeign:
			return nil, fmt.Errorf("%w: %q", ErrForeignFile, clip(e.Name()))
		case k == kindRecord:
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// signedStates is every state dir's state/ holds, by root, and every run id
// it holds a close of.
func signedStates(dir string) (map[string]State, []string, error) {
	st, err := openDir(filepath.Join(dir, StateDir), roleState, ownedByThisUser)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = st.close() }()
	entries, err := st.readDir()
	if err != nil {
		return nil, nil, err
	}
	if _, err := st.scan(entries); err != nil {
		return nil, nil, err
	}
	out := map[string]State{}
	var closed []string
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), closedSuffix); ok && checkRunID(id) == nil {
			closed = append(closed, id)
			continue
		}
		root, ok := strings.CutSuffix(e.Name(), stateSuffix)
		if !ok || checkRunID(root) != nil {
			continue
		}
		s, err := st.readState(root)
		if err != nil {
			return nil, nil, err
		}
		out[root] = s
	}
	return out, closed, nil
}
