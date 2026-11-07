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
)

// RestoreSigned carries the close of every run whose record live's or
// backup's records/ names into live's state/, and joins each state backup's
// state/ holds into live's. A state live's state/ lacks is a root's first
// only while live holds neither its lock file nor a record of its id; with
// either, it was lost, and joins as lostState. It reads the records' names
// and judges no record: a close carried is the safe side. It writes nothing
// to records/, and step is called before each write. An empty backup is
// none: live's runs are closed all the same.
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
	out.States, err = joinSigned(live, states, recorded, step)
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
func joinSigned(live string, states map[string]State, recorded map[string]bool, step func(string) error) (n int, err error) {
	st, err := openState(live)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, st.close()) }()
	for _, root := range sortedKeys(states) {
		have, err := st.readState(root)
		missing := errors.Is(err, fs.ErrNotExist)
		switch {
		case missing:
			if have, err = missingState(st, root, recorded[root]); err != nil {
				return n, err
			}
		case err != nil:
			return n, err
		}
		next := JoinStates(have, states[root])
		if next == have && !missing {
			continue
		}
		if err := step("state " + root); err != nil {
			return n, err
		}
		if err := st.writeSignedState(root, next); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
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

// signedBackup is the run ids backup's records/ names and the states its
// state/ holds; an empty backup is none.
func signedBackup(backup string) ([]string, map[string]State, error) {
	if backup == "" {
		return nil, map[string]State{}, nil
	}
	ids, err := signedIDs(backup)
	if err != nil {
		return nil, nil, err
	}
	states, err := signedStates(backup)
	if err != nil {
		return nil, nil, err
	}
	return ids, states, nil
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

// signedStates is every state dir's state/ holds, by root.
func signedStates(dir string) (map[string]State, error) {
	st, err := openDir(filepath.Join(dir, StateDir), roleState, ownedByThisUser)
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.close() }()
	entries, err := st.readDir()
	if err != nil {
		return nil, err
	}
	if _, err := st.scan(entries); err != nil {
		return nil, err
	}
	out := map[string]State{}
	for _, e := range entries {
		root, ok := strings.CutSuffix(e.Name(), stateSuffix)
		if !ok || checkRunID(root) != nil {
			continue
		}
		s, err := st.readState(root)
		if err != nil {
			return nil, err
		}
		out[root] = s
	}
	return out, nil
}

// writeSignedState writes root's state, then its lock file where it is
// missing, the order a plane starts a root in: a lock file without a state
// reads as a state lost, so a write stopped between the two is never taken
// for one.
func (d *dir) writeSignedState(root string, s State) error {
	body, err := encodeState(root, s)
	if err != nil {
		return err
	}
	if err := d.replace(root+stateTemp, root+stateSuffix, body); err != nil {
		return err
	}
	return d.createEmpty(root + lockSuffix)
}
