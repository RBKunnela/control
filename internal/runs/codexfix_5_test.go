//go:build unix

package runs_test

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/runs"
)

// lockHeld reports whether another open file holds the lock at path, the
// lock Plane.Raise takes.
func lockHeld(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); {
	case err == nil:
		return false
	case errors.Is(err, syscall.EWOULDBLOCK):
		return true
	default:
		t.Fatal(err)
		return false
	}
}

// raiseDuring is a restore step that, at the write of root's state, raises
// root through p to secret: at once where the restore holds no lock on it,
// and otherwise once the restore lets the lock go. wait returns the raise's
// error once it ran, and whether the restore held the lock at its write.
func raiseDuring(t *testing.T, p *runs.Plane, root, lock string) (step func(string) error, wait func() (bool, error)) {
	done := make(chan error, 1)
	held, ran := false, false
	raise := func() {
		done <- p.Raise(t.Context(), root, func(s runs.State) runs.State {
			return runs.JoinStates(s, runs.State{MaxRead: controlv1.Sensitivity_SENSITIVITY_SECRET})
		})
	}
	step = func(what string) error {
		if what != "state "+root || ran {
			return nil
		}
		ran = true
		if held = lockHeld(t, lock); held {
			go raise()
			return nil
		}
		raise()
		return nil
	}
	wait = func() (bool, error) {
		if !ran {
			t.Fatalf("the restore never wrote the state of %s", root)
		}
		return held, <-done
	}
	return step, wait
}

// TestRestoreSignedNeverLowersARaiseItRacesWith: a plane sharing the runs
// directory raises a root while a signed restore joins its state; the
// restore writes under the root's lock, so the raise lands on the restored
// state and nothing lowers it.
func TestRestoreSignedNeverLowersARaiseItRacesWith(t *testing.T) {
	live, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	p := signedPlane(t, live, alicesJudge)
	setState(t, p, rec.ID, runs.State{Untrusted: true, MaxRead: confidential})
	backup := copyTree(t, live)
	setState(t, p, rec.ID, runs.State{Untrusted: false, MaxRead: confidential})
	step, wait := raiseDuring(t, p, rec.ID, live+"/state/"+rec.ID+".lock")
	if _, err := runs.RestoreSigned(t.Context(), live, backup, step); err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	held, err := wait()
	if err != nil {
		t.Fatalf("the raise during the restore: %v", err)
	}
	if s, err := p.State(t.Context(), rec.ID); err != nil || s != (runs.State{Untrusted: true, MaxRead: secret}) {
		t.Errorf("state = %+v, %v; want untrusted and SECRET, the raise during the restore kept", s, err)
	}
	if !held {
		t.Errorf("the restore wrote the state of %s without the lock Plane.Raise takes", rec.ID)
	}
}

// TestRestoreUnsignedNeverLowersARaiseItRacesWith is the same race over an
// unsigned runs directory.
func TestRestoreUnsignedNeverLowersARaiseItRacesWith(t *testing.T) {
	live, a, p := setup(t)
	rec, _ := openRoot(t, a)
	setState(t, p, rec.ID, runs.State{Untrusted: true, MaxRead: confidential})
	backup := copyTree(t, live)
	setState(t, p, rec.ID, runs.State{Untrusted: false, MaxRead: confidential})
	step, wait := raiseDuring(t, p, rec.ID, live+"/"+rec.ID+".lock")
	if _, err := runs.RestoreUnsigned(t.Context(), live, backup, restoredAt, step); err != nil {
		t.Fatalf("RestoreUnsigned: %v", err)
	}
	held, err := wait()
	if err != nil {
		t.Fatalf("the raise during the restore: %v", err)
	}
	if s := stateOf(t, live, rec.ID); s != (runs.State{Untrusted: true, MaxRead: secret}) {
		t.Errorf("state = %+v; want untrusted and SECRET, the raise during the restore kept", s)
	}
	if !held {
		t.Errorf("the restore wrote the state of %s without the lock Plane.Raise takes", rec.ID)
	}
}

// twoRoots is a runs directory, signed or not, with two roots whose backup
// state is untrusted and CONFIDENTIAL and whose live state is trusted, the
// plane on it, the backup, the roots' ids in the order a restore writes
// them, and the path of a root's lock file.
func twoRoots(t *testing.T, signed bool) (live string, p *runs.Plane, backup string, ids []string, lock func(string) string) {
	t.Helper()
	var roots []string
	if signed {
		var a *runs.Admin
		live, a = newSigned(t)
		for range 2 {
			rec, _ := openSignedRoot(t, a, "alice")
			roots = append(roots, rec.ID)
		}
		p = signedPlane(t, live, alicesJudge)
		lock = func(id string) string { return live + "/state/" + id + ".lock" }
	} else {
		var a *runs.Admin
		live, a, p = setup(t)
		for range 2 {
			rec, _ := openRoot(t, a)
			roots = append(roots, rec.ID)
		}
		lock = func(id string) string { return live + "/" + id + ".lock" }
	}
	for _, id := range roots {
		setState(t, p, id, runs.State{Untrusted: true, MaxRead: confidential})
	}
	backup = copyTree(t, live)
	for _, id := range roots {
		setState(t, p, id, runs.State{Untrusted: false, MaxRead: confidential})
	}
	slices.Sort(roots)
	return live, p, backup, roots, lock
}

func restoreEither(t *testing.T, signed bool, live, backup string, step func(string) error) error {
	t.Helper()
	if signed {
		_, err := runs.RestoreSigned(t.Context(), live, backup, step)
		return err
	}
	_, err := runs.RestoreUnsigned(t.Context(), live, backup, restoredAt, step)
	return err
}

func toSecret(s runs.State) runs.State {
	return runs.JoinStates(s, runs.State{MaxRead: controlv1.Sensitivity_SENSITIVITY_SECRET})
}

// TestRestoreJoinsARaiseMadeBeforeItTookTheLock: while a restore writes the
// first root, a plane raises the second, whose lock the restore does not
// hold yet. The restore reads the second's state under its lock and joins
// the raise in.
func TestRestoreJoinsARaiseMadeBeforeItTookTheLock(t *testing.T) {
	for _, signed := range []bool{true, false} {
		t.Run(fmt.Sprintf("signed=%v", signed), func(t *testing.T) {
			live, p, backup, ids, _ := twoRoots(t, signed)
			raised := false
			step := func(what string) error {
				if what == "state "+ids[0] && !raised {
					raised = true
					return p.Raise(t.Context(), ids[1], toSecret)
				}
				return nil
			}
			if err := restoreEither(t, signed, live, backup, step); err != nil {
				t.Fatalf("restore: %v", err)
			}
			if s, err := p.State(t.Context(), ids[1]); err != nil || s != (runs.State{Untrusted: true, MaxRead: secret}) {
				t.Fatalf("state = %+v, %v; want untrusted and SECRET, the raise before the lock kept", s, err)
			}
		})
	}
}

// TestRestoreRefusesALockFileReplacedUnderIt: a lock file replaced while the
// restore holds the old one would let a raise through the new one, so the
// restore writes nothing and says so.
func TestRestoreRefusesALockFileReplacedUnderIt(t *testing.T) {
	for _, signed := range []bool{true, false} {
		t.Run(fmt.Sprintf("signed=%v", signed), func(t *testing.T) {
			live, p, backup, ids, lock := twoRoots(t, signed)
			step := func(what string) error {
				if what != "state "+ids[0] {
					return nil
				}
				if err := os.Remove(lock(ids[0])); err != nil {
					return err
				}
				return os.WriteFile(lock(ids[0]), nil, 0o600)
			}
			if err := restoreEither(t, signed, live, backup, step); !errors.Is(err, runs.ErrLockChanged) {
				t.Fatalf("restore with the lock file replaced = %v, want ErrLockChanged", err)
			}
			if s, err := p.State(t.Context(), ids[0]); err != nil || s != (runs.State{Untrusted: false, MaxRead: confidential}) {
				t.Fatalf("state = %+v, %v; want live's, unwritten", s, err)
			}
		})
	}
}

// TestRestoreSignedKeepsTheStateAPlaneStartedFirst: live holds no record,
// state or lock file of a root the backup holds, and a plane starts and
// raises the root while the restore makes its state. The restore's own
// state is never written over the plane's; it joins into it.
func TestRestoreSignedKeepsTheStateAPlaneStartedFirst(t *testing.T) {
	live, a := newSigned(t)
	rec, _ := openSignedRoot(t, a, "alice")
	p := signedPlane(t, live, alicesJudge)
	setState(t, p, rec.ID, runs.State{Untrusted: true, MaxRead: confidential})
	backup := copyTree(t, live)
	for _, path := range []string{recordPath(live, rec.ID), live + "/state/" + rec.ID + ".state.json", live + "/state/" + rec.ID + ".lock"} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	raised := false
	step := func(what string) error {
		if what == "state "+rec.ID && !raised {
			raised = true
			return p.Raise(t.Context(), rec.ID, toSecret)
		}
		return nil
	}
	if _, err := runs.RestoreSigned(t.Context(), live, backup, step); err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	if !raised {
		t.Fatal("the restore never made the root's state")
	}
	if s, err := p.State(t.Context(), rec.ID); err != nil || s != (runs.State{Untrusted: true, MaxRead: secret}) {
		t.Fatalf("state = %+v, %v; want untrusted and SECRET, the plane's raise and the backup's taint", s, err)
	}
}

// TestRestoreSignedJoinsAStateWhoseLockFileIsGone: a state left without its
// lock file, as a plane stopped between the two leaves it, gets the lock
// file back and is joined under it like any other.
func TestRestoreSignedJoinsAStateWhoseLockFileIsGone(t *testing.T) {
	live, p, backup, ids, lock := twoRoots(t, true)
	if err := os.Remove(lock(ids[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.RestoreSigned(t.Context(), live, backup, nil); err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	if _, err := os.Lstat(lock(ids[0])); err != nil {
		t.Fatalf("the lock file: %v", err)
	}
	if s, err := p.State(t.Context(), ids[0]); err != nil || s != (runs.State{Untrusted: true, MaxRead: confidential}) {
		t.Fatalf("state = %+v, %v; want live's joined with the backup's", s, err)
	}
}
