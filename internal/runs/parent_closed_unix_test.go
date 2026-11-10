//go:build unix

package runs_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// openSignedChild signs a child of parent for alice the way the operator's
// command does: the parent's record read and judged from records/ alone.
func openSignedChild(t *testing.T, a *runs.Admin, parent string, now time.Time) (runs.Record, string) {
	t.Helper()
	req := runs.OpenRequest{Who: alice, Parent: parent, TTL: 10 * time.Minute, Now: now}
	rec, token, err := a.OpenSigned(t.Context(), req, testSigner("alice"), alicesJudge)
	if err != nil {
		t.Fatalf("OpenSigned under %s: %v", parent, err)
	}
	return rec, token
}

func closeSigned(t *testing.T, a *runs.Admin, id string, now time.Time) {
	t.Helper()
	if _, _, err := a.CloseSigned(t.Context(), id, now, testSigner("alice"), alicesJudge); err != nil {
		t.Fatalf("CloseSigned %s: %v", id, err)
	}
}

func seenPath(dir, id string) string { return filepath.Join(dir, "state", id+".seen") }

func requireSeen(t *testing.T, dir, id string, want bool) {
	t.Helper()
	_, err := os.Lstat(seenPath(dir, id))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if got := err == nil; got != want {
		t.Fatalf("state/%s.seen exists = %v, want %v", id, got, want)
	}
}

// requireParentClosed requires a refusal as closed for a parent closed
// before the run's first admission, which is not a replay.
func requireParentClosed(t *testing.T, err error) {
	t.Helper()
	if causeOf(t, err) != runs.CauseClosed || !errors.Is(err, runs.ErrParentClosed) || errors.Is(err, runs.ErrReplayed) {
		t.Fatalf("Resolve = %v, want closed with ErrParentClosed", err)
	}
	if !strings.Contains(err.Error(), "was closed before this run was first admitted") {
		t.Fatalf("Resolve = %v, want it to say the parent closed before the first admission", err)
	}
}

// TestAChildSignedAfterItsParentsCarriedCloseIsRefused: the parent's close
// carried, its open record put back, a child signed under it the way the
// operator's command does is refused, at every resolve, whichever way the
// plane carried the close.
func TestAChildSignedAfterItsParentsCarriedCloseIsRefused(t *testing.T) {
	for _, carriedBy := range []string{"resolve", "survey"} {
		t.Run(carriedBy, func(t *testing.T) {
			dir, a := newSigned(t)
			parent, parentToken := openSignedRoot(t, a, "alice")
			parentOpen := readBytes(t, recordPath(dir, parent.ID))
			closeSigned(t, a, parent.ID, opened.Add(time.Minute))
			p := signedPlane(t, dir, alicesJudge)
			at := opened.Add(2 * time.Minute)
			if carriedBy == "resolve" {
				if _, err := p.Resolve(t.Context(), parentToken, alice, at); causeOf(t, err) != runs.CauseClosed {
					t.Fatalf("Resolve of the closed parent = %v, want closed", err)
				}
			} else if s, err := p.CarryCloses(t.Context(), 100, at); err != nil || s.Carried != 1 {
				t.Fatalf("CarryCloses = %+v, %v", s, err)
			}
			writeFile(t, recordPath(dir, parent.ID), parentOpen)
			_, childToken := openSignedChild(t, a, parent.ID, at)
			for range 2 {
				_, err := p.Resolve(t.Context(), childToken, alice, at.Add(time.Minute))
				requireParentClosed(t, err)
			}
			if got := p.SignedCounts()["refused_parent_closed"]; got != 2 {
				t.Errorf("refused_parent_closed = %d, want 2", got)
			}
			if got := p.SignedCounts()["refused_replayed"]; got != 0 {
				t.Errorf("refused_replayed = %d, want 0: the child was never closed", got)
			}
			requireSeen(t, dir, idOf(t, childToken), false)
		})
	}
}

// TestAChildAdmittedBeforeItsParentsCloseKeepsRunning: closing a parent
// closes none of the children the plane admitted before it carried the
// close, on the same plane and on one started after it.
func TestAChildAdmittedBeforeItsParentsCloseKeepsRunning(t *testing.T) {
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, parent.ID, opened)
	first, err := runs.OpenSignedPlane(dir, ownedHere)
	if err != nil {
		t.Fatal(err)
	}
	at := opened.Add(time.Minute)
	if run, err := first.Resolve(t.Context(), childToken, alice, at); err != nil || run.ID != child.ID || run.Root != parent.ID {
		t.Fatalf("the child's first call = %+v, %v", run, err)
	}
	requireSeen(t, dir, child.ID, true)
	closeSigned(t, a, parent.ID, at)
	if _, err := first.Resolve(t.Context(), parentToken, alice, at.Add(time.Minute)); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed parent = %v, want closed", err)
	}
	if _, err := first.Resolve(t.Context(), childToken, alice, at.Add(time.Minute)); err != nil {
		t.Fatalf("the child admitted before the carry, after it: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := signedPlane(t, dir, alicesJudge)
	if _, err := second.CarryCloses(t.Context(), 100, at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Resolve(t.Context(), childToken, alice, at.Add(2*time.Minute)); err != nil {
		t.Fatalf("the child admitted before the carry, after a restart: %v", err)
	}
}

// TestAChildSignedBeforeTheCloseFirstCalledAfterItIsRefused: the plane
// tells children apart by what it admitted, never by signed times, so a
// child signed while its parent was open whose first call comes after the
// carry is refused all the same.
func TestAChildSignedBeforeTheCloseFirstCalledAfterItIsRefused(t *testing.T) {
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, parent.ID, opened)
	closeSigned(t, a, parent.ID, opened.Add(time.Minute))
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(2 * time.Minute)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed parent = %v, want closed", err)
	}
	_, err := p.Resolve(t.Context(), childToken, alice, at)
	requireParentClosed(t, err)
	requireSeen(t, dir, child.ID, false)
}

// TestAHeldParentCloseRefusesAnUnseenChild: a parent's close state/ refused
// to take, held in the plane, refuses a child it never admitted as a close
// written does.
func TestAHeldParentCloseRefusesAnUnseenChild(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes a directory whatever its mode")
	}
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	_, childToken := openSignedChild(t, a, parent.ID, opened)
	closeSigned(t, a, parent.ID, opened.Add(time.Minute))
	p := signedPlane(t, dir, alicesJudge)
	state := filepath.Join(dir, "state")
	if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // G302: read and search only, so no close can be carried
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: as the layout made it
	at := opened.Add(2 * time.Minute)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed parent = %v, want closed", err)
	}
	if got := p.SignedCounts()["carry_failed"]; got != 1 {
		t.Fatalf("carry_failed = %d, want 1", got)
	}
	_, err := p.Resolve(t.Context(), childToken, alice, at)
	requireParentClosed(t, err)
}

// TestAFirstAdmissionThatCannotBeRecordedIsRefused: a child whose .seen
// state/ refuses to take is refused and admitted nowhere, though its parent
// is open and its root's state stands; once state/ takes it, it runs.
func TestAFirstAdmissionThatCannotBeRecordedIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes a directory whatever its mode")
	}
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, parent.ID, opened)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); err != nil {
		t.Fatalf("the parent's call, which starts the root's state: %v", err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // G302: read and search only, so no file can be made
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: as the layout made it
	run, err := p.Resolve(t.Context(), childToken, alice, at)
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, fs.ErrPermission) || run != (runs.Run{}) {
		t.Fatalf("Resolve with state/ refusing the .seen = %+v, %v, want unreadable and nothing admitted", run, err)
	}
	writable(t, dir)
	requireSeen(t, dir, child.ID, false)
	if _, err := p.Resolve(t.Context(), childToken, alice, at); err != nil {
		t.Fatalf("Resolve once state/ takes the .seen: %v", err)
	}
	requireSeen(t, dir, child.ID, true)
}

// TestASeenMarkerThePlaneCannotTrustIsRefused: a .seen a group may write, or
// one that is no regular file, refuses its child's call as unreadable rather
// than count as an admission or as none.
func TestASeenMarkerThePlaneCannotTrustIsRefused(t *testing.T) {
	for name, spoil := range map[string]func(t *testing.T, path string){
		"group-writable": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o620); err != nil { //nolint:gosec // G302: the mode under test
				t.Fatal(err)
			}
		},
		"a link": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(path), "elsewhere"), path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, a := newSigned(t)
			parent, _ := openSignedRoot(t, a, "alice")
			child, childToken := openSignedChild(t, a, parent.ID, opened)
			p := signedPlane(t, dir, alicesJudge)
			at := opened.Add(time.Minute)
			if _, err := p.Resolve(t.Context(), childToken, alice, at); err != nil {
				t.Fatalf("the child's first call: %v", err)
			}
			spoil(t, seenPath(dir, child.ID))
			_, err := p.Resolve(t.Context(), childToken, alice, at)
			if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrForeignFile) {
				t.Fatalf("Resolve with the .seen spoiled = %v, want unreadable, ErrForeignFile", err)
			}
		})
	}
}

// TestAnUnsignedChildOfAClosedParentStillResolves: off a signed layout a
// child of a closed parent resolves as it did, and no .seen is written.
func TestAnUnsignedChildOfAClosedParentStillResolves(t *testing.T) {
	dir, a, p := setup(t)
	parent, _ := openRoot(t, a)
	child, childToken := openUnder(t, a, parent.ID, alice)
	if err := a.CloseRun(t.Context(), parent.ID, opened.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if run, err := p.Resolve(t.Context(), childToken, alice, opened.Add(2*time.Minute)); err != nil || run.ID != child.ID {
		t.Fatalf("Resolve of the child of a closed parent = %+v, %v", run, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".seen") {
			t.Errorf("an unsigned directory holds %s", e.Name())
		}
	}
}

// TestRestoreSignedTakesSeenMarkers: a restore over a state/ holding .seen
// markers, in live and in the backup, refuses neither and counts none as a
// run.
func TestRestoreSignedTakesSeenMarkers(t *testing.T) {
	live, a := newSigned(t)
	parent, _ := openSignedRoot(t, a, "alice")
	_, childToken := openSignedChild(t, a, parent.ID, opened)
	if _, err := signedPlane(t, live, alicesJudge).Resolve(t.Context(), childToken, alice, opened.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	requireSeen(t, live, idOf(t, childToken), true)
	backup := copyTree(t, live)
	if err := runs.CheckRestoreSigned(live, backup); err != nil {
		t.Fatalf("CheckRestoreSigned: %v", err)
	}
	got, err := runs.RestoreSigned(t.Context(), live, backup, nil)
	if err != nil {
		t.Fatalf("RestoreSigned: %v", err)
	}
	if got.Carried != 2 || got.States != 0 {
		t.Fatalf("Restored = %+v, want the two runs' closes carried and no state written", got)
	}
}
