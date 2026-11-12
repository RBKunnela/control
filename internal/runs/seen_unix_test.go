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

var errSyncFailed = errors.New("the directory sync failed")

func syncFails() error { return errSyncFailed }

// carryParentClose closes parent and has p carry the close by resolving it.
func carryParentClose(t *testing.T, a *runs.Admin, p *runs.Plane, parent runs.Record, parentToken string, at time.Time) {
	t.Helper()
	closeSigned(t, a, parent.ID, at)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("Resolve of the closed parent = %v, want closed", err)
	}
}

// TestAFirstAdmissionThatFailsLeavesNoSeen: a child's first call refused
// because a write of its admission failed after its .seen could have been
// made leaves no .seen, so once its parent's close is carried the child is
// refused as one the plane never admitted.
func TestAFirstAdmissionThatFailsLeavesNoSeen(t *testing.T) {
	for name, c := range map[string]struct {
		rootStarted bool
		// failing is the run whose write fails and the file it makes.
		failing func(root, child string) (string, string)
		// fail fails the directory's sync or the file's own.
		fail func(name string, fail func() error) func()
	}{
		"the root's state":        {false, func(root, _ string) (string, string) { return root, root + ".lock" }, runs.FailSyncAfterMaking},
		"the child's .seen":       {true, func(_, child string) (string, string) { return child, child + ".seen" }, runs.FailSyncAfterMaking},
		"the child's .seen's own": {true, func(_, child string) (string, string) { return child, child + ".seen" }, runs.FailFileSyncOf},
	} {
		t.Run(name, func(t *testing.T) {
			dir, a := newSigned(t)
			parent, parentToken := openSignedRoot(t, a, "alice")
			child, childToken := openSignedChild(t, a, parent.ID, opened)
			p := signedPlane(t, dir, alicesJudge)
			at := opened.Add(time.Minute)
			if c.rootStarted {
				if _, err := p.Resolve(t.Context(), parentToken, alice, at); err != nil {
					t.Fatalf("the parent's call, which starts the root's state: %v", err)
				}
			}
			id, file := c.failing(parent.ID, child.ID)
			restore := c.fail(file, syncFails)
			t.Cleanup(restore)
			run, err := p.Resolve(t.Context(), childToken, alice, at)
			if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, errSyncFailed) || run != (runs.Run{}) {
				t.Fatalf("Resolve with %s failing = %+v, %v, want unreadable and nothing admitted", file, run, err)
			}
			if !strings.Contains(err.Error(), id) {
				t.Errorf("Resolve = %v, want it to name %s", err, id)
			}
			restore()
			carryParentClose(t, a, p, parent, parentToken, at)
			_, err = p.Resolve(t.Context(), childToken, alice, at.Add(time.Minute))
			requireParentClosed(t, err)
			requireSeen(t, dir, child.ID, false)
		})
	}
}

// TestAFoundSeenSurvivesAFailingCall: a .seen an earlier call made is not a
// later call's to remove. A call refused because its root's state cannot be
// made keeps it, and the child keeps running after its parent's close is
// carried.
func TestAFoundSeenSurvivesAFailingCall(t *testing.T) {
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, parent.ID, opened)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	if _, err := p.Resolve(t.Context(), childToken, alice, at); err != nil {
		t.Fatalf("the child's first call: %v", err)
	}
	for _, name := range []string{parent.ID + ".state.json", parent.ID + ".lock"} {
		if err := os.Remove(filepath.Join(dir, "state", name)); err != nil {
			t.Fatal(err)
		}
	}
	restore := runs.FailSyncAfterMaking(parent.ID+".lock", syncFails)
	t.Cleanup(restore)
	if _, err := p.Resolve(t.Context(), childToken, alice, at); causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, errSyncFailed) {
		t.Fatalf("Resolve with the root's state failing = %v, want unreadable", err)
	}
	restore()
	requireSeen(t, dir, child.ID, true)
	carryParentClose(t, a, p, parent, parentToken, at)
	for range 2 {
		if _, err := p.Resolve(t.Context(), childToken, alice, at.Add(time.Minute)); err != nil {
			t.Fatalf("the child admitted before the carry, after it: %v", err)
		}
	}
	requireSeen(t, dir, child.ID, true)
}

// TestASeenThatCannotBeRemovedIsInTheError: a .seen a failed first admission
// made and cannot remove stays, and the refusal names the failed removal
// beside the failed write.
func TestASeenThatCannotBeRemovedIsInTheError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser removes from a directory whatever its mode")
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
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: as the layout made it
	restore := runs.FailSyncAfterMaking(child.ID+".seen", func() error {
		if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // G302: read and search only, so nothing can be removed
			return err
		}
		return errSyncFailed
	})
	t.Cleanup(restore)
	_, err := p.Resolve(t.Context(), childToken, alice, at)
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, errSyncFailed) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Resolve = %v, want unreadable with the failed sync and the failed removal", err)
	}
	restore()
	writable(t, dir)
	requireSeen(t, dir, child.ID, true)
}

// TestARemovedSeenIsForcedToDisk: the .seen a failed first admission made is
// removed and the directory then forced to disk, so a crash after the
// refusal cannot bring the marker back.
func TestARemovedSeenIsForcedToDisk(t *testing.T) {
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, parent.ID, opened)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); err != nil {
		t.Fatalf("the parent's call, which starts the root's state: %v", err)
	}
	t.Cleanup(runs.FailFileSyncOf(child.ID+".seen", syncFails))
	var gone []bool
	t.Cleanup(runs.FailSyncAfterMaking(child.ID+".seen", func() error {
		_, err := os.Lstat(seenPath(dir, child.ID))
		gone = append(gone, errors.Is(err, fs.ErrNotExist))
		return nil
	}))
	if _, err := p.Resolve(t.Context(), childToken, alice, at); causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, errSyncFailed) {
		t.Fatalf("Resolve with the .seen's own sync failing = %v, want unreadable", err)
	}
	if len(gone) != 1 || !gone[0] {
		t.Fatalf("the directory syncs for the .seen, true where it was gone = %v, want [true]", gone)
	}
	requireSeen(t, dir, child.ID, false)
}
