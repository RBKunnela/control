package recovery_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/recovery"
)

// TestRestoreRefusesAFloorBuiltUnderAnotherClasssName: the plane floor's
// directory is lost, and a restore builds it again under .floors.restoring
// beside it, the name the configuration gives the route floor. The restore
// refuses before its first write rather than remove the route floor and
// build it again from the backup's lower serial.
func TestRestoreRefusesAFloorBuiltUnderAnotherClasssName(t *testing.T) {
	p, _, _ := stopsPlane(t)
	p.raiseFloor(t, 1, d1, t0)
	cfg := string(readOrFail(t, p.path("plane.yaml")))
	writeFile(t, p.path("plane.yaml"), []byte(strings.Replace(cfg, "floor_dir: routefloor", "floor_dir: .floors.restoring", 1)))
	p.load(t)
	routeFloor := p.path(".floors.restoring")
	if err := policystate.InitRoute(t.Context(), routeFloor, "refunds"); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.RaiseRoute(t.Context(), routeFloor, "refunds", 4, d1); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if _, err := policystate.RaiseRoute(t.Context(), routeFloor, "refunds", 7, d2); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(p.path("floors")); err != nil {
		t.Fatal(err)
	}
	before := tree(t, p.root)
	_, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
	if err == nil {
		got, rerr := policystate.ReadRoute(routeFloor, "refunds")
		t.Fatalf("Restore = nil; the route floor holds serial %d (%v), and held 7", got.Serial, rerr)
	}
	if !errors.Is(err, recovery.ErrStaging) || !strings.Contains(err.Error(), "reaction.floor_dir") {
		t.Fatalf("Restore = %v, want ErrStaging naming reaction.floor_dir", err)
	}
	if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("a refused restore changed the plane's tree")
	}
}

// TestARestoreRefusesAStagingPathTheHoldJournalHolds: the hold journal, a
// directory no backup holds, sits at the name the plane floor's directory is
// built under. The restore refuses before its first write, and the journal,
// which keeps an approval from counting twice, is as it was.
func TestARestoreRefusesAStagingPathTheHoldJournalHolds(t *testing.T) {
	for _, c := range []struct {
		name  string
		plane func(*testing.T) *plane
	}{
		{"a journal with its ledger", func(t *testing.T) *plane {
			p := newPlane(t, strings.Replace(directoryBlock, "hold_journal_dir: holds", "hold_journal_dir: .floors.restoring", 1))
			j, err := holdjournal.Open(p.path(".floors.restoring"))
			if err != nil {
				if err := os.Mkdir(p.path(".floors.restoring"), 0o700); err != nil {
					t.Fatal(err)
				}
				if j, err = holdjournal.Open(p.path(".floors.restoring")); err != nil {
					t.Fatal(err)
				}
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"beside a stop list", func(t *testing.T) *plane {
			p, _, _ := stopsPlane(t)
			if err := os.Mkdir(p.path(".floors.restoring"), 0o700); err != nil {
				t.Fatal(err)
			}
			cfg := string(readOrFail(t, p.path("plane.yaml")))
			writeFile(t, p.path("plane.yaml"), []byte(strings.Replace(cfg, "hold_journal_dir: holds", "hold_journal_dir: .floors.restoring", 1)))
			p.load(t)
			return p
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := c.plane(t)
			writeFile(t, p.path(".floors.restoring/spent"), []byte("an approval this plane spent"))
			p.raiseFloor(t, 1, d1, t0)
			dir := filepath.Join(t.TempDir(), "backup")
			if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
				t.Fatalf("Backup: %v", err)
			}
			if err := os.RemoveAll(p.path("floors")); err != nil {
				t.Fatal(err)
			}
			before := tree(t, p.root)
			_, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
			if !errors.Is(err, recovery.ErrStaging) || !strings.Contains(err.Error(), "approvals.hold_journal_dir") {
				t.Errorf("Restore = %v, want ErrStaging naming approvals.hold_journal_dir", err)
			}
			if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatalf("the restore changed the plane's tree; the hold journal holds %q", tree(t, p.path(".floors.restoring")))
			}
		})
	}
}

// TestARestoreJudgesAStagingPathByWhatItNames: the route floor is named by
// a spelling the plane floor's build name does not match as text, in
// another case or through a link to the plane's own directory. Either may be
// the build's directory, on a file system that folds case or through the
// link, so the restore refuses both on every file system, and the route
// floor keeps the serial it held after the backup.
func TestARestoreJudgesAStagingPathByWhatItNames(t *testing.T) {
	for _, c := range []struct {
		name, floorDir, made string
		link                 bool
	}{
		{"in another case", ".FLOORS.restoring", ".FLOORS.restoring", false},
		{"through a link", "alias/.floors.restoring", ".floors.restoring", true},
	} {
		t.Run(c.name, func(t *testing.T) { restoreBesideAnotherSpelling(t, c.floorDir, c.made, c.link) })
	}
}

// restoreBesideAnotherSpelling is one case of
// TestARestoreJudgesAStagingPathByWhatItNames: reaction.floor_dir set to
// floorDir, made at made under the plane's directory.
func restoreBesideAnotherSpelling(t *testing.T, floorDir, made string, link bool) {
	p, _, _ := stopsPlane(t)
	p.raiseFloor(t, 1, d1, t0)
	if link {
		if err := os.Symlink(".", p.path("alias")); err != nil {
			t.Fatal(err)
		}
	}
	cfg := string(readOrFail(t, p.path("plane.yaml")))
	writeFile(t, p.path("plane.yaml"), []byte(strings.Replace(cfg, "floor_dir: routefloor", "floor_dir: "+floorDir, 1)))
	p.load(t)
	routeFloor := p.path(made)
	dir := backUpBetweenRouteSerials(t, p, routeFloor)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, recovery.ErrStaging) {
		t.Errorf("Restore = %v over a route floor that may be the build's name, want ErrStaging", err)
	}
	if got, err := policystate.ReadRoute(routeFloor, "refunds"); err != nil || got.Serial != 7 {
		t.Fatalf("the route floor holds serial %d (%v), and held 7", got.Serial, err)
	}
}

// backUpBetweenRouteSerials backs p up with its route floor at serial 4,
// raises that floor to 7 and loses the plane floor's directory, and returns
// the backup.
func backUpBetweenRouteSerials(t *testing.T, p *plane, routeFloor string) string {
	t.Helper()
	if err := policystate.InitRoute(t.Context(), routeFloor, "refunds"); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.RaiseRoute(t.Context(), routeFloor, "refunds", 4, d1); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if _, err := policystate.RaiseRoute(t.Context(), routeFloor, "refunds", 7, d2); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(p.path("floors")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestARestoreRefusesBeforeItsFirstWriteAStagingNameNothingHoldsYet: both
// floors are lost, and the plane floor is configured at the route floor's
// staging name in another case, through a link, or at that very name. No
// directory stands at either name, so the file system cannot tell whether
// they are one; the restore refuses before it writes anything rather than
// build the plane floor and then refuse the route floor over it.
func TestARestoreRefusesBeforeItsFirstWriteAStagingNameNothingHoldsYet(t *testing.T) {
	for _, c := range []struct{ name, stateDir string }{
		{"in another case", ".ROUTEFLOOR.restoring"},
		{"through a link", "alias/.routefloor.restoring"},
		{"at that name", ".routefloor.restoring"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, _ := stopsPlane(t)
			if err := os.Symlink(".", p.path("alias")); err != nil {
				t.Fatal(err)
			}
			cfg := string(readOrFail(t, p.path("plane.yaml")))
			writeFile(t, p.path("plane.yaml"), []byte(strings.Replace(cfg, "state_dir: floors", "state_dir: "+c.stateDir, 1)))
			p.load(t)
			planeFloorAt(t, p.cfg.Resolve(p.cfg.Policy.StateDir))
			dir := backUpBetweenRouteSerials(t, p, p.path("routefloor"))
			for _, lost := range []string{p.cfg.Resolve(p.cfg.Policy.StateDir), p.path("routefloor")} {
				if err := os.RemoveAll(lost); err != nil {
					t.Fatal(err)
				}
			}
			before := tree(t, p.root, "alias")
			_, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
			if !errors.Is(err, recovery.ErrStaging) || !strings.Contains(err.Error(), "policy.state_dir") {
				t.Errorf("Restore = %v, want ErrStaging naming policy.state_dir", err)
			}
			if after := tree(t, p.root, "alias"); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Errorf("the restore wrote before it refused: the tree holds %q", after)
			}
			if _, err := os.Lstat(p.cfg.Resolve(p.cfg.Policy.StateDir)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the plane floor after the refusal: %v, want none", err)
			}
		})
	}
}

// planeFloorAt makes a plane floor directory at dir holding serial 3.
func planeFloorAt(t *testing.T, dir string) {
	t.Helper()
	if err := policystate.Init(t.Context(), dir, policystate.KindPlane, bundleID); err != nil {
		t.Fatal(err)
	}
	s, err := policystate.Open(dir, policystate.KindPlane)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Raise(t.Context(), statement(t, 3, d1, t0), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
