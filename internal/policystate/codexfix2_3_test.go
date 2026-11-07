package policystate_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policystate"
)

// listedWithoutFile is a backup whose marker lists idB with no floor file,
// and a live directory whose idB floor took a statement at serial 5 issued
// at issued.
func listedWithoutFile(t *testing.T, issued string) (live, backup string, old policy.Statement) {
	t.Helper()
	backup = floorsAt(t, 3, d3, "10:00:00")
	if err := policystate.Init(t.Context(), backup, policystate.KindPlane, idB); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(backup, fileB)); err != nil {
		t.Fatal(err)
	}
	live = floorsAt(t, 3, d3, "10:00:00")
	if err := policystate.Init(t.Context(), live, policystate.KindPlane, idB); err != nil {
		t.Fatal(err)
	}
	old = statement(t, idB, 5, d5, issued)
	if _, err := open(t, live).Raise(t.Context(), old, noon(t)); err != nil {
		t.Fatalf("Raise of B: %v", err)
	}
	return live, backup, old
}

// TestRestorePlaneStampsAFloorTheBackupListsWithoutAFile: the backup's
// marker lists B but holds no file of it, so live's floor of B is the only
// one; it is stamped at the restore as a live-only floor is.
func TestRestorePlaneStampsAFloorTheBackupListsWithoutAFile(t *testing.T) {
	live, backup, old := listedWithoutFile(t, "11:00:00")
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil); err != nil {
		t.Fatalf("RestorePlane: %v", err)
	}
	after, err := floorOf(t, live, idB)
	if err != nil {
		t.Fatal(err)
	}
	if err := after.Takes(old, at(t, "14:00:00")); !errors.Is(err, policy.ErrBelowFloor) {
		t.Fatalf("B's statement issued before the restore, after it: err = %v, want ErrBelowFloor (floor %s)", err, describe(after))
	}
}

// TestRestorePlaneRefusesAClockBehindAFloorTheBackupListsWithoutAFile: the
// same floor is held to the restore clock.
func TestRestorePlaneRefusesAClockBehindAFloorTheBackupListsWithoutAFile(t *testing.T) {
	live, backup, _ := listedWithoutFile(t, "11:30:00")
	if err := policystate.CheckPlane(t.Context(), live, backup, at(t, "11:00:00")); !errors.Is(err, policy.ErrClockBehindFloor) {
		t.Fatalf("CheckPlane behind B's floor: err = %v, want ErrClockBehindFloor", err)
	}
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "11:00:00"), nil); !errors.Is(err, policy.ErrClockBehindFloor) {
		t.Fatalf("RestorePlane behind B's floor: err = %v, want ErrClockBehindFloor", err)
	}
}
