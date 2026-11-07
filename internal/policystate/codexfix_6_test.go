package policystate_test

import (
	"errors"
	"testing"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policystate"
)

// TestRestorePlaneStampsAFloorOnlyLiveHolds: bundle B came after the backup
// and its floor took a statement live alone holds. That statement confirms
// B's floor before the restore and nothing after it, as every plane floor a
// restore leaves is stamped at the restore.
func TestRestorePlaneStampsAFloorOnlyLiveHolds(t *testing.T) {
	backup := floorsAt(t, 3, d3, "10:00:00")
	live := floorsAt(t, 3, d3, "10:00:00")
	if err := policystate.Init(t.Context(), live, policystate.KindPlane, idB); err != nil {
		t.Fatal(err)
	}
	old := statement(t, idB, 5, d5, "11:00:00")
	if _, err := open(t, live).Raise(t.Context(), old, noon(t)); err != nil {
		t.Fatalf("Raise of B: %v", err)
	}
	before, err := floorOf(t, live, idB)
	if err != nil {
		t.Fatal(err)
	}
	if err := before.Takes(old, at(t, "14:00:00")); err != nil {
		t.Fatalf("B's own statement before the restore: %v", err)
	}
	got, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil)
	if err != nil {
		t.Fatalf("RestorePlane: %v", err)
	}
	after, err := floorOf(t, live, idB)
	if err != nil {
		t.Fatal(err)
	}
	if err := after.Takes(old, at(t, "14:00:00")); !errors.Is(err, policy.ErrBelowFloor) {
		t.Fatalf("B's statement issued before the restore, after it: err = %v, want ErrBelowFloor (floor %s, wrote %v)", err, describe(after), got.Written)
	}
	if want := "bundle-b serial 5 " + d5 + " issued 2026-09-11T13:00:00Z latest 2026-09-11T13:00:00Z"; describe(after) != want {
		t.Fatalf("B's floor = %s, want %s", describe(after), want)
	}
}

// TestRestorePlaneRefusesAClockBehindAFloorOnlyLiveHolds: a live-only floor
// is stamped by the same rule, so a restore clock behind its latest
// statement is refused rather than lower it.
func TestRestorePlaneRefusesAClockBehindAFloorOnlyLiveHolds(t *testing.T) {
	backup := floorsAt(t, 3, d3, "10:00:00")
	live := floorsAt(t, 3, d3, "10:00:00")
	if err := policystate.Init(t.Context(), live, policystate.KindPlane, idB); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, live).Raise(t.Context(), statement(t, idB, 5, d5, "11:30:00"), noon(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "11:00:00"), nil); !errors.Is(err, policy.ErrClockBehindFloor) {
		t.Fatalf("RestorePlane behind B's floor: err = %v, want ErrClockBehindFloor", err)
	}
	if err := policystate.CheckPlane(t.Context(), live, backup, at(t, "11:00:00")); !errors.Is(err, policy.ErrClockBehindFloor) {
		t.Fatalf("CheckPlane behind B's floor: err = %v, want ErrClockBehindFloor", err)
	}
}
