package recovery_test

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/recovery"
)

// TestRestoreStampsAPlaneFloorTheBackupHasNoClassFor: the backup was taken
// before the plane had a floor directory, so it holds no floor class at all.
// The floor live took since is stamped at the restore all the same, and the
// statement it took confirms it no more.
func TestRestoreStampsAPlaneFloorTheBackupHasNoClassFor(t *testing.T) {
	p := newPlane(t, directoryBlock)
	p.openRun(t, confidential)
	dir := filepath.Join(t.TempDir(), "backup")
	taken, err := recovery.Backup(t.Context(), p.cfg, dir, t0)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if !slices.Contains(taken.Absent, "policy.state_dir") {
		t.Fatalf("Absent = %q, want the floor directory absent from the backup", taken.Absent)
	}
	issued := t0.Add(time.Hour)
	p.raiseFloor(t, 1, d1, issued)
	old := statement(t, 1, d1, issued)
	if err := p.floor(t).Takes(old, restoreAt.Add(time.Minute)); err != nil {
		t.Fatalf("the floor's own statement before the restore: %v", err)
	}
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := p.floor(t).Takes(old, restoreAt.Add(time.Minute)); !errors.Is(err, policy.ErrBelowFloor) {
		t.Fatalf("the statement issued before the restore, after it: err = %v, want ErrBelowFloor (floor %s)", err, describe(p.floor(t)))
	}
}
