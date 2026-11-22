//go:build unix

package recovery_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/runs"
)

// TestSignedRestoreRefusesALockItCannotTakeBeforeWriting: a surviving
// root's lock file the group may write is one the join under it refuses, so
// the restore refuses before it stamps a floor or carries a close.
func TestSignedRestoreRefusesALockItCannotTakeBeforeWriting(t *testing.T) {
	p, dir, rec := signedPlaneOf(t, signedBlock, func(p *plane, rec runs.Record) {
		pl, err := runs.OpenSignedPlane(p.path("runs"), runs.SignedOptions{Judge: takeAll{}, PlaneOwned: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = pl.Close() }()
		if err := pl.Raise(t.Context(), rec.ID, func(s runs.State) runs.State { return s }); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Chmod(p.path("runs/state/"+rec.ID+".lock"), 0o660); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	before := tree(t, p.root)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err == nil {
		t.Fatal("a restore over a lock file the group may write succeeded")
	}
	if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("a refused restore changed the plane's tree")
	}
}

// TestABackupHoldsItsModesWhateverTheUmask: under a umask that takes the
// owner's read and execute, the backup's directories are still 0700 and its
// files 0600, as the recovery guide says.
func TestABackupHoldsItsModesWhateverTheUmask(t *testing.T) {
	p, _, _ := backedUp(t)
	dir := filepath.Join(t.TempDir(), "under-umask")
	old := syscall.Umask(0o577)
	_, err := recovery.Backup(t.Context(), p.cfg, dir, t0)
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("Backup under umask 0577: %v", err)
	}
	files := 0
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		} else {
			files++
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s is mode %04o, want %04o", path, info.Mode().Perm(), want)
		}
		return nil
	})
	if err != nil || files == 0 {
		t.Fatalf("walking the backup: %d files, %v", files, err)
	}
}
