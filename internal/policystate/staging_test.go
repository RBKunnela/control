package policystate_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/policystate"
)

// TestABuildRemovesOnlyAStagingDirectoryABuildMade: a missing floor
// directory is built under its staging name. What stands there that no build
// made, a directory holding a file or an empty one, refuses the build and is
// left as it was.
func TestABuildRemovesOnlyAStagingDirectoryABuildMade(t *testing.T) {
	backup := floorsAt(t, 3, d3, "10:00:00")
	for _, c := range []struct {
		name string
		put  func(t *testing.T, staging string)
	}{
		{"a directory holding a file", func(t *testing.T, staging string) {
			if err := os.Mkdir(staging, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(staging, "ledger"), []byte("spent"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"an empty directory", func(t *testing.T, staging string) {
			if err := os.Mkdir(staging, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			live := newDir(t)
			staging := policystate.StagingPath(live)
			c.put(t, staging)
			before, err := os.ReadDir(staging)
			if err != nil {
				t.Fatal(err)
			}
			_, err = policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil)
			if !errors.Is(err, policystate.ErrStagingTaken) {
				t.Errorf("RestorePlane over %s at the staging name = %v, want ErrStagingTaken", c.name, err)
			}
			after, aerr := os.ReadDir(staging)
			if aerr != nil || len(after) != len(before) {
				t.Errorf("the staging name holds %d entries (%v) after the refusal, and held %d", len(after), aerr, len(before))
			}
			if _, err := os.Lstat(live); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refused build left the floor directory: %v", err)
			}
		})
	}
}

// TestABuildStoppedBeforeItsRenameIsFinishedByARerun: what a build stopped
// before its rename left at the staging name is removed, and the build run
// again ends with the floor in place.
func TestABuildStoppedBeforeItsRenameIsFinishedByARerun(t *testing.T) {
	backup := floorsAt(t, 3, d3, "10:00:00")
	live := newDir(t)
	stop := errors.New("stopped")
	_, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), func(what string) error {
		if what == "rename "+live {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("RestorePlane stopped before its rename = %v", err)
	}
	if _, err := os.Lstat(policystate.StagingPath(live)); err != nil {
		t.Fatalf("the stopped build left no staging directory: %v", err)
	}
	if _, err := policystate.RestorePlane(t.Context(), live, backup, at(t, "13:00:00"), nil); err != nil {
		t.Fatalf("RestorePlane run again = %v", err)
	}
	if f, err := floorOf(t, live, idA); err != nil || f.Serial() != 3 {
		t.Fatalf("floor after the rerun = %+v, %v", f, err)
	}
}
