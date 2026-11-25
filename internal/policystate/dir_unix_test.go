//go:build unix

package policystate_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
)

func TestAnotherOwnerIsRefused(t *testing.T) {
	otherUID := func() int { return os.Geteuid() + 1 }
	t.Run("the directory at Open and Init", func(t *testing.T) {
		dir := initDir(t, policystate.KindPlane)
		restore := policystate.SetEffectiveUID(otherUID)
		defer restore()
		if _, err := policystate.Open(dir, policystate.KindPlane); !errors.Is(err, policystate.ErrOwner) {
			t.Errorf("Open: %v, want ErrOwner", err)
		}
		if err := policystate.Init(t.Context(), dir, policystate.KindPlane, idB); !errors.Is(err, policystate.ErrOwner) {
			t.Errorf("Init: %v, want ErrOwner", err)
		}
	})
	t.Run("the floor file at a read and a raise", func(t *testing.T) {
		dir, s := raised(t)
		before := readFile(t, filepath.Join(dir, fileA))
		restore := policystate.SetEffectiveUID(otherUID)
		defer restore()
		if _, err := s.Floor(t.Context(), idA); !errors.Is(err, policystate.ErrOwner) {
			t.Errorf("Floor: %v, want ErrOwner", err)
		}
		if _, err := s.Raise(t.Context(), statement(t, idA, 6, d6, "11:30:00"), noon(t)); !errors.Is(err, policystate.ErrOwner) {
			t.Errorf("Raise: %v, want ErrOwner", err)
		}
		if after := readFile(t, filepath.Join(dir, fileA)); after != before {
			t.Errorf("a refused raise wrote %s", after)
		}
	})
}

func TestAModeGivingTheGroupOrTheWorldAccessIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o740, 0o704, 0o710, 0o701} {
		t.Run("the directory at Open "+mode.String(), func(t *testing.T) {
			dir := initDir(t, policystate.KindPlane)
			chmod(t, dir, mode)
			if _, err := policystate.Open(dir, policystate.KindPlane); !errors.Is(err, policystate.ErrPermissions) {
				t.Errorf("Open: %v, want ErrPermissions", err)
			}
		})
		t.Run("the directory once open "+mode.String(), func(t *testing.T) {
			dir, s := raised(t)
			chmod(t, dir, mode)
			if _, err := s.Floor(t.Context(), idA); !errors.Is(err, policystate.ErrDirectoryChanged) {
				t.Errorf("Floor: %v, want ErrDirectoryChanged", err)
			}
		})
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o610, 0o601} {
		t.Run("the floor file "+mode.String(), func(t *testing.T) {
			dir, s := raised(t)
			chmod(t, filepath.Join(dir, fileA), mode)
			if _, err := s.Floor(t.Context(), idA); !errors.Is(err, policystate.ErrPermissions) {
				t.Errorf("Floor: %v, want ErrPermissions", err)
			}
			if _, err := s.Raise(t.Context(), statement(t, idA, 6, d6, "11:30:00"), noon(t)); !errors.Is(err, policystate.ErrPermissions) {
				t.Errorf("Raise: %v, want ErrPermissions", err)
			}
		})
		t.Run("the marker "+mode.String(), func(t *testing.T) {
			dir := initDir(t, policystate.KindPlane)
			chmod(t, filepath.Join(dir, "floors.meta"), mode)
			if _, err := policystate.Open(dir, policystate.KindPlane); !errors.Is(err, policystate.ErrPermissions) {
				t.Errorf("Open: %v, want ErrPermissions", err)
			}
		})
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestALinkIsRefusedWhereAFileOrTheDirectoryShouldStand(t *testing.T) {
	t.Run("at the floor file", func(t *testing.T) {
		dir, s := raised(t)
		elsewhere := filepath.Join(t.TempDir(), "floor.json")
		writeFile(t, elsewhere, readFile(t, filepath.Join(dir, fileA)))
		if err := os.Remove(filepath.Join(dir, fileA)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(dir, fileA)); err != nil {
			t.Fatal(err)
		}
		if f, err := s.Floor(t.Context(), idA); !errors.Is(err, policystate.ErrForeignFile) {
			t.Errorf("Floor through a link: %s, %v; want ErrForeignFile", describe(f), err)
		}
		if _, err := policystate.Open(dir, policystate.KindPlane); !errors.Is(err, policystate.ErrForeignFile) {
			t.Errorf("Open beside a link: %v, want ErrForeignFile", err)
		}
	})
	t.Run("at the directory's name", func(t *testing.T) {
		dir := initDir(t, policystate.KindPlane)
		link := filepath.Join(t.TempDir(), "floors")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if _, err := policystate.Open(link, policystate.KindPlane); !errors.Is(err, policystate.ErrNotStateDir) {
			t.Errorf("Open of a link to a floor directory: %v, want ErrNotStateDir", err)
		}
		if err := policystate.Init(t.Context(), link, policystate.KindPlane, idB); !errors.Is(err, policystate.ErrNotStateDir) {
			t.Errorf("Init through a link: %v, want ErrNotStateDir", err)
		}
	})
}

func TestAPipeAtTheFloorsNameIsRefusedWithoutWaiting(t *testing.T) {
	dir, s := raised(t)
	if err := os.Remove(filepath.Join(dir, fileA)); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, fileA), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.Floor(t.Context(), idA); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, policystate.ErrForeignFile) {
			t.Errorf("Floor of a pipe: %v, want ErrForeignFile", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Floor waited on a pipe")
	}
	if _, err := policystate.Open(dir, policystate.KindPlane); !errors.Is(err, policystate.ErrForeignFile) {
		t.Errorf("Open beside a pipe: %v, want ErrForeignFile", err)
	}
}

func TestADirectorySwappedAtItsNameIsRefused(t *testing.T) {
	dir, s := raised(t)
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := policystate.Init(t.Context(), dir, policystate.KindPlane, idA); err != nil {
		t.Fatal(err)
	}
	if f, err := s.Floor(t.Context(), idA); !errors.Is(err, policystate.ErrDirectoryChanged) {
		t.Errorf("Floor once another directory stands at the name: %s, %v; want ErrDirectoryChanged", describe(f), err)
	}
	if f, err := s.Raise(t.Context(), statement(t, idA, 1, d3, "11:30:00"), noon(t)); !errors.Is(err, policystate.ErrDirectoryChanged) {
		t.Errorf("Raise once another directory stands at the name: %s, %v; want ErrDirectoryChanged", describe(f), err)
	}
	if got := readFile(t, filepath.Join(dir, fileA)); got != emptyBodyA {
		t.Errorf("the new directory's floor is %s", got)
	}
}

func TestTheModesInitWritesDoNotFollowTheUmask(t *testing.T) {
	for _, mask := range []int{0, 0o077, 0o027} {
		dir := func() string {
			saved := syscall.Umask(mask)
			defer syscall.Umask(saved)
			return initDir(t, policystate.KindPlane)
		}()
		for path, want := range map[string]os.FileMode{
			dir:                               0o700,
			filepath.Join(dir, "floors.meta"): 0o600,
			filepath.Join(dir, fileA):         0o600,
		} {
			if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != want {
				t.Errorf("umask %03o: %s is %v, %v; want %04o", mask, filepath.Base(path), info.Mode(), err, want)
			}
		}
	}
}

// TestEveryInitMakesItsDirectoryOwnerOnlyUnderAnyUmask: a umask that takes
// the owner's own write bit leaves each kind's new directory 0700 and the
// init done; the control is the same init under no mask.
func TestEveryInitMakesItsDirectoryOwnerOnlyUnderAnyUmask(t *testing.T) {
	inits := map[string]func(dir string) error{
		"Init":          func(dir string) error { return policystate.Init(t.Context(), dir, policystate.KindSigner, idA) },
		"InitAuthority": func(dir string) error { return policystate.InitAuthority(t.Context(), dir, "roster-a") },
		"InitRoute":     func(dir string) error { return policystate.InitRoute(t.Context(), dir, "route-a") },
		"InitPause":     func(dir string) error { return policystate.InitPause(t.Context(), dir, "t1", "A") },
		"InitStops":     func(dir string) error { return policystate.InitStops(t.Context(), dir, "t1", "A") },
	}
	for name, init := range inits {
		for _, mask := range []int{0, 0o200, 0o100} {
			dir := filepath.Join(t.TempDir(), "floors")
			err := func() error {
				saved := syscall.Umask(mask)
				defer syscall.Umask(saved)
				return init(dir)
			}()
			info, statErr := os.Lstat(dir)
			if err != nil || statErr != nil || info.Mode().Perm() != 0o700 {
				t.Errorf("%s under umask %03o = %v; the directory %v, %v; want done and 0700", name, mask, err, info.Mode(), statErr)
			}
		}
	}
}

func TestANameThePackageDoesNotWriteRefusesTheDirectory(t *testing.T) {
	for _, name := range []string{
		"notes.txt", fileA + ".bak", "D8832A1B44E0743B0465F2C7DAA51EFA12D7C5538FBC27240B46ADAEB465AB87.floor.json",
		"73449d42.floor.json", ".tmp-ABC", ".tmp-abcdefghijklmnopqrstuvwxyz", leftover + "A", "runs.meta",
	} {
		t.Run(name, func(t *testing.T) {
			dir := initDir(t, policystate.KindPlane)
			writeFile(t, filepath.Join(dir, name), "{}")
			if _, err := policystate.Open(dir, policystate.KindPlane); !errors.Is(err, policystate.ErrForeignFile) {
				t.Errorf("Open: %v, want ErrForeignFile", err)
			}
			if err := policystate.Init(t.Context(), dir, policystate.KindPlane, idB); !errors.Is(err, policystate.ErrForeignFile) {
				t.Errorf("Init: %v, want ErrForeignFile", err)
			}
		})
	}
	t.Run("a directory", func(t *testing.T) {
		dir := initDir(t, policystate.KindPlane)
		if err := os.Mkdir(filepath.Join(dir, leftover), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := policystate.Open(dir, policystate.KindPlane); !errors.Is(err, policystate.ErrForeignFile) {
			t.Errorf("Open: %v, want ErrForeignFile", err)
		}
	})
	t.Run("a leftover of a write is not foreign", func(t *testing.T) {
		dir := initDir(t, policystate.KindPlane)
		writeFile(t, filepath.Join(dir, leftover), `{"schema_ver`)
		if _, err := policystate.Open(dir, policystate.KindPlane); err != nil {
			t.Errorf("Open beside a leftover: %v", err)
		}
		if err := policystate.Init(t.Context(), dir, policystate.KindPlane, idB); err != nil {
			t.Errorf("Init beside a leftover: %v", err)
		}
	})
}

func TestResetJudgesWhatTheDirectoryHolds(t *testing.T) {
	for name, plant := range map[string]func(path string) error{
		"a foreign file": func(p string) error { return os.WriteFile(p, []byte("{}"), 0o600) },
		"a pipe":         func(p string) error { return syscall.Mkfifo(p, 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			dir, _ := raised(t)
			before := readFile(t, filepath.Join(dir, fileA))
			if err := plant(filepath.Join(dir, "notes.txt")); err != nil {
				t.Fatal(err)
			}
			if _, err := policystate.Reset(t.Context(), dir, policystate.KindPlane, floorAt3(t, "09:30:00"), "withdrawn"); !errors.Is(err, policystate.ErrForeignFile) {
				t.Errorf("Reset: %v, want ErrForeignFile", err)
			}
			if after := readFile(t, filepath.Join(dir, fileA)); after != before {
				t.Errorf("a refused Reset wrote %s", after)
			}
		})
	}
}

// TestAnInitUnderAUmaskTakingTheOwnersReadBitLeavesNoDirectory: a umask
// that takes the owner's read bit leaves a directory Init cannot open to set
// its mode; Init is refused and removes it, so the next Init, under an
// ordinary umask, makes it 0700.
func TestAnInitUnderAUmaskTakingTheOwnersReadBitLeavesNoDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser opens a directory whatever its mode")
	}
	for _, mask := range []int{0o400, 0o700} {
		dir := filepath.Join(t.TempDir(), "floors")
		err := func() error {
			saved := syscall.Umask(mask)
			defer syscall.Umask(saved)
			return policystate.InitAuthority(t.Context(), dir, "roster-a")
		}()
		if !errors.Is(err, policystate.ErrNotStateDir) {
			t.Errorf("InitAuthority under umask %03o = %v, want ErrNotStateDir", mask, err)
		}
		if info, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("under umask %03o the directory was left: %v, %v", mask, info.Mode(), err)
			_ = os.Chmod(dir, 0o700) //nolint:gosec // G302: a directory, opened again so the test can remove it
			continue
		}
		if err := policystate.InitAuthority(t.Context(), dir, "roster-a"); err != nil {
			t.Fatalf("the next InitAuthority, under the test's umask: %v", err)
		}
		if info, err := os.Lstat(dir); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("the directory the next InitAuthority made: %v, %v; want 0700", info.Mode(), err)
		}
	}
}
