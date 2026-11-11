//go:build unix

package gatewayconfig

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/files"
)

// plane is the uid these tests take for the plane's account; every entry is
// read as root's but those a test gives the plane.
const plane = 4242

// planeOwns makes the check read the plane as plane, each of paths, by
// identity, as the plane's, and every other entry as root's.
func planeOwns(t *testing.T, paths ...string) {
	t.Helper()
	planeIs(t, plane)
	owned := identities(t, paths...)
	ownedAs(t, func(info fs.FileInfo, _ int) int {
		if owned(info) {
			return plane
		}
		return 0
	})
}

// planeIs makes the check take uid as the plane's account.
func planeIs(t *testing.T, uid int) {
	t.Helper()
	was := ownerWanted
	ownerWanted = func(fs.FileInfo) int { return uid }
	t.Cleanup(func() { ownerWanted = was })
}

// writableAt makes the check read each of paths, by identity, and nothing
// else, as one the plane's account may write.
func writableAt(t *testing.T, paths ...string) {
	t.Helper()
	writable := identities(t, paths...)
	planeMayWrite = func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return false, err
		}
		return writable(info), nil
	}
	t.Cleanup(func() { planeMayWrite = accessWrite })
}

// aclAt makes the check read each of paths, by identity, and nothing else,
// as an entry that carries an access control list.
func aclAt(t *testing.T, paths ...string) {
	t.Helper()
	carries := identities(t, paths...)
	hasACL = func(_ string, info fs.FileInfo) (bool, error) { return carries(info), nil }
	t.Cleanup(func() { hasACL = aclPresent })
}

// identities reports whether an entry is, by identity, one of paths as they
// stand now.
func identities(t *testing.T, paths ...string) func(fs.FileInfo) bool {
	t.Helper()
	var want []fs.FileInfo
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, info)
	}
	return func(info fs.FileInfo) bool {
		for _, w := range want {
			if os.SameFile(w, info) {
				return true
			}
		}
		return false
	}
}

// tempDir is a fresh directory named with no link in it, as the walk names
// what it passes.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// rootsTree lays out conf/gateway.yaml under a fresh directory, a file of
// mode 0644 in a directory of mode 0755, and returns the directory and the
// file.
func rootsTree(t *testing.T) (dir, file string) {
	t.Helper()
	dir = mkdirMode(t, filepath.Join(tempDir(t), "conf"), 0o755)
	return dir, fileAt(t, filepath.Join(dir, "gateway.yaml"), 0o644)
}

// refusedAt checks that err is want and names the entry as says spells it.
func refusedAt(t *testing.T, err, want error, says string) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("accepted, want %v at %s", want, says)
	case !errors.Is(err, want):
		t.Errorf("refused with %v, want %v", err, want)
	case !strings.Contains(err.Error(), says):
		t.Errorf("the refusal %q does not say %q", err, says)
	case strings.Contains(err.Error(), "orders-assistant"):
		t.Errorf("the refusal %q quotes the file", err)
	}
}

// TestRootsTreeIsNotThePlanes: a file and the directory holding it, root's
// and closed to the plane, from the root of the file system down, pass, read
// as a file and as a directory, and through a link of root's.
func TestRootsTreeIsNotThePlanes(t *testing.T) {
	dir, file := rootsTree(t)
	link := symlink(t, file, filepath.Join(tempDir(t), "gateway.yaml"))
	planeOwns(t)
	writableAt(t)
	for _, path := range []string{file, dir, link} {
		if err := CheckNotPlaneWritable(path); err != nil {
			t.Errorf("CheckNotPlaneWritable(%s), root's: %v", path, err)
		}
	}
	end, err := JudgeNotPlaneWritable(link)
	if err != nil {
		t.Fatalf("JudgeNotPlaneWritable(%s), root's: %v", link, err)
	}
	target, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(end, target) {
		t.Errorf("JudgeNotPlaneWritable(%s) returned an entry other than the file the walk judged, %s", link, file)
	}
}

// TestAnEntryThePlaneOwnsIsRefused: an owner may change an entry's mode
// whatever it says, and replace what a directory of its own holds, so every
// entry on the path the plane owns is refused, sticky or not.
func TestAnEntryThePlaneOwnsIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		lay  func(t *testing.T) (path, owned, says string)
	}{
		{"the file", func(t *testing.T) (string, string, string) {
			_, file := rootsTree(t)
			return file, file, file
		}},
		{"the directory it ends at", func(t *testing.T) (string, string, string) {
			dir, _ := rootsTree(t)
			return dir, dir, "the directory " + dir
		}},
		{"a directory above the file", func(t *testing.T) (string, string, string) {
			dir, file := rootsTree(t)
			return file, dir, "the directory " + dir
		}},
		{"a sticky directory above the file", func(t *testing.T) (string, string, string) {
			dir, file := rootsTree(t)
			mkdirMode(t, dir, fs.ModeSticky|0o755)
			return file, dir, "the directory " + dir
		}},
		{"a link on the path", func(t *testing.T) (string, string, string) {
			_, file := rootsTree(t)
			link := symlink(t, file, filepath.Join(tempDir(t), "gateway.yaml"))
			return link, link, "the link " + link
		}},
		{"the root of the file system", func(t *testing.T) (string, string, string) {
			_, file := rootsTree(t)
			return file, string(filepath.Separator), "the directory " + string(filepath.Separator) + ":"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path, owned, says := c.lay(t)
			writableAt(t)
			planeOwns(t)
			if err := CheckNotPlaneWritable(path); err != nil {
				t.Fatalf("CheckNotPlaneWritable(%s) before the plane owned anything: %v", path, err)
			}
			planeOwns(t, owned)
			refusedAt(t, CheckNotPlaneWritable(path), errPlaneOwns, says)
		})
	}
}

// TestAnEntryThePlaneMayWriteIsRefused: whoever may write the file rewrites
// it, and whoever may write a directory on the path that is not sticky
// replaces what it holds.
func TestAnEntryThePlaneMayWriteIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		lay  func(t *testing.T) (path, writable, says string)
	}{
		{"the file", func(t *testing.T) (string, string, string) {
			_, file := rootsTree(t)
			return file, file, file
		}},
		{"the directory above the file", func(t *testing.T) (string, string, string) {
			dir, file := rootsTree(t)
			return file, dir, "the directory " + dir
		}},
		{"the directory it ends at", func(t *testing.T) (string, string, string) {
			dir, _ := rootsTree(t)
			return dir, dir, "the directory " + dir
		}},
		{"a sticky directory it ends at", func(t *testing.T) (string, string, string) {
			dir, _ := rootsTree(t)
			mkdirMode(t, dir, fs.ModeSticky|0o777)
			return dir, dir, "the directory " + dir
		}},
		{"the root of the file system", func(t *testing.T) (string, string, string) {
			_, file := rootsTree(t)
			return file, string(filepath.Separator), "the directory " + string(filepath.Separator) + ":"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path, writable, says := c.lay(t)
			planeOwns(t)
			writableAt(t, writable)
			refusedAt(t, CheckNotPlaneWritable(path), errPlaneWrites, says)
		})
	}
}

// TestAStickyDirectoryPassesOnlyWhatThePlaneDoesNotOwn: a sticky directory
// lets nobody but an entry's owner, or the directory's, replace the entry,
// so one the plane may write passes an entry of root's and refuses the
// plane's own.
func TestAStickyDirectoryPassesOnlyWhatThePlaneDoesNotOwn(t *testing.T) {
	dir, file := rootsTree(t)
	mkdirMode(t, dir, fs.ModeSticky|0o777)
	writableAt(t, dir)
	planeOwns(t)
	if err := CheckNotPlaneWritable(file); err != nil {
		t.Errorf("root's file in a sticky directory the plane may write: %v", err)
	}
	planeOwns(t, file)
	refusedAt(t, CheckNotPlaneWritable(file), errPlaneOwns, file)
}

// TestAMissingPathIsRefused: a file the plane could create is one it may
// write, and the check cannot tell who may create it, so a missing entry
// anywhere on the path is refused.
func TestAMissingPathIsRefused(t *testing.T) {
	dir, _ := rootsTree(t)
	planeOwns(t)
	writableAt(t)
	for _, path := range []string{
		filepath.Join(dir, "absent.yaml"),
		filepath.Join(dir, "absent", "gateway.yaml"),
	} {
		refusedAt(t, CheckNotPlaneWritable(path), fs.ErrNotExist, "absent")
	}
}

// TestALoopOfLinksIsRefused: a loop is refused at the walk's bound, not
// followed.
func TestALoopOfLinksIsRefused(t *testing.T) {
	base := tempDir(t)
	symlink(t, "b", filepath.Join(base, "a"))
	loop := symlink(t, "a", filepath.Join(base, "b"))
	planeOwns(t)
	writableAt(t)
	refusedAt(t, CheckNotPlaneWritable(loop), errTooManyLinks, "more than 40")
}

// TestAPlaneRunningAsRootIsRefused: root may write every path whatever its
// owner and mode, so no placement protects anything from a plane run as
// root; the tree root's alone passes as another account.
func TestAPlaneRunningAsRootIsRefused(t *testing.T) {
	_, file := rootsTree(t)
	planeOwns(t)
	writableAt(t)
	if err := CheckNotPlaneWritable(file); err != nil {
		t.Fatalf("root's tree, the plane another account: %v", err)
	}
	planeIs(t, 0)
	refusedAt(t, CheckNotPlaneWritable(file), errPlaneIsRoot, file)
}

// TestAnUnansweredQuestionIsRefused: an owner the platform does not name and
// a write the kernel does not answer show nothing closed to the plane.
func TestAnUnansweredQuestionIsRefused(t *testing.T) {
	t.Run("the write", func(t *testing.T) {
		_, file := rootsTree(t)
		planeOwns(t)
		unanswered := errors.New("no answer")
		planeMayWrite = func(path string) (bool, error) {
			if path == file {
				return false, unanswered
			}
			return false, nil
		}
		t.Cleanup(func() { planeMayWrite = accessWrite })
		refusedAt(t, CheckNotPlaneWritable(file), unanswered, file)
	})
	t.Run("the owner", func(t *testing.T) {
		_, file := rootsTree(t)
		planeOwns(t)
		writableAt(t)
		unnamed := identities(t, file)
		ownerOf = func(info fs.FileInfo) (int, bool) { return 0, !unnamed(info) }
		refusedAt(t, CheckNotPlaneWritable(file), files.ErrOwnerUnknown, file)
	})
	t.Run("the plane's account", func(t *testing.T) {
		_, file := rootsTree(t)
		planeOwns(t)
		writableAt(t)
		planeIs(t, -1)
		refusedAt(t, CheckNotPlaneWritable(file), files.ErrOwnerUnknown, string(filepath.Separator))
	})
}

// TestADirectorySwappedWhileAskedIsRefused: the kernel is asked by name, so
// the entry asked about has to be the one whose owner was judged; a
// directory of the plane's put at the name while the kernel answered is
// refused.
func TestADirectorySwappedWhileAskedIsRefused(t *testing.T) {
	dir, file := rootsTree(t)
	planted := filepath.Join(filepath.Dir(dir), "planted")
	mkdirMode(t, planted, 0o755)
	fileAt(t, filepath.Join(planted, "gateway.yaml"), 0o644)
	planeOwns(t, planted)
	swapped := false
	planeMayWrite = func(path string) (bool, error) {
		if path == dir && !swapped {
			swapped = true
			if err := os.Rename(dir, dir+".judged"); err != nil {
				return false, err
			}
			if err := os.Rename(planted, dir); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	t.Cleanup(func() { planeMayWrite = accessWrite })
	refusedAt(t, CheckNotPlaneWritable(file), errChanged, "the directory "+dir)
	if !swapped {
		t.Error("the kernel was never asked about the directory, so nothing was swapped")
	}
}

// TestAnEndSwappedForALinkAfterTheWalkIsRefused: the walk reaches a path
// that holds no link, so a link put at its end once the walk passed is
// refused rather than judged as the link alone.
func TestAnEndSwappedForALinkAfterTheWalkIsRefused(t *testing.T) {
	dir, file := rootsTree(t)
	elsewhere := fileAt(t, filepath.Join(dir, "elsewhere.yaml"), 0o644)
	planeOwns(t)
	writableAt(t)
	atStep(t, stepWalked,
		func() error { return os.Remove(file) },
		func() error { return os.Symlink(elsewhere, file) })
	refusedAt(t, CheckNotPlaneWritable(file), errChanged, file)
}

// TestTheKernelIsAsked: with no seam faked, the kernel answers for this
// account: a directory it made is writable, a file of mode 0400 is not, a
// missing name is no answer, and a file this account made is refused as the
// plane's own. Root's own file, where the system has one, passes.
func TestTheKernelIsAsked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every path is writable; the case needs another account")
	}
	dir, file := rootsTree(t)
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path string
		want bool
	}{{dir, true}, {file, false}} {
		if got, err := accessWrite(c.path); err != nil || got != c.want {
			t.Errorf("accessWrite(%s) = %v, %v; want %v", c.path, got, err, c.want)
		}
	}
	if got, err := accessWrite(filepath.Join(dir, "absent")); err == nil {
		t.Errorf("accessWrite(a missing name) = %v with no error", got)
	}
	refusedAt(t, CheckNotPlaneWritable(file), errPlaneOwns, file)
	root := rootFile(t)
	if err := CheckNotPlaneWritable(root); err != nil {
		t.Errorf("CheckNotPlaneWritable(%s), root's: %v", root, err)
	}
}

// TestAnEmptyPathIsRefused: an empty path names no entry, and is not read as
// the working directory.
func TestAnEmptyPathIsRefused(t *testing.T) {
	refusedAt(t, CheckNotPlaneWritable(""), errEmptyPath, "empty")
}

// TestAnEntryCarryingAnACLIsRefused: access(2) does not ask for the append,
// delete or ownership an access control list may grant, so any entry on the
// path that carries one is refused, a sticky directory and a link among
// them, and so is an entry the platform cannot answer for.
func TestAnEntryCarryingAnACLIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		lay  func(t *testing.T) (path, carries, says string)
	}{
		{"the file", func(t *testing.T) (string, string, string) {
			_, file := rootsTree(t)
			return file, file, file
		}},
		{"a directory above the file", func(t *testing.T) (string, string, string) {
			dir, file := rootsTree(t)
			return file, dir, "the directory " + dir
		}},
		{"a sticky directory above the file", func(t *testing.T) (string, string, string) {
			dir, file := rootsTree(t)
			mkdirMode(t, dir, fs.ModeSticky|0o777)
			return file, dir, "the directory " + dir
		}},
		{"a link on the path", func(t *testing.T) (string, string, string) {
			_, file := rootsTree(t)
			link := symlink(t, file, filepath.Join(tempDir(t), "gateway.yaml"))
			return link, link, "the link " + link
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path, carries, says := c.lay(t)
			planeOwns(t)
			writableAt(t)
			aclAt(t)
			if err := CheckNotPlaneWritable(path); err != nil {
				t.Fatalf("CheckNotPlaneWritable(%s) with no access control list: %v", path, err)
			}
			aclAt(t, carries)
			refusedAt(t, CheckNotPlaneWritable(path), errACL, says)
		})
	}
	t.Run("unanswered", func(t *testing.T) {
		_, file := rootsTree(t)
		planeOwns(t)
		writableAt(t)
		unanswered := errors.New("no answer")
		hasACL = func(path string, _ fs.FileInfo) (bool, error) {
			if path == file {
				return false, unanswered
			}
			return false, nil
		}
		t.Cleanup(func() { hasACL = aclPresent })
		refusedAt(t, CheckNotPlaneWritable(file), unanswered, file)
	})
}

// TestAnACLIsSeen makes an access control list that lets this account append
// to a file of mode 0400, which access(2) calls not writable, and reads it
// through the platform's own question.
func TestAnACLIsSeen(t *testing.T) {
	_, file := rootsTree(t)
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatal(err)
	}
	planeOwns(t)
	writableAt(t)
	if err := CheckNotPlaneWritable(file); err != nil {
		t.Fatalf("CheckNotPlaneWritable(%s) before the list was made: %v", file, err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("chmod", "+a", "user:"+me.Username+" allow append", file).CombinedOutput() //nolint:gosec // G204: the test's own file and account
	if err != nil {
		t.Skipf("chmod +a cannot make an access control list here: %v: %s", err, strings.Join(strings.Fields(string(out)), " "))
	}
	refusedAt(t, CheckNotPlaneWritable(file), errACL, file)
}

// TestTheKernelAnswersOnlyForTheRealIDs: access(2) answers for the real uid
// and gid, so a plane whose effective uid or gid differs is refused rather
// than answered for another account; equal ids are answered.
func TestTheKernelAnswersOnlyForTheRealIDs(t *testing.T) {
	dir := tempDir(t)
	was := planeIDs
	t.Cleanup(func() { planeIDs = was })
	for _, c := range []struct {
		name string
		ids  [4]int
		says string
	}{
		{"the uids", [4]int{501, 0, 20, 20}, "uids differ"},
		{"the gids", [4]int{501, 501, 20, 0}, "gids differ"},
	} {
		t.Run(c.name, func(t *testing.T) {
			planeIDs = func() (int, int, int, int) { return c.ids[0], c.ids[1], c.ids[2], c.ids[3] }
			if _, err := accessWrite(dir); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("accessWrite with %s apart = %v, want a refusal saying %q", c.name, err, c.says)
			}
		})
	}
	planeIDs = func() (int, int, int, int) { return 501, 501, 20, 20 }
	if _, err := accessWrite(dir); err != nil {
		t.Errorf("accessWrite with equal ids: %v", err)
	}
}
