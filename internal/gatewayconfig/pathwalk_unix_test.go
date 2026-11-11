//go:build unix

package gatewayconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/guardana/control/internal/files"
)

// mkdirMode makes dir and gives it mode, set after the make so the umask
// cannot narrow it.
func mkdirMode(t *testing.T, dir string, mode fs.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fileAt writes the document at path with mode, set after the write.
func fileAt(t *testing.T, path string, mode fs.FileMode) string {
	t.Helper()
	if err := os.Rename(writeDocument(t, document), path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func symlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

// ownedAs makes the loader read each entry's owner as as answers it, given
// the owner the platform names.
func ownedAs(t *testing.T, as func(info fs.FileInfo, uid int) int) {
	t.Helper()
	ownerOf = func(info fs.FileInfo) (int, bool) {
		uid, ok := statOwner(info)
		if !ok {
			return uid, ok
		}
		return as(info, uid), true
	}
	t.Cleanup(func() { ownerOf = statOwner })
}

// readOnlyAt makes the loader read each of dirs, and no other directory, as
// one on a read-only mount.
func readOnlyAt(t *testing.T, dirs ...string) {
	t.Helper()
	var want []fs.FileInfo
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, info)
	}
	onReadOnlyMount = func(d *os.File) (bool, error) {
		got, err := d.Stat()
		if err != nil {
			return false, err
		}
		for _, w := range want {
			if os.SameFile(w, got) {
				return true, nil
			}
		}
		return false, nil
	}
	t.Cleanup(func() { onReadOnlyMount = readOnlyMount })
}

// loads checks that the configuration at path is read.
func loads(t *testing.T, path string) {
	t.Helper()
	if _, err := Load(path, nil); err != nil {
		t.Errorf("Load(%s): %v", path, err)
	}
}

// TestEveryDirectoryOnThePathIsJudged: whoever may write any directory the
// path passes may put another tree under it, so each is judged, not only the
// file's own, its group's write bit among the others'; a sticky one lets
// nobody but an entry's owner replace the entry.
func TestEveryDirectoryOnThePathIsJudged(t *testing.T) {
	for _, c := range []struct {
		name     string
		upper    fs.FileMode
		conf     fs.FileMode
		fileMode fs.FileMode
		want     error
	}{
		{"a directory others may write above the file's", 0o777, 0o755, 0o644, files.ErrMode},
		{"a directory only others may write above the file's", 0o703, 0o755, 0o644, files.ErrMode},
		{"a sticky directory others may write above the file's", fs.ModeSticky | 0o777, 0o755, 0o644, nil},
		{"a directory the group may write above the file's", 0o775, 0o755, 0o644, files.ErrMode},
		{"a group-writable file in a group-writable tree", 0o775, 0o775, 0o664, files.ErrMode},
	} {
		t.Run(c.name, func(t *testing.T) {
			upper := filepath.Join(t.TempDir(), "upper")
			conf := mkdirMode(t, filepath.Join(upper, "conf"), c.conf)
			path := fileAt(t, filepath.Join(conf, "gateway.yaml"), c.fileMode)
			mkdirMode(t, upper, c.upper)
			if c.want == nil {
				loads(t, path)
				return
			}
			_, err := Load(path, nil)
			refusedFor(t, err, c.want, path)
		})
	}
}

// TestARelativePathIsJudgedFromTheRoot: the working directory and every
// directory above it decide what a relative path names, so they are judged
// as an absolute path's would be.
func TestARelativePathIsJudgedFromTheRoot(t *testing.T) {
	upper := filepath.Join(t.TempDir(), "upper")
	conf := mkdirMode(t, filepath.Join(upper, "conf"), 0o755)
	fileAt(t, filepath.Join(conf, "gateway.yaml"), 0o644)
	t.Chdir(upper)
	loads(t, filepath.Join("conf", "gateway.yaml"))
	mkdirMode(t, upper, 0o777)
	_, err := Load(filepath.Join("conf", "gateway.yaml"), nil)
	refusedFor(t, err, files.ErrMode, filepath.Join("conf", "gateway.yaml"))
}

// TestALinkIsJudgedWhereItLies: whoever may write the directory holding a
// link may point it anywhere, so the directories a link lies in are judged
// as well as those of the file it reaches, and so are the directories its
// target names on the way.
func TestALinkIsJudgedWhereItLies(t *testing.T) {
	good := placed(t, 0o755, 0o644)
	t.Run("a link in a directory others may write", func(t *testing.T) {
		open := mkdirMode(t, filepath.Join(t.TempDir(), "open"), 0o777)
		link := symlink(t, good, filepath.Join(open, "gateway.yaml"))
		_, err := Load(link, nil)
		refusedFor(t, err, files.ErrMode, link)
	})
	t.Run("a directory link in a directory others may write", func(t *testing.T) {
		open := mkdirMode(t, filepath.Join(t.TempDir(), "open"), 0o777)
		symlink(t, filepath.Dir(good), filepath.Join(open, "conf"))
		path := filepath.Join(open, "conf", "gateway.yaml")
		_, err := Load(path, nil)
		refusedFor(t, err, files.ErrMode, path)
	})
	t.Run("a link whose target passes a directory others may write", func(t *testing.T) {
		base := t.TempDir()
		conf := mkdirMode(t, filepath.Join(base, "open", "conf"), 0o755)
		fileAt(t, filepath.Join(conf, "gateway.yaml"), 0o644)
		mkdirMode(t, filepath.Join(base, "open"), 0o777)
		link := symlink(t, filepath.Join("open", "conf", "gateway.yaml"), filepath.Join(base, "gateway.yaml"))
		_, err := Load(link, nil)
		refusedFor(t, err, files.ErrMode, link)
	})
	t.Run("a link in a sticky directory", func(t *testing.T) {
		sticky := mkdirMode(t, filepath.Join(t.TempDir(), "sticky"), fs.ModeSticky|0o777)
		loads(t, symlink(t, good, filepath.Join(sticky, "gateway.yaml")))
	})
}

// TestALinksParentIsTheDirectoryItReached: ".." in a link's target names the
// parent of the directory the walk reached, and a name below a file is
// refused, as the kernel refuses it, rather than read past.
func TestALinksParentIsTheDirectoryItReached(t *testing.T) {
	good := placed(t, 0o755, 0o644)
	links := mkdirMode(t, filepath.Join(filepath.Dir(filepath.Dir(good)), "links"), 0o755)
	loads(t, symlink(t, filepath.Join("..", "conf", "gateway.yaml"), filepath.Join(links, "gateway.yaml")))
	past := symlink(t, "../conf/gateway.yaml/../gateway.yaml", filepath.Join(links, "past.yaml"))
	_, err := Load(past, nil)
	refusedFor(t, err, files.ErrNotDirectory, past)
}

// TestAnEntryAnotherAccountOwnsIsRefused: another account may repoint a link
// it owns, and replace what a directory it owns holds, whatever the modes
// say, and a sticky directory lets the owner of an entry replace it. The
// seam names an account other than this one; the same layout read with every
// entry this account's is shown to load.
func TestAnEntryAnotherAccountOwnsIsRefused(t *testing.T) {
	other := os.Geteuid() + 1
	links := func(info fs.FileInfo, uid int) int {
		if info.Mode()&fs.ModeSymlink != 0 {
			return other
		}
		return uid
	}
	upper := func(info fs.FileInfo, uid int) int {
		if info.IsDir() && info.Name() == "upper" {
			return other
		}
		return uid
	}
	for _, c := range []struct {
		name  string
		path  func(t *testing.T) string
		owner func(fs.FileInfo, int) int
	}{
		{"a link", func(t *testing.T) string {
			return symlink(t, placed(t, 0o755, 0o644), filepath.Join(t.TempDir(), "gateway.yaml"))
		}, links},
		{"a link in a sticky directory", func(t *testing.T) string {
			sticky := mkdirMode(t, filepath.Join(t.TempDir(), "sticky"), fs.ModeSticky|0o777)
			return symlink(t, placed(t, 0o755, 0o644), filepath.Join(sticky, "gateway.yaml"))
		}, links},
		{"a directory above the file's", func(t *testing.T) string {
			conf := mkdirMode(t, filepath.Join(t.TempDir(), "upper", "conf"), 0o755)
			return fileAt(t, filepath.Join(conf, "gateway.yaml"), 0o644)
		}, upper},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := c.path(t)
			loads(t, path)
			ownedAs(t, c.owner)
			_, err := Load(path, nil)
			refusedFor(t, err, files.ErrOwner, path)
		})
	}
}

// TestAFileWithASecondNameIsRefused: a second name may lie in a directory
// others may write, where whoever may write it reaches the file through it,
// and the file's mode and owner say nothing about where its names lie.
func TestAFileWithASecondNameIsRefused(t *testing.T) {
	t.Run("in its own directory", func(t *testing.T) {
		path := placed(t, 0o755, 0o644)
		loads(t, path)
		if err := os.Link(path, filepath.Join(filepath.Dir(path), "copy.yaml")); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path, nil)
		refusedFor(t, err, errSecondName, path)
	})
	t.Run("read through a name in a sticky directory", func(t *testing.T) {
		sticky := mkdirMode(t, filepath.Join(t.TempDir(), "sticky"), fs.ModeSticky|0o777)
		path := filepath.Join(sticky, "gateway.yaml")
		if err := os.Link(placed(t, 0o755, 0o644), path); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path, nil)
		refusedFor(t, err, errSecondName, path)
	})
	t.Run("a second name for root's file in a sticky directory", func(t *testing.T) {
		source := rootFile(t)
		sticky := mkdirMode(t, filepath.Join(t.TempDir(), "sticky"), fs.ModeSticky|0o777)
		path := filepath.Join(sticky, "gateway.yaml")
		if err := os.Link(source, path); err != nil {
			t.Skipf("this system refuses a second name for root's file: %v", err)
		}
		_, _, err := readConfigFile(path, path)
		refusedFor(t, err, errSecondName, path)
	})
}

// TestTheLinksAPathPassesAreBounded: a loop of links is refused, not
// followed, and so is a chain one link longer than the bound; a chain at the
// bound is read. The chain lies under a path with no link in it, so it is the
// only link the walk passes.
func TestTheLinksAPathPassesAreBounded(t *testing.T) {
	chain := func(t *testing.T, n int) string {
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		conf := mkdirMode(t, filepath.Join(base, "conf"), 0o755)
		target := filepath.Base(conf) + "/" + filepath.Base(fileAt(t, filepath.Join(conf, "gateway.yaml"), 0o644))
		for i := range n {
			target = filepath.Base(symlink(t, target, filepath.Join(base, fmt.Sprintf("link%02d", i))))
		}
		return filepath.Join(base, target)
	}
	loads(t, chain(t, 40))
	long := chain(t, 41)
	_, err := Load(long, nil)
	refusedFor(t, err, errTooManyLinks, long)

	base := t.TempDir()
	symlink(t, "b", filepath.Join(base, "a"))
	loop := symlink(t, "a", filepath.Join(base, "b"))
	_, err = Load(loop, nil)
	refusedFor(t, err, errTooManyLinks, loop)
}

// configMap lays a mounted ConfigMap's file out under a fresh directory: the
// mount holds a link to a link to a timestamped directory that holds the
// file. The kubelet gives the mount mode 0777 and mounts it read-only.
func configMap(t *testing.T, mountMode fs.FileMode) (mount, path string) {
	t.Helper()
	mount = filepath.Join(t.TempDir(), "mount")
	stamped := mkdirMode(t, filepath.Join(mount, "..2026_10_06_12_00_00.000000001"), 0o755)
	fileAt(t, filepath.Join(stamped, "gateway.yaml"), 0o644)
	symlink(t, filepath.Base(stamped), filepath.Join(mount, "..data"))
	path = symlink(t, filepath.Join("..data", "gateway.yaml"), filepath.Join(mount, "gateway.yaml"))
	mkdirMode(t, mount, mountMode)
	return mount, path
}

// TestAConfigMapUnderRootIsRead: every entry of a cluster's ConfigMap, from
// the root of the file system down, is root's. The seam reads every entry as
// root's. The mount's mode lets others write it, which the read-only mount
// overrules; on a mount others may write, the same tree is refused.
func TestAConfigMapUnderRootIsRead(t *testing.T) {
	ownedAs(t, func(fs.FileInfo, int) int { return 0 })
	t.Run("a mount of mode 0755", func(t *testing.T) {
		_, path := configMap(t, 0o755)
		loads(t, path)
	})
	t.Run("a read-only mount of mode 0777", func(t *testing.T) {
		mount, path := configMap(t, 0o777)
		readOnlyAt(t, mount)
		loads(t, path)
	})
	t.Run("a writable mount of mode 0777", func(t *testing.T) {
		_, path := configMap(t, 0o777)
		_, err := Load(path, nil)
		refusedFor(t, err, files.ErrMode, path)
	})
	t.Run("a read-only mount above a directory others may write", func(t *testing.T) {
		mount, path := configMap(t, 0o777)
		readOnlyAt(t, filepath.Dir(mount))
		_, err := Load(path, nil)
		refusedFor(t, err, files.ErrMode, path)
	})
}

// TestTheFilesDirectoryOnAReadOnlyMountIsTaken: a directory of root's that
// no account may write through its mount, since the mount is read-only, is
// taken whatever its mode says. One of another account's is not: that account
// may write it through another mount.
func TestTheFilesDirectoryOnAReadOnlyMountIsTaken(t *testing.T) {
	path := placed(t, 0o777, 0o644)
	conf, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	readOnlyAt(t, filepath.Dir(path))
	_, err = Load(path, nil)
	refusedFor(t, err, files.ErrMode, path)
	ownedAs(t, func(info fs.FileInfo, uid int) int {
		if os.SameFile(info, conf) {
			return 0
		}
		return uid
	})
	loads(t, path)
}

// readOnlyMounts names the mount points the system lists as read-only, read
// from a source other than the check under test.
func readOnlyMounts(t *testing.T) []string {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		raw, err := os.ReadFile("/proc/self/mounts")
		if err != nil {
			t.Skipf("no mount table to read: %v", err)
		}
		return linuxReadOnly(string(raw))
	case "darwin":
		out, err := exec.Command("/sbin/mount").Output()
		if err != nil {
			t.Skipf("no mount table to read: %v", err)
		}
		return darwinReadOnly(string(out))
	}
	t.Skipf("no mount table read on %s", runtime.GOOS)
	return nil
}

// linuxReadOnly names the mount points /proc/self/mounts lists with the ro
// option, leaving out a point whose name the table escapes.
func linuxReadOnly(table string) []string {
	var points []string
	for line := range strings.Lines(table) {
		f := strings.Fields(line)
		if len(f) >= 4 && strings.HasPrefix(f[3]+",", "ro,") && !strings.Contains(f[1], `\`) {
			points = append(points, f[1])
		}
	}
	return points
}

// darwinReadOnly names the mount points mount(8) lists as read-only.
func darwinReadOnly(table string) []string {
	var points []string
	for line := range strings.Lines(table) {
		_, rest, ok := strings.Cut(line, " on ")
		if !ok {
			continue
		}
		point, opts, ok := strings.Cut(rest, " (")
		if ok && strings.Contains(opts, "read-only") {
			points = append(points, point)
		}
	}
	return points
}

// TestAReadOnlyMountIsSeen reads the mount flags of a directory the test
// wrote, which is on a writable mount, and of each read-only mount the system
// lists that the test can open.
func TestAReadOnlyMountIsSeen(t *testing.T) {
	d, err := files.OpenDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ro, err := readOnlyMount(d)
	_ = d.Close()
	if err != nil || ro {
		t.Fatalf("readOnlyMount(a directory the test wrote) = %v, %v; want false", ro, err)
	}
	seen := 0
	for _, point := range readOnlyMounts(t) {
		d, err := files.OpenDir(point)
		if err != nil {
			continue
		}
		ro, err := readOnlyMount(d)
		_ = d.Close()
		if err != nil || !ro {
			t.Errorf("readOnlyMount(%s), listed read-only = %v, %v; want true", point, ro, err)
		}
		seen++
	}
	if seen == 0 {
		t.Skip("no read-only mount to open")
	}
}

// rootFile names a file root owns and may alone write, with one name, in a
// directory root owns, as a read-only mount presents the configuration.
func rootFile(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("as root, root's file is the plane's own; the case needs another account")
	}
	for _, p := range []string{"/etc/shells", "/etc/protocols", "/etc/hosts", "/etc/group"} {
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		info, err := os.Lstat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigBytes || !rootsAlone(info) || !singleName(info) {
			continue
		}
		if dir, err := os.Stat(filepath.Dir(resolved)); err == nil && rootsAlone(dir) {
			return p
		}
	}
	t.Skip("no file of root's with one name to read")
	return ""
}

// rootsAlone reports whether root owns info's file and nobody else may write
// it.
func rootsAlone(info fs.FileInfo) bool {
	uid, ok := statOwner(info)
	return ok && uid == 0 && info.Mode().Perm()&0o022 == 0
}

// TestTheRootDirectoryIsJudged: the walk starts at the root of the file
// system, which is judged as every directory below it.
func TestTheRootDirectoryIsJudged(t *testing.T) {
	path := placed(t, 0o755, 0o644)
	other := os.Geteuid() + 1
	ownedAs(t, func(info fs.FileInfo, uid int) int {
		if info.Name() == string(filepath.Separator) {
			return other
		}
		return uid
	})
	_, err := Load(path, nil)
	refusedFor(t, err, files.ErrOwner, path)
}

// TestAMountWhoseFlagsCannotBeReadIsRefused: a directory others may write is
// taken only where its mount is shown read-only; a mount that cannot answer
// has not shown it, whatever else the answer says.
func TestAMountWhoseFlagsCannotBeReadIsRefused(t *testing.T) {
	onReadOnlyMount = func(*os.File) (bool, error) { return true, errors.New("no flags to read") }
	t.Cleanup(func() { onReadOnlyMount = readOnlyMount })
	upper := filepath.Join(t.TempDir(), "upper")
	conf := mkdirMode(t, filepath.Join(upper, "conf"), 0o755)
	above := fileAt(t, filepath.Join(conf, "gateway.yaml"), 0o644)
	mkdirMode(t, upper, 0o777)
	for _, path := range []string{above, placed(t, 0o777, 0o644)} {
		_, err := Load(path, nil)
		refusedFor(t, err, files.ErrMode, path)
	}
}

// TestADirectorySwappedOnTheWalkIsRefused: a directory others may write is
// opened to read its mount, and the directory opened has to be the one looked
// up, though both stand on a read-only mount.
func TestADirectorySwappedOnTheWalkIsRefused(t *testing.T) {
	base := t.TempDir()
	upper := filepath.Join(base, "upper")
	conf := mkdirMode(t, filepath.Join(upper, "conf"), 0o755)
	path := fileAt(t, filepath.Join(conf, "gateway.yaml"), 0o644)
	mkdirMode(t, upper, 0o777)
	planted := filepath.Join(base, "planted")
	mkdirMode(t, filepath.Join(planted, "conf"), 0o755)
	fileAt(t, filepath.Join(planted, "conf", "gateway.yaml"), 0o644)
	mkdirMode(t, planted, 0o777)
	readOnlyAt(t, upper, planted)
	ownedAs(t, func(info fs.FileInfo, uid int) int {
		if info.Name() == "upper" || info.Name() == "planted" {
			return 0
		}
		return uid
	})
	loads(t, path)
	atStep(t, stepDirLooked,
		func() error { return os.Rename(upper, upper+".judged") },
		func() error { return os.Rename(planted, upper) })
	_, err := Load(path, nil)
	if err == nil || !strings.Contains(err.Error(), "changed while it was read") {
		t.Errorf("Load after a directory on the path was swapped = %v, want a refusal of a changed directory", err)
	}
}

// TestTheFilesDirectorySwappedAfterTheWalkIsRefused: the file's directory is
// judged again on the descriptor the read goes through, so a directory others
// may write, or another account owns, put at its name once the walk passed,
// is refused.
func TestTheFilesDirectorySwappedAfterTheWalkIsRefused(t *testing.T) {
	for _, c := range []struct {
		name    string
		mode    fs.FileMode
		another bool
		want    error
	}{
		{"one others may write", 0o777, false, files.ErrMode},
		{"one another account owns", 0o755, true, files.ErrOwner},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := placed(t, 0o755, 0o644)
			conf := filepath.Dir(path)
			planted := filepath.Dir(placed(t, c.mode, 0o644))
			if c.another {
				plantedInfo, err := os.Stat(planted)
				if err != nil {
					t.Fatal(err)
				}
				other := os.Geteuid() + 1
				ownedAs(t, func(info fs.FileInfo, uid int) int {
					if os.SameFile(info, plantedInfo) {
						return other
					}
					return uid
				})
			}
			atStep(t, stepWalked,
				func() error { return os.Rename(conf, conf+".judged") },
				func() error { return os.Rename(planted, conf) })
			_, err := Load(path, nil)
			refusedFor(t, err, c.want, path)
		})
	}
}

// TestARootOwnedFileIsRead reads a file root owns through the loader's own
// judge, as a read-only mount presents one, where the system has one to read.
func TestARootOwnedFileIsRead(t *testing.T) {
	p := rootFile(t)
	if _, _, err := readConfigFile(p, p); err != nil && !errors.Is(err, files.ErrTooLarge) {
		t.Errorf("readConfigFile(%s), root's: %v", p, err)
	}
}

// TestThePathIsCleanedThenWalked: ".." after a link names the link's own
// directory, as File and the start check that judges it do, not the parent
// of what the link reached, where the kernel would go; a "." or an empty name
// below a file a link names is refused as the kernel refuses it. The kernel's
// own answer is read beside the loader's.
func TestThePathIsCleanedThenWalked(t *testing.T) {
	base := t.TempDir()
	target := mkdirMode(t, filepath.Join(base, "real"), 0o755)
	mkdirMode(t, filepath.Join(target, "sub"), 0o755)
	good := fileAt(t, filepath.Join(target, "gateway.yaml"), 0o644)
	d := mkdirMode(t, filepath.Join(base, "d"), 0o755)
	named := fileAt(t, filepath.Join(d, "gateway.yaml"), 0o666)
	symlink(t, filepath.Join("..", "real", "sub"), filepath.Join(d, "lnk"))
	through := filepath.Join(d, "lnk") + string(filepath.Separator) + ".." + string(filepath.Separator) + "gateway.yaml"
	if kernel, err := os.Stat(through); err != nil || !sameAs(t, kernel, good) {
		t.Fatalf("the kernel reads %s as %v, %v; want %s", through, kernel, err, good)
	}
	_, err := Load(through, nil)
	refusedFor(t, err, files.ErrMode, through)
	if err := os.Chmod(named, 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := Load(through, nil); err != nil || cfg.File() != named {
		t.Errorf("Load(%s) = %v; want %s read", through, err, named)
	}
	for _, target := range []string{good + string(filepath.Separator) + ".", good + string(filepath.Separator)} {
		link := symlink(t, target, filepath.Join(t.TempDir(), "gateway.yaml"))
		if _, err := os.Stat(link); err == nil {
			t.Fatalf("the kernel reads %s through %q", link, target)
		}
		_, err := Load(link, nil)
		refusedFor(t, err, files.ErrNotDirectory, link)
	}
}

func sameAs(t *testing.T, info fs.FileInfo, path string) bool {
	t.Helper()
	other, err := os.Stat(path)
	return err == nil && os.SameFile(info, other)
}
