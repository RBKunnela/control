package segmentlog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/guardana/control/internal/files"
)

const errSync Error = "the sync failed"

// TestTheParentOfTheDirectoryIsSynced: an open syncs the directory the log's
// directory is named in, so the name of one it just made survives a crash;
// a sync of the parent that fails refuses the open.
func TestTheParentOfTheDirectoryIsSynced(t *testing.T) {
	base := t.TempDir()
	var synced []string
	ops := osOps
	ops.sync = func(root *os.Root) error {
		synced = append(synced, filepath.Clean(root.Name()))
		return osOps.sync(root)
	}
	l, err := openWith(config(filepath.Join(base, "log"), 8, 64), ops)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if !slices.Contains(synced, base) {
		t.Errorf("an open making its directory synced %q, not its parent %s", synced, base)
	}
	ops.sync = func(root *os.Root) error {
		if filepath.Clean(root.Name()) == base {
			return errSync
		}
		return osOps.sync(root)
	}
	if l, err := openWith(config(filepath.Join(base, "log"), 8, 64), ops); !errors.Is(err, errSync) {
		t.Errorf("an open whose parent's sync failed = %v, want the failure", err)
		if l != nil {
			_ = l.Close()
		}
	}
}

// TestAParentTheGroupOrOthersMayWriteIsRefused: a directory to be made in a
// parent the group or others may write, and that is not sticky, is refused
// and not made.
func TestAParentTheGroupOrOthersMayWriteIsRefused(t *testing.T) {
	for _, mode := range []fs.FileMode{0o770, 0o702} {
		refusedIn(t, parentOfMode(t, mode), fmt.Sprintf("a parent of mode %v", mode))
	}
}

// TestAStickyParentTheGroupOrOthersMayWriteTakesALog: in a sticky parent
// only the owner of a name may remove or rename it, so a log is made and
// opened there however widely the parent may be written.
func TestAStickyParentTheGroupOrOthersMayWriteTakesALog(t *testing.T) {
	for _, mode := range []fs.FileMode{0o777 | fs.ModeSticky, 0o770 | fs.ModeSticky} {
		dir := filepath.Join(parentOfMode(t, mode), "log")
		l, err := Open(config(dir, 8, 64))
		if err != nil {
			t.Errorf("a parent of mode %v: %v", mode, err)
			continue
		}
		_ = l.Close()
		if _, err := os.Lstat(filepath.Join(dir, ManifestName)); err != nil {
			t.Errorf("a parent of mode %v: no manifest: %v", mode, err)
		}
	}
}

// parentOfMode is a directory of this account of mode.
func parentOfMode(t *testing.T, mode fs.FileMode) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, mode); err != nil {
		t.Fatal(err)
	}
	return parent
}

// TestARootOwnedParentIsJudgedAsThisAccounts: root may replace any name in
// any directory, so a parent root owns, as the file system's root is, is
// taken as one of this account's.
func TestARootOwnedParentIsJudgedAsThisAccounts(t *testing.T) {
	info, err := os.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	if err := files.CheckOwnedBy(info, 0); err != nil || info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("the file system's root is not root's, closed to the group's and others' writes: %v, mode %v", err, info.Mode())
	}
	saved := ownerWanted
	t.Cleanup(func() { ownerWanted = saved })
	ownerWanted = func(fs.FileInfo) int { return os.Geteuid() + 1 }
	if err := judgeParent(info, "/"); err != nil {
		t.Errorf("a parent root owns: %v", err)
	}
}

// refusedIn checks a log to be made in parent is refused, and not made.
func refusedIn(t *testing.T, parent, what string) {
	t.Helper()
	dir := filepath.Join(parent, "log")
	if l, err := Open(config(dir, 8, 64)); !errors.Is(err, ErrDirectory) {
		t.Errorf("%s: %v, want ErrDirectory", what, err)
		if l != nil {
			_ = l.Close()
		}
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s: the directory was made: %v", what, err)
	}
}

// TestAParentOfAnotherAccountIsRefused: a directory to be made in a parent
// another account owns is refused and not made; the same parent of this
// account, which the group and others may only read, takes it.
func TestAParentOfAnotherAccountIsRefused(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o755); err != nil { //nolint:gosec // G301: a parent the group and others may read
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil { //nolint:gosec // G302: a parent the group and others may read
		t.Fatal(err)
	}
	held, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	saved := ownerWanted
	t.Cleanup(func() { ownerWanted = saved })
	ownerWanted = func(info fs.FileInfo) int {
		if os.SameFile(info, held) {
			return os.Geteuid() + 1
		}
		return os.Geteuid()
	}
	refusedIn(t, parent, "a parent of another account")
	ownerWanted = saved
	l, err := Open(config(filepath.Join(parent, "log"), 8, 64))
	if err != nil {
		t.Fatalf("a parent the group and others may only read: %v", err)
	}
	_ = l.Close()
}

// TestAManifestThatIsALinkIsRefused: the manifest's bytes in the lock file
// and the manifest a link to it is no manifest a writer leaves, so the
// writer's open and a view are both refused.
func TestAManifestThatIsALinkIsRefused(t *testing.T) {
	cfg := config(logDir(t), 8, 64)
	_ = openLog(t, cfg).Close()
	body := fileText(t, filepath.Join(cfg.Dir, ManifestName))
	writeIn(t, cfg.Dir, LockName, body)
	removeIn(t, cfg.Dir, ManifestName)
	if err := os.Symlink(LockName, filepath.Join(cfg.Dir, ManifestName)); err != nil {
		t.Fatal(err)
	}
	if l, err := openSegments(cfg); !errors.Is(err, ErrManifest) {
		t.Errorf("an open over a manifest that is a link = %v, want ErrManifest", err)
		if l != nil {
			_ = l.Close()
		}
	}
	if _, err := Inspect(cfg.Dir, 1<<10); !errors.Is(err, ErrManifest) {
		t.Errorf("a view of a manifest that is a link = %v, want ErrManifest", err)
	}
}

// TestAPruneRefusesAFileReplacedSinceTheOpen: a file put at a sealed
// segment's name after the log opened, of the same length, is not unlinked
// by a prune, which is refused with the manifest left as it was.
func TestAPruneRefusesAFileReplacedSinceTheOpen(t *testing.T) {
	dir := logDir(t)
	l := threeSegments(t, dir)
	manifest := fileText(t, filepath.Join(dir, ManifestName))
	removeIn(t, dir, "segment-00000001.jsonl")
	writeIn(t, dir, "segment-00000001.jsonl", "xxx\nyyy\n")
	if err := l.Prune(1); !errors.Is(err, ErrManifest) {
		t.Errorf("a prune of a segment whose file was replaced = %v, want ErrManifest", err)
	}
	if got := fileText(t, filepath.Join(dir, "segment-00000001.jsonl")); got != "xxx\nyyy\n" {
		t.Errorf("the replacement now holds %q", got)
	}
	if got := fileText(t, filepath.Join(dir, ManifestName)); got != manifest {
		t.Errorf("the refused prune changed the manifest to %s", got)
	}
	removeIn(t, dir, "segment-00000001.jsonl")
	writeIn(t, dir, "segment-00000001.jsonl", "aaa\nbbb\n")
	if err := l.Prune(1); err != nil {
		t.Errorf("a prune once the file is back = %v", err)
	}
}

// TestAViewReadAcrossASealIsMoved: a seal that names the live segment sealed
// and renames its file between a view's read of the manifest and its open of
// the live file is no empty live segment after the sealed ones: the view is
// refused as moved, and the next one names the segment sealed.
func TestAViewReadAcrossASealIsMoved(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 8, 64))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc")
	t.Cleanup(func() { inspected = func() {} })
	inspected = func() {
		inspected = func() {}
		if err := l.Seal(); err != nil {
			t.Error(err)
		}
	}
	if v, err := Inspect(dir, 1<<10); !errors.Is(err, ErrMoved) {
		var m Manifest
		if v != nil {
			m = v.Manifest()
		}
		t.Errorf("a view across a seal = %v, naming %d sealed segment(s) and %d live line(s); want ErrMoved", err,
			len(m.Segments), m.Live.Lines)
	}
	v, err := Inspect(dir, 1<<10)
	if err != nil || len(v.Manifest().Segments) != 2 {
		t.Fatalf("the view after the seal: %v", err)
	}
}

// TestASealAndANewLiveFileBetweenTheReadsAreMoved: a seal, and the empty live
// file the next append makes, both between a view's read of the manifest and
// its open of the live file, are no empty live segment after the sealed ones
// the view names: the view is refused as moved.
func TestASealAndANewLiveFileBetweenTheReadsAreMoved(t *testing.T) {
	dir := logDir(t)
	l := openLog(t, config(dir, 8, 64))
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc")
	t.Cleanup(func() { inspected = func() {} })
	inspected = func() {
		inspected = func() {}
		if err := l.Seal(); err != nil {
			t.Error(err)
		}
		writeIn(t, dir, LiveName, "")
	}
	if v, err := Inspect(dir, 1<<10); !errors.Is(err, ErrMoved) {
		var m Manifest
		if v != nil {
			m = v.Manifest()
		}
		t.Errorf("a view across a seal and a new live file = %v, naming %d sealed segment(s) and %d live line(s); "+
			"want ErrMoved", err, len(m.Segments), m.Live.Lines)
	}
}

// TestAPruneLeavesAFilePutAtTheNameAfterItsRead: a file put at a sealed
// segment's name after the prune read the segment, while it writes the
// tombstone, is not unlinked; the log fails, and the file is left.
func TestAPruneLeavesAFilePutAtTheNameAfterItsRead(t *testing.T) {
	dir := logDir(t)
	ops := osOps
	swap := false
	ops.replace = func(root *os.Root, name string, body []byte) error {
		err := osOps.replace(root, name, body)
		if swap {
			swap = false
			removeIn(t, dir, "segment-00000001.jsonl")
			writeIn(t, dir, "segment-00000001.jsonl", "xxx\n")
		}
		return err
	}
	l, err := openWith(config(dir, 8, 64), ops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	mustAppend(t, l, "aaa", "bbb")
	mustAppend(t, l, "ccc")
	swap = true
	if err := l.Prune(1); !errors.Is(err, ErrFailed) {
		t.Errorf("a prune whose segment's name holds another file at the unlink = %v, want ErrFailed", err)
	}
	if got := fileText(t, filepath.Join(dir, "segment-00000001.jsonl")); got != "xxx\n" {
		t.Errorf("the file put at the name now holds %q", got)
	}
}

// TestADirectoryNamedThroughALinkAndDotDotIsTheOneJudged: a directory named
// P/l/../trail, l a link to W/x in a directory W the group and others may
// write, is P/trail, the one in the parent judged; nothing is made or
// written in W/trail.
func TestADirectoryNamedThroughALinkAndDotDotIsTheOneJudged(t *testing.T) {
	parent, shared := t.TempDir(), parentOfMode(t, 0o777)
	for _, name := range []string{"x", "trail"} {
		if err := os.Mkdir(filepath.Join(shared, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(shared, "x"), filepath.Join(parent, "l")); err != nil {
		t.Fatal(err)
	}
	l, err := Open(config(parent+"/l/../trail", 8, 64))
	if err != nil {
		t.Fatalf("a log named through l/..: %v", err)
	}
	_ = l.Close()
	if _, err := os.Lstat(filepath.Join(parent, "trail", ManifestName)); err != nil {
		t.Errorf("the log is not in %s/trail: %v", parent, err)
	}
	if got := dirNames(t, filepath.Join(shared, "trail")); len(got) != 0 {
		t.Errorf("the directory the link reaches holds %v", got)
	}
}

// TestADirectoryThatIsALinkIsRefused: the log's directory named by a link,
// even to a directory a log could be in, is refused, as a link may be
// changed to name another.
func TestADirectoryThatIsALinkIsRefused(t *testing.T) {
	parent := t.TempDir()
	if err := os.Mkdir(filepath.Join(parent, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(parent, "log")); err != nil {
		t.Fatal(err)
	}
	if l, err := Open(config(filepath.Join(parent, "log"), 8, 64)); !errors.Is(err, ErrDirectory) {
		t.Errorf("a log directory that is a link = %v, want ErrDirectory", err)
		if l != nil {
			_ = l.Close()
		}
	}
	if got := dirNames(t, filepath.Join(parent, "real")); len(got) != 0 {
		t.Errorf("the link's directory holds %v", got)
	}
}
