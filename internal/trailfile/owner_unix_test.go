//go:build unix

package trailfile

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"
	"testing"
)

// tornTail is a cut through the opening of a line, which Open removes from a
// file it takes and leaves in one it refuses.
const tornTail = `{"eventId":"e2`

// TestOpenRefusesADirectoryAnotherAccountOwns: whoever owns the directory can
// put any file at the trail's name, so neither a new file nor an existing one
// is opened in it.
func TestOpenRefusesADirectoryAnotherAccountOwns(t *testing.T) {
	wantOwner(t, func(fs.FileInfo) int { return os.Geteuid() + 1 })
	fresh := trailPath(t)
	if w, err := Open(fresh); !errors.Is(err, ErrOwner) || w != nil {
		t.Errorf("Open of a new file = %v, %v; want ErrOwner", w, err)
	}
	if _, err := os.Lstat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused Open left a file: %v", err)
	}
	existing := trailPath(t)
	writeFile(t, existing, firstLine+tornTail)
	if w, err := Open(existing); !errors.Is(err, ErrOwner) || w != nil {
		t.Errorf("Open of an existing file = %v, %v; want ErrOwner", w, err)
	}
	if got := contents(t, existing); got != firstLine+tornTail {
		t.Errorf("the refused Open changed the file to %q", got)
	}
	ownerWanted = func(fs.FileInfo) int { return os.Geteuid() }
	openWriter(t, existing)
}

// TestOpenRefusesAFileOfAnotherAccountInItsOwnDirectory: the directory being
// this account's does not make the file in it this account's, so the file's
// own owner is judged, and the refused file is left as it was found.
func TestOpenRefusesAFileOfAnotherAccountInItsOwnDirectory(t *testing.T) {
	path := trailPath(t)
	writeFile(t, path, firstLine+tornTail)
	wantOwner(t, func(info fs.FileInfo) int {
		if info.IsDir() {
			return os.Geteuid()
		}
		return os.Geteuid() + 1
	})
	if w, err := Open(path); !errors.Is(err, ErrOwner) || w != nil {
		t.Errorf("Open = %v, %v; want ErrOwner", w, err)
	}
	if got := contents(t, path); got != firstLine+tornTail {
		t.Errorf("the refused Open changed the file to %q", got)
	}
}

// TestOpenRefusesADirectoryRootOwns: with the account check as it ships, a
// directory root owns is another account's to any other process, so a trail
// is neither opened nor made in it. The root directory's mode lets neither the
// group nor others write, so the owner is what refuses it.
func TestOpenRefusesADirectoryRootOwns(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the root directory is this process's own; the refusal needs another account")
	}
	dir := rootOwnedDir(t)
	path := filepath.Join(dir, "owner-probe.trail")
	if w, err := Open(path); !errors.Is(err, ErrOwner) || w != nil {
		t.Errorf("Open in a directory root owns = %v, %v; want ErrOwner", w, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused Open left something at %s: %v", path, err)
	}
}

// rootOwnedDir is the root directory, after checking it is root's and that
// neither the group nor others may write it.
func rootOwnedDir(t *testing.T) string {
	t.Helper()
	const dir = "/"
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("reading the root directory: %v", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode().Perm()&forbidden != 0 {
		t.Fatalf("the root directory is not root's alone (stat %T, mode %04o); this test has nothing to judge", info.Sys(), info.Mode().Perm())
	}
	return dir
}

// wantOwner makes uid name the account each file and directory Open judges
// has to belong to, until the test ends.
func wantOwner(t *testing.T, uid func(fs.FileInfo) int) {
	t.Helper()
	saved := ownerWanted
	ownerWanted = uid
	t.Cleanup(func() { ownerWanted = saved })
}

// TestOpenRefusesAFileAnotherAccountOwns: that account can write the evidence
// whatever the mode says. Giving a file away needs root.
func TestOpenRefusesAFileAnotherAccountOwns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file another owner needs root; this run is not root")
	}
	path := trailPath(t)
	writeFile(t, path, firstLine+tornTail)
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if w, err := Open(path); !errors.Is(err, ErrOwner) || w != nil {
		t.Errorf("Open = %v, %v; want ErrOwner", w, err)
	}
	if got := contents(t, path); got != firstLine+tornTail {
		t.Errorf("the refused Open changed the file to %q", got)
	}
}

// TestOpenRefusesALinkAtTheFile: a link that stays in the directory is one a
// handle on the directory would follow, so it is refused by its own entry,
// whether its target exists or not, and its target is never made or changed.
func TestOpenRefusesALinkAtTheFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	writeFile(t, target, firstLine+tornTail)
	for name, to := range map[string]string{"to a trail": "target", "to nothing": "absent"} {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
		if w, err := Open(link); !errors.Is(err, ErrNotRegular) || w != nil {
			t.Errorf("a link %s: Open = %v, %v; want ErrNotRegular", name, w, err)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	if got := contents(t, target); got != firstLine+tornTail {
		t.Errorf("the link's target changed to %q", got)
	}
	if _, err := os.Lstat(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dangling link's target was made: %v", err)
	}
}

// TestARefusedOpenKeepsNoDescriptor: an Open refused for the owner of the
// directory or of the file gives back the directory and the file it opened.
func TestARefusedOpenKeepsNoDescriptor(t *testing.T) {
	stopCollector(t)
	path := trailPath(t)
	writeFile(t, path, firstLine)
	before := openDescriptors(t)
	for _, dirsToo := range []bool{true, false} {
		wantOwner(t, func(info fs.FileInfo) int {
			if info.IsDir() && !dirsToo {
				return os.Geteuid()
			}
			return os.Geteuid() + 1
		})
		for range 16 {
			if w, err := Open(path); !errors.Is(err, ErrOwner) || w != nil {
				t.Fatalf("Open = %v, %v; want ErrOwner", w, err)
			}
		}
	}
	if after := openDescriptors(t); after != before {
		t.Errorf("%d descriptors open after the refused opens, %d before", after, before)
	}
}

// TestAnOpenedWriterKeepsOnlyItsFile: Open gives back the directory it opened
// the file through, and Close the file, so a collector reopened again and
// again does not run out of descriptors.
func TestAnOpenedWriterKeepsOnlyItsFile(t *testing.T) {
	stopCollector(t)
	path := trailPath(t)
	before := openDescriptors(t)
	for range 16 {
		w, err := Open(path)
		if err != nil {
			t.Fatalf("Open = %v", err)
		}
		if got := openDescriptors(t); got != before+1 {
			t.Errorf("%d descriptors open while a writer is, %d before it", got, before)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
	}
	if after := openDescriptors(t); after != before {
		t.Errorf("%d descriptors open after the opens and closes, %d before", after, before)
	}
}

// TestAnOpenRefusedByALinkKeepsNoDescriptor: an Open refused for the link at
// the file's name gives back the directory it opened.
func TestAnOpenRefusedByALinkKeepsNoDescriptor(t *testing.T) {
	stopCollector(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "target"), firstLine)
	link := filepath.Join(dir, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	before := openDescriptors(t)
	for range 16 {
		if w, err := Open(link); !errors.Is(err, ErrNotRegular) || w != nil {
			t.Fatalf("Open = %v, %v; want ErrNotRegular", w, err)
		}
	}
	if after := openDescriptors(t); after != before {
		t.Errorf("%d descriptors open after the refused opens, %d before", after, before)
	}
}

func openDescriptors(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatalf("listing this process's descriptors: %v", err)
	}
	return len(fds)
}

// stopCollector keeps the collector off until t ends: os.File and os.Root
// close their descriptor in a finalizer, which would hide a leak from the
// count. The setting is the process's, so a test calling it is never parallel.
func stopCollector(t *testing.T) {
	t.Helper()
	percent := debug.SetGCPercent(-1)
	limit := debug.SetMemoryLimit(math.MaxInt64)
	t.Cleanup(func() {
		debug.SetMemoryLimit(limit)
		debug.SetGCPercent(percent)
	})
}

// openHeldBeforeLock starts an Open of path, returns once it has judged the
// file and before it locks it, and gives back what lets it go on.
func openHeldBeforeLock(t *testing.T, path string) (resume func() (*Writer, error)) {
	t.Helper()
	held, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	prev := ownerWanted
	ownerWanted = func(info fs.FileInfo) int {
		if info.Mode().IsRegular() {
			stop := false
			first.Do(func() { stop = true })
			if stop {
				close(held)
				<-release
			}
		}
		return prev(info)
	}
	type opened struct {
		w   *Writer
		err error
	}
	done := make(chan opened, 1)
	go func() {
		w, err := Open(path)
		done <- opened{w, err}
	}()
	<-held
	var r opened
	var finish sync.Once
	resume = func() (*Writer, error) {
		finish.Do(func() {
			close(release)
			r = <-done
		})
		return r.w, r.err
	}
	t.Cleanup(func() {
		if w, _ := resume(); w != nil {
			_ = w.Close()
		}
		ownerWanted = prev
	})
	return resume
}

// TestOpenCutsByTheLengthItFindsUnderItsLock: a second Open takes the file
// while the first waits to lock it, cuts the torn line and appends; the first
// then keeps those lines and indexes them.
func TestOpenCutsByTheLengthItFindsUnderItsLock(t *testing.T) {
	path := trailPath(t)
	head := lines(t, event(1))
	writeFile(t, path, head+tornTail)
	resume := openHeldBeforeLock(t, path)

	b, err := Open(path)
	if err != nil {
		t.Fatalf("the second Open = %v", err)
	}
	mustAppend(t, b, event(2), event(3))
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	appended := contents(t, path)
	if len(appended) <= len(head) {
		t.Fatalf("the second Open's append left %d bytes, no more than the %d before it", len(appended), len(head))
	}

	a, err := resume()
	if err != nil {
		t.Fatalf("the first Open = %v", err)
	}
	if got := contents(t, path); got != appended {
		t.Errorf("after the first Open the file holds %d bytes, want the %d the second one appended", len(got), len(appended))
	}
	mustAppend(t, a, event(3))
	if got := contents(t, path); got != appended {
		t.Errorf("appending the second Open's last record again changed the file to %d bytes, want %d", len(got), len(appended))
	}
}

// TestOpenJudgesTheFileAgainUnderItsLock: the file is judged as it is once
// locked, not only as it was before.
func TestOpenJudgesTheFileAgainUnderItsLock(t *testing.T) {
	path := trailPath(t)
	body := lines(t, event(1)) + tornTail
	writeFile(t, path, body)
	resume := openHeldBeforeLock(t, path)
	if err := os.Chmod(path, 0o620); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	if w, err := resume(); !errors.Is(err, ErrFileMode) || w != nil {
		t.Errorf("Open = %v, %v; want ErrFileMode", w, err)
	}
	if got := contents(t, path); got != body {
		t.Errorf("the refused Open changed the file to %d bytes, want %d", len(got), len(body))
	}
}
