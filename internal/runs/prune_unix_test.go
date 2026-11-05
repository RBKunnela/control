//go:build unix

package runs_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// pruneRig is a runs directory with an expired tree, a root and its child
// expiring an hour after opened, and a live root expiring three hours after.
type pruneRig struct {
	dir                string
	admin              *runs.Admin
	root, child, alive runs.Record
}

func newPruneRig(t *testing.T) pruneRig {
	t.Helper()
	dir, a, _ := setup(t)
	root, _ := openRoot(t, a)
	child, _ := openUnder(t, a, root.ID, alice)
	alive, _, err := a.Open(t.Context(), runs.OpenRequest{Who: alice, TTL: 3 * time.Hour, Now: opened})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return pruneRig{dir: dir, admin: a, root: root, child: child, alive: alive}
}

// treeNames is every file the expired tree holds in the runs directory.
func (r pruneRig) treeNames() []string {
	return []string{r.root.ID + ".run.json", r.root.ID + ".state.json", r.root.ID + ".lock", r.child.ID + ".run.json"}
}

func (r pruneRig) prune(t *testing.T, cutoff time.Time, archive string) (runs.Pruned, error) {
	t.Helper()
	return r.admin.Prune(t.Context(), runs.PruneRequest{ExpiredBefore: cutoff, Archive: archive, Now: cutoff})
}

// namesIn is every name in dir, sorted.
func namesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func expectPresent(t *testing.T, dir string, names []string) {
	t.Helper()
	for _, name := range names {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v, want it in place", name, err)
		}
	}
}

func readAll(t *testing.T, dir string, names []string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: a file under the test's temp dir
		if err != nil {
			t.Fatal(err)
		}
		out[name] = raw
	}
	return out
}

// TestPruneArchivesAnExpiredTreeAndThenRemovesIt: the tree whose runs all
// expired before the cutoff is copied byte for byte into a new directory of
// its owner's alone, which reads as a runs directory, and then removed; the
// live tree is left as it was and is not named.
func TestPruneArchivesAnExpiredTreeAndThenRemovesIt(t *testing.T) {
	r := newPruneRig(t)
	kept := []string{r.root.ID + ".run.json", r.root.ID + ".state.json", r.child.ID + ".run.json", "runs.meta"}
	before := readAll(t, r.dir, kept)
	archive := filepath.Join(t.TempDir(), "archive")
	got, err := r.prune(t, opened.Add(2*time.Hour), archive)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if !slices.Equal(got.Trees, []string{r.root.ID}) || got.Runs != 2 || len(got.Refused) != 0 {
		t.Errorf("Prune = %+v, want the expired tree of 2 runs alone", got)
	}
	if after := readAll(t, archive, kept); !mapsEqual(after, before) {
		t.Errorf("the archive holds %v, want the tree's files as they were", namesIn(t, archive))
	}
	for _, name := range r.treeNames() {
		if _, err := os.Lstat(filepath.Join(r.dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s after the prune: %v, want it gone", name, err)
		}
	}
	expectPresent(t, r.dir, []string{r.alive.ID + ".run.json", r.alive.ID + ".state.json", r.alive.ID + ".lock"})
	expectArchiveMode(t, archive)
	a, err := runs.OpenAdmin(t.Context(), archive)
	if err != nil {
		t.Fatalf("the archive does not open as a runs directory: %v", err)
	}
	defer func() { _ = a.Close() }()
	if l, err := a.List(t.Context(), 10); err != nil || len(l.Records) != 2 {
		t.Errorf("the archive lists %+v, %v; want the two runs", l, err)
	}
}

func expectArchiveMode(t *testing.T, archive string) {
	t.Helper()
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatalf("the archive: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("the archive has mode %v, want 0700", info.Mode().Perm())
	}
}

func mapsEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if string(b[k]) != string(v) {
			return false
		}
	}
	return true
}

// TestPruneCutsOffBeforeTheCutoffAndNoLaterThanNow: a run expiring at the
// cutoff has not expired before it, so the tree is not reached; a nanosecond
// later it goes. A cutoff after the clock reading is refused, since a run
// expiring before it may be serving now.
func TestPruneCutsOffBeforeTheCutoffAndNoLaterThanNow(t *testing.T) {
	r := newPruneRig(t)
	at := r.root.ExpiresAt
	if got, err := r.prune(t, at, filepath.Join(t.TempDir(), "a")); err != nil || len(got.Trees) != 0 || len(got.Refused) != 0 {
		t.Errorf("a cutoff at the expiry = %+v, %v; want nothing reached", got, err)
	}
	future := runs.PruneRequest{ExpiredBefore: at.Add(2 * time.Nanosecond), Archive: filepath.Join(t.TempDir(), "b"), Now: at.Add(time.Nanosecond)}
	if _, err := r.admin.Prune(t.Context(), future); !errors.Is(err, runs.ErrPruneTime) {
		t.Errorf("a cutoff after now: %v, want ErrPruneTime", err)
	}
	if got, err := r.prune(t, at.Add(time.Nanosecond), filepath.Join(t.TempDir(), "c")); err != nil || !slices.Equal(got.Trees, []string{r.root.ID}) {
		t.Errorf("a cutoff a nanosecond past the expiry = %+v, %v; want the tree", got, err)
	}
}

// TestPruneRefusesATreeWithALiveRun: a child rewritten to outlive the cutoff
// keeps its whole tree in place, named with the cause, and nothing of it
// reaches the archive.
func TestPruneRefusesATreeWithALiveRun(t *testing.T) {
	r := newPruneRig(t)
	rewrite(t, r.dir, r.child.ID+".run.json", func(m map[string]json.RawMessage) {
		m["expires_at"] = json.RawMessage(`"2026-03-01T15:00:00Z"`)
	})
	archive := filepath.Join(t.TempDir(), "archive")
	got, err := r.prune(t, opened.Add(2*time.Hour), archive)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(got.Trees) != 0 || len(got.Refused) != 1 || got.Refused[0].Root != r.root.ID || !errors.Is(got.Refused[0].Err, runs.ErrTreeLive) {
		t.Errorf("Prune = %+v, want the tree refused as live", got)
	}
	expectPresent(t, r.dir, r.treeNames())
	if names := namesIn(t, archive); !slices.Equal(names, []string{"runs.meta"}) {
		t.Errorf("the archive holds %v, want the marker alone", names)
	}
}

// TestPruneRefusesAnArchiveItCannotOwn: a directory that exists, and one in
// the runs directory, are refused before anything is removed.
func TestPruneRefusesAnArchiveItCannotOwn(t *testing.T) {
	r := newPruneRig(t)
	exists := t.TempDir()
	if _, err := r.prune(t, opened.Add(2*time.Hour), exists); !errors.Is(err, runs.ErrArchive) {
		t.Errorf("an archive that exists: %v, want ErrArchive", err)
	}
	inside := filepath.Join(r.dir, "archive")
	if _, err := r.prune(t, opened.Add(2*time.Hour), inside); !errors.Is(err, runs.ErrArchive) {
		t.Errorf("an archive in the runs directory: %v, want ErrArchive", err)
	}
	if _, err := os.Lstat(inside); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused archive was made in the runs directory: %v", err)
	}
	expectPresent(t, r.dir, r.treeNames())
	if names := namesIn(t, exists); len(names) != 0 {
		t.Errorf("a refused prune wrote %v into a directory that existed", names)
	}
}

// TestAPruneStoppedAfterTheArchiveLeavesTheTree: stopped once the copy is on
// disk, the tree stands whole beside its copy; a second prune into a new
// archive then removes it.
func TestAPruneStoppedAfterTheArchiveLeavesTheTree(t *testing.T) {
	r := newPruneRig(t)
	killed := errors.New("killed")
	first := filepath.Join(t.TempDir(), "first")
	req := runs.PruneRequest{ExpiredBefore: opened.Add(2 * time.Hour), Archive: first, Now: opened.Add(2 * time.Hour)}
	if _, err := r.admin.PruneStoppedAfterArchive(t.Context(), req, func() error { return killed }); !errors.Is(err, killed) {
		t.Fatalf("a stopped prune: %v, want the stop", err)
	}
	expectPresent(t, r.dir, r.treeNames())
	expectPresent(t, first, []string{r.root.ID + ".run.json", r.root.ID + ".state.json", r.child.ID + ".run.json"})
	if got, err := r.prune(t, opened.Add(2*time.Hour), filepath.Join(t.TempDir(), "second")); err != nil || got.Runs != 2 {
		t.Errorf("the second prune = %+v, %v; want the tree's 2 runs", got, err)
	}
}

// TestPruneRefusesATreeWhoseStateAPlaneHolds: the root's state lock held by
// another file keeps the tree; released, the same prune takes it.
func TestPruneRefusesATreeWhoseStateAPlaneHolds(t *testing.T) {
	r := newPruneRig(t)
	lock, err := os.OpenFile(filepath.Join(r.dir, r.root.ID+".lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	got, err := r.prune(t, opened.Add(2*time.Hour), filepath.Join(t.TempDir(), "held"))
	if err != nil || len(got.Refused) != 1 || !errors.Is(got.Refused[0].Err, runs.ErrTreeLocked) {
		t.Errorf("a prune of a held tree = %+v, %v; want it refused as locked", got, err)
	}
	expectPresent(t, r.dir, r.treeNames())
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if got, err := r.prune(t, opened.Add(2*time.Hour), filepath.Join(t.TempDir(), "free")); err != nil || got.Runs != 2 {
		t.Errorf("the control, once released = %+v, %v", got, err)
	}
}

// TestPruneRefusesATreeItCannotReadWhole: a state that does not decode keeps
// its tree, and a record that does not decode refuses the whole prune before
// any archive is made.
func TestPruneRefusesATreeItCannotReadWhole(t *testing.T) {
	r := newPruneRig(t)
	writeFile(t, filepath.Join(r.dir, r.root.ID+".state.json"), []byte("{"))
	got, err := r.prune(t, opened.Add(2*time.Hour), filepath.Join(t.TempDir(), "state"))
	if err != nil || len(got.Refused) != 1 || got.Refused[0].Root != r.root.ID {
		t.Errorf("a prune of a tree with a spoiled state = %+v, %v; want it refused", got, err)
	}
	expectPresent(t, r.dir, r.treeNames())
	writeFile(t, filepath.Join(r.dir, r.child.ID+".run.json"), []byte("{"))
	archive := filepath.Join(t.TempDir(), "record")
	if _, err := r.prune(t, opened.Add(2*time.Hour), archive); err == nil {
		t.Errorf("a prune over a spoiled record ran")
	}
	if _, err := os.Lstat(archive); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a prune refused over a spoiled record made its archive: %v", err)
	}
	expectPresent(t, r.dir, r.treeNames())
}

// TestPruneLeavesALiveRootWithAnExpiredChild: a root that lives past the
// cutoff keeps its tree whole and unnamed, though a child under it expired:
// the tree is in use, which is no refusal.
func TestPruneLeavesALiveRootWithAnExpiredChild(t *testing.T) {
	_, a, _ := setup(t)
	root, _, err := a.Open(t.Context(), runs.OpenRequest{Who: alice, TTL: 3 * time.Hour, Now: opened})
	if err != nil {
		t.Fatal(err)
	}
	child, _ := openUnder(t, a, root.ID, alice)
	cutoff := opened.Add(2 * time.Hour)
	if !child.ExpiresAt.Before(cutoff) || root.ExpiresAt.Before(cutoff) {
		t.Fatalf("the child expires at %s and the root at %s, so the case examines nothing", child.ExpiresAt, root.ExpiresAt)
	}
	got, err := a.Prune(t.Context(), runs.PruneRequest{ExpiredBefore: cutoff, Archive: filepath.Join(t.TempDir(), "a"), Now: cutoff})
	if err != nil || len(got.Trees) != 0 || len(got.Refused) != 0 {
		t.Errorf("Prune = %+v, %v; want nothing removed and nothing refused", got, err)
	}
}

// TestPruneRefusesATreeWhoseRootHasNoRecord: a child whose root record is
// gone is kept and named, as a broken tree.
func TestPruneRefusesATreeWhoseRootHasNoRecord(t *testing.T) {
	r := newPruneRig(t)
	if err := os.Remove(filepath.Join(r.dir, r.root.ID+".run.json")); err != nil {
		t.Fatal(err)
	}
	got, err := r.prune(t, opened.Add(2*time.Hour), filepath.Join(t.TempDir(), "archive"))
	if err != nil || len(got.Refused) != 1 || got.Refused[0].Root != r.root.ID || !errors.Is(got.Refused[0].Err, runs.ErrTreeBroken) {
		t.Errorf("a prune of a tree with no root record = %+v, %v; want it refused as broken", got, err)
	}
	expectPresent(t, r.dir, []string{r.child.ID + ".run.json", r.root.ID + ".state.json"})
}
