package pause_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/guardana/control/internal/pause"
)

// emptyDir is a fresh directory of mode 0700 and the pause file's path in it.
func emptyDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "pause.json")
}

func entry(id string, scope pause.Scope) pause.Entry {
	return pause.Entry{ID: id, Scope: scope, CreatedAt: at(), Reason: "because"}
}

func ids(t *testing.T, path string) []string {
	t.Helper()
	doc, err := pause.List(path)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var out []string
	for _, e := range doc.Entries {
		out = append(out, e.ID)
	}
	return out
}

func TestTheWriterKeepsOneDocument(t *testing.T) {
	ctx := context.Background()
	path := emptyDir(t)
	if err := pause.Init(ctx, path); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := pause.Init(ctx, path); !errors.Is(err, pause.ErrExists) {
		t.Errorf("a second Init = %v, want ErrExists", err)
	}
	if s := pause.Read(path, at(), interval); s.State() != pause.Clear {
		t.Fatalf("after Init: %s, %q", s.State(), s.Detail())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the pause file's mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	addTwo(t, path)
	if err := pause.Remove(ctx, path, "p9"); !errors.Is(err, pause.ErrNoEntry) {
		t.Errorf("Remove of an id nothing holds = %v, want ErrNoEntry", err)
	}
	for _, id := range []string{"p2", "p1"} {
		if err := pause.Remove(ctx, path, id); err != nil {
			t.Fatalf("Remove %s: %v", id, err)
		}
	}
	// The last removal leaves a file that pauses nothing, never no file.
	if s := pause.Read(path, at(), interval); s.State() != pause.Clear {
		t.Errorf("after the last removal: %s, %q; want clear", s.State(), s.Cause())
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), "*"))
	if err != nil || len(leftovers) != 1 {
		t.Errorf("the directory holds %v, want the pause file alone", leftovers)
	}
}

// addTwo adds a tool pause and a global one, and holds the writer to its
// refusals on the way.
func addTwo(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	tool := pause.Scope{Kind: "action", Action: "tool", Provider: "orders", Name: "refund"}
	if err := pause.Add(ctx, path, entry("p1", tool)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := pause.Add(ctx, path, entry("p2", pause.Scope{Kind: "global"})); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := pause.Add(ctx, path, entry("p1", pause.Scope{Kind: "global"})); !errors.Is(err, pause.ErrDuplicateID) {
		t.Errorf("Add under a taken id = %v, want ErrDuplicateID", err)
	}
	if err := pause.Add(ctx, path, entry("p3", pause.Scope{Kind: "agent"})); !errors.Is(err, pause.ErrMalformed) {
		t.Errorf("Add of a scope the reader refuses = %v, want ErrMalformed", err)
	}
	if got := ids(t, path); fmt.Sprint(got) != "[p1 p2]" {
		t.Errorf("entries = %v, want [p1 p2]", got)
	}
	s := pause.Read(path, at(), interval)
	if s.State() != pause.Paused || !s.Covers("tool", "payments", "x", pause.Vouched{}) {
		t.Errorf("after two adds: %s, and the global entry covers nothing", s.State())
	}
}

// TestTheWriterRefusesWhatThePlaneRefuses: a file the plane would read as
// unknown is not rewritten into one it reads, and a directory others may
// write is not written in.
func TestTheWriterRefusesWhatThePlaneRefuses(t *testing.T) {
	ctx := context.Background()
	add := entry("p1", pause.Scope{Kind: "global"})
	broken := dirWith(t, `{"schema_version":"2","entries":[`, 0o600)
	if err := pause.Add(ctx, broken, add); !errors.Is(err, pause.ErrMalformed) {
		t.Errorf("Add over a malformed file = %v, want ErrMalformed", err)
	}
	if err := pause.Add(ctx, emptyDir(t), add); !errors.Is(err, pause.ErrMissing) {
		t.Errorf("Add with no file = %v, want ErrMissing", err)
	}
	wide := dirWith(t, docJSON(), 0o600)
	if err := os.Chmod(filepath.Dir(wide), 0o770); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	if err := pause.Add(ctx, wide, add); !errors.Is(err, pause.ErrDirMode) {
		t.Errorf("Add in a directory the group may write = %v, want ErrDirMode", err)
	}
	if err := pause.Init(ctx, filepath.Join(filepath.Dir(wide), "other.json")); !errors.Is(err, pause.ErrDirMode) {
		t.Errorf("Init in a directory the group may write = %v, want ErrDirMode", err)
	}
	path := emptyDir(t)
	if err := pause.Init(ctx, path); err != nil {
		t.Fatal(err)
	}
	for i := range 64 {
		if err := pause.Add(ctx, path, entry(fmt.Sprintf("e%d", i), pause.Scope{Kind: "global"})); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	if err := pause.Add(ctx, path, entry("one-too-many", pause.Scope{Kind: "global"})); !errors.Is(err, pause.ErrMalformed) {
		t.Errorf("the 65th entry = %v, want ErrMalformed", err)
	}
	link := filepath.Join(filepath.Dir(path), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := pause.Init(ctx, link); !errors.Is(err, pause.ErrExists) {
		t.Errorf("Init over a link = %v, want ErrExists", err)
	}
}

// TestWritersNeverLoseAnEntry: writers in parallel each add one entry, and
// every one of them is in the file afterwards.
func TestWritersNeverLoseAnEntry(t *testing.T) {
	ctx := context.Background()
	path := emptyDir(t)
	if err := pause.Init(ctx, path); err != nil {
		t.Fatal(err)
	}
	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Go(func() {
			errs <- pause.Add(ctx, path, entry(fmt.Sprintf("w%d", i), pause.Scope{Kind: "global"}))
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Add: %v", err)
		}
	}
	if got := ids(t, path); len(got) != writers {
		t.Errorf("the file holds %d entries after %d adds: %v", len(got), writers, got)
	}
}
