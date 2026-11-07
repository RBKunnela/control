//go:build unix

package runs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The exclusive create every temporary file and every lock file goes through
// refuses a name that is there already: a file keeps its bytes, and a link,
// even one naming nothing, is not written through.
func TestTheExclusiveCreateRefusesAnExistingName(t *testing.T) {
	path, d := ownDir(t)
	existing := filepath.Join(path, "run-0.lock")
	if err := os.WriteFile(existing, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(outside, filepath.Join(path, "run-0.state.tmp")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"run-0.lock", "run-0.state.tmp"} {
		f, err := d.createNew(name)
		if err == nil {
			_ = f.Close()
		}
		if !errors.Is(err, fs.ErrExist) {
			t.Errorf("%s: %v, want fs.ErrExist", name, err)
		}
	}
	if raw, err := os.ReadFile(existing); err != nil || string(raw) != "held" { //nolint:gosec // G304: the test's own directory
		t.Errorf("the existing file now holds %q, %v", raw, err)
	}
	if _, err := os.Lstat(outside); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link's target was created: %v", err)
	}
	f, err := d.createNew("run-1.lock")
	if err != nil {
		t.Fatalf("a fresh name: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// ownDir is an empty directory only its owner may write, opened.
func ownDir(t *testing.T) (string, *dir) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runs")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := openDir(path, roleFlat, ownedByThisUser)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close() })
	return path, d
}
