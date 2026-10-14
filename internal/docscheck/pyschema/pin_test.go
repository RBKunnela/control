package pyschema

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoFS resolves the repository from this file's own compiled-in path
// rather than the working directory, and refuses a root with no go.mod: the
// pin would read some other tree.
func repoFS(t *testing.T) fs.FS {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this file's own path; refusing to fall back on the working directory")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(self))))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %q holds no go.mod: %v", root, err)
	}
	return os.DirFS(root)
}

func firstDifference(got, want []byte) string {
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")
	for i := range max(len(gotLines), len(wantLines)) {
		g, w := "<end of file>", "<end of file>"
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g != w {
			return fmt.Sprintf("first difference at line %d\nrendered:  %q\ncommitted: %q", i+1, g, w)
		}
	}
	return "the two differ in trailing bytes only"
}

// The pin between the compiled contract and the table the Python client
// reads. The renderer is called directly, never through `go run`. A table
// that is not there fails: a client with no table reads no answer.
func TestThePythonTableIsCurrent(t *testing.T) {
	want, err := fs.ReadFile(repoFS(t), Path)
	if err != nil {
		t.Fatalf("reading %s: %v; write it with `make docs-gen`", Path, err)
	}
	got := realTable(t)
	if !bytes.Equal(got, want) {
		t.Errorf("%s is not what the generator writes; rebuild it with `make docs-gen`\n%s", Path, firstDifference(got, want))
	}
}
