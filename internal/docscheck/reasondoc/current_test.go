package reasondoc

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

const (
	docPath          = "docs/reference/reason-codes.md"
	generatorCommand = "make docs-gen"
)

// The pin between the table and the page. The renderer is called directly, not
// through `go run`: a subprocess resolves its program through $PATH, so a shim
// named go that printed the committed page would have made this test pass while
// nothing rendered.
func TestReasonCodesDocIsCurrent(t *testing.T) {
	got, err := Page()
	if err != nil {
		t.Fatalf("rendering the page: %v", err)
	}

	// Read through a filesystem rooted at the repository, as
	// internal/docscheck does: the page is named by a constant that cannot
	// send this test reading outside the tree, and gosec does not have to take
	// that on trust.
	want, err := fs.ReadFile(os.DirFS(repoRoot(t)), docPath)
	if err != nil {
		t.Fatalf("reading %s: %v", docPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is not what the renderer produces; rebuild it with `%s`\n%s",
			docPath, generatorCommand, firstDifference(got, want))
	}
}

// firstDifference names the first line that differs, so a failure reads as one
// line rather than as two whole pages.
func firstDifference(got, want []byte) string {
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")
	for i := range max(len(gotLines), len(wantLines)) {
		gotLine, wantLine := line(gotLines, i), line(wantLines, i)
		if gotLine != wantLine {
			// Quoted, because the difference is sometimes a trailing space or
			// a carriage return, and two lines that print identically read as
			// a broken test rather than a stale page.
			return fmt.Sprintf("first difference at line %d\nrendered:  %q\ncommitted: %q",
				i+1, gotLine, wantLine)
		}
	}
	return "the pages differ in trailing bytes only"
}

func line(lines []string, i int) string {
	if i >= len(lines) {
		return "<end of file>"
	}
	return lines[i]
}

// repoRoot walks up from this file's compiled-in path, not from the working
// directory a caller can change, and refuses a directory that holds no go.mod:
// reading the page from somewhere else would compare this registry against
// another tree's document. Under `go test -trimpath` the path resolves to
// nothing and the test fails loudly.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this file's own path; refusing to fall back on the working directory")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(self))))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %q holds no go.mod: %v", root, err)
	}
	return root
}
