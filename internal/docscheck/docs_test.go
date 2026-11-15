// The documentation consistency gate: a link that stops resolving, a capability
// claim that loses its status label, a project law file that grew past what
// anyone reads. A green run over an empty set is the failure this file exists to
// prevent, so the walk also proves it examined something.
package docscheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/docscheck/impact"
)

const (
	agentsLineLimit  = 200
	minMarkdownFiles = 5
)

var (
	linkTarget     = regexp.MustCompile(`\]\(([^)]*)\)`)
	uriScheme      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)
	tableSeparator = regexp.MustCompile(`^\s*\|[\s:|-]*-[\s:|-]*\|\s*$`)
	claimPhrase    = regexp.MustCompile(`(?i)supports\s|provides\s|integrates\s+with\s`)
	statusLabel    = regexp.MustCompile("implemented|experimental|planned")
)

// repoFS resolves the repository from this file's own compiled-in path rather
// than the working directory, and refuses to guess: a root with no go.mod means
// the gate would examine some other tree and report a pass over nothing.
func repoFS(t *testing.T) fs.FS {
	t.Helper()
	return os.DirFS(repoRoot(t))
}

// repoRoot is the directory repoFS reads, for a test that runs a script there.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this file's own path; refusing to fall back on the working directory")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(self)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %q holds no go.mod: %v", root, err)
	}
	return root
}

// repoFiles is what the repository at root holds: git's list in a work tree,
// tracked and untracked files alike but none it ignores; the commit's own list
// in the export scripts/gate-commit.sh made; and a walk of any other tree with
// no .git, an export, which holds nothing else. A .git that git cannot list
// fails the test: the walk would judge local files git ignores.
func repoFiles(t *testing.T, root string) []string {
	t.Helper()
	files, err := impact.RepositoryFiles(root, os.Environ())
	if err != nil {
		t.Fatalf("listing the repository: %v", err)
	}
	slices.Sort(files.Paths)
	return files.Paths
}

// markdownFiles returns every Markdown file the repository at root holds, as a
// repository-relative slash path. A page nobody has added yet is judged; a
// file git ignores, such as local notes, is not.
func markdownFiles(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	for _, rel := range repoFiles(t, root) {
		if strings.HasSuffix(rel, ".md") {
			found = append(found, rel)
		}
	}
	return found
}

func readLines(t *testing.T, fsys fs.FS, rel string) []string {
	t.Helper()
	data, err := fs.ReadFile(fsys, rel)
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), "\n")
}

func tableCells(line string) []string {
	cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i, c := range cells {
		cells[i] = strings.TrimSpace(c)
	}
	return cells
}

// TestAgentsFileStaysShort keeps the project law file readable in one sitting.
func TestAgentsFileStaysShort(t *testing.T) {
	if n := len(readLines(t, repoFS(t), "AGENTS.md")); n > agentsLineLimit {
		t.Errorf("AGENTS.md is %d lines, limit is %d", n, agentsLineLimit)
	}
}

// TestLocalMarkdownLinksResolve reports every broken link, not just the first:
// a path that does not exist, a #fragment that names no heading of the
// Markdown file it points into, and a reference no definition names.
func TestLocalMarkdownLinksResolve(t *testing.T) {
	for _, problem := range brokenLinks(t, repoRoot(t)) {
		t.Error(problem)
	}
}

// brokenLinks is every link problem of every Markdown file the repository at
// root holds.
func brokenLinks(t *testing.T, root string) []string {
	t.Helper()
	fsys := os.DirFS(root)
	anchors := newAnchorIndex(fsys)
	var problems []string
	for _, rel := range markdownFiles(t, root) {
		problems = append(problems, markdownLinkProblems(anchors, rel, readLines(t, fsys, rel))...)
	}
	return problems
}

// TestCapabilityClaims fails a capability sentence carrying no status label, in
// every Markdown file the walk finds: a claim on a page nobody thought to list
// is still read as a claim. Fenced code and table separators are not prose and
// are skipped; a paragraph is read whole, so a claim wrapped at its verb is
// still a claim.
//
// What this does not do: it cannot tell whether a label that is present is
// true. A page that calls a planned thing `implemented` passes here, and on
// the reference pages that carry the project's honesty claim that is held by
// review, not by this gate. Widening claimPhrase would not fix it either,
// because the sentence that lies need not contain any of these verbs.
func TestCapabilityClaims(t *testing.T) {
	fsys := repoFS(t)
	for _, rel := range markdownFiles(t, repoRoot(t)) {
		for _, problem := range capabilityClaimProblems(rel, readLines(t, fsys, rel)) {
			t.Error(problem)
		}
	}
}

// TestGateExaminedSomething states the false-green case as its own test: a walk
// that found nothing must never read as documentation in order.
func TestGateExaminedSomething(t *testing.T) {
	fsys := repoFS(t)
	if n := len(markdownFiles(t, repoRoot(t))); n < minMarkdownFiles {
		t.Errorf("walk found %d Markdown files, want at least %d", n, minMarkdownFiles)
	}
	for _, rel := range []string{"README.md", "AGENTS.md", "ROADMAP.md", "docs/status.md"} {
		if _, err := fs.Stat(fsys, rel); err != nil {
			t.Errorf("required document %s is missing: %v", rel, err)
		}
	}
}
