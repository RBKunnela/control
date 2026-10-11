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
	minComponentRows = 10 // fewer means the table was not parsed, not that it emptied
)

var (
	linkTarget     = regexp.MustCompile(`\]\(([^)]*)\)`)
	uriScheme      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)
	tableSeparator = regexp.MustCompile(`^\s*\|[\s:|-]*-[\s:|-]*\|\s*$`)
	claimPhrase    = regexp.MustCompile(`(?i)supports\s|provides\s|integrates\s+with\s`)
	statusLabel    = regexp.MustCompile("implemented|experimental|planned")
	allowedStatus  = map[string]bool{"`implemented`": true, "`experimental`": true, "`planned`": true}
	componentHead  = "Component | Status | Where"
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

// componentTable returns docs/status.md and the line indexes of the pipe rows
// under "## Components". A section that went missing or lost its rows is fatal,
// so neither test below can pass over nothing.
func componentTable(t *testing.T) ([]string, []int) {
	t.Helper()
	lines := readLines(t, repoFS(t), "docs/status.md")
	var table []int
	in := false
	for i, line := range lines {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "## ") {
			in = s == "## Components"
		} else if in && strings.HasPrefix(s, "|") {
			table = append(table, i)
		}
	}
	if len(table) < minComponentRows+2 {
		t.Fatalf(`docs/status.md: "## Components" holds %d table lines, want a header, a separator and at least %d rows`, len(table), minComponentRows)
	}
	return lines, table
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

// TestStatusComponentTableShape fails on a renamed or reordered column and a
// missing separator: each makes the label check read the wrong cell, or none.
func TestStatusComponentTableShape(t *testing.T) {
	lines, table := componentTable(t)
	if got := strings.Join(tableCells(lines[table[0]]), " | "); got != componentHead {
		t.Errorf("docs/status.md:%d: header is %q, want %q", table[0]+1, got, componentHead)
	}
	if !tableSeparator.MatchString(lines[table[1]]) {
		t.Errorf("docs/status.md:%d: want the header separator row, got %q", table[1]+1, strings.TrimSpace(lines[table[1]]))
	}
}

// TestStatusComponentTableLabels is the load-bearing check. The root documents
// no longer keep their own inventories, they all point here, so this table is
// the only place the project states what is implemented, experimental or
// planned; a row that loses its label takes the honesty claim with it.
func TestStatusComponentTableLabels(t *testing.T) {
	lines, table := componentTable(t)
	for _, i := range table[2:] {
		if cells := tableCells(lines[i]); len(cells) != 3 {
			t.Errorf("docs/status.md:%d: row has %d cells, want 3: %s", i+1, len(cells), strings.TrimSpace(lines[i]))
		} else if !allowedStatus[cells[1]] {
			t.Errorf("docs/status.md:%d: %q has status %q, want one of `implemented`, `experimental`, `planned`", i+1, cells[0], cells[1])
		}
	}
}
