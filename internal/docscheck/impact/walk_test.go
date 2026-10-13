package impact

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const goodPage = "---\ntitle: The guide\nsummary: How to run it.\ntype: how-to\ncovers: [cmd/**]\n---\n\n# The guide\n"

func TestWalkPagesParsesEveryPageTheConfigurationAdmits(t *testing.T) {
	fsys := fstest.MapFS{
		"docs/guides/run.md":    {Data: []byte(goodPage)},
		"docs/README.md":        {Data: []byte("# no frontmatter here\n")},
		"docs/notes.txt":        {Data: []byte(goodPage)},
		"docs/notes/plan.md":    {Data: []byte("not a page\n")},
		"docs/draft.md":         {Data: []byte("not a page\n")},
		"docs/reference/bad.md": {Data: []byte("# missing frontmatter\n")},
		"docs/local/x.md":       {Data: []byte("not a page\n")},
		"docs/guides/local.md":  {Data: []byte("not a page\n")},
	}
	listed := []string{"docs/guides/run.md", "docs/README.md", "docs/notes.txt", "docs/notes/plan.md", "docs/draft.md", "docs/reference/bad.md"}
	excluded := func(rel string) bool { return rel == "docs/notes/" || rel == "docs/draft.md" }
	pages, broken, err := WalkPages(fsys, "docs", LeftOut(listed, excluded).Skips)
	if err != nil {
		t.Fatalf("WalkPages: %v", err)
	}
	if len(pages) != 1 || pages[0].Path != "docs/guides/run.md" || strings.Join(pages[0].Covers, ",") != "cmd/**" {
		t.Errorf("pages = %+v, want the guide alone with its covers", pages)
	}
	if len(broken) != 1 || broken[0].Path != "docs/reference/bad.md" || broken[0].Err == nil {
		t.Errorf("broken = %+v, want the one page without frontmatter and its reason", broken)
	}
}

func nothing(string) bool { return false }

func TestWalkPagesNamesEveryBrokenPageWhenNoneParsed(t *testing.T) {
	fsys := fstest.MapFS{
		"docs/a.md":          {Data: []byte("# a\n")},
		"docs/b.md":          {Data: []byte("---\ntitle: b\n")},
		"docs/sub/c.md":      {Data: []byte("---\nbogus: c\n---\n")},
		"docs/sub/README.md": {Data: []byte("# readme\n")},
	}
	_, _, err := WalkPages(fsys, "docs", nothing)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("WalkPages = %v, want ErrInvalid", err)
	}
	for _, want := range []string{"3 pages", "docs/a.md", "docs/b.md", "docs/sub/c.md"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestWalkPagesRefusesADirectoryWithNoPage(t *testing.T) {
	fsys := fstest.MapFS{"docs/README.md": {Data: []byte("# readme\n")}}
	_, _, err := WalkPages(fsys, "docs", nothing)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "no page") {
		t.Errorf("WalkPages = %v, want ErrInvalid saying no page", err)
	}
	if _, _, err := WalkPages(fsys, "missing", nothing); err == nil {
		t.Error("WalkPages over a directory that does not exist passed")
	}
}

// walkKept and walkDropped are the files WalkFiles keeps and leaves out;
// TestIgnoreMirrorsAgreeWithGit holds git to the same names.
func walkKept() []string {
	return []string{
		"Makefile", "cmd/gw/main.go", ".github/workflows/ci.yml", ".env.example",
		"bench/results/.keep", "bench/results/20260927T010203Z-darwin-arm64.txt",
		"docs/design/other.md", "go.work.example", "clients/python/src/m/__init__.py",
	}
}

func walkDropped() []string {
	return []string{
		".git/HEAD", ".tooling/x", "bin/gw", "dist/gw", "coverage/c.out", "node_modules/m/i.js",
		"cmd/.DS_Store", "cmd/gw.test", "clients/python/src/m/__pycache__/x.cpython-314.pyc",
		"clients/python/.venv/bin/python", "clients/python/.mypy_cache/x.json",
		"cmd/cover.out", ".env", ".env.local", "go.work", "go.work.sum", "AGENTS.local.md",
		"bench/results/run.txt", "bench/results/deep/run.txt", "bench/results/local/20260927T010203Z.txt",
		"bench/results/local/a-b-c.txt", "bench/results/local/.keep", "bench/results/my-bench-notes.txt",
	}
}

func TestWalkFilesLeavesOutWhatTheRepositoryIgnores(t *testing.T) {
	kept, dropped := walkKept(), walkDropped()
	fsys := fstest.MapFS{}
	for _, p := range slices.Concat(kept, dropped) {
		fsys[p] = &fstest.MapFile{Data: []byte("x")}
	}
	got, err := WalkFiles(fsys)
	if err != nil {
		t.Fatalf("WalkFiles: %v", err)
	}
	slices.Sort(kept)
	if !slices.Equal(got, kept) {
		t.Errorf("WalkFiles = %q\nwant %q", got, kept)
	}
}

func TestWalkFilesRefusesAnEmptyTree(t *testing.T) {
	_, err := WalkFiles(fstest.MapFS{"bin/gw": {Data: []byte("x")}})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "no file") {
		t.Errorf("WalkFiles = %v, want ErrInvalid saying no file", err)
	}
}
