package impact

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/guardana/control/internal/docscheck/frontmatter"
)

// Unparsed is a page whose frontmatter did not parse, with the reason.
type Unparsed struct {
	Path string
	Err  error
}

// WalkPages parses every page under dir that leftOut does not name, a
// directory as "dir/" and a file as its path. README.md files carry no
// frontmatter by the configuration's own rule and are not pages. A page that
// does not parse is returned as broken, never skipped; when no page parsed
// at all the run cannot be made and the error names every broken one.
func WalkPages(fsys fs.FS, dir string, leftOut func(string) bool) ([]Page, []Unparsed, error) {
	var pages []Page
	var broken []Unparsed
	err := fs.WalkDir(fsys, dir, func(rel string, d fs.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil:
			return walkErr
		case d.IsDir():
			if leftOut(rel + "/") {
				return fs.SkipDir
			}
			return nil
		case !strings.HasSuffix(rel, ".md"), d.Name() == "README.md", leftOut(rel):
			return nil
		}
		data, err := fs.ReadFile(fsys, rel)
		if err != nil {
			return err
		}
		if meta, _, parseErr := frontmatter.Parse(data); parseErr != nil {
			broken = append(broken, Unparsed{Path: rel, Err: parseErr})
		} else {
			pages = append(pages, Page{Path: rel, Covers: meta.Covers})
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, nil, fmt.Errorf("walking %s: %w", dir, err)
	case len(pages)+len(broken) == 0:
		return nil, nil, fmt.Errorf("%w: no page under %s", ErrInvalid, dir)
	case len(pages) == 0:
		return nil, nil, fmt.Errorf("%w: none of the %d pages under %s parsed:\n%s", ErrInvalid, len(broken), dir, describe(broken))
	}
	return pages, broken, nil
}

func describe(broken []Unparsed) string {
	lines := make([]string, 0, len(broken))
	for _, b := range broken {
		lines = append(lines, fmt.Sprintf("  %s: %v", b.Path, b.Err))
	}
	return strings.Join(lines, "\n")
}

// What a walk of a tree with no .git leaves out, mirroring the find fallback
// of scripts/lib/repo-files.sh: dot-directories but .github, the build
// directories, and the files .gitignore names.
var (
	prunedDirs   = []string{"bin", "dist", "coverage", "node_modules"}
	ignoredNames = []string{".DS_Store", "*.out", "*.test", "*.pyc", ".env", "go.work", "go.work.sum"}
	ignoredPaths = []string{"AGENTS.local.md"}
)

// WalkFiles lists every file under fsys that the repository would hold. It
// stands in for git in an export, so it applies the same exclusions the
// gate's own fallback does; a walk that finds nothing is refused.
func WalkFiles(fsys fs.FS) ([]string, error) {
	var files []string
	err := fs.WalkDir(fsys, ".", func(rel string, d fs.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil:
			return walkErr
		case rel == ".":
			return nil
		case d.IsDir():
			if prunedDir(rel, d.Name()) {
				return fs.SkipDir
			}
		case !ignoredFile(rel, d.Name()):
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking the tree: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: the walk found no file", ErrInvalid)
	}
	return files, nil
}

func prunedDir(rel, name string) bool {
	hidden := strings.HasPrefix(name, ".") && rel != ".github"
	return hidden || slices.Contains(prunedDirs, rel)
}

// publishedRun reports whether rel is a benchmark run scripts/bench.sh
// published, which .gitignore keeps: a <stamp>-<os>-<arch>.txt directly in
// bench/results/.
func publishedRun(rel, name string) bool {
	ok, err := path.Match("[0-9]*T[0-9]*Z-*-*.txt", name)
	return err == nil && ok && rel == "bench/results/"+name
}

func ignoredFile(rel, name string) bool {
	switch {
	case slices.Contains(ignoredPaths, rel):
		return true
	case strings.HasPrefix(name, ".env.") && name != ".env.example":
		return true
	case strings.HasPrefix(rel, "bench/results/") && rel != "bench/results/.keep" && !publishedRun(rel, name):
		return true
	}
	return slices.ContainsFunc(ignoredNames, func(pattern string) bool {
		ok, err := path.Match(pattern, name)
		return err == nil && ok
	})
}
