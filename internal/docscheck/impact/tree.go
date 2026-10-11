package impact

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// TreeFiles lists the files of the tree fsys holds: git's list where git
// answers, and a walk only for a tree with no .git, which holds nothing the
// repository does not track. A tree holding .git that git cannot list is an
// error: the walk would judge local files git ignores.
func TreeFiles(run Runner, fsys fs.FS) (Files, error) {
	return ListFiles(run, func() ([]string, error) {
		if err := exportOnly(fsys); err != nil {
			return nil, err
		}
		return WalkFiles(fsys)
	})
}

func exportOnly(fsys fs.FS) error {
	switch _, err := fs.Stat(fsys, ".git"); {
	case err == nil:
		return fmt.Errorf("%w: the tree holds .git, but git cannot list it", ErrNotMeasured)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: looking for .git: %w", ErrNotMeasured, err)
	}
	return nil
}

// RepositoryFiles is TreeFiles over the directory root with the git binary,
// with one difference repo_files in scripts/lib/repo-files.sh shares: a tree
// with no .git whose physical path is REPO_FILES_LIST_ROOT in environ is the
// export scripts/gate-commit.sh made, and its files are the commit's own list
// REPO_FILES_LIST names, not a walk that prunes every dot-directory.
func RepositoryFiles(root string, environ []string) (Files, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Files{}, err
	}
	fsys := os.DirFS(abs)
	return listFiles(Repository(Git(abs, environ), abs), func() ([]string, string, error) {
		if err := exportOnly(fsys); err != nil {
			return nil, "", err
		}
		list, err := commitList(abs, environ)
		switch {
		case err != nil:
			return nil, "", err
		case list == "":
			paths, err := WalkFiles(fsys)
			return paths, "a walk of the tree", err
		}
		paths, err := readCommitList(fsys, list)
		return paths, "the commit's file list " + list, err
	})
}

// commitList is the path REPO_FILES_LIST names when REPO_FILES_LIST_ROOT is
// abs with every link resolved, and empty for any other tree.
func commitList(abs string, environ []string) (string, error) {
	var list, listRoot string
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, "REPO_FILES_LIST="); ok {
			list = v
		} else if v, ok := strings.CutPrefix(kv, "REPO_FILES_LIST_ROOT="); ok {
			listRoot = v
		}
	}
	if list == "" || listRoot == "" {
		return "", nil
	}
	physical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%w: resolving %s: %w", ErrNotMeasured, abs, err)
	}
	if physical != listRoot {
		return "", nil
	}
	return list, nil
}

// readCommitList reads the NUL-terminated paths of the list and holds each to
// the tree: a path that is not clean, is listed twice or is not on disk means
// the list is not this tree's, and an empty list is no commit's.
func readCommitList(fsys fs.FS, list string) ([]string, error) {
	info, err := os.Stat(list)
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	var data []byte
	if err == nil {
		data, err = os.ReadFile(list) //nolint:gosec // G304: the list scripts/gate-commit.sh names for this tree
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the commit's file list %s cannot be read: %w", ErrNotMeasured, list, err)
	}
	paths, err := parseZ(data)
	if err != nil {
		return nil, fmt.Errorf("%w: the commit's file list %s: %w", ErrInvalid, list, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: the commit's file list %s lists no file", ErrInvalid, list)
	}
	for _, p := range paths {
		if _, err := fs.Stat(fsys, p); err != nil {
			return nil, fmt.Errorf("%w: the commit's file list %s: %s is not on disk: %w", ErrInvalid, list, p, err)
		}
	}
	return paths, nil
}

// Listing is what a walk of the tree may read: the files the repository lists
// and, apart from them, what docs.json excludes from the page checks.
type Listing struct {
	held     map[string]bool
	excluded func(string) bool
}

// LeftOut is the listing of paths with excluded on top.
func LeftOut(paths []string, excluded func(string) bool) Listing {
	held := make(map[string]bool, 2*len(paths))
	for _, p := range paths {
		held[p] = true
		for i := strings.LastIndexByte(p, '/'); i > 0; i = strings.LastIndexByte(p[:i], '/') {
			held[p[:i+1]] = true
		}
	}
	return Listing{held: held, excluded: excluded}
}

// Lists reports whether rel, a file or a directory spelled with a trailing
// slash, is a listed file or holds one.
func (l Listing) Lists(rel string) bool { return l.held[rel] }

// Skips reports whether a walk leaves rel out: the listing does not hold it,
// or excluded names it. A Listing that LeftOut did not build skips everything.
func (l Listing) Skips(rel string) bool {
	return !l.held[rel] || l.excluded == nil || l.excluded(rel)
}
