package impact

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// exportWithList is a tree with no .git holding a file in a dot-directory,
// which the walk prunes, and a file the list leaves out, which the walk
// finds, with the commit's NUL-delimited list written outside it. It returns
// the tree's physical path and the list's path.
func exportWithList(t *testing.T, list string) (string, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"README.md", "docs/guide.md", "docs/.hidden/guide.md", "stray.md"} {
		write(t, dir, f, []byte("x\n"))
	}
	path := filepath.Join(t.TempDir(), "files")
	if err := os.WriteFile(path, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

const committedList = "README.md\x00docs/.hidden/guide.md\x00docs/guide.md\x00"

func TestRepositoryFilesReadsTheCommitsListInItsExport(t *testing.T) {
	dir, list := exportWithList(t, committedList)
	got, err := RepositoryFiles(dir, append(fixtureEnv(dir), "REPO_FILES_LIST="+list, "REPO_FILES_LIST_ROOT="+dir))
	if err != nil {
		t.Fatalf("RepositoryFiles: %v", err)
	}
	slices.Sort(got.Paths)
	want := []string{"README.md", "docs/.hidden/guide.md", "docs/guide.md"}
	if !slices.Equal(got.Paths, want) || !strings.Contains(got.Source, "the commit's file list") {
		t.Errorf("RepositoryFiles = %q from %q, want %q from the commit's file list", got.Paths, got.Source, want)
	}

	link := filepath.Join(t.TempDir(), "export")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	got, err = RepositoryFiles(link, append(fixtureEnv(link), "REPO_FILES_LIST="+list, "REPO_FILES_LIST_ROOT="+dir))
	slices.Sort(got.Paths)
	if err != nil || !slices.Equal(got.Paths, want) {
		t.Errorf("RepositoryFiles through a link to the export = %q, %v; want %q", got.Paths, err, want)
	}
}

func TestRepositoryFilesWalksAnyOtherTree(t *testing.T) {
	dir, list := exportWithList(t, committedList)
	walked := []string{"README.md", "docs/guide.md", "stray.md"}
	for name, env := range map[string][]string{
		"no list named":         nil,
		"a list without a root": {"REPO_FILES_LIST=" + list},
		"a root without a list": {"REPO_FILES_LIST_ROOT=" + dir},
		"another tree's list":   {"REPO_FILES_LIST=" + list, "REPO_FILES_LIST_ROOT=" + t.TempDir()},
		"the root not resolved": {"REPO_FILES_LIST=" + list, "REPO_FILES_LIST_ROOT=" + dir + "/."},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RepositoryFiles(dir, append(fixtureEnv(dir), env...))
			if err != nil {
				t.Fatalf("RepositoryFiles: %v", err)
			}
			slices.Sort(got.Paths)
			if !slices.Equal(got.Paths, walked) || !strings.Contains(got.Source, "walk") {
				t.Errorf("RepositoryFiles = %q from %q, want the walk's %q", got.Paths, got.Source, walked)
			}
		})
	}
}

func TestRepositoryFilesRefusesACommitListItCannotTrust(t *testing.T) {
	for name, c := range map[string]struct {
		list    string
		missing bool
		want    error
		says    string
	}{
		"a list that is not there": {list: committedList, missing: true, want: ErrNotMeasured, says: "cannot be read"},
		"an empty list":            {list: "", want: ErrInvalid, says: "lists no file"},
		"a path out of the tree":   {list: "README.md\x00../outside.md\x00", want: ErrInvalid, says: "not a clean path"},
		"an absolute path":         {list: "/etc/hosts\x00", want: ErrInvalid, says: "not a relative slash path"},
		"a path listed twice":      {list: "README.md\x00README.md\x00", want: ErrInvalid, says: "listed twice"},
		"a path not on disk":       {list: "README.md\x00docs/gone.md\x00", want: ErrInvalid, says: "docs/gone.md is not on disk"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, list := exportWithList(t, c.list)
			if c.missing {
				if err := os.Remove(list); err != nil {
					t.Fatal(err)
				}
			}
			got, err := RepositoryFiles(dir, append(fixtureEnv(dir), "REPO_FILES_LIST="+list, "REPO_FILES_LIST_ROOT="+dir))
			if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.says) {
				t.Errorf("RepositoryFiles = %q from %q, %v; want %v saying %q", got.Paths, got.Source, err, c.want, c.says)
			}
		})
	}
}

func TestRepositoryFilesKeepsRefusingAGitItCannotRead(t *testing.T) {
	dir, list := exportWithList(t, committedList)
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	got, err := RepositoryFiles(dir, append(fixtureEnv(dir), "REPO_FILES_LIST="+list, "REPO_FILES_LIST_ROOT="+dir))
	if !errors.Is(err, ErrNotMeasured) || !strings.Contains(err.Error(), "holds .git") {
		t.Errorf("RepositoryFiles = %q, %v; want NOT MEASURED saying the tree holds .git", got.Paths, err)
	}
}
