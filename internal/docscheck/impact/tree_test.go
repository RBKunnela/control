package impact

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// fixtureEnv is the environment git runs with in a fixture repository: no
// user or system configuration, and an identity for a commit.
// fixtureEnv is the process's environment for a fixture tree, without the
// commit file list a gate-commit export runs under, which names another tree.
func fixtureEnv(dir string) []string {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "REPO_FILES_LIST=") || strings.HasPrefix(kv, "REPO_FILES_LIST_ROOT=")
	})
	return append(env,
		"HOME="+dir, "XDG_CONFIG_HOME="+dir, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
}

func gitIn(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	var stderr bytes.Buffer
	cmd := gitCommand(dir, fixtureEnv(dir), args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// fixtureRepository is a new repository in a temporary directory whose
// .git/info/exclude ends with localExclude, the way a developer keeps local
// material out of the tracked ignore file.
func fixtureRepository(t *testing.T, localExclude string) string {
	t.Helper()
	needGit(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "config", "core.ignorecase", "false")
	exclude := filepath.Join(dir, ".git", "info", "exclude")
	if err := os.MkdirAll(filepath.Dir(exclude), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exclude, []byte(localExclude), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRepositoryFilesInAWorkTreeAreWhatGitWouldHold(t *testing.T) {
	dir := fixtureRepository(t, "/local/\n")
	write(t, dir, ".gitignore", []byte("/ignored/\n"))
	for _, f := range []string{"tracked.md", "ignored/a.md", "local/b.md", "new.md", "docs/guides/run.md"} {
		write(t, dir, f, []byte("x\n"))
	}
	gitIn(t, dir, "add", "tracked.md")
	got, err := RepositoryFiles(dir, fixtureEnv(dir))
	if err != nil {
		t.Fatalf("RepositoryFiles: %v", err)
	}
	slices.Sort(got.Paths)
	want := []string{".gitignore", "docs/guides/run.md", "new.md", "tracked.md"}
	if !slices.Equal(got.Paths, want) || got.Source != "git ls-files" {
		t.Errorf("RepositoryFiles = %q from %q, want %q from git ls-files", got.Paths, got.Source, want)
	}
}

func TestRepositoryFilesRefusesATreeWhoseGitCannotAnswer(t *testing.T) {
	needGit(t)
	for name, gitEntry := range map[string]func(t *testing.T, dir string){
		"an empty .git directory": func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
		},
		"a .git file naming nothing": func(t *testing.T, dir string) {
			write(t, dir, ".git", []byte("gitdir: "+filepath.Join(dir, "missing")+"\n"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			gitEntry(t, dir)
			write(t, dir, "docs/notes/local.md", []byte("x\n"))
			got, err := RepositoryFiles(dir, fixtureEnv(dir))
			if !errors.Is(err, ErrNotMeasured) || !strings.Contains(err.Error(), "holds .git") {
				t.Errorf("RepositoryFiles = %q, %v; want NOT MEASURED saying the tree holds .git", got.Paths, err)
			}
		})
	}
}

func TestTreeFilesWalksOnlyATreeWithNoGit(t *testing.T) {
	r := noGit(errors.New("fatal: not a git repository"))
	export := fstest.MapFS{"Makefile": {Data: []byte("x")}, "bin/gw": {Data: []byte("x")}}
	got, err := TreeFiles(r, export)
	if err != nil || strings.Join(got.Paths, ",") != "Makefile" || !strings.Contains(got.Source, "walk") {
		t.Errorf("TreeFiles over an export = %+v, %v; want the walk's one file", got, err)
	}
	export[".git/HEAD"] = &fstest.MapFile{Data: []byte("ref: refs/heads/main\n")}
	if got, err := TreeFiles(r, export); !errors.Is(err, ErrNotMeasured) || !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("TreeFiles over a tree holding .git = %+v, %v; want NOT MEASURED with git's reason", got, err)
	}
}

// TestRepositoryFilesOfAnExportAreGitsList commits a tree under the
// repository's own .gitignore, exports the commit as git archive does, and
// holds the export walk and the find fallback of scripts/lib/repo-files.sh
// to the commit's own file list. No file here sits in a dot-directory but
// .github, which both walks prune by design.
func TestRepositoryFilesOfAnExportAreGitsList(t *testing.T) {
	gitignore, err := os.ReadFile(filepath.Join(repoRoot, ".gitignore"))
	if err != nil {
		t.Fatalf("read the repository's .gitignore: %v", err)
	}
	dir := fixtureRepository(t, "/scratch/\n")
	write(t, dir, ".gitignore", gitignore)
	tracked := []string{
		".env.example", ".github/workflows/ci.yml", "AGENTS.md", "Makefile",
		"bench/results/.keep", "bench/results/20260927T010203Z-darwin-arm64.txt",
		"cmd/gw/main.go", "docs/guides/run.md", "docs/notes/n.md", "go.work.example",
	}
	untracked := []string{
		".DS_Store", ".env", "AGENTS.local.md", "bench/results/local/x.txt", "bin/gw",
		"cmd/gw.test", "coverage/c.out", "go.work", "scratch/plan.md",
	}
	for _, f := range slices.Concat(tracked, untracked) {
		write(t, dir, f, []byte("x\n"))
	}
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "tree")
	want := append(slices.Clone(tracked), ".gitignore")
	slices.Sort(want)
	if committed := lines(gitIn(t, dir, "ls-tree", "-r", "--name-only", "HEAD")); !slices.Equal(committed, want) {
		t.Fatalf("the commit holds\n%q\nwant\n%q", committed, want)
	}

	work, err := RepositoryFiles(dir, fixtureEnv(dir))
	if err != nil {
		t.Fatalf("RepositoryFiles over the work tree: %v", err)
	}
	slices.Sort(work.Paths)
	if !slices.Equal(work.Paths, want) {
		t.Errorf("the work tree lists\n%q\nwant\n%q", work.Paths, want)
	}

	export, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	extract(t, gitIn(t, dir, "archive", "--format=tar", "HEAD"), export)
	walked, err := RepositoryFiles(export, fixtureEnv(export))
	if err != nil {
		t.Fatalf("RepositoryFiles over the export: %v", err)
	}
	slices.Sort(walked.Paths)
	if !slices.Equal(walked.Paths, want) || !strings.Contains(walked.Source, "walk") {
		t.Errorf("the export walk lists\n%q from %q\nwant\n%q from a walk", walked.Paths, walked.Source, want)
	}
	lib := filepath.Join(repoRoot, "scripts", "lib", "repo-files.sh")
	//nolint:gosec // G204: the script is a constant and its arguments are this test's own paths
	found := run(t, exec.Command("bash", "-c", `. "$1" && _repo_files_find "$2"`, "_", lib, export))
	if !slices.Equal(found, want) {
		t.Errorf("the find fallback lists\n%q\nwant\n%q", found, want)
	}
}

func lines(out []byte) []string {
	list := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	slices.Sort(list)
	return list
}

// extract writes the regular files of a tar stream under dir.
func extract(t *testing.T, archive []byte, dir string) {
	t.Helper()
	r := tar.NewReader(bytes.NewReader(archive))
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		write(t, dir, h.Name, data)
	}
}

func TestLeftOutKeepsWhatTheListHoldsAndExcludedAdmits(t *testing.T) {
	listing := LeftOut([]string{"README.md", "docs/guides/run.md", "docs/notes/n.md"},
		func(rel string) bool { return rel == "docs/notes/" || rel == "docs/notes/n.md" })
	for rel, want := range map[string][2]bool{
		"README.md":          {true, false},
		"docs/":              {true, false},
		"docs/guides/":       {true, false},
		"docs/guides/run.md": {true, false},
		"docs/notes/":        {true, true},
		"docs/notes/n.md":    {true, true},
		"docs/local/":        {false, true},
		"docs/local/x.md":    {false, true},
		"docs/guides":        {false, true},
		"docs/guides/r":      {false, true},
		"guides/":            {false, true},
	} {
		if got := [2]bool{listing.Lists(rel), listing.Skips(rel)}; got != want {
			t.Errorf("Lists, Skips(%q) = %v, want %v", rel, got, want)
		}
	}
	if !LeftOut([]string{"README.md"}, nil).Skips("README.md") || !(Listing{}).Skips("README.md") {
		t.Error("a listing with no excluded predicate reads a file")
	}
}
