package impact

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The repository root, from this package's directory.
const repoRoot = "../../.."

// TestIgnoreMirrorsAgreeWithGit holds both hand-written mirrors of
// .gitignore, WalkFiles and the find fallback of scripts/lib/repo-files.sh,
// to what git itself lists over the repository's real .gitignore, on a tree
// built to sit on the edges of the bench/results/ rules. Nothing else
// compares them, so a mirror that drifted would only show in an export.
func TestIgnoreMirrorsAgreeWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is needed to compare the mirrors with it: %v", err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("bash is needed to run the find fallback: %v", err)
	}
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	gitignore, err := fs.ReadFile(os.DirFS(root), ".gitignore")
	if err != nil {
		t.Fatalf("read the repository's .gitignore: %v", err)
	}
	lib := filepath.Join(root, "scripts", "lib", "repo-files.sh")
	if _, err := os.Stat(lib); err != nil {
		t.Fatalf("the find fallback: %v", err)
	}

	// Every name the WalkFiles unit test uses, but .git/HEAD, which git init
	// owns, and bench/results/.keep, which the layouts below vary.
	common := []string{
		"bench/README.md",
		"bench/results/20260927T010203Z-darwin-arm64.txt",
		"bench/results/20260101T000001Z-darwin-arm64.TXT",
		"bench/results/20260927T010203Z-darwin-arm64.txt.partial",
		"bench/results/20260927T010203Z.txt",
		"bench/results/2026-09-27-notes.txt",
		"bench/results/a20260927T010203Z-darwin-arm64.txt",
		"bench/results/20260927T010203Z-darwin.txt",
		"bench/results/20260927TxZ-a-b.txt",
		"bench/results/local/20260927T010203Z.txt",
		"bench/results/local/20260927T010203Z-darwin-arm64.txt",
		"bench/results/local/.keep",
		"bench/results/deep/20260927T010203Z-linux-amd64.txt",
		"bench/results/20260101T000000Z-linux-amd64.txt/inner.txt",
		"bench/results/20260101T000000Z-linux-amd64.txt/20260101T000000Z-linux-amd64.txt",
		"bench/results/.env.a-b-c.txt",
		"bench/results/my-bench-notes.txt",
		"bench/results/--.txt",
		"bench/results/.run.Ab12Cd",
		"notes/20260927T010203Z-darwin-arm64.txt",
	}
	for _, name := range slices.Concat(walkKept(), walkDropped()) {
		if name != ".git/HEAD" && name != "bench/results/.keep" {
			common = append(common, name)
		}
	}
	// What git keeps in both layouts. .tooling/x is in it: git ignores no
	// dot-directory the .gitignore does not name, while both mirrors prune
	// every one but .github, which mirrorsKeep accounts for.
	gitKeeps := []string{
		".env.example", ".github/workflows/ci.yml", ".gitignore", ".tooling/x",
		"Makefile", "bench/README.md", "bench/results/20260927T010203Z-darwin-arm64.txt",
		"clients/python/src/m/__init__.py",
		"cmd/gw/main.go", "docs/design/other.md", "go.work.example",
		"notes/20260927T010203Z-darwin-arm64.txt",
	}
	layouts := []struct {
		name  string
		files []string
		want  []string
	}{
		{
			name:  "keep is a file",
			files: append(slices.Clone(common), "bench/results/.keep"),
			want:  append(slices.Clone(gitKeeps), "bench/results/.keep"),
		},
		{
			name:  "keep is a directory",
			files: append(slices.Clone(common), "bench/results/.keep/20260927T010203Z-darwin-arm64.txt"),
			want:  slices.Clone(gitKeeps),
		},
	}
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) { compareMirrors(t, gitignore, lib, l.files, l.want) })
	}
}

// compareMirrors writes files beside the .gitignore into a new directory
// and holds git's listing to want and both mirrors to git's.
func compareMirrors(t *testing.T, gitignore []byte, lib string, files, want []string) {
	t.Helper()
	dir := t.TempDir()
	written := append(slices.Clone(files), ".gitignore")
	slices.Sort(written)
	written = slices.Compact(written)
	write(t, dir, ".gitignore", gitignore)
	for _, f := range files {
		write(t, dir, f, []byte("x\n"))
	}
	// A case-insensitive disk would merge two names that differ in
	// case only, and the comparison below would then be over fewer
	// files than the fixture names.
	if onDisk := filesUnder(t, dir); !slices.Equal(onDisk, written) {
		t.Fatalf("the disk holds\n%q\nthe fixture wrote\n%q", onDisk, written)
	}

	fromGit := listGit(t, dir)
	slices.Sort(want)
	if !slices.Equal(fromGit, want) {
		t.Errorf(".gitignore keeps\n%q\nwant\n%q", fromGit, want)
	}
	mirrors := mirrorsKeep(fromGit)
	walked, err := WalkFiles(os.DirFS(dir))
	if err != nil {
		t.Fatalf("WalkFiles: %v", err)
	}
	slices.Sort(walked)
	if !slices.Equal(walked, mirrors) {
		t.Errorf("WalkFiles lists\n%q\nwant git's list without dot-directories\n%q", walked, mirrors)
	}
	//nolint:gosec // G204: the script is a constant and its arguments are this test's own paths
	found := run(t, exec.Command("bash", "-c", `. "$1" && _repo_files_find "$2"`, "_", lib, dir))
	if !slices.Equal(found, mirrors) {
		t.Errorf("the find fallback lists\n%q\nwant git's list without dot-directories\n%q", found, mirrors)
	}
}

// mirrorsKeep is git's list less every path under a dot-directory other
// than .github, which both mirrors prune by design.
func mirrorsKeep(fromGit []string) []string {
	var out []string
	for _, p := range fromGit {
		dirs := strings.Split(p, "/")
		hidden := slices.ContainsFunc(dirs[:len(dirs)-1], func(d string) bool {
			return strings.HasPrefix(d, ".") && d != ".github"
		})
		if !hidden {
			out = append(out, p)
		}
	}
	return out
}

// filesUnder lists every file under dir by the names the disk holds.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := fs.WalkDir(os.DirFS(dir), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func write(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	p := filepath.FromSlash(rel)
	if err := r.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// listGit is what git would add in dir: every file its ignore rules keep,
// case-sensitively and with no user or system configuration read.
func listGit(t *testing.T, dir string) []string {
	t.Helper()
	environ := append(os.Environ(),
		"HOME="+dir, "XDG_CONFIG_HOME="+dir,
		"GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	run(t, gitCommand(dir, environ, "init", "-q"))
	run(t, gitCommand(dir, environ, "config", "core.ignorecase", "false"))
	return run(t, gitCommand(dir, environ, "ls-files", "-z", "--others", "--exclude-standard"))
}

// run executes cmd and returns its NUL-delimited output sorted.
func run(t *testing.T, cmd *exec.Cmd) []string {
	t.Helper()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, stderr.String())
	}
	var list []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			list = append(list, p)
		}
	}
	slices.Sort(list)
	return list
}
