package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// gitEnv is this process's environment without git's repository-local
// variables, with no global or system configuration, so a test repository
// is the one git reads and nothing configured elsewhere signs or hooks it.
func gitEnv(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--local-env-vars").Output()
	if err != nil {
		t.Fatalf("git rev-parse --local-env-vars: %v", err)
	}
	local := strings.Fields(string(out))
	var env []string
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); !slices.Contains(local, name) {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
}

// coldGateOn commits a README and one symbolic link to target in a new
// repository and runs scripts/gate-commit.sh there, returning its output.
func coldGateOn(t *testing.T, link, target string) (string, error) {
	t.Helper()
	repo := t.TempDir()
	env := gitEnv(t)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=probe", "-c", "user.email=probe@example.invalid"}, args...)...) //nolint:gosec // G204: git with arguments this test names
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q", "--template=")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("probe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, filepath.Dir(link)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(repo, link)); err != nil {
		t.Fatal(err)
	}
	git("add", "README.md", link)
	git("commit", "-q", "-m", "probe")
	cmd := exec.Command("/bin/bash", filepath.Join(repoRoot(t), "scripts", "gate-commit.sh")) //nolint:gosec // G204: the repository's own script
	cmd.Dir = repo
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestTheColdGateRefusesALinkOutOfTheCommit: the archive check compares a
// symbolic link's text, while the gate's tests open what it names, so a
// committed link that is absolute or climbs with .. would let a stamp rest on
// bytes the commit does not hold. A link that stays below its own directory
// passes the archive check, and the run stops later, at the repo_files this
// tree lacks. No run prints one of git's hints, which a maintainer would have
// to read past in every gate log.
func TestTheColdGateRefusesALinkOutOfTheCommit(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "fixture.jsonl")
	if err := os.WriteFile(outside, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const passed = "the archive holds all"
	for name, c := range map[string]struct{ link, target string }{
		"an absolute link":            {"internal/p/testdata/fixture.jsonl", outside},
		"a link that climbs out":      {"internal/p/testdata/fixture.jsonl", "../../../../outside/fixture.jsonl"},
		"a link that climbs and back": {"fixture.jsonl", "docs/../../fixture.jsonl"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := coldGateOn(t, c.link, c.target)
			want := c.link + " is a symbolic link to " + c.target + ", which can lead out of the commit"
			if err == nil || strings.Contains(out, passed) || !strings.Contains(out, want) {
				t.Errorf("gate-commit.sh = %v, want a refusal saying %q before %q:\n%.800s", err, want, passed, out)
			}
			noHint(t, out)
		})
	}
	out, err := coldGateOn(t, "docs/link.md", "inside/page.md")
	if err == nil || !strings.Contains(out, passed) {
		t.Errorf("gate-commit.sh over a link that stays inside = %v, want the archive check passed and a later stop:\n%.800s", err, out)
	}
	noHint(t, out)
}

func noHint(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "hint:") {
		t.Errorf("gate-commit.sh printed a hint of git's:\n%.800s", out)
	}
}
