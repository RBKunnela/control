package docscheck

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// commitGraph is a commit-graph file read whole, with the offsets of the
// chunks that name its commits and hold their parents.
type commitGraph struct {
	b                      []byte
	fanout, names, commits int
}

func readCommitGraph(t *testing.T, path string) commitGraph {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a file under this test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 8 || string(b[:4]) != "CGPH" || b[5] != 1 {
		t.Fatalf("%s is no commit-graph of SHA-1 object names", path)
	}
	chunks := map[string]int{}
	for i := range int(b[6]) {
		at := 8 + 12*i
		chunks[string(b[at:at+4])] = int(binary.BigEndian.Uint64(b[at+4 : at+12])) //nolint:gosec // G115: offsets git wrote into a small file
	}
	g := commitGraph{b: b, fanout: chunks["OIDF"], names: chunks["OIDL"], commits: chunks["CDAT"]}
	if g.fanout == 0 || g.names == 0 || g.commits == 0 {
		t.Fatalf("%s lacks a chunk of the fan-out, the names or the commit data: %v", path, chunks)
	}
	return g
}

// position is the index of sha among the commits the graph names.
func (g commitGraph) position(t *testing.T, sha string) int {
	t.Helper()
	raw, err := hex.DecodeString(sha)
	if err != nil {
		t.Fatal(err)
	}
	count := int(binary.BigEndian.Uint32(g.b[g.fanout+4*255:]))
	for i := range count {
		if string(g.b[g.names+20*i:g.names+20*i+20]) == string(raw) {
			return i
		}
	}
	t.Fatalf("the commit-graph does not hold %s", sha)
	return 0
}

// patchCommitGraph rewrites, in the commit-graph file at path, the first
// parent of commit to parent, both of which the file must hold. git takes a
// commit's parents from that file without checking them against the object.
func patchCommitGraph(t *testing.T, path, commit, parent string) {
	t.Helper()
	g := readCommitGraph(t, path)
	entry := g.commits + 36*g.position(t, commit)
	binary.BigEndian.PutUint32(g.b[entry+20:], uint32(g.position(t, parent))) //nolint:gosec // G115: a position among the few commits written
	if err := os.WriteFile(path, g.b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// hiddenCommitRepo is a repository whose remote's main is base and whose
// remote topic holds base, one, two and three, with two and three stamped
// green and one not.
type hiddenCommitRepo struct {
	work, base, two, three string
	env                    []string
}

func (r hiddenCommitRepo) git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=probe", "-c", "user.email=probe@example.invalid"}, args...)...) //nolint:gosec // G204: git with arguments this test names
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func newHiddenCommitRepo(t *testing.T) hiddenCommitRepo {
	t.Helper()
	tmp := t.TempDir()
	r := hiddenCommitRepo{work: filepath.Join(tmp, "work"), env: gitEnv(t)}
	r.git(t, tmp, "init", "-q", "--template=", "--bare", "origin.git")
	r.git(t, tmp, "init", "-q", "--template=", "-b", "main", "work")
	commit := func(msg string) string {
		r.git(t, r.work, "commit", "-q", "--allow-empty", "-m", msg)
		return r.git(t, r.work, "rev-parse", "HEAD")
	}
	r.base = commit("base")
	r.git(t, r.work, "remote", "add", "origin", filepath.Join(tmp, "origin.git"))
	r.git(t, r.work, "push", "-q", "origin", "main")
	commit("one")
	r.two, r.three = commit("two"), commit("three")
	r.git(t, r.work, "push", "-q", "origin", "HEAD:refs/heads/topic")
	stamps := filepath.Join(r.work, ".git", "gate-green")
	if err := os.MkdirAll(stamps, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{r.two, r.three} {
		if err := os.WriteFile(filepath.Join(stamps, sha), []byte("2026-01-01T00:00:00Z quality: green\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// pushThree runs the hook as git would for a push of three to main, with
// extra added to the environment.
func (r hiddenCommitRepo) pushThree(t *testing.T, extra ...string) (string, error) {
	cmd := exec.Command("/bin/bash", filepath.Join(repoRoot(t), "scripts", "pre-push.sh"), "origin") //nolint:gosec // G204: the repository's own hook
	cmd.Dir = r.work
	cmd.Env = append(slices.Clone(r.env), extra...)
	cmd.Stdin = strings.NewReader("refs/heads/main " + r.three + " refs/heads/main " + r.base + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// graphFile is the one graph file git wrote: the single file, or the one
// layer of a chain.
func (r hiddenCommitRepo) graphFile(t *testing.T) string {
	t.Helper()
	info := filepath.Join(r.work, ".git", "objects", "info")
	files, err := filepath.Glob(filepath.Join(info, "commit-graphs", "*.graph"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(info, "commit-graph")); err == nil {
		files = append(files, filepath.Join(info, "commit-graph"))
	}
	if len(files) != 1 {
		t.Fatalf("git wrote %d graph file(s), want 1: %v", len(files), files)
	}
	if err := os.Chmod(files[0], 0o600); err != nil {
		t.Fatal(err)
	}
	return files[0]
}

// TestPrePushReadsParentsFromTheCommitsThemselves: a commit-graph, a single
// file or a chain of them, that names base as the parent of two hides one,
// which no stamp covers, from a hook that trusts it, while the push would
// still send one to the remote. The hook reads the parents the objects name,
// also when the pusher's `git -c core.commitGraph=true` turns the graph on.
func TestPrePushReadsParentsFromTheCommitsThemselves(t *testing.T) {
	const ungated = "1 of 3 commit(s) ungated"
	for name, write := range map[string][]string{
		"a commit-graph file":  {"commit-graph", "write", "--reachable"},
		"a commit-graph chain": {"commit-graph", "write", "--reachable", "--split"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newHiddenCommitRepo(t)
			if out, err := r.pushThree(t); err == nil || !strings.Contains(out, ungated) {
				t.Fatalf("pre-push with no commit-graph = %v, want %q:\n%s", err, ungated, out)
			}
			r.git(t, r.work, write...)
			patchCommitGraph(t, r.graphFile(t), r.two, r.base)
			if listed := strings.Fields(r.git(t, r.work, "rev-list", r.base+".."+r.three)); len(listed) != 2 {
				t.Fatalf("git reads %d commit(s) between base and three through the patched graph, want 2, so the case hides nothing", len(listed))
			}
			if out, err := r.pushThree(t); err == nil || !strings.Contains(out, ungated) {
				t.Errorf("pre-push with %s that hides one = %v, want %q:\n%s", name, err, ungated, out)
			}
			if out, err := r.pushThree(t, "GIT_CONFIG_PARAMETERS='core.commitgraph'='true'"); err == nil || !strings.Contains(out, ungated) {
				t.Errorf("pre-push under git -c core.commitGraph=true with %s that hides one = %v, want %q:\n%s", name, err, ungated, out)
			}
		})
	}
}

// TestGateCommitSetsGitAsThePrePushHookDoes: scripts/gate-commit.sh picks the
// commit it archives through the same git settings the hook's test above
// holds, so a graph, a graft, a shallow file or a replace ref hides nothing
// from either. The settings are compared line for line.
func TestGateCommitSetsGitAsThePrePushHookDoes(t *testing.T) {
	block := func(script string) string {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", script)) //nolint:gosec // G304: a script of this repository
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		from := strings.Index(s, "\nn=\"${GIT_CONFIG_COUNT:-0}\"\n")
		to := strings.Index(s, "'core.commitgraph'='false'\"\n")
		if from < 0 || to < from {
			t.Fatalf("scripts/%s does not set git's config from GIT_CONFIG_COUNT through GIT_CONFIG_PARAMETERS", script)
		}
		return s[from:to]
	}
	if hook, gate := block("pre-push.sh"), block("gate-commit.sh"); hook != gate {
		t.Errorf("scripts/gate-commit.sh sets git as\n%s\nwhile scripts/pre-push.sh sets it as\n%s", gate, hook)
	}
}
