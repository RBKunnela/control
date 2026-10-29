//go:build unix

package refundsupervision

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
)

// The identity the plane's listener names and every run is opened for.
const (
	tenant    = "acme"
	principal = "agent-runner"
	agent     = "refund-assistant"
	bundleID  = "refund-supervision"
)

// tree is one example laid out as a release archive is: the binaries in
// bin/ and the example's files two directories below, where plane.yaml's
// command path reaches the orders server. The keys sit apart, under keys/.
type tree struct {
	root, dir        string
	gateway, control string
}

func (tr tree) path(parts ...string) string {
	return filepath.Join(append([]string{tr.dir}, parts...)...)
}

// newTree builds the gateway, the control command and the orders server into
// a fresh tree and copies the example's files there.
func newTree(t *testing.T) tree {
	t.Helper()
	root := t.TempDir()
	tr := tree{root: root, dir: filepath.Join(root, "examples", "refund-supervision"),
		gateway: filepath.Join(root, "bin", brand.Gateway), control: filepath.Join(root, "bin", brand.CLI)}
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(root, "bin")+string(filepath.Separator), //nolint:gosec // G204: the go tool on this tree
		"./cmd/"+brand.Gateway, "./cmd/"+brand.CLI, "./examples/vulnerable-mcp-agent")
	build.Dir = module
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	for _, d := range []string{tr.dir, tr.path("state"), tr.path("journal"), tr.path("trail"), filepath.Join(root, "keys")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"plane.yaml", "policy.json", "refund.procedure.json", procedure02, casesFile, "runtime.source.json", "route.json"} {
		writeFile(t, tr.path(name), readFile(t, name))
	}
	return tr
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// run runs a built binary to its end within a minute and returns its exit
// status and standard output; anything but a clean exit or an exit status
// fails the test.
func run(t *testing.T, dir, bin string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: a binary this test built
	cmd.Dir, cmd.Env = dir, environ()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("%s %s did not end within a minute", filepath.Base(bin), strings.Join(args, " "))
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out) + stderr.String()
	case err != nil:
		t.Fatalf("%s did not run: %v", filepath.Base(bin), err)
	}
	return 0, string(out)
}

// must is run that requires exit 0.
func must(t *testing.T, dir, bin string, args ...string) string {
	t.Helper()
	code, out := run(t, dir, bin, args...)
	if code != 0 {
		t.Fatalf("%s %s exited %d:\n%s", filepath.Base(bin), strings.Join(args, " "), code, out)
	}
	return out
}

// values is the `name: value` lines of a command's output.
func values(out string) map[string]string {
	v := map[string]string{}
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		if name, value, ok := strings.Cut(s.Text(), ": "); ok {
			v[name] = value
		}
	}
	return v
}

// sign makes the bundle key and the freshness key, signs the policy, vouches
// that the bundle is current, makes the plane's floor and state directories,
// and writes the plane's configuration with the keys and addresses filled
// in.
func (tr tree) sign(t *testing.T, collector string) {
	t.Helper()
	keys := values(must(t, tr.root, tr.control, "policy", "keygen", "--out", "keys/bundle"))
	fresh := values(must(t, tr.root, tr.control, "policy", "keygen", "--out", "keys/freshness"))
	must(t, tr.root, tr.control, "policy", "sign", "--key", "keys/bundle/signing.key", "--out", tr.path("state", "policy.bundle"), tr.path("policy.json"))
	must(t, tr.root, tr.control, "policy", "state", "init", "--kind", "signer", "--bundle-id", bundleID, "keys/signer-floors")
	must(t, tr.root, tr.control, "policy", "renew", "--key", "keys/freshness/signing.key", "--bundle", tr.path("state", "policy.bundle"),
		"--bundle-public-key", "keys/bundle/signing.pub", "--floor", "keys/signer-floors", "--out", tr.path("state", "policy.statement"))
	must(t, tr.dir, tr.control, "policy", "state", "init", "--kind", "plane", "--bundle-id", bundleID, "state/floors")
	for _, d := range []string{"spool", "runs", "approvals", "holds"} {
		if err := os.Mkdir(tr.path("state", d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := readFile(t, "plane.yaml")
	for old, new := range map[string]string{
		"BUNDLE_KEY_ID_FROM_KEYGEN": keys["key_id"], "BUNDLE_PUBLIC_KEY_FROM_KEYGEN": keys["public_key"],
		"FRESHNESS_KEY_ID_FROM_KEYGEN": fresh["key_id"], "FRESHNESS_PUBLIC_KEY_FROM_KEYGEN": fresh["public_key"],
		"address: 127.0.0.1:8080": "address: 127.0.0.1:0", "address: 127.0.0.1:8081": "address: 127.0.0.1:0",
		"endpoint: http://127.0.0.1:4318/v1/logs": "endpoint: " + collector,
	} {
		if strings.Count(config, old) != 1 || new == "" {
			t.Fatalf("plane.yaml holds %q %d times, want once, to put %q in its place", old, strings.Count(config, old), new)
		}
		config = strings.Replace(config, old, new, 1)
	}
	writeFile(t, tr.path("plane.yaml"), config)
}

// openedRun is what runs open printed for one run.
type openedRun struct{ id, token, expiresAt string }

// openRun opens a run for the listener's identity.
func (tr tree) openRun(t *testing.T) openedRun {
	t.Helper()
	v := values(must(t, tr.dir, tr.control, "runs", "open", "--project", "refunds", "--tenant", tenant, "--principal-type", "service",
		"--principal", principal, "--agent", agent, "--ttl", "1h", "state/runs"))
	if !strings.HasPrefix(v["token"], v["run_id"]+".") || v["expires_at"] == "" {
		t.Fatalf("runs open printed no run, token and expiry: %q", v)
	}
	return openedRun{id: v["run_id"], token: v["token"], expiresAt: v["expires_at"]}
}

// environ is this process's environment without the product's variables,
// which would override the configuration the test wrote.
func environ() []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, brand.EnvPrefix) {
			out = append(out, kv)
		}
	}
	return out
}

// lockedBuffer is a buffer a process writes while the test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// process is a long-running binary: a collector or a plane.
type process struct {
	cmd    *exec.Cmd
	out    *lockedBuffer
	exited chan struct{}
}

func start(t *testing.T, dir string, env []string, bin string, args ...string) *process {
	t.Helper()
	cmd := exec.Command(bin, args...) //nolint:gosec // G204: a binary this test built
	p := &process{cmd: cmd, out: &lockedBuffer{}, exited: make(chan struct{})}
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, p.out, p.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-p.exited
	})
	return p
}

// after waits up to thirty seconds for a line that begins with prefix and
// returns the rest of it.
func (p *process) after(t *testing.T, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		for _, line := range strings.Split(p.out.String(), "\n") {
			if rest, ok := strings.CutPrefix(line, prefix); ok {
				return rest
			}
		}
		select {
		case <-p.exited:
			t.Fatalf("%s exited before it printed %q:\n%s", filepath.Base(p.cmd.Path), prefix, p.out.String())
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not print %q within 30s:\n%s", filepath.Base(p.cmd.Path), prefix, p.out.String())
		}
	}
}

// interrupt stops the process as an operator does and requires it to exit 0
// within twenty seconds.
func (p *process) interrupt(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.exited:
	case <-time.After(20 * time.Second):
		t.Fatalf("%s did not exit within 20s of an interrupt:\n%s", filepath.Base(p.cmd.Path), p.out.String())
	}
	if code := p.cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("%s exited %d after an interrupt:\n%s", filepath.Base(p.cmd.Path), code, p.out.String())
	}
}

// waitForTrails runs the trail command until the collector's trail file
// holds n whole trails, the plane's spool having shipped them, within ten
// seconds.
func (tr tree) waitForTrails(t *testing.T, n int) {
	t.Helper()
	want := fmt.Sprintf("trails %d: ok %d,", n, n)
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, out := run(t, tr.dir, tr.gateway, "trail", "trail/plane.jsonl")
		if code == 0 && strings.Contains(out, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the trail did not reach %q within 10s:\n%s", want, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
