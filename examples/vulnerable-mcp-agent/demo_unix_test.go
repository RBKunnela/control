//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
)

// demoTree is the layout the tutorial builds: the gateway, the approver and
// the victims in bin/ at the root, and the demo's configuration two
// directories below, where its command path reaches them.
var demoTree struct {
	once   sync.Once
	root   string
	config string
	err    error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if demoTree.root != "" {
		_ = os.RemoveAll(demoTree.root)
	}
	os.Exit(code)
}

// builtDemo builds the three binaries of this tree once and returns the
// gateway's path and the copy of demo.yaml that reaches the victims.
func builtDemo(t *testing.T) (gateway, config string) {
	t.Helper()
	demoTree.once.Do(func() {
		demoTree.root, demoTree.err = os.MkdirTemp("", "demo-tree-")
		if demoTree.err != nil {
			return
		}
		demoTree.err = buildDemo(demoTree.root)
		demoTree.config = filepath.Join(demoTree.root, "examples", "vulnerable-mcp-agent", "demo.yaml")
	})
	if demoTree.err != nil {
		t.Fatalf("building the demo: %v", demoTree.err)
	}
	return filepath.Join(demoTree.root, "bin", brand.Gateway), demoTree.config
}

func buildDemo(root string) error {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("cannot resolve this file's own path")
	}
	here := filepath.Dir(self)
	cmd := exec.Command("go", "build", "-o", filepath.Join(root, "bin")+string(filepath.Separator), //nolint:gosec // G204: the go tool on this tree
		"./cmd/"+brand.Gateway, "./cmd/"+brand.CLI, "./examples/vulnerable-mcp-agent")
	cmd.Dir = filepath.Dir(filepath.Dir(here))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build: %w\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(here, "demo.yaml")) //nolint:gosec // G304: this package's own file
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "examples", "vulnerable-mcp-agent")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "demo.yaml"), raw, 0o600)
}

// demoRun is what one run of dev wrote and how it ended.
type demoRun struct {
	code           int
	stdout, stderr string
}

// runDev runs dev over the demo with a silent decision point and the
// scenario files given, the victims journalling into journal and the planes'
// state under state, and waits at most two minutes for it.
func runDev(t *testing.T, journal, state string, scenarios ...string) demoRun {
	t.Helper()
	return runDevWith(t, journal, append([]string{"--decision-point=silent", "--state", state}, scenarioArgs(scenarios)...)...)
}

func scenarioArgs(files []string) []string {
	var out []string
	for _, f := range files {
		out = append(out, "--scenario", f)
	}
	return out
}

// runDevWith runs dev over the demo with the flags given after its
// configuration and policy.
func runDevWith(t *testing.T, journal string, flags ...string) demoRun {
	t.Helper()
	gateway, config := builtDemo(t)
	policy, err := filepath.Abs("policy.json")
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"dev", "--config", config, "--policy", policy}, flags...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, gateway, args...) //nolint:gosec // G204: the binary this test built
	cmd.Env = append(environ(), journalDirVariable+"="+journal)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	run := demoRun{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Fatalf("dev did not end within its bound:\n%s\n%s", run.stdout, run.stderr)
	case err == nil:
	case errors.As(err, &exit):
		run.code = exit.ExitCode()
	default:
		t.Fatalf("dev did not run: %v", err)
	}
	return run
}

// environ is this process's environment without the product's variables,
// which dev refuses.
func environ() []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, brand.EnvPrefix) && !strings.HasPrefix(kv, journalDirVariable+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// journalled is what the victim name wrote into dir, one entry per line; a
// file that does not exist fails the test, since each victim creates its
// file when it starts.
func journalled(t *testing.T, dir, name string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name+".jsonl")) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatalf("the %s victim left no journal: %v", name, err)
	}
	var got []string
	s := bufio.NewScanner(bytes.NewReader(raw))
	for s.Scan() {
		var e entry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("%s journal line %q: %v", name, s.Text(), err)
		}
		got = append(got, e.Call+" "+string(e.Args))
	}
	return got
}

// demoScenarios is each scenario of the demo and what each victim received
// while it ran, in order.
var demoScenarios = []struct {
	file        string
	orders, web []string
}{
	{"allow.json", []string{`read_order {"id":"ord-1"}`}, nil},
	{"deny.json", []string{`read_order {"id":"ord-1"}`}, nil},
	{"approval.json", []string{`update_order {"id":"ord-1","status":"cancelled"}`}, nil},
	{"digest-invalidation.json", []string{`update_order {"id":"ord-2","status":"shipped"}`}, nil},
	{"fail-closed.json", []string{`read_order {"id":"ord-1"}`}, nil},
	{"pause.json", []string{`read_order {"id":"ord-1"}`}, nil},
	{"toxic-flow.json", []string{`read_order {"id":"ord-1"}`}, []string{`fetch_page {"url":"https://shop.example.com/rates"}`}},
}

// segmentsText returns the lines of every segment file in a trail directory,
// sealed and live, in name order.
func segmentsText(t *testing.T, dir string) []byte {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(names) == 0 {
		t.Fatalf("the trail directory %s holds no segment: %v", dir, err)
	}
	slices.Sort(names)
	var all []byte
	for _, name := range names {
		b, err := os.ReadFile(name) //nolint:gosec // G304: the test's own directory
		if err != nil {
			t.Fatalf("the trail: %v", err)
		}
		all = append(all, b...)
	}
	return all
}

// TestEveryDemoScenarioPassesOnItsOwnPlane runs dev once per scenario, as
// the tutorial does, and requires it to pass and each victim to have
// received exactly what the scenario let through: no refund, no export, no
// mail, and an update only once it was approved. The export's trail records
// the silent decision point's question as timed out, never as unreachable.
func TestEveryDemoScenarioPassesOnItsOwnPlane(t *testing.T) {
	builtDemo(t)
	started := time.Now()
	for _, s := range demoScenarios {
		journal, state := t.TempDir(), filepath.Join(t.TempDir(), "state")
		run := runDev(t, journal, state, filepath.Join("scenarios", s.file))
		if run.code != 0 || !strings.HasSuffix(run.stdout, "\n"+s.file+" passed\n") || strings.Contains(run.stdout, "could not run") {
			t.Fatalf("%s: exit %d, want 0 and passed:\n%s\n%s", s.file, run.code, run.stdout, run.stderr)
		}
		trail := segmentsText(t, filepath.Join(state, "1-"+s.file, "trail"))
		timedOut := strings.Contains(string(trail), "PDP_TIMEOUT")
		if timedOut != (s.file == "fail-closed.json") || strings.Contains(string(trail), "PDP_UNAVAILABLE") {
			t.Errorf("%s: the trail names PDP_TIMEOUT: %v, PDP_UNAVAILABLE: %v", s.file, timedOut, strings.Contains(string(trail), "PDP_UNAVAILABLE"))
		}
		if got := journalled(t, journal, "orders"); !slices.Equal(got, s.orders) {
			t.Errorf("%s: the orders victim received %q, want %q", s.file, got, s.orders)
		}
		if got := journalled(t, journal, "web"); !slices.Equal(got, s.web) {
			t.Errorf("%s: the web victim received %q, want %q", s.file, got, s.web)
		}
	}
	t.Logf("seven scenarios, each on a plane of its own, took %v", time.Since(started).Round(time.Millisecond))
}

// demoMutant changes one expected member of one scenario: the nth
// occurrence of old becomes new, and the runner must name member at step.
type demoMutant struct {
	file     string
	old, new string
	nth      int
	step     int
	member   string
}

var demoMutants = []demoMutant{
	{"allow.json", `"verdict": "ALLOW"`, `"verdict": "DENY"`, 1, 0, "decided.verdict"},
	{"deny.json", `"codes": ["RULE_DENY"]}`, `"codes": ["RULE_DENY", "PAUSED"]}`, 1, 0, "answer.codes"},
	{"approval.json", `, "ACTION_COMPLETED"]`, `]`, 1, 2, "trail.kinds"},
	{"digest-invalidation.json", `"request": "new"`, `"request": "step[0]"`, 2, 2, "trail.request"},
	{"fail-closed.json", `"RULE_UNDETERMINED", "PDP_TIMEOUT"], "obligations"`, `"RULE_UNDETERMINED", "PDP_UNAVAILABLE"], "obligations"`, 1, 0, "decided.codes"},
	{"pause.json", `"kind": "result"`, `"kind": "error"`, 1, 3, "answer.kind"},
	{"toxic-flow.json", `"verdict": "DENY"`, `"verdict": "INDETERMINATE"`, 1, 3, "decided.verdict"},
}

// write puts the mutated scenario under dir with its own file name, which is
// its id.
func (m demoMutant) write(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("scenarios", m.file))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	parts := strings.SplitN(text, m.old, m.nth+1)
	if len(parts) < m.nth+1 {
		t.Fatalf("%s holds %q %d time(s), fewer than %d", m.file, m.old, strings.Count(text, m.old), m.nth)
	}
	mutated := strings.Join(parts[:m.nth], m.old) + m.new + parts[m.nth]
	path := filepath.Join(dir, m.file)
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestEveryDemoMutantIsCaught runs one mutant of each scenario, each on a
// plane of its own in one run of dev. Each has to fail on exactly the member
// it changed; dev has to exit 1, and a scenario that could not run, which is
// exit 2, does not count as its mutant caught.
func TestEveryDemoMutantIsCaught(t *testing.T) {
	if len(demoMutants) != len(demoScenarios) {
		t.Fatalf("%d mutants for %d scenarios", len(demoMutants), len(demoScenarios))
	}
	dir := t.TempDir()
	var files []string
	for _, m := range demoMutants {
		files = append(files, m.write(t, dir))
	}
	run := runDev(t, t.TempDir(), filepath.Join(t.TempDir(), "state"), files...)
	if run.code != 1 || strings.Contains(run.stdout, "could not run") {
		t.Fatalf("exit %d, want 1 and every scenario run:\n%s\n%s", run.code, run.stdout, run.stderr)
	}
	for _, m := range demoMutants {
		var diffs []string
		for _, line := range strings.Split(run.stdout, "\n") {
			if strings.HasPrefix(line, m.file+" step[") && strings.Contains(line, ": want ") {
				diffs = append(diffs, line)
			}
		}
		prefix := fmt.Sprintf("%s step[%d].%s: want ", m.file, m.step, m.member)
		if len(diffs) != 1 || !strings.HasPrefix(diffs[0], prefix) || !strings.Contains(run.stdout, "\n"+m.file+" failed\n") {
			t.Errorf("%s: the differences are %q, want one beginning %q and the scenario failed", m.file, diffs, prefix)
			continue
		}
		t.Logf("caught: %s", diffs[0])
	}
}

// TestTheDemoNeedsTheSilentDecisionPoint: the policy asks a decision point
// and demo.yaml names none, so without --decision-point=silent the plane
// refuses the bundle and the scenario cannot run.
func TestTheDemoNeedsTheSilentDecisionPoint(t *testing.T) {
	run := runDevWith(t, t.TempDir(), "--state", filepath.Join(t.TempDir(), "state"), "--scenario", filepath.Join("scenarios", "allow.json"))
	if run.code != 2 || !strings.Contains(run.stdout, "allow.json could not run: its plane did not start: ") || !strings.Contains(run.stdout, "set pdp.identifier") {
		t.Fatalf("exit %d, want 2 with the plane refusing a bundle that reads external:\n%s\n%s", run.code, run.stdout, run.stderr)
	}
}
