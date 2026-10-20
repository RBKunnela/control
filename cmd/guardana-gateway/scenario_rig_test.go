package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
)

// binaries are the two commands built once for every case that runs them as
// processes, side by side in one directory as an install puts them.
var binaries struct {
	once sync.Once
	dir  string
	err  error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binaries.dir != "" {
		_ = os.RemoveAll(binaries.dir)
	}
	os.Exit(code)
}

// builtBinaries returns the paths of the gateway and of the approver's binary,
// built from this tree.
func builtBinaries(t *testing.T) (gatewayBin, controlBin string) {
	t.Helper()
	binaries.once.Do(func() {
		binaries.dir, binaries.err = os.MkdirTemp("", "scenario-bin-")
		if binaries.err != nil {
			return
		}
		for _, name := range []string{brand.Gateway, brand.CLI} {
			if binaries.err = goBuild(filepath.Join(binaries.dir, name), name); binaries.err != nil {
				return
			}
		}
	})
	if binaries.err != nil {
		t.Fatalf("building the binaries: %v", binaries.err)
	}
	return filepath.Join(binaries.dir, brand.Gateway), filepath.Join(binaries.dir, brand.CLI)
}

// goBuild builds ./cmd/<name> of this tree to out, with ldflags if any.
func goBuild(out, name string, ldflags ...string) error {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("cannot resolve this file's own path")
	}
	args := []string{"build", "-o", out}
	if len(ldflags) > 0 {
		args = append(args, "-ldflags", strings.Join(ldflags, " "))
	}
	cmd := exec.Command("go", append(args, "./cmd/"+name)...) //nolint:gosec // G204: the go tool on this tree
	cmd.Dir = filepath.Dir(filepath.Dir(filepath.Dir(self)))
	if raw, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build ./cmd/%s: %w\n%s", name, err, raw)
	}
	return nil
}

// liveDocument allows reads and updates and denies transfers. Under APPROVE
// an allowed update is held for an approval.
const liveDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"scenario-fixture","version":"2026-09-24.1","serial":1,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"allow-updates","effect":"ALLOW","when":{"action":{"effect":["WRITE"]}}},
    {"id":"deny-transfers","effect":"DENY","when":{"action":{"effect":["TRANSACT"]}}}
  ]}`

// liveTool is one tool the test upstream serves and how the plane's operator
// classifies it.
type liveTool struct {
	name, effect, returnsTrust string
	answer                     string
}

var liveTools = []liveTool{
	{name: "read_order", effect: "READ", returnsTrust: "TRUSTED_INTERNAL", answer: "order ord-1 is open"},
	{name: "read_web", effect: "READ", returnsTrust: "UNTRUSTED_EXTERNAL", answer: "a page from elsewhere"},
	{name: "update_order", effect: "WRITE", returnsTrust: "TRUSTED_INTERNAL", answer: "order updated"},
	{name: "transfer", effect: "TRANSACT", returnsTrust: "TRUSTED_INTERNAL", answer: "the transfer ran"},
	{name: "relay", effect: "READ", returnsTrust: "TRUSTED_INTERNAL", answer: "relayed"},
}

func (lt liveTool) tool() *sdk.Tool {
	return &sdk.Tool{Name: lt.name, Description: "does " + lt.name, InputSchema: map[string]any{
		"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}},
	}}
}

// liveUpstream is the MCP server the plane calls. Its relay tool calls the
// plane back as a second client before it answers.
type liveUpstream struct {
	url   string
	plane atomic.Pointer[string]
}

func newLiveUpstream(t *testing.T) *liveUpstream {
	t.Helper()
	return startLiveUpstream(t, false)
}

// startLiveUpstream serves the live tools. With dropEnd it keeps a session per
// client and drops the connection of the request that ends one, so a plane's
// close of this upstream fails.
func startLiveUpstream(t *testing.T, dropEnd bool) *liveUpstream {
	t.Helper()
	up := &liveUpstream{}
	server := sdk.NewServer(&sdk.Implementation{Name: "scenario-upstream", Version: "0"}, nil)
	for _, lt := range liveTools {
		server.AddTool(lt.tool(), func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			if lt.name == "relay" {
				if err := up.callBack(ctx); err != nil {
					return nil, err
				}
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: lt.answer}}}, nil
		})
	}
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: !dropEnd})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dropEnd && r.Method == http.MethodDelete {
			if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	up.url = ts.URL
	return up
}

// callBack is a second client calling the plane while the first one's call
// is under way.
func (up *liveUpstream) callBack(ctx context.Context) error {
	addr := up.plane.Load()
	if addr == nil {
		return errors.New("no plane to call back")
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "second-client", Version: "0"}, nil).Connect(ctx,
		&sdk.StreamableClientTransport{Endpoint: "http://" + *addr}, &sdk.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		return err
	}
	defer func() { _ = cs.Close() }()
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "read_order", Arguments: map[string]any{"id": "ord-2"}})
	return err
}

// rig is one plane under test: a collector writing the trail file, the plane
// sending to it, and the directories both keep, each in the rig's own tree.
type rig struct {
	t                *testing.T
	gateway, control string
	dir, config      string
	trail            string
	up               *liveUpstream
	listen, health   string
	// pausePoll is how often the plane reads its pause file.
	pausePoll string
}

// newRig lays out and starts one plane that reads its pause file every
// 100ms.
func newRig(t *testing.T) *rig {
	t.Helper()
	return newRigPolling(t, "100ms")
}

// newRigPolling lays out and starts one plane that reads its pause file
// every interval.
func newRigPolling(t *testing.T, interval string) *rig {
	t.Helper()
	gatewayBin, controlBin := builtBinaries(t)
	r := &rig{t: t, gateway: gatewayBin, control: controlBin, dir: t.TempDir(), up: newLiveUpstream(t), pausePoll: interval}
	for _, d := range []string{"spool", "records", "holds", "pause"} {
		if err := os.MkdirAll(filepath.Join(r.dir, d), 0o750); err != nil {
			t.Fatalf("making %s: %v", d, err)
		}
	}
	writeBundle(t, filepath.Join(r.dir, "policy.bundle"), liveDocument)
	pauseFile := filepath.Join(r.dir, "pause", "pause.json")
	if out, err := exec.Command(controlBin, "pause", "init", pauseFile).CombinedOutput(); err != nil { //nolint:gosec // G204: the binary this test built
		t.Fatalf("pause init: %v\n%s", err, out)
	}
	r.trail = filepath.Join(r.dir, "trail.jsonl")
	collector := r.startProcess("collect", "--listen", "127.0.0.1:0", "--out", r.trail)
	endpoint := strings.TrimPrefix(collector.waitFor(t, "collect: listening on "), "collect: listening on ")
	r.config = filepath.Join(r.dir, "plane.yaml")
	if err := os.WriteFile(r.config, []byte(r.planeConfig(endpoint)), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	plane := r.startProcess("run", "--config", r.config)
	r.listen = afterPrefix(plane.waitFor(t, "listening for agents on "), "listening for agents on ")
	r.health = afterPrefix(plane.waitFor(t, "answering /healthz, /metrics and /brand on "), "answering /healthz, /metrics and /brand on ")
	r.up.plane.Store(&r.listen)
	return r
}

func afterPrefix(line, prefix string) string {
	return strings.TrimSpace(line[strings.Index(line, prefix)+len(prefix):])
}

// planeConfig is the plane's configuration: APPROVE over the live document,
// approvals in a directory an approver outside the plane writes, a pause file
// read every r.pausePoll, and each tool classified from its fingerprint.
func (r *rig) planeConfig(endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `mode: APPROVE
project_id: orders
tenant_id: acme
environment: dev
listener:
  kind: stateless_http
  address: 127.0.0.1:0
  principal:
    id: agent-runner
  agent:
    id: orders-assistant
health:
  address: 127.0.0.1:0
policy:
  bundle_id: scenario-fixture
  bundle_file: policy.bundle
  key_id: %s
  public_key: %s
%sapprovals:
  provider: file
  dir: records
  hold_journal_dir: holds
pause:
  file: pause/pause.json
  poll_interval: %s
evidence:
  dir: spool
export:
  endpoint: %s
  allow_plaintext: true
  linger: 5ms
upstreams:
  - name: orders
    endpoint: %s
    tenant_id: acme
    environment: dev
overrides:
`, fixtureKeyID, fixturePublicKey(), freshnessKeys(r.t, r.dir, "scenario-fixture"), r.pausePoll, endpoint, r.up.url)
	for _, lt := range liveTools {
		fp, err := adaptermcp.Fingerprint(lt.tool())
		if err != nil {
			r.t.Fatalf("fingerprint of %s: %v", lt.name, err)
		}
		fmt.Fprintf(&b, "  - upstream: orders\n    tool: %s\n    fingerprint: %s\n    effect: %s\n    resource_type: order\n    resource_from: /id\n"+
			"    trust_zone: TRUSTED_INTERNAL\n    returns:\n      trust: %s\n      sensitivity: PUBLIC\n", lt.name, fp, lt.effect, lt.returnsTrust)
	}
	return b.String()
}

// environ is this process's environment without the product's variables, so
// a developer's shell never reaches a plane under test.
func environ(extra ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, brand.EnvPrefix) {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}

// process is one command of the rig, read through its standard output.
type process struct {
	cmd *exec.Cmd
	out *syncBuffer
}

func (r *rig) startProcess(args ...string) *process {
	r.t.Helper()
	cmd := exec.Command(r.gateway, args...) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	p := &process{cmd: cmd, out: &syncBuffer{}}
	cmd.Stdout, cmd.Stderr = p.out, p.out
	if err := cmd.Start(); err != nil {
		r.t.Fatalf("starting %s: %v", args[0], err)
	}
	r.t.Cleanup(func() { p.stop(r.t) })
	return p
}

func (p *process) waitFor(t *testing.T, prefix string) string {
	t.Helper()
	return waitFor(t, p.out, prefix)
}

// stop asks the process to stop, and kills it past a bound.
func (p *process) stop(t *testing.T) {
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
		t.Errorf("%s did not stop within its bound:\n%s", p.cmd.Args[1], p.out.String())
	}
}

// runScenarios runs the built gateway's scenario command against the rig's
// plane with extra flags and the named scenario files, and returns its exit
// and everything it wrote.
func (r *rig) runScenarios(extra []string, files ...string) (int, string) {
	r.t.Helper()
	args := append([]string{"scenario", "run", "--config", r.config, "--trail", r.trail}, extra...)
	cmd := exec.Command(r.gateway, append(args, files...)...) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ(
		brand.Env(gatewayconfig.EnvName("listener.address"))+"="+r.listen,
		brand.Env(gatewayconfig.EnvName("health.address"))+"="+r.health,
	)
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), out.String()
	}
	r.t.Fatalf("running the scenarios: %v\n%s", err, out.String())
	return -1, ""
}

// lines is what a command wrote, one entry per line.
func lines(out string) []string {
	var got []string
	s := bufio.NewScanner(strings.NewReader(out))
	// A process table can hold a command line past the scanner's default
	// token size, which would end the scan there and hide every later line.
	s.Buffer(nil, len(out)+1)
	for s.Scan() {
		got = append(got, s.Text())
	}
	return got
}

// runBinary runs a built binary with no product variable in its environment
// and returns everything it wrote.
func runBinary(path string, args ...string) (string, error) {
	cmd := exec.Command(path, args...) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// exitOf is the exit status a finished command's error carries, 0 for none.
func exitOf(t *testing.T, err error) int {
	t.Helper()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	t.Fatalf("the command did not run: %v", err)
	return -1
}

// TestLinesReadsALineLongerThanTheScannersDefault: a process table with one
// command line of 200 KiB still yields every line after it.
func TestLinesReadsALineLongerThanTheScannersDefault(t *testing.T) {
	got := lines("1 0 a\n2 1 " + strings.Repeat("x", 200<<10) + "\n3 2 console\n")
	if len(got) != 3 || got[2] != "3 2 console" {
		t.Fatalf("read %d lines, want 3 ending in the console line", len(got))
	}
}
