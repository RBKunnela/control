package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
)

// demo is a demo's two inputs as dev takes them: a configuration without the
// keys dev sets, and a policy document.
type demo struct {
	config, policy string
}

// writeDemo writes a demo whose plane runs APPROVE over the live document,
// calls upstream, reads its pause file as often as it may and holds exported
// records for linger, with extra appended to the configuration.
func writeDemo(t *testing.T, upstream, linger, extra string) demo {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, `mode: APPROVE
project_id: orders
tenant_id: acme
environment: dev
listener:
  kind: stateless_http
  principal:
    id: agent-runner
  agent:
    id: orders-assistant
policy:
  bundle_id: scenario-fixture
  poll_interval: 1s
pause:
  poll_interval: 100ms
export:
  linger: %s
upstreams:
  - name: orders
    endpoint: %s
    tenant_id: acme
    environment: dev
overrides:
`, linger, upstream)
	for _, lt := range liveTools {
		fp, err := adaptermcp.Fingerprint(lt.tool())
		if err != nil {
			t.Fatalf("fingerprint of %s: %v", lt.name, err)
		}
		fmt.Fprintf(&b, "  - upstream: orders\n    tool: %s\n    fingerprint: %s\n    effect: %s\n    resource_type: order\n    resource_from: /id\n"+
			"    trust_zone: TRUSTED_INTERNAL\n    returns:\n      trust: %s\n      sensitivity: PUBLIC\n", lt.name, fp, lt.effect, lt.returnsTrust)
	}
	b.WriteString(extra)
	dir := t.TempDir()
	d := demo{config: filepath.Join(dir, "demo.yaml"), policy: filepath.Join(dir, "policy.json")}
	if err := os.WriteFile(d.config, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.policy, []byte(liveDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

// runDev runs dev in this process, whose test binary has no approver beside
// it: a refusal that comes first is the one dev prints.
func runDev(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), append([]string{"dev"}, args...), &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

// untouched fails the test when dir was created.
func untouched(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("--state %s was created: %v", dir, err)
	}
}

// TestDevRefusesAProductVariable: a variable of the plane's, which dev would
// not read, is named, its value is not, and nothing is laid out.
func TestDevRefusesAProductVariable(t *testing.T) {
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
	state := filepath.Join(t.TempDir(), "state")
	setEnv(t, "listener.address", "0.0.0.0:0")
	status, stdout, stderr := runDev(t, "--config", d.config, "--policy", d.policy, "--state", state)
	if status != exitFail || !strings.Contains(stderr, brand.Env(gatewayconfig.EnvName("listener.address"))+" is set") ||
		strings.Contains(stderr, "0.0.0.0") || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 1 naming the variable and not its value", status, stdout, stderr)
	}
	untouched(t, state)
}

// TestDevRefusesAPolicyItCannotSign: a document dev reads but the signer
// refuses is refused as the policy before anything is laid out.
func TestDevRefusesAPolicyItCannotSign(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
	if err := os.WriteFile(d.policy, []byte(`{"not":"a policy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	status, stdout, stderr := runDev(t, "--config", d.config, "--policy", d.policy, "--state", state)
	if status != exitFail || !strings.HasPrefix(stderr, brand.Gateway+": dev: --policy: ") || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 1 refusing the policy", status, stdout, stderr)
	}
	untouched(t, state)
}

// TestDevRefusesAnUndeclaredObligationParameter: dev signs the bundle it
// runs, so a document the obligation parameter check refuses is refused as
// the policy, with that refusal, before anything is laid out.
func TestDevRefusesAnUndeclaredObligationParameter(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
	doc := `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"orders","version":"1","serial":1,"maxStaleSeconds":300},` +
		`"rules":[{"id":"r","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_rate","params":{"per_minute":"60"},"advisory":true}],"when":{"action":{"effect":["READ"]}}}]}`
	if err := os.WriteFile(d.policy, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	status, stdout, stderr := runDev(t, "--config", d.config, "--policy", d.policy, "--state", state)
	if status != exitFail || !strings.HasPrefix(stderr, brand.Gateway+": dev: --policy: ") || stdout != "" ||
		!strings.Contains(stderr, "rules: a parameter the obligation's type does not declare or requires") {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 1 refusing the policy for its parameter", status, stdout, stderr)
	}
	untouched(t, state)
}

// TestDevRefusesAnExistingState: a directory that is there, empty or not,
// is refused and left as it was.
func TestDevRefusesAnExistingState(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
	state := t.TempDir()
	status, _, stderr := runDev(t, "--config", d.config, "--policy", d.policy, "--state", state)
	if status != exitFail || !strings.Contains(stderr, "--state "+state+": it exists") {
		t.Fatalf("exit %d, stderr %q; want 1 naming the state", status, stderr)
	}
	if entries, err := os.ReadDir(state); err != nil || len(entries) != 0 {
		t.Errorf("the existing state holds %v, %v", entries, err)
	}
}

// ownedKeys is every key dev owns, spelled here and not taken from the code
// that owns them, each with a value the loader would otherwise take.
var ownedKeys = [][2]string{
	{"listener.address", "127.0.0.1:18080"},
	{"health.address", "127.0.0.1:18081"},
	{"policy.bundle_file", "orders.bundle"},
	{"policy.key_id", "k1"},
	{"policy.public_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	{"policy.statement_file", "orders.statement"},
	{"policy.state_dir", "floors"},
	{"policy.freshness_key_id", "f1"},
	{"policy.freshness_public_key", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="},
	{"approvals.provider", "file"},
	{"approvals.dir", "records"},
	{"approvals.hold_journal_dir", "holds"},
	{"runs.dir", "runs"},
	{"approvals.ttl", "1m"},
	{"approvals.retry_after", "1s"},
	{"approvals.max_held", "3"},
	{"approvals.max_open", "3"},
	{"approvals.max_records", "3"},
	{"approvals.max_record_bytes", "4096"},
	{"approvals.reconcile_max", "3"},
	{"pause.file", "elsewhere/pause.json"},
	{"evidence.dir", "spool"},
	{"export.endpoint", "http://127.0.0.1:4318/v1/logs"},
	{"export.allow_plaintext", "true"},
}

// TestDevRefusesADemoThatSetsWhatDevOwns: each key dev owns, set in the
// demo's configuration, is refused by name before anything is laid out; a
// value the loader refuses by itself is refused as a key dev owns too; and
// the keys dev leaves to the demo are taken.
func TestDevRefusesADemoThatSetsWhatDevOwns(t *testing.T) {
	t.Parallel()
	for _, kv := range append(ownedKeys, [2]string{"export.endpoint", "not a collector"}) {
		t.Run(kv[0]+"="+kv[1], func(t *testing.T) {
			t.Parallel()
			group, leaf, _ := strings.Cut(kv[0], ".")
			d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", fmt.Sprintf("%s:\n  %s: %q\n", group, leaf, kv[1]))
			err := checkDemo(devInputs{config: d.config}, filepath.Join(t.TempDir(), "state"))
			if err == nil || !strings.HasPrefix(err.Error(), kv[0]+": "+d.config+" sets it, and dev owns it") {
				t.Fatalf("checkDemo = %v, want the refusal naming %s", err, kv[0])
			}
		})
	}
	for _, extra := range []string{"", "list:\n  shaping: hide\n", "policy.max_stale: 1m\n"} {
		d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", extra)
		if err := checkDemo(devInputs{config: d.config}, filepath.Join(t.TempDir(), "state")); err != nil {
			t.Errorf("a demo adding %q: %v", extra, err)
		}
	}
}

// TestDevChecksADemoWithoutAStateAgainstNoKnownPath: with no --state the demo
// is held to a state directory whose name nobody can know ahead of dev and
// which is never created, so a link planted in the temporary directory under
// the name dev would otherwise use does not refuse it.
func TestDevChecksADemoWithoutAStateAgainstNoKnownPath(t *testing.T) {
	tmp := t.TempDir()
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
	planted := filepath.Join(tmp, brand.Gateway+"-dev")
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(planted, "approvals")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	if err := checkDemo(devInputs{config: d.config}, ""); err != nil {
		t.Fatalf("checkDemo = %v", err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 1 || entries[0].Name() != brand.Gateway+"-dev" {
		t.Errorf("the temporary directory holds %v, %v; want the planted directory alone", entries, err)
	}
}

// TestDevRefusesAStdioListener: a demo whose agent speaks over a pipe has
// no listener dev can put on the loopback.
func TestDevRefusesAStdioListener(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
	raw, err := os.ReadFile(d.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.config, bytes.Replace(raw, []byte("kind: stateless_http"), []byte("kind: stdio"), 1), 0o600); err != nil { //nolint:gosec // G703: a file under the test's own directory
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	status, _, stderr := runDev(t, "--config", d.config, "--policy", d.policy, "--state", state)
	if status != exitFail || !strings.Contains(stderr, "listener.kind is stdio") {
		t.Fatalf("exit %d, stderr %q; want 1 naming the stdio listener", status, stderr)
	}
	untouched(t, state)
}

// TestDevAddressesAreLoopbackLiterals: an address dev resolved or a demo's
// upstream or decision point names that is not a loopback IP literal is
// refused by the key it came from, a name included; an upstream run as a
// command and a decision point left unset name no address.
func TestDevAddressesAreLoopbackLiterals(t *testing.T) {
	t.Parallel()
	good := func() *gatewayconfig.Config {
		c := &gatewayconfig.Config{}
		c.Listener.Address, c.Health.Address, c.Export.Endpoint = "127.0.0.1:1", "127.0.0.1:2", "http://127.0.0.1:3/v1/logs"
		c.Upstreams = []gatewayconfig.UpstreamConfig{{Command: "orders-server"}, {Endpoint: "http://127.0.0.1/mcp"}}
		c.PDP.Identifier, c.PDP.EvaluationEndpoint = "https://[::1]:8443/pdp", "https://[::1]:8443/pdp/access/v1/evaluation"
		c.PDP.Proxy = "http://user:sesame@127.0.0.1:3128"
		return c
	}
	if err := devAddresses(good()); err != nil {
		t.Fatalf("loopback literals refused: %v", err)
	}
	unset := good()
	unset.PDP = gatewayconfig.PDPConfig{}
	if err := devAddresses(unset); err != nil {
		t.Fatalf("no decision point refused: %v", err)
	}
	for _, c := range []struct {
		key string
		set func(*gatewayconfig.Config)
	}{
		{"listener.address", func(c *gatewayconfig.Config) { c.Listener.Address = "0.0.0.0:1" }},
		{"health.address", func(c *gatewayconfig.Config) { c.Health.Address = "localhost:2" }},
		{"export.endpoint", func(c *gatewayconfig.Config) { c.Export.Endpoint = "http://192.0.2.1:3/v1/logs" }},
		{"upstreams.1.endpoint", func(c *gatewayconfig.Config) { c.Upstreams[1].Endpoint = "http://192.0.2.1/mcp" }},
		{"upstreams.1.endpoint", func(c *gatewayconfig.Config) { c.Upstreams[1].Endpoint = "http://orders.example/mcp" }},
		{"pdp.identifier", func(c *gatewayconfig.Config) { c.PDP.Identifier = "https://192.0.2.1:8443/pdp" }},
		{"pdp.evaluation_endpoint", func(c *gatewayconfig.Config) { c.PDP.EvaluationEndpoint = "https://[2001:db8::1]/access/v1/evaluation" }},
		{"pdp.proxy", func(c *gatewayconfig.Config) { c.PDP.Proxy = "http://user:sesame@192.0.2.1:3128" }},
	} {
		cfg := good()
		c.set(cfg)
		err := devAddresses(cfg)
		if err == nil || !strings.HasPrefix(err.Error(), c.key+": ") || strings.Contains(err.Error(), "sesame") {
			t.Errorf("%s off the loopback: %v", c.key, err)
		}
	}
}

// TestDevRenewsSoonEnoughForItsPollInterval: a statement is renewed every
// third of the budget, and sooner when a long poll interval would let one be
// read so late that it aged past the budget; an interval of half the budget
// or more leaves no period that holds, and is refused.
func TestDevRenewsSoonEnoughForItsPollInterval(t *testing.T) {
	for _, c := range []struct {
		budget, poll, want time.Duration
	}{
		{6 * time.Second, time.Second, 2 * time.Second},
		{6 * time.Second, 2 * time.Second, 2 * time.Second},
		{6 * time.Second, 2500 * time.Millisecond, time.Second},
		{90 * time.Second, time.Second, 30 * time.Second},
		{90 * time.Second, 40 * time.Second, 10 * time.Second},
		{6 * time.Second, 3 * time.Second, 0},
		{6 * time.Second, 4 * time.Second, 0},
	} {
		got, err := renewalEvery(c.budget, c.poll)
		switch {
		case c.want == 0 && (err == nil || !strings.Contains(err.Error(), "policy.poll_interval")):
			t.Errorf("a %v budget polled every %v: %v, %v; want a refusal naming policy.poll_interval", c.budget, c.poll, got, err)
		case c.want != 0 && (err != nil || got != c.want):
			t.Errorf("a %v budget polled every %v: %v, %v; want %v", c.budget, c.poll, got, err, c.want)
		}
	}
}
