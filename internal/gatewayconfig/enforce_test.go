package gatewayconfig

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	"github.com/guardana/control/internal/brand"
)

// enforceDocument is a plane serving the enforcement API: complete in its
// required keys, silent on every bound, one tool and no upstream.
const enforceDocument = `mode: OBSERVE
project_id: orders
tenant_id: acme
environment: dev

listener:
  kind: enforce_api
  socket: /run/plane/enforce.sock
  execution_lifetime: 30s
  principal:
    id: agent-runner
  agent:
    id: refund-worker

runs:
  dir: runs

policy:
  bundle_id: fixture
  bundle_file: policy.bundle
  key_id: k1
  public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  statement_file: policy.statement
  state_dir: floors
  freshness_key_id: f1
  freshness_public_key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
  poll_interval: 5s

evidence:
  dir: spool

export:
  endpoint: http://127.0.0.1:4318/v1/logs
  allow_plaintext: true

tools:
  - name: refund
    effect: TRANSACT
    provider: payments
    resource_type: order
    resource_from: /order_id
`

// enforceWithout is enforceDocument with one of its lines removed; a line it
// does not hold is fatal, since removing it would silence nothing.
func enforceWithout(t *testing.T, lines ...string) string {
	t.Helper()
	out := enforceDocument
	for _, line := range lines {
		next := strings.Replace(out, line+"\n", "", 1)
		if next == out {
			t.Fatalf("the document has no line %q to remove", line)
		}
		out = next
	}
	return out
}

// refusedSaying loads doc with the variables env sets and fails unless the
// refusal says want.
func refusedSaying(t *testing.T, doc string, env map[string]string, want string) {
	t.Helper()
	path := writeDocument(t, doc)
	for key, value := range env {
		setEnv(t, key, value)
	}
	_, err := Load(path, os.Environ())
	if err == nil {
		t.Fatalf("accepted; want a refusal saying %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal is %q, which does not say %q", err, want)
	}
}

// TestAnEnforceAPIListenerLoads: the listener, its bounds and its tool table
// read as written, the body bound stands at 128 KiB when silent, and a tool
// silent on its trust declares none.
func TestAnEnforceAPIListenerLoads(t *testing.T) {
	cfg := load(t, writeDocument(t, enforceDocument))
	l := cfg.Listener
	if l.Kind != "enforce_api" || l.Socket != "/run/plane/enforce.sock" || l.ExecutionLifetime != 30*time.Second || l.MaxBodyBytes != 131072 {
		t.Errorf("the listener loaded as %+v", l)
	}
	if cfg.Resolve(l.Socket) != "/run/plane/enforce.sock" {
		t.Errorf("an absolute socket resolves to %q", cfg.Resolve(l.Socket))
	}
	want := ToolConfig{Name: "refund", Effect: "TRANSACT", Provider: "payments", ResourceType: "order", ResourceFrom: "/order_id"}
	if len(cfg.Tools) != 1 || cfg.Tools[0] != want {
		t.Fatalf("the tools loaded as %+v, want [%+v]", cfg.Tools, want)
	}
	if got, want := trustOf(&cfg.Tools[0]), "TRUST_ZONE_UNSPECIFIED TRUST_ZONE_UNSPECIFIED SENSITIVITY_UNSPECIFIED"; got != want {
		t.Errorf("a tool silent on its trust reads as %s, want %s", got, want)
	}
}

// trustOf is the tool's destination zone, returned trust and returned
// sensitivity as the contract names them, or the first error.
func trustOf(tool *ToolConfig) string {
	zone, err := tool.Zone()
	if err != nil {
		return err.Error()
	}
	trust, err := tool.ReturnsZone()
	if err != nil {
		return err.Error()
	}
	level, err := tool.ReturnsLevel()
	if err != nil {
		return err.Error()
	}
	return zone.String() + " " + trust.String() + " " + level.String()
}

// TestAToolDeclaresItsTrust: trust_zone, returns.trust and returns.sensitivity
// are read as the contract's values, each into its own field.
func TestAToolDeclaresItsTrust(t *testing.T) {
	cfg := load(t, writeDocument(t, enforceDocument+"    trust_zone: PARTNER\n    returns:\n      trust: TRUSTED_INTERNAL\n      sensitivity: CONFIDENTIAL\n"))
	if got, want := trustOf(&cfg.Tools[0]), "TRUST_ZONE_PARTNER TRUST_ZONE_TRUSTED_INTERNAL SENSITIVITY_CONFIDENTIAL"; got != want {
		t.Errorf("the tool's trust reads as %s, want %s", got, want)
	}
}

// TestAnEnforceAPIListenerNeedsASocket: it serves on a Unix socket and binds
// no address, and the refusals name the key.
func TestAnEnforceAPIListenerNeedsASocket(t *testing.T) {
	refusedSaying(t, enforceWithout(t, "  socket: /run/plane/enforce.sock"), nil, "listener.socket: ")
	refusedSaying(t, enforceDocument, map[string]string{"listener.address": "127.0.0.1:8080"}, "listener.address: ")
	refusedSaying(t, enforceDocument, map[string]string{"listener.address": ""}, "listener.address: ")
	refusedSaying(t, strings.Replace(enforceDocument, "  socket:", "  origins:\n    - http://localhost:5173\n  socket:", 1), nil, "listener.origins: ")
}

// TestTheMCPKindsRefuseTheEnforceAPIKeys: a key only the enforcement API reads
// is refused on every MCP kind, naming the key and the kind; the document
// silent on them is the control.
func TestTheMCPKindsRefuseTheEnforceAPIKeys(t *testing.T) {
	tools := "\ntools:\n  - name: refund\n    effect: TRANSACT\n    provider: payments\n    resource_type: order\n"
	for _, kind := range []string{"stateless_http", "stateful_http", "stdio"} {
		doc := document
		if kind == "stdio" {
			doc = without(t, "  address: 127.0.0.1:8080")
		}
		t.Run(kind, func(t *testing.T) {
			if _, err := Load(writeDocument(t, doc), append(os.Environ(), envOf("listener.kind", kind))); err != nil {
				t.Fatalf("the control was refused: %v", err)
			}
			for key, value := range map[string]string{
				"listener.socket":             "sock/enforce.sock",
				"listener.execution_lifetime": "30s",
				"listener.max_body_bytes":     "128KiB",
			} {
				refusedSaying(t, doc, map[string]string{"listener.kind": kind, key: value}, key+": ")
				refusedSaying(t, doc, map[string]string{"listener.kind": kind, key: value}, kind)
			}
			refusedSaying(t, doc+tools, map[string]string{"listener.kind": kind}, "tools: ")
		})
	}
}

func envOf(path, value string) string {
	return brand.Env(EnvName(path)) + "=" + value
}

// TestTheExecutionLifetimeIsRequiredAndBounded: no default, one second to an
// hour, at each bound and not one step past it.
func TestTheExecutionLifetimeIsRequiredAndBounded(t *testing.T) {
	refusedSaying(t, enforceWithout(t, "  execution_lifetime: 30s"), nil, "listener.execution_lifetime: no value")
	for value, want := range map[string]time.Duration{"1s": time.Second, "1h": time.Hour, "5m": 5 * time.Minute} {
		path := writeDocument(t, enforceDocument)
		setEnv(t, "listener.execution_lifetime", value)
		cfg, err := Load(path, os.Environ())
		if err != nil {
			t.Fatalf("%s was refused: %v", value, err)
		}
		if cfg.Listener.ExecutionLifetime != want {
			t.Errorf("%s reads as %v, want %v", value, cfg.Listener.ExecutionLifetime, want)
		}
	}
	for _, value := range []string{"999ms", "1h0m0.001s", "0s", "-1s"} {
		refusedSaying(t, enforceDocument, map[string]string{"listener.execution_lifetime": value}, "listener.execution_lifetime: ")
	}
}

// TestTheBodyBoundIsBounded: 1 KiB to 256 KiB, at each bound and not one byte
// past it.
func TestTheBodyBoundIsBounded(t *testing.T) {
	for value, want := range map[string]int64{"1KiB": 1024, "256KiB": 262144, "65536": 65536} {
		path := writeDocument(t, enforceDocument)
		setEnv(t, "listener.max_body_bytes", value)
		cfg, err := Load(path, os.Environ())
		if err != nil {
			t.Fatalf("%s was refused: %v", value, err)
		}
		if cfg.Listener.MaxBodyBytes != want {
			t.Errorf("%s reads as %d, want %d", value, cfg.Listener.MaxBodyBytes, want)
		}
	}
	for _, value := range []string{"1023", "262145", "0"} {
		refusedSaying(t, enforceDocument, map[string]string{"listener.max_body_bytes": value}, "listener.max_body_bytes: ")
	}
}

// TestTheBoundsAreTheAdapters: the configuration admits exactly what the
// enforcement adapter takes, so no value doctor passes is one run refuses.
func TestTheBoundsAreTheAdapters(t *testing.T) {
	if minExecutionLifetime != enforce.MinExecutionLifetime || maxExecutionLifetime != enforce.MaxExecutionLifetime {
		t.Errorf("the lifetime is bounded %v to %v here, %v to %v by the adapter",
			minExecutionLifetime, maxExecutionLifetime, enforce.MinExecutionLifetime, enforce.MaxExecutionLifetime)
	}
	if minBodyBytes != enforce.MinBodyBytes || maxBodyBytes != enforce.MaxBodyBytes {
		t.Errorf("the body is bounded %d to %d here, %d to %d by the adapter", minBodyBytes, maxBodyBytes, enforce.MinBodyBytes, enforce.MaxBodyBytes)
	}
	cfg := load(t, writeDocument(t, enforceDocument))
	if cfg.Listener.MaxBodyBytes != enforce.DefaultBodyBytes {
		t.Errorf("the body bound defaults to %d here, %d in the adapter", cfg.Listener.MaxBodyBytes, enforce.DefaultBodyBytes)
	}
}

// TestAnEnforceAPIListenerNeedsARunsDirectory: every request presents a run
// token, and with no runs directory no token resolves.
func TestAnEnforceAPIListenerNeedsARunsDirectory(t *testing.T) {
	refusedSaying(t, enforceWithout(t, "runs:", "  dir: runs"), nil, "runs.dir: ")
}

// TestAnEnforceAPIListenerRefusesTheMCPSide: upstreams, overrides and the keys
// that bound an upstream or shape a tool list apply to nothing here.
func TestAnEnforceAPIListenerRefusesTheMCPSide(t *testing.T) {
	refusedSaying(t, enforceDocument+"\nupstreams:\n  - name: orders\n    endpoint: http://127.0.0.1:1/mcp\n", nil, "upstreams: ")
	refusedSaying(t, enforceDocument+"\noverrides:\n  - upstream: orders\n    tool: read_order\n    fingerprint: sha256:00\n    effect: READ\n    resource_type: order\n", nil, "overrides: ")
	for key, value := range map[string]string{
		"upstream.call_timeout": "30s",
		"upstream.list_timeout": "10s",
		"list.shaping":          "none",
		"list.ttl":              "1m",
	} {
		refusedSaying(t, enforceDocument, map[string]string{key: value}, key+": ")
	}
}

// TestAnEnforceAPIListenerNeedsATool: an empty table would leave every call
// unclassified.
func TestAnEnforceAPIListenerNeedsATool(t *testing.T) {
	doc := enforceWithout(t, "tools:", "  - name: refund", "    effect: TRANSACT", "    provider: payments",
		"    resource_type: order", "    resource_from: /order_id")
	refusedSaying(t, doc, nil, "tools: ")
}

// TestAToolNeedsItsKeys: a name, an effect, a provider and a resource type
// are each required, and the refusal names the entry's key; resource_from may
// be left out.
func TestAToolNeedsItsKeys(t *testing.T) {
	for _, line := range []string{"effect: TRANSACT", "provider: payments", "resource_type: order"} {
		key, _, _ := strings.Cut(line, ":")
		refusedSaying(t, enforceWithout(t, "    "+line), nil, "tools.0."+key+": no value")
	}
	refusedSaying(t, strings.Replace(enforceDocument, "  - name: refund\n    effect:", "  - effect:", 1), nil, "tools.0.name: no value")
	if cfg := load(t, writeDocument(t, enforceWithout(t, "    resource_from: /order_id"))); cfg.Tools[0].ResourceFrom != "" {
		t.Errorf("resource_from left out reads as %q", cfg.Tools[0].ResourceFrom)
	}
}

// TestAToolTakesTheContractsValues: the effect, the trust zones and the
// sensitivity take the spellings an override takes but SPAWN_OR_DELEGATE,
// which needs a delegation the API does not carry, and nothing else; a key
// an override does not have, or a tenant of its own, is not a key.
func TestAToolTakesTheContractsValues(t *testing.T) {
	for _, c := range []struct{ key, value string }{
		{"effect", "PAY"},
		{"effect", "transact"},
		{"effect", "SPAWN_OR_DELEGATE"},
		{"trust_zone", "INTERNAL"},
		{"returns.trust", "SECRET"},
		{"returns.sensitivity", "TRUSTED_INTERNAL"},
	} {
		refusedSaying(t, enforceDocument, map[string]string{"tools.0." + c.key: c.value}, "tools.0."+c.key+": not one of")
	}
	for _, key := range []string{"tenant_id", "environment", "fingerprint", "upstream"} {
		refusedSaying(t, enforceDocument+"    "+key+": x\n", nil, "tools.0."+key+" is not a configuration key")
	}
}

// TestAToolNameIsUnique: the adapter refuses a second entry of one name, so
// the loader names both; one name in another case is another tool.
func TestAToolNameIsUnique(t *testing.T) {
	entry := func(name, effect string) string {
		return "  - name: " + name + "\n    effect: " + effect + "\n    provider: payments\n    resource_type: order\n"
	}
	refusedSaying(t, enforceDocument+entry("lookup", "READ")+entry("refund", "READ"), nil, `tools.2: the tool "refund" is classified by tools.0 already`)
	if cfg := load(t, writeDocument(t, enforceDocument+entry("Refund", "READ"))); len(cfg.Tools) != 2 {
		t.Errorf("two tools of two names loaded as %+v", cfg.Tools)
	}
}

// TestTheEnvironmentReachesATool: a variable sets a key of a tool the file
// declares and wins over it, and never adds one.
func TestTheEnvironmentReachesATool(t *testing.T) {
	path := writeDocument(t, enforceDocument)
	setEnv(t, "tools.0.effect", "WRITE")
	cfg, err := Load(path, os.Environ())
	if err != nil || cfg.Tools[0].Effect != "WRITE" {
		t.Fatalf("tools.0.effect from the environment: %v, %+v", err, cfg)
	}
	refusedSaying(t, enforceDocument, map[string]string{"tools.1.effect": "READ"}, "names no tools entry the file declares")
}

// TestUnsetLifetimeIsPrintedEmpty: doctor shows a lifetime nobody set as no
// value rather than a zero that reads as a bound.
func TestUnsetLifetimeIsPrintedEmpty(t *testing.T) {
	cfg := load(t, write(t, ""))
	for _, s := range cfg.Settings() {
		if s.Path == "listener.execution_lifetime" {
			if s.Value != "" {
				t.Errorf("an unset lifetime prints as %q", s.Value)
			}
			return
		}
	}
	t.Error("the settings list no listener.execution_lifetime")
}
