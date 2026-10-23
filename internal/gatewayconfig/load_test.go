package gatewayconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/classify"
)

// document is the configuration every loader test starts from: complete in
// its required keys, silent on every bound, one upstream.
const document = `# One gateway that observes one MCP server.
mode: OBSERVE
project_id: orders
tenant_id: acme
environment: dev

listener:
  kind: stateless_http
  address: 127.0.0.1:8080
  origins:
    - http://localhost:5173
  principal:
    id: agent-runner
  agent:
    id: orders-assistant
    framework: example

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

upstreams:
  - name: orders
    endpoint: http://127.0.0.1:1/mcp
`

// write puts the document, with add appended, in a temporary directory and
// clears the product's variables, so nothing of the developer's shell reaches
// the loader.
func write(t *testing.T, add string) string {
	t.Helper()
	return writeDocument(t, document+add)
}

// without is the document with one of its lines removed; a line it does not
// hold is fatal, since removing it would silence nothing.
func without(t *testing.T, line string) string {
	t.Helper()
	out := strings.Replace(document, line+"\n", "", 1)
	if out == document {
		t.Fatalf("the document has no line %q to remove", line)
	}
	return out
}

func writeDocument(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	for _, kv := range os.Environ() {
		if name, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(name, brand.EnvPrefix) {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatalf("unsetting %s: %v", name, err)
			}
		}
	}
	return path
}

// setEnv sets one configuration key through its environment variable for the
// duration of the test.
func setEnv(t *testing.T, path, value string) {
	t.Helper()
	t.Setenv(brand.Env(EnvName(path)), value)
}

func load(t *testing.T, path string) *Config {
	t.Helper()
	cfg, err := Load(path, os.Environ())
	if err != nil {
		t.Fatalf("Load refused a configuration this test builds as valid: %v", err)
	}
	return cfg
}

// TestDefaultsStandWhereTheFileIsSilent pins the bounds a configuration that
// says nothing about them runs with, as literals: a default read from the table
// the loader uses would test nothing.
func TestDefaultsStandWhereTheFileIsSilent(t *testing.T) {
	cfg := load(t, writeDocument(t, without(t, "  allow_plaintext: true")))
	for _, want := range []struct {
		path string
		got  string
		want string
	}{
		{"log.level", cfg.LogLevel, "info"},
		{"listener.principal.type", cfg.Listener.PrincipalType, "service"},
		{"health.address", cfg.Health.Address, "127.0.0.1:8081"},
		{"evidence.fsync", cfg.Evidence.Fsync, "every_record"},
		{"evidence.on_unwritable", cfg.Evidence.OnUnwritable, "block"},
		{"list.shaping", cfg.List.Shaping, "none"},
		{"policy.max_stale", cfg.Policy.MaxStale.String(), "10m0s"},
		{"approvals.ttl", cfg.Approvals.TTL.String(), "15m0s"},
		{"approvals.retry_after", cfg.Approvals.RetryAfter.String(), "30s"},
		{"export.timeout", cfg.Export.Timeout.String(), "10s"},
		{"upstream.call_timeout", cfg.Upstream.CallTimeout.String(), "30s"},
	} {
		if want.got != want.want {
			t.Errorf("%s is %q, want %q", want.path, want.got, want.want)
		}
	}
	for _, want := range []struct {
		path string
		got  int64
		want int64
	}{
		{"evidence.max_bytes", cfg.Evidence.MaxBytes, 1 << 30},
		{"evidence.segment_bytes", cfg.Evidence.SegmentBytes, 64 << 20},
		{"evidence.closing_reserve", cfg.Evidence.ClosingReserve, 64 << 10},
	} {
		if want.got != want.want {
			t.Errorf("%s is %d, want %d", want.path, want.got, want.want)
		}
	}
	if cfg.Approvals.MaxHeld != 128 || cfg.Approvals.MaxOpen != 256 || cfg.Export.InFlight != 4 || cfg.Export.MaxBatch != 128 {
		t.Errorf("the bounds are %d held, %d open, %d in flight, %d per batch", cfg.Approvals.MaxHeld, cfg.Approvals.MaxOpen, cfg.Export.InFlight, cfg.Export.MaxBatch)
	}
	if cfg.Policy.FailOpenRead {
		t.Error("fail-open reads are on by default; the safe default is off")
	}
	if cfg.Export.AllowPlaintext {
		t.Error("a plaintext collector is allowed by default; the safe default is off")
	}
}

// TestTheFileIsRead holds what the document says, so a parser that dropped a
// nested key or a sequence entry cannot pass.
func TestTheFileIsRead(t *testing.T) {
	cfg := load(t, write(t, ""))
	switch {
	case cfg.ModeName != "OBSERVE":
		t.Errorf("mode is %q", cfg.ModeName)
	case cfg.Listener.PrincipalID != "agent-runner":
		t.Errorf("listener.principal.id is %q", cfg.Listener.PrincipalID)
	case cfg.Listener.AgentFramework != "example":
		t.Errorf("listener.agent.framework is %q", cfg.Listener.AgentFramework)
	case len(cfg.Listener.Origins) != 1 || cfg.Listener.Origins[0] != "http://localhost:5173":
		t.Errorf("listener.origins is %q", cfg.Listener.Origins)
	case len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Name != "orders" || cfg.Upstreams[0].Endpoint != "http://127.0.0.1:1/mcp":
		t.Errorf("upstreams is %+v", cfg.Upstreams)
	}
}

// TestSourcesNameWhatSetEachKey: the file's keys carry their line, a key the
// environment set carries the variable, and a key at its default is absent,
// which is what `doctor` prints beside every value.
func TestSourcesNameWhatSetEachKey(t *testing.T) {
	path := write(t, "")
	setEnv(t, "approvals.ttl", "90s")
	cfg := load(t, path)
	sources := cfg.Sources()
	if got := sources["mode"]; got != path+":2" {
		t.Errorf("mode's source is %q, want the file's line 2", got)
	}
	if got := sources["approvals.ttl"]; got != brand.Env("APPROVALS_TTL") {
		t.Errorf("approvals.ttl's source is %q, want the variable", got)
	}
	if _, ok := sources["health.address"]; ok {
		t.Error("health.address stands at its default and has a source")
	}
	if len(sources) != 25 {
		t.Errorf("%d keys have a source, want the document's 24 and the variable", len(sources))
	}
	sources["mode"] = "elsewhere"
	if cfg.Sources()["mode"] == "elsewhere" {
		t.Error("Sources returned the loader's own map, so a caller can rewrite where a key came from")
	}
}

// TestSettingsFollowTheTable: every scalar key in the table's order, showing
// the value the configuration holds and not the default.
func TestSettingsFollowTheTable(t *testing.T) {
	path := write(t, "")
	setEnv(t, "approvals.max_held", "7")
	settings := load(t, path).Settings()
	if len(settings) != len(configFields) {
		t.Fatalf("%d settings, want one per scalar key (%d)", len(settings), len(configFields))
	}
	if settings[0].Path != "mode" || settings[0].Value != "OBSERVE" {
		t.Errorf("the first setting is %+v, want mode OBSERVE", settings[0])
	}
	for _, s := range settings {
		if s.Path == "approvals.max_held" && s.Value != "7" {
			t.Errorf("approvals.max_held shows %q, want the environment's 7", s.Value)
		}
	}
}

// TestResolveIsAgainstTheFilesDirectory: a relative path means the same thing
// wherever the program is started, and an absolute one is left alone.
func TestResolveIsAgainstTheFilesDirectory(t *testing.T) {
	path := write(t, "")
	cfg := load(t, path)
	if got, want := cfg.Resolve("spool"), filepath.Join(filepath.Dir(path), "spool"); got != want {
		t.Errorf("Resolve(spool) = %q, want %q", got, want)
	}
	abs := filepath.Join(string(filepath.Separator), "var", "spool")
	if got := cfg.Resolve(abs); got != abs {
		t.Errorf("Resolve(%q) = %q, want it unchanged", abs, got)
	}
	if got := cfg.Resolve(""); got != "" {
		t.Errorf("Resolve(\"\") = %q, want the empty path back", got)
	}
}

// TestModeAndZoneAreTheContractsValues: the spellings the table admits map to
// the contract's numbers, and an empty zone is UNSPECIFIED.
func TestModeAndZoneAreTheContractsValues(t *testing.T) {
	cfg := load(t, write(t, ""))
	mode, err := cfg.Mode()
	if err != nil || mode.String() != "ENFORCEMENT_MODE_OBSERVE" {
		t.Errorf("Mode() = %v, %v", mode, err)
	}
	cfg.ModeName = "AUDIT"
	if _, err := cfg.Mode(); err == nil {
		t.Error("Mode() accepted a spelling the contract does not declare")
	}
	for _, c := range []struct {
		zone string
		want string
	}{{"", "TRUST_ZONE_UNSPECIFIED"}, {"PARTNER", "TRUST_ZONE_PARTNER"}} {
		got, err := (&OverrideConfig{Spelling: classify.Spelling{Effect: "READ", ResourceType: "r", TrustZone: c.zone}}).Classification()
		if err != nil || got.TrustZone.String() != c.want {
			t.Errorf("trust_zone %q = %v, %v, want %s", c.zone, got.TrustZone, err, c.want)
		}
	}
	if _, err := (&OverrideConfig{Spelling: classify.Spelling{Effect: "READ", ResourceType: "r", TrustZone: "INTERNAL"}}).Classification(); err == nil {
		t.Error("Classification() accepted a zone the contract does not declare")
	}
}

// TestTheEnvironmentWinsOverTheFile is the rule an operator relies on to keep a
// credential and a per-host path out of a file under version control.
func TestTheEnvironmentWinsOverTheFile(t *testing.T) {
	path := write(t, "")
	setEnv(t, "mode", "ENFORCE")
	setEnv(t, "approvals.ttl", "90s")
	setEnv(t, "upstreams.0.name", "billing")
	cfg := load(t, path)
	switch {
	case cfg.ModeName != "ENFORCE":
		t.Errorf("mode is %q, want the environment's", cfg.ModeName)
	case cfg.Approvals.TTL != 90*time.Second:
		t.Errorf("approvals.ttl is %v, want the environment's", cfg.Approvals.TTL)
	case cfg.Upstreams[0].Name != "billing":
		t.Errorf("upstreams.0.name is %q, want the environment's", cfg.Upstreams[0].Name)
	}
	if where := cfg.Sources()["mode"]; where != brand.Env(EnvName("mode")) {
		t.Errorf("mode's source is %q, want the variable that set it", where)
	}
}

// TestAHeaderComesFromTheEnvironment keeps a collector's credential out of
// the file: the variable's underscores are the header's hyphens.
func TestAHeaderComesFromTheEnvironment(t *testing.T) {
	path := write(t, "")
	t.Setenv(brand.EnvPrefix+EnvName(HeadersPrefix)+"X_API_KEY", "s3cret-token")
	cfg := load(t, path)
	if cfg.Export.Headers["X-Api-Key"] != "s3cret-token" {
		t.Fatalf("export.headers is %v, want the variable's header", cfg.Export.Headers)
	}
}

// TestEveryRefusalNamesWhatIsWrong is the table of configurations the loader
// will not return. Each case is the smallest change to the document that
// makes it wrong, and each message has to name the key, because an operator
// reads the message and not this file.
func TestEveryRefusalNamesWhatIsWrong(t *testing.T) {
	for _, c := range []struct {
		name  string
		add   string
		env   [2]string
		wants string
	}{
		{name: "a key nothing declares", add: "spool_dir: /tmp/x\n", wants: "is not a configuration key"},
		{name: "a nested key nothing declares", add: "policy:\n  bundle_key: k\n", wants: "policy.bundle_key is not a configuration key"},
		{name: "a key set twice", add: "mode: ENFORCE\n", wants: "is set twice"},
		{name: "a mode this build does not name", env: [2]string{"mode", "AUDIT"}, wants: "not one of OBSERVE"},
		{name: "a duration that is not one", env: [2]string{"approvals.ttl", "soon"}, wants: "not a duration"},
		{name: "a byte count that is not one", env: [2]string{"evidence.max_bytes", "lots"}, wants: "not a byte count"},
		{name: "an integer that is not one", env: [2]string{"approvals.max_held", "many"}, wants: "not an integer"},
		{name: "a boolean that is not one", env: [2]string{"policy.fail_open_read", "yes"}, wants: "not true or false"},
		{name: "a required key with no value", env: [2]string{"project_id", ""}, wants: "project_id: no value"},
		{name: "shaping in a mode that does not enforce", env: [2]string{"list.shaping", "hide"}, wants: "shaping is none in a mode that does not enforce"},
		{name: "an interval policy with no interval", env: [2]string{"evidence.fsync", "interval"}, wants: "evidence.fsync_interval: the interval policy needs a positive interval"},
		{name: "an interval under the every-record policy", env: [2]string{"evidence.fsync_interval", "5s"}, wants: "only the interval policy takes one"},
		{name: "a segment larger than the budget", env: [2]string{"evidence.segment_bytes", "2GiB"}, wants: "is over evidence.max_bytes"},
		{name: "a collector endpoint that is not a URL", env: [2]string{"export.endpoint", "collector:4318"}, wants: "export.endpoint"},
		{name: "an upstream with no transport", env: [2]string{"upstreams.0.endpoint", ""}, wants: "name either an endpoint or a command"},
		{name: "an upstream with two transports", env: [2]string{"upstreams.0.command", "/bin/echo"}, wants: "name either an endpoint or a command"},
		{name: "an upstream endpoint that is not a URL", env: [2]string{"upstreams.0.endpoint", "orders:8080"}, wants: "upstreams.0.endpoint"},
		{name: "an address on a listener that binds nothing", env: [2]string{"listener.kind", "stdio"}, wants: "a stdio listener serves one agent over a pipe"},
		{name: "a loopback origin on a listener the network reaches", env: [2]string{"listener.address", "0.0.0.0:8080"}, wants: "a loopback origin is admitted only"},
		{name: "an upstream the file does not declare", env: [2]string{"upstreams.1.name", "billing"}, wants: "it does not add one"},
		{name: "an override of an upstream nothing serves", add: overrideOf("billing"), wants: "is not a configured upstream"},
		{name: "an override with no fingerprint", add: overrideWithout("fingerprint"), wants: "overrides.0.fingerprint: no value"},
		{name: "an effect class the contract does not name", add: overrideEffect("INSPECT"), wants: "not one of READ"},
		{name: "an effect class the contract never had", add: overrideEffect("ADMIN"), wants: "overrides.0.effect: not one of READ"},
		{name: "the effect class nobody declared", add: overrideEffect("UNSPECIFIED"), wants: "overrides.0.effect: not one of READ"},
		{name: "a file over the bound", add: strings.Repeat("# padding\n", maxConfigBytes/10+1), wants: "over 1048576 bytes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := write(t, c.add)
			if c.env[0] != "" {
				setEnv(t, c.env[0], c.env[1])
			}
			_, err := Load(path, os.Environ())
			if err == nil {
				t.Fatalf("the loader accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Errorf("the refusal is %q, which does not name %q", err.Error(), c.wants)
			}
		})
	}
}

// TestAFileAtTheBoundIsRead: the bound bites one byte past it, not at it.
func TestAFileAtTheBoundIsRead(t *testing.T) {
	padding := strings.Repeat("#", maxConfigBytes-len(document)-1) + "\n"
	cfg := load(t, write(t, padding))
	if cfg.ModeName != "OBSERVE" {
		t.Errorf("mode is %q after a file exactly at the bound", cfg.ModeName)
	}
}

// TestAVariableThatNamesNoKeyIsRefused: a misspelled variable that is ignored
// is a setting the operator believes is in force.
func TestAVariableThatNamesNoKeyIsRefused(t *testing.T) {
	path := write(t, "")
	t.Setenv(brand.Env("EVIDENCE_DIRECTORY"), "/var/tmp")
	_, err := Load(path, os.Environ())
	if err == nil {
		t.Fatal("the loader ignored a variable under the product's prefix that names no key")
	}
	if !strings.Contains(err.Error(), "names no configuration key") {
		t.Errorf("the refusal is %q", err.Error())
	}
}

// TestAVariableOfAnotherProductIsLeftAlone: only the product's own prefix is
// read, so a host running several tools has no collisions.
func TestAVariableOfAnotherProductIsLeftAlone(t *testing.T) {
	path := write(t, "")
	t.Setenv("OTHER_TOOL_MODE", "ENFORCE")
	if cfg := load(t, path); cfg.ModeName != "OBSERVE" {
		t.Errorf("mode is %q; a variable of another product was read", cfg.ModeName)
	}
}

func overrideOf(upstream string) string {
	return "\noverrides:\n  - upstream: " + upstream + "\n    tool: read_order\n    fingerprint: abc\n" +
		"    effect: READ\n    resource_type: order\n    resource_from: /id\n    trust_zone: PARTNER\n"
}

func overrideWithout(key string) string {
	out := overrideOf("orders")
	return strings.ReplaceAll(out, "    "+key+": abc\n", "")
}

func overrideEffect(effect string) string {
	return strings.ReplaceAll(overrideOf("orders"), "effect: READ", "effect: "+effect)
}

// TestASequenceIndexIsSpelledOnce: an index of the upstreams or of their
// arguments that is negative, written a second way or past the items read is
// refused, from the file and from the environment, and never crashes the
// loader.
func TestASequenceIndexIsSpelledOnce(t *testing.T) {
	withArgs := func(items string) string {
		return strings.Replace(document, "    endpoint: http://127.0.0.1:1/mcp\n", "    command: /bin/echo\n    args:\n"+items, 1)
	}
	for _, c := range []struct {
		name  string
		doc   string
		env   string
		wants string
	}{
		{name: "upstreams.0.args.-1", doc: withArgs("      -1: x\n"), wants: "args takes a sequence"},
		{name: "upstreams.0.args.00", doc: withArgs("      0: a\n      00: b\n"), wants: "args takes a sequence"},
		{name: "upstreams.0.args.+0", doc: withArgs("      0: a\n      +0: b\n"), wants: "args takes a sequence"},
		{name: "upstreams.0.args past the items", doc: withArgs("      1: a\n"), wants: "args takes a sequence"},
		{name: "upstreams.00.name", doc: document + "upstreams:\n  00:\n    name: billing\n", wants: "upstreams.00.name is not a configuration key"},
		{name: "upstreams.-1.name", doc: document + "upstreams:\n  -1:\n    name: billing\n", wants: "upstreams.-1.name is not a configuration key"},
		{name: "upstreams.2.name", doc: document + "upstreams:\n  2:\n    name: billing\n", wants: "upstreams.2.name follows no entry 1"},
		{name: "UPSTREAMS_00_NAME", doc: document, env: "UPSTREAMS_00_NAME", wants: "names no upstreams entry"},
		{name: "UPSTREAMS_-1_NAME", doc: document, env: "UPSTREAMS_-1_NAME", wants: "names no upstreams entry"},
		{name: "UPSTREAMS_0_ARGS_00", doc: withArgs("      - a\n"), env: "UPSTREAMS_0_ARGS_00", wants: "names no upstreams entry"},
		{name: "UPSTREAMS_0_ARGS_-1", doc: withArgs("      - a\n"), env: "UPSTREAMS_0_ARGS_-1", wants: "names no upstreams entry"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeDocument(t, c.doc)
			if c.env != "" {
				t.Setenv(brand.Env(c.env), "billing")
			}
			err := loadRecovering(t, path)
			if err == nil {
				t.Fatalf("the loader accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Errorf("the refusal is %q, which does not say %q", err, c.wants)
			}
		})
	}
}

// loadRecovering loads path and turns a panic into the test's failure, so a
// crash names the case that caused it.
func loadRecovering(t *testing.T, path string) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the loader panicked: %v", r)
		}
	}()
	_, err = Load(path, os.Environ())
	return err
}

// A mode is never assumed: OBSERVE runs every call whatever the verdict, so a
// document that names no mode would otherwise fail open without saying so.
func TestAConfigurationNamingNoModeIsRefused(t *testing.T) {
	_, err := Load(writeDocument(t, without(t, "mode: OBSERVE")), os.Environ())
	if err == nil || !strings.Contains(err.Error(), "mode: no value, and it has no default") {
		t.Fatalf("Load = %v, want the missing mode named", err)
	}
	path := writeDocument(t, without(t, "mode: OBSERVE"))
	setEnv(t, "mode", "ENFORCE")
	if cfg := load(t, path); cfg.ModeName != "ENFORCE" {
		t.Errorf("mode from the variable = %q, want ENFORCE", cfg.ModeName)
	}
}
