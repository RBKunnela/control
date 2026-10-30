package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
)

// coverageTree is an inventory, a plane's configuration, a source descriptor
// and its log directory, each as an operator would leave them.
type coverageTree struct{ dir, inventory, plane, source, log string }

const coverageInventory = `{"schema_version":"0.1","paths":[
 {"id":"orders.read-file","kind":"mcp_tool","upstream":"orders","tool":"read_file",
  "sources":[{"source_id":"agent-runtime","name":"read_file","server_address":"files.example"}]}%s
]}`

const coveragePlane = `mode: ENFORCE
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
    environment: dev

overrides:
  - upstream: orders
    tool: read_file
    fingerprint: sha256:00
    effect: WRITE
    resource_type: file
    resource_from: /path
`

// freshSpan is one OTLP/JSON line of the descriptor's service with one tool
// call, its times filled in by the caller.
const freshSpan = `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"support-agent"}}]},` +
	`"scopeSpans":[{"scope":{"name":"agent-sdk","version":"1.0.0"},"schemaUrl":"https://opentelemetry.io/schemas/1.41.0","spans":[` +
	`{"traceId":"4bf92f3577b34da6a3ce929d0e0e4736","spanId":"00f067aa0ba90001","name":"span-1","kind":3,` +
	`"startTimeUnixNano":"%d","endTimeUnixNano":"%d","attributes":[` +
	`{"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},` +
	`{"key":"gen_ai.tool.name","value":{"stringValue":"read_file"}},` +
	`{"key":"server.address","value":{"stringValue":"files.example"}}],"status":{"code":1}}]}],` +
	`"schemaUrl":"https://opentelemetry.io/schemas/1.41.0"}]}` + "\n"

func newCoverageTree(t *testing.T, morePaths string) coverageTree {
	t.Helper()
	dir := t.TempDir()
	tr := coverageTree{dir: dir, inventory: filepath.Join(dir, "inventory.json"), plane: filepath.Join(dir, "gateway.yaml"),
		source: filepath.Join(dir, "source.json"), log: filepath.Join(dir, "log")}
	descriptor, err := os.ReadFile("testdata/observe/descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, tr.inventory, fmt.Sprintf(coverageInventory, morePaths))
	writeFixture(t, tr.plane, coveragePlane)
	writeFixture(t, tr.source, string(descriptor))
	if err := os.Mkdir(tr.log, 0o700); err != nil {
		t.Fatal(err)
	}
	return tr
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil { //nolint:gosec // G703: a path in this test's own directory
		t.Fatal(err)
	}
}

// importFresh imports one tool call that ended a second ago, so the source
// is live within its heartbeat.
func (tr coverageTree) importFresh(t *testing.T) {
	t.Helper()
	end := time.Now().Add(-time.Second).UnixNano()
	input := filepath.Join(tr.dir, "spans.jsonl")
	writeFixture(t, input, fmt.Sprintf(freshSpan, end-int64(time.Second), end))
	if code, out, stderr := invoke(t, "observe", "import", "--source", tr.source, "--log", tr.log, input); code != exitOK {
		t.Fatalf("import: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}

func (tr coverageTree) args(extra ...string) []string {
	return append([]string{"coverage", "--inventory", tr.inventory, "--source", tr.source, "--log", tr.log}, extra...)
}

func outputLines(stdout string) []string {
	return strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
}

// TestCoverageOfAnEnforcedObservedPathExitsZero: a path a plane in ENFORCE
// classifies and a live source observed prints its line, the plane's and the
// source's beside it, and the standing row last, and exits 0.
func TestCoverageOfAnEnforcedObservedPathExitsZero(t *testing.T) {
	tr := newCoverageTree(t, "")
	tr.importFresh(t)
	code, stdout, stderr := invoke(t, tr.args("--plane", tr.plane)...)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	lines := outputLines(stdout)
	if want := "orders.read-file enforced: planes " + tr.plane; lines[0] != want {
		t.Errorf("first line %q, want %q", lines[0], want)
	}
	if want := "  plane " + tr.plane + ": enforced: ENFORCE;"; !strings.HasPrefix(lines[1], want) {
		t.Errorf("plane line %q, want one starting %q", lines[1], want)
	}
	if want := "  source agent-runtime: observed, self_reported: last heard "; !strings.HasPrefix(lines[2], want) {
		t.Errorf("source line %q, want one starting %q", lines[2], want)
	}
	if !strings.Contains(stdout, "  join: 1 not checked\n") {
		t.Errorf("no join line counting the one observation as not checked:\n%s", stdout)
	}
	if last := lines[len(lines)-1]; last != "undeclared paths: unknown" {
		t.Errorf("last line %q, want the standing row", last)
	}
}

// TestCoverageOfAPathNothingCoversExitsOne: beside an observed path, a
// declared egress path no plane and no source covers prints not covered and
// makes the exit status 1.
func TestCoverageOfAPathNothingCoversExitsOne(t *testing.T) {
	tr := newCoverageTree(t, `, {"id":"egress.api","kind":"egress","host":"api.example"}`)
	tr.importFresh(t)
	code, stdout, stderr := invoke(t, tr.args()...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	for _, want := range []string{
		"orders.read-file observed, self_reported: sources agent-runtime\n",
		"egress.api not covered: no live source observed it; no plane decides egress\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, stdout)
		}
	}
}

// TestCoverageWithAnAbsentDescriptorIsNotCovered: a --source that names no
// file is a removed descriptor, which covers nothing, not a refused input.
func TestCoverageWithAnAbsentDescriptorIsNotCovered(t *testing.T) {
	tr := newCoverageTree(t, "")
	tr.importFresh(t)
	if err := os.Remove(tr.source); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := invoke(t, tr.args()...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	lines := outputLines(stdout)
	if want := "orders.read-file not covered: no plane classifies it and no live source observed it"; lines[0] != want {
		t.Errorf("first line %q, want %q", lines[0], want)
	}
	if want := "  source agent-runtime: not covered: no --source given for it, or its descriptor is absent: " + tr.source +
		"; a removed descriptor covers nothing"; lines[1] != want {
		t.Errorf("source line %q, want %q", lines[1], want)
	}
}

// TestCoverageOfALogDirectoryWithoutALogIsUnknown: a source whose log
// directory holds no log yet was never heard, which is unknown, not a
// refused input.
func TestCoverageOfALogDirectoryWithoutALogIsUnknown(t *testing.T) {
	tr := newCoverageTree(t, "")
	code, stdout, stderr := invoke(t, tr.args()...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	if lines := outputLines(stdout); lines[0] != "orders.read-file unknown: sources agent-runtime" {
		t.Errorf("first line %q", lines[0])
	}
}

// TestCoverageIgnoresTheShellEnvironment: a plane's configuration is read
// without the environment of the shell running the command, so a mode
// variable there does not change the mode a plane line shows.
func TestCoverageIgnoresTheShellEnvironment(t *testing.T) {
	tr := newCoverageTree(t, "")
	tr.importFresh(t)
	t.Setenv(brand.EnvPrefix+"MODE", "OBSERVE")
	code, stdout, stderr := invoke(t, tr.args("--plane", tr.plane)...)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	if want := "  plane " + tr.plane + ": enforced: ENFORCE;"; !strings.Contains(stdout, want) {
		t.Errorf("stdout does not hold %q:\n%s", want, stdout)
	}
}

// refusedCoverage runs the command, wants it refused with exit 2, nothing on
// stdout and one stderr line naming each of names, and returns that line.
func refusedCoverage(t *testing.T, args []string, names ...string) string {
	t.Helper()
	code, stdout, stderr := invoke(t, args...)
	if code != 2 || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 2 and no map", code, stdout, stderr)
	}
	line := oneStderrLine(t, stderr)
	if !strings.HasPrefix(line, brand.CLI+": coverage: ") {
		t.Errorf("stderr %q is not the command's own refusal", line)
	}
	for _, name := range names {
		if !strings.Contains(line, name) {
			t.Errorf("stderr %q does not name %q", line, name)
		}
	}
	return line
}

// TestCoverageRefusesAGroupWritableInventory: an inventory another account
// could write is refused before it is parsed, and the refusal names the
// flag and the file but none of its content.
func TestCoverageRefusesAGroupWritableInventory(t *testing.T) {
	tr := newCoverageTree(t, "")
	if err := os.Chmod(tr.inventory, 0o620); err != nil { //nolint:gosec // G302: the inventory mode coverage must refuse
		t.Fatal(err)
	}
	line := refusedCoverage(t, tr.args(), "--inventory", tr.inventory)
	if strings.Contains(line, "schema_version") || strings.Contains(line, "orders.read-file") {
		t.Errorf("the refusal repeats the inventory's content: %q", line)
	}
}

// TestCoverageRefusesAnExportItCannotRead: an export that is not one, or a
// name that is not a regular file, refuses the whole map.
func TestCoverageRefusesAnExportItCannotRead(t *testing.T) {
	tr := newCoverageTree(t, "")
	malformed := filepath.Join(tr.dir, "export.jsonl")
	writeFixture(t, malformed, "not an export\n")
	line := refusedCoverage(t, tr.args("--evidence", malformed), "--evidence", malformed)
	if strings.Contains(line, "not an export") {
		t.Errorf("the refusal repeats the export's content: %q", line)
	}
	refusedCoverage(t, tr.args("--evidence", tr.log), "--evidence", tr.log)
}

// TestCoverageRefusesUnpairedSources: each --source needs its --log, in
// order, and the inventory is given exactly once.
func TestCoverageRefusesUnpairedSources(t *testing.T) {
	tr := newCoverageTree(t, "")
	for name, args := range map[string][]string{
		"a source without a log":  {"coverage", "--inventory", tr.inventory, "--source", tr.source},
		"a log without a source":  {"coverage", "--inventory", tr.inventory, "--log", tr.log},
		"two sources, one log":    tr.args("--source", tr.source),
		"no inventory":            {"coverage", "--source", tr.source, "--log", tr.log},
		"the inventory twice":     tr.args("--inventory", tr.inventory),
		"an argument beside them": tr.args(tr.inventory),
	} {
		t.Run(name, func(t *testing.T) {
			refusedCoverage(t, args, "--inventory", "--source", "--log")
		})
	}
}
