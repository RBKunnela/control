//go:build unix

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// runsDocument allows reads and mail, and denies a call to an untrusted
// destination from a run that took in something untrusted and read something
// confidential.
const runsDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"runs-fixture","version":"2026-10-01.1","serial":1,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"allow-mail","effect":"ALLOW","when":{"action":{"effect":["COMMUNICATE"]}}},
    {"id":"no-orders-to-strangers","effect":"DENY","reason":"TOXIC_FLOW_SENSITIVE_TO_EXTERNAL",
      "when":{"destination":{"trustZone":["UNTRUSTED_EXTERNAL"]},"flow":{"toxicAtLeast":"CONFIDENTIAL"}}}
  ]}`

// The identity every run of these cases is opened for: the listener's, and
// the project of the plane newRunsPlane lays out.
const (
	runsProject   = "orders"
	runsTenant    = "acme"
	runsPrincipal = "agent-runner"
	runsAgent     = "orders-assistant"
)

// The two tools of the runs upstream. A ticket comes from outside and holds
// confidential data, so one read of it taints a run; mail goes to a stranger.
const (
	toolReadTicket = "read_ticket"
	toolSendMail   = "send_mail"
	codeToxicFlow  = "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL"
)

// runsUpstream serves the two tools and counts how often each ran.
type runsUpstream struct {
	url string

	mu  sync.Mutex
	ran map[string]int
}

func newRunsUpstream(t *testing.T) *runsUpstream {
	t.Helper()
	up := &runsUpstream{ran: map[string]int{}}
	server := sdk.NewServer(&sdk.Implementation{Name: "runs-upstream", Version: "0"}, nil)
	for _, tool := range runsTools() {
		server.AddTool(tool, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			up.mu.Lock()
			up.ran[tool.Name]++
			up.mu.Unlock()
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: tool.Name + " ran"}}}, nil
		})
	}
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	up.url = ts.URL
	return up
}

func (up *runsUpstream) count(tool string) int {
	up.mu.Lock()
	defer up.mu.Unlock()
	return up.ran[tool]
}

func runsTools() []*sdk.Tool {
	schema := func(field string) map[string]any {
		return map[string]any{"type": "object", "properties": map[string]any{field: map[string]any{"type": "string"}}}
	}
	return []*sdk.Tool{
		{Name: toolReadTicket, Description: "reads a support ticket", InputSchema: schema("id")},
		{Name: toolSendMail, Description: "sends mail", InputSchema: schema("to")},
	}
}

// runsPlane is one plane with a runs directory, the built binaries it runs
// as, the collector its trail goes to and the upstream it calls.
type runsPlane struct {
	t                *testing.T
	gateway, control string
	dir, runs        string
	project          string
	config           string
	up               *runsUpstream
	collector        *acceptingCollector
}

// newRunsPlane lays out a plane of runsProject whose listener is kind, with
// an empty runs directory, and writes its configuration. Nothing starts.
func newRunsPlane(t *testing.T, kind string) *runsPlane {
	t.Helper()
	return newRunsPlaneOver(t, kind, runsProject, "")
}

// newRunsPlaneOver lays out a plane of project over the runs directory runs,
// or over an empty one of its own where runs is empty, with a spool, a
// collector and an upstream of its own.
func newRunsPlaneOver(t *testing.T, kind, project, runs string) *runsPlane {
	t.Helper()
	gatewayBin, controlBin := builtBinaries(t)
	rp := &runsPlane{
		t: t, gateway: gatewayBin, control: controlBin, dir: t.TempDir(), runs: runs, project: project,
		up: newRunsUpstream(t), collector: newAcceptingCollector(t),
	}
	if err := os.MkdirAll(filepath.Join(rp.dir, "spool"), 0o750); err != nil {
		t.Fatalf("making the spool: %v", err)
	}
	if rp.runs == "" {
		rp.runs = filepath.Join(rp.dir, "runs")
		if err := os.Mkdir(rp.runs, 0o700); err != nil {
			t.Fatalf("making the runs directory: %v", err)
		}
	}
	writeBundle(t, filepath.Join(rp.dir, "policy.bundle"), runsDocument)
	rp.config = filepath.Join(rp.dir, "plane.yaml")
	if err := os.WriteFile(rp.config, []byte(rp.planeConfig(kind)), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	return rp
}

// planeConfig is ENFORCE over runsDocument, every call under a run opened in
// the runs directory, and each tool classified from its fingerprint. A stdio
// plane answers no health address: everything it writes to standard output
// is the agent's, and it binds no listener address.
func (rp *runsPlane) planeConfig(kind string) string {
	address, health := "  address: 127.0.0.1:0\n", "health:\n  address: 127.0.0.1:0\n"
	if kind == "stdio" {
		address, health = "", "health:\n  address: \"\"\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, `mode: ENFORCE
project_id: %s
tenant_id: %s
environment: dev
listener:
  kind: %s
%s  principal:
    id: %s
  agent:
    id: %s
%spolicy:
  bundle_id: runs-fixture
  bundle_file: policy.bundle
  key_id: %s
  public_key: %s
%sruns:
  dir: %s
evidence:
  dir: spool
export:
  endpoint: %s
  allow_plaintext: true
  in_flight: 1
  linger: 5ms
upstreams:
  - name: orders
    endpoint: %s
    tenant_id: %s
    environment: dev
overrides:
`, rp.project, runsTenant, kind, address, runsPrincipal, runsAgent, health, fixtureKeyID, fixturePublicKey(),
		freshnessKeys(rp.t, rp.dir, "runs-fixture"), strconv.Quote(rp.runs), rp.collector.url, rp.up.url, runsTenant)
	classes := map[string]string{
		toolReadTicket: "    effect: READ\n    resource_type: ticket\n    resource_from: /id\n    trust_zone: TRUSTED_INTERNAL\n" +
			"    returns:\n      trust: UNTRUSTED_EXTERNAL\n      sensitivity: CONFIDENTIAL\n",
		toolSendMail: "    effect: COMMUNICATE\n    resource_type: mailbox\n    resource_from: /to\n    trust_zone: UNTRUSTED_EXTERNAL\n" +
			"    returns:\n      trust: TRUSTED_INTERNAL\n      sensitivity: PUBLIC\n",
	}
	for _, tool := range runsTools() {
		fp, err := adaptermcp.Fingerprint(tool)
		if err != nil {
			rp.t.Fatalf("fingerprint of %s: %v", tool.Name, err)
		}
		fmt.Fprintf(&b, "  - upstream: orders\n    tool: %s\n    fingerprint: %s\n%s", tool.Name, fp, classes[tool.Name])
	}
	return b.String()
}

// servingPlane is a started HTTP plane and the addresses it bound.
type servingPlane struct {
	proc           *process
	listen, health string
}

// start runs the built gateway over the configuration and reads back the
// addresses it bound.
func (rp *runsPlane) start() *servingPlane {
	rp.t.Helper()
	cmd := exec.Command(rp.gateway, "run", "--config", rp.config) //nolint:gosec // G204: the binary this test built
	cmd.Env = environ()
	p := &process{cmd: cmd, out: &syncBuffer{}}
	cmd.Stdout, cmd.Stderr = p.out, p.out
	if err := cmd.Start(); err != nil {
		rp.t.Fatalf("starting the plane: %v", err)
	}
	rp.t.Cleanup(func() { p.stop(rp.t) })
	const listening, answering = "listening for agents on ", "answering /healthz, /metrics and /brand on "
	return &servingPlane{
		proc:   p,
		listen: afterPrefix(p.waitFor(rp.t, listening), listening),
		health: afterPrefix(p.waitFor(rp.t, answering), answering),
	}
}

// openedRun is what runs open printed.
type openedRun struct{ id, root, token string }

// open opens a run with the built approver binary, for the listener's
// identity and the plane's project unless args name another agent or
// project.
func (rp *runsPlane) open(args ...string) openedRun {
	rp.t.Helper()
	full := append([]string{"runs", "open", "--tenant", runsTenant, "--principal-type", "service",
		"--principal", runsPrincipal, "--ttl", "1h"}, args...)
	if !hasFlag(args, "--agent") {
		full = append(full, "--agent", runsAgent)
	}
	if !hasFlag(args, "--project") {
		full = append(full, "--project", rp.project)
	}
	out, err := runBinary(rp.control, append(full, rp.runs)...)
	if err != nil {
		rp.t.Fatalf("runs open %v: %v\n%s", args, err, out)
	}
	var run openedRun
	for _, line := range lines(out) {
		key, value, _ := strings.Cut(line, ": ")
		switch key {
		case "run_id":
			run.id = value
		case "root":
			run.root = value
		case "token":
			run.token = value
		}
	}
	if run.id == "" || run.root == "" || !strings.HasPrefix(run.token, run.id+".") {
		rp.t.Fatalf("runs open printed no run, root and token:\n%s", out)
	}
	return run
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// closeRun closes a run with the built approver binary.
func (rp *runsPlane) closeRun(id string) {
	rp.t.Helper()
	out, err := runBinary(rp.control, "runs", "close", rp.runs, id)
	if err != nil || strings.TrimSpace(out) != "closed "+id {
		rp.t.Fatalf("runs close %s: %v\n%s", id, err, out)
	}
}

// tokenTransport presents one run token on every request, as an orchestrator
// configures an agent's client to.
type tokenTransport struct{ token string }

func (tt tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(adaptermcp.RunTokenHeader, tt.token)
	return http.DefaultTransport.RoundTrip(r)
}

// agentUnder connects an agent that presents token on every request.
func agentUnder(t *testing.T, address, token string) *sdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "agent-under-run", Version: "0"}, nil).Connect(ctx,
		&sdk.StreamableClientTransport{Endpoint: "http://" + address, HTTPClient: &http.Client{Transport: tokenTransport{token}}},
		&sdk.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatalf("connecting under a run: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// callTool makes one call and fails the case on a protocol error.
func callTool(t *testing.T, cs *sdk.ClientSession, tool string) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	field := map[string]string{toolReadTicket: "id", toolSendMail: "to"}[tool]
	value := map[string]string{toolReadTicket: "tk-1", toolSendMail: "orders-backup@example.net"}[tool]
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: map[string]any{field: value}})
	if err != nil {
		t.Fatalf("calling %s: %v", tool, err)
	}
	return res
}

// expectRan fails unless the call ran: an answer that is not an error.
func expectRan(t *testing.T, what string, res *sdk.CallToolResult) {
	t.Helper()
	if res.IsError {
		t.Errorf("%s was blocked: %+v", what, res.StructuredContent)
	}
}

// expectToxic fails unless the call was blocked by the flow rule.
func expectToxic(t *testing.T, what string, res *sdk.CallToolResult) {
	t.Helper()
	codes, _ := planeFields(res.Meta)["reason_codes"].([]any)
	for _, c := range codes {
		if c == codeToxicFlow && res.IsError {
			return
		}
	}
	t.Errorf("%s was not denied by the flow rule: isError %t, %+v", what, res.IsError, res.StructuredContent)
}

// runsHealth reads /healthz's runs object.
func runsHealth(t *testing.T, health string) (runs map[string]any, pipeline map[string]any) {
	t.Helper()
	resp, err := http.Get("http://" + health + "/healthz")
	if err != nil {
		t.Fatalf("reading /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		Runs     map[string]any `json:"runs"`
		Pipeline map[string]any `json:"pipeline"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("decoding /healthz: %v", err)
	}
	return answer.Runs, answer.Pipeline
}

// refusedAt is the count by cause under one of the runs object's refusals.
func refusedAt(t *testing.T, runs map[string]any, key string) map[string]float64 {
	t.Helper()
	raw, ok := runs[key].(map[string]any)
	if !ok {
		t.Fatalf("/healthz runs.%s is %v", key, runs[key])
	}
	out := map[string]float64{}
	for cause, n := range raw {
		f, ok := n.(float64)
		if !ok {
			t.Fatalf("/healthz runs.%s.%s is %v", key, cause, n)
		}
		out[cause] = f
	}
	return out
}

// settled waits until the collector holds want trails that each reached
// their last event, a completion or a block, and returns every trail it
// holds by request.
func (rp *runsPlane) settled(want int) map[string][]*controlv1.Event {
	rp.t.Helper()
	var trails map[string][]*controlv1.Event
	rp.collector.waitUntil(rp.t, fmt.Sprintf("%d finished call(s)", want), func(events []*controlv1.Event) bool {
		trails = byRequest(events)
		finished := 0
		for _, trail := range trails {
			switch trail[len(trail)-1].GetKind() {
			case controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED, controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
				finished++
			default:
			}
		}
		return finished >= want
	})
	return trails
}

// toolOf is the tool a proposed call names.
func toolOf(e *controlv1.Event) string {
	name := e.GetProposed().GetAction().GetName()
	for _, tool := range []string{toolReadTicket, toolSendMail} {
		if strings.HasSuffix(name, tool) {
			return tool
		}
	}
	return name
}

// hasTag reports whether a proposed call's run context carries tag.
func hasTag(e *controlv1.Event, tag string) bool {
	for _, got := range e.GetProposed().GetContext().GetTags() {
		if got == tag {
			return true
		}
	}
	return false
}
