//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// stdioUpstreamLog turns this test binary into the stdio upstream a chaos case
// configures, and names the file it records into. The upstream's env list
// names it, so the plane passes it to its child without reading it.
const stdioUpstreamLog = "INLINE_STDIO_UPSTREAM_LOG"

// chaosBundleID is the bundle every chaos plane serves.
const chaosBundleID = "chaos-fixture"

// chaosDocument allows reads and writes, so a write is a material call the
// plane sends.
const chaosDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"chaos-fixture","version":"2026-09-26.1","serial":1,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"allow-writes","effect":"ALLOW","when":{"action":{"effect":["WRITE"]}}}
  ]}`

// chaosVetoDocument allows reads unless the decision point denies them.
const chaosVetoDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"chaos-fixture","version":"2026-09-26.2","serial":2,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"veto-reads","effect":"DENY","when":{"action":{"effect":["READ"]},"external":{"denies":true}}}
  ]}`

// The tools the chaos upstreams serve. Each takes an id, which the operator's
// classification reads as the resource.
var (
	toolReadOrder = chaosTool("read_order")
	toolPostEntry = chaosTool("post_entry")
	toolReadNote  = chaosTool("read_note")
	toolWriteNote = chaosTool("write_note")
)

func chaosTool(name string) *sdk.Tool {
	return &sdk.Tool{Name: name, Description: "does " + name, InputSchema: map[string]any{
		"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}},
	}}
}

// TestHelperServesAStdioUpstream is this binary as the stdio upstream a chaos
// case configures. It records its own start and every call it receives,
// answers read_note, and exits in the middle of write_note without answering.
func TestHelperServesAStdioUpstream(t *testing.T) {
	path := os.Getenv(stdioUpstreamLog)
	if path == "" {
		t.Skip("this case is the stdio upstream a chaos case starts; it runs in that child process alone")
	}
	record(t, path, "start")
	server := sdk.NewServer(&sdk.Implementation{Name: "stdio-upstream", Version: "0"}, nil)
	server.AddTool(toolReadNote, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		record(t, path, toolReadNote.Name)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "a note"}}}, nil
	})
	server.AddTool(toolWriteNote, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		record(t, path, toolWriteNote.Name)
		os.Exit(3)
		return nil, nil
	})
	if err := server.Run(context.Background(), &sdk.StdioTransport{}); err != nil {
		t.Fatalf("the stdio upstream stopped: %v", err)
	}
}

// record appends one line to the helper's log and syncs it, so the line is on
// disk before the process can die.
func record(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G703: a path in this test's own directory
	if err != nil {
		t.Fatalf("opening the upstream's log: %v", err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("writing the upstream's log: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("syncing the upstream's log: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the upstream's log: %v", err)
	}
}

// recorded counts the lines of the helper's log that equal line.
func recorded(t *testing.T, path, line string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading the upstream's log: %v", err)
	}
	n := 0
	for _, l := range lines(string(raw)) {
		if l == line {
			n++
		}
	}
	return n
}

// dropKind is what an HTTP chaos upstream does with one tools/call.
type dropKind int

const (
	// answerCall passes the call to the server, which answers it.
	answerCall dropKind = iota
	// dropBeforeStatus reads the request and closes the connection with
	// nothing written.
	dropBeforeStatus
	// dropAfterStatus reads the request, sends the status line and the
	// headers of an event stream, and closes the connection before any event.
	dropAfterStatus
)

// httpUpstream is an MCP server over stateless Streamable HTTP that counts
// every tools/call it receives, per tool, before it decides what to do with
// it.
type httpUpstream struct {
	t       *testing.T
	url     string
	handler http.Handler
	drop    func(tool string, n int) dropKind

	mu       sync.Mutex
	received map[string]int
}

func newHTTPUpstream(t *testing.T, drop func(tool string, n int) dropKind, tools ...*sdk.Tool) *httpUpstream {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "http-upstream", Version: "0"}, nil)
	for _, tool := range tools {
		server.AddTool(tool, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: tool.Name + " ran"}}}, nil
		})
	}
	up := &httpUpstream{
		t: t,
		handler: sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
			&sdk.StreamableHTTPOptions{Stateless: true}),
		drop: drop, received: map[string]int{},
	}
	ts := httptest.NewServer(up)
	t.Cleanup(ts.Close)
	up.url = ts.URL
	return up
}

func (up *httpUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &msg) == nil && msg.Method == "tools/call" {
		up.mu.Lock()
		up.received[msg.Params.Name]++
		n := up.received[msg.Params.Name]
		up.mu.Unlock()
		switch up.drop(msg.Params.Name, n) {
		case dropBeforeStatus:
			up.dropConnection(w)
			return
		case dropAfterStatus:
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			up.dropConnection(w)
			return
		case answerCall:
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	up.handler.ServeHTTP(w, r)
}

// dropConnection takes the connection from the server, which writes out
// whatever headers were written, and closes it.
func (up *httpUpstream) dropConnection(w http.ResponseWriter) {
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		up.t.Errorf("the upstream could not drop the connection: %v", err)
		return
	}
	if err := conn.Close(); err != nil {
		up.t.Errorf("the upstream could not close the connection: %v", err)
	}
}

// count is how many tools/call requests for tool the upstream received.
func (up *httpUpstream) count(tool string) int {
	up.mu.Lock()
	defer up.mu.Unlock()
	return up.received[tool]
}

// answerEvery is an upstream that drops nothing.
func answerEvery(string, int) dropKind { return answerCall }

// chaosUpstream is one entry of a chaos plane's upstreams: an endpoint, or a
// command with its arguments.
type chaosUpstream struct {
	name, endpoint, command string
	args, env               []string
}

// classified is one tool the operator classifies, on the upstream that lists
// it.
type classified struct {
	upstream string
	tool     *sdk.Tool
	effect   string
}

// chaosSetup is what a chaos plane runs on.
type chaosSetup struct {
	document  string
	collector string
	upstreams []chaosUpstream
	tools     []classified
	// evidence is further keys of the evidence block, each line indented.
	evidence string
	// extra is further top-level configuration, such as a pause or a decision
	// point block.
	extra string
}

// stdioHelper is the upstream entry that runs this test binary as the stdio
// upstream; log is where it records.
func stdioHelper(t *testing.T, name, log string) chaosUpstream {
	t.Helper()
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("resolving the test binary: %v", err)
	}
	t.Setenv(stdioUpstreamLog, log)
	return chaosUpstream{name: name, command: self,
		args: []string{"-test.run=^TestHelperServesAStdioUpstream$", "-test.timeout=5m"},
		env:  []string{stdioUpstreamLog}}
}

func (s chaosSetup) config(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, `mode: ENFORCE
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
  bundle_id: %s
  bundle_file: policy.bundle
  key_id: %s
  public_key: %s
%sapprovals:
  authority: memory
evidence:
  dir: spool
%sexport:
  endpoint: %s
  allow_plaintext: true
  in_flight: 1
  linger: 5ms
  backoff: 20ms
  max_backoff: 200ms
upstreams:
`, chaosBundleID, fixtureKeyID, fixturePublicKey(), freshnessKeys(t, dir, chaosBundleID), s.evidence, s.collector)
	for _, up := range s.upstreams {
		fmt.Fprintf(&b, "  - name: %s\n    tenant_id: acme\n    environment: dev\n", up.name)
		if up.endpoint != "" {
			fmt.Fprintf(&b, "    endpoint: %s\n", up.endpoint)
			continue
		}
		fmt.Fprintf(&b, "    command: %q\n    args:\n", up.command)
		for _, arg := range up.args {
			fmt.Fprintf(&b, "      - %q\n", arg)
		}
		if len(up.env) > 0 {
			b.WriteString("    env:\n")
		}
		for _, name := range up.env {
			fmt.Fprintf(&b, "      - %s\n", name)
		}
	}
	b.WriteString("overrides:\n")
	for _, c := range s.tools {
		fp, err := adaptermcp.Fingerprint(c.tool)
		if err != nil {
			t.Fatalf("fingerprint of %s: %v", c.tool.Name, err)
		}
		fmt.Fprintf(&b, "  - upstream: %s\n    tool: %s\n    fingerprint: %s\n    effect: %s\n"+
			"    resource_type: record\n    resource_from: /id\n", c.upstream, c.tool.Name, fp, c.effect)
	}
	b.WriteString(s.extra)
	return b.String()
}

// chaosPlane is one gateway process, the built binary's `run`, and the
// addresses it printed.
type chaosPlane struct {
	proc           *process
	dir            string
	listen, health string
}

// startChaosPlane lays out a tree under dir and runs the built gateway over
// it until the test ends.
func startChaosPlane(t *testing.T, dir string, s chaosSetup) *chaosPlane {
	t.Helper()
	gatewayBin, _ := builtBinaries(t)
	if err := os.MkdirAll(filepath.Join(dir, "spool"), 0o750); err != nil {
		t.Fatalf("making the spool directory: %v", err)
	}
	writeBundle(t, filepath.Join(dir, "policy.bundle"), s.document)
	config := filepath.Join(dir, "plane.yaml")
	if err := os.WriteFile(config, []byte(s.config(t, dir)), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	proc := (&rig{t: t, gateway: gatewayBin}).startProcess("run", "--config", config)
	return &chaosPlane{
		proc: proc, dir: dir,
		listen: afterPrefix(proc.waitFor(t, "listening for agents on "), "listening for agents on "),
		health: afterPrefix(proc.waitFor(t, "answering /healthz, /metrics and /brand on "), "answering /healthz, /metrics and /brand on "),
	}
}

// healthz is the plane's /healthz answer, whatever its status.
func (c *chaosPlane) healthz(t *testing.T) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.health+"/healthz", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("/healthz answered %d with a body that does not parse: %v", res.StatusCode, err)
	}
	return body
}

// waitHealth waits until the plane's /healthz satisfies ok.
func (c *chaosPlane) waitHealth(t *testing.T, what string, ok func(map[string]any) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		body := c.healthz(t)
		if ok(body) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("within 30s /healthz never said %s: %v", what, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// member reads a nested member of a health answer by its path.
func member(body map[string]any, path ...string) any {
	var v any = body
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

// chaosCall makes one call to tool with id as its argument and returns what
// the plane answered, a result or an error.
func chaosCall(t *testing.T, cs *sdk.ClientSession, tool *sdk.Tool, id string) (*sdk.CallToolResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return cs.CallTool(ctx, &sdk.CallToolParams{Name: tool.Name, Arguments: map[string]any{"id": id}})
}

// ran fails unless the plane answered the upstream's own success.
func ran(t *testing.T, res *sdk.CallToolResult, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: the plane answered an error: %v", what, err)
	}
	if res.IsError {
		t.Fatalf("%s: the plane answered a refusal: %+v", what, res.StructuredContent)
	}
}

// blockedWith fails unless the plane answered a block carrying code.
func blockedWith(t *testing.T, res *sdk.CallToolResult, err error, code, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: the plane answered an error instead of a block: %v", what, err)
	}
	codes, _ := planeFields(res.Meta)["reason_codes"].([]any)
	if !res.IsError || !slices.Contains(codes, any(code)) {
		t.Fatalf("%s: the plane answered %+v, want a block carrying %s", what, res, code)
	}
}

// trailOfTool is the one trail whose proposal names tool and id.
func trailOfTool(t *testing.T, events []*controlv1.Event, tool, id string) []*controlv1.Event {
	t.Helper()
	var found [][]*controlv1.Event
	for _, trail := range byRequest(events) {
		proposed := trail[0].GetProposed()
		if proposed.GetAction().GetName() == tool && proposed.GetResource().GetId() == id {
			found = append(found, trail)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the collector holds %d trail(s) of %s %s, want 1", len(found), tool, id)
	}
	return found[0]
}

// allClosed reports whether the collector holds want trails and every one
// ends in an event nothing follows.
func allClosed(want int) func([]*controlv1.Event) bool {
	return func(events []*controlv1.Event) bool {
		trails := byRequest(events)
		for _, trail := range trails {
			if !closedTrail(trail) {
				return false
			}
		}
		return len(trails) == want
	}
}

// validChains fails for a trail whose chain does not validate.
func validChains(t *testing.T, events []*controlv1.Event) {
	t.Helper()
	for id, trail := range byRequest(events) {
		if err := evidence.ValidateChain(trail); err != nil {
			t.Errorf("ValidateChain over the trail of %s: %v\n%s", id, err, kinds(trail))
		}
	}
}

// endedUnfinished fails unless trail was started and closed as failed, with a
// result that is not a success.
func endedUnfinished(t *testing.T, trail []*controlv1.Event, what string) *controlv1.ActionResult {
	t.Helper()
	want := []controlv1.EventKind{kProposed, kDecided, kStarted, controlv1.EventKind_EVENT_KIND_ACTION_FAILED}
	got := make([]controlv1.EventKind, 0, len(trail))
	for _, e := range trail {
		got = append(got, e.GetKind())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s: the trail is\n%s want PROPOSED, DECIDED, STARTED, FAILED", what, kinds(trail))
	}
	result := trail[len(trail)-1].GetResult()
	switch result.GetStatus() {
	case controlv1.ResultStatus_RESULT_STATUS_FAILURE, controlv1.ResultStatus_RESULT_STATUS_UNKNOWN:
	default:
		t.Errorf("%s: the closing record says %v, want a failure or an unknown", what, result.GetStatus())
	}
	return result
}

// endedBlocked fails unless the trail of tool with id never started and ends
// ACTION_BLOCKED with code among the reasons.
func endedBlocked(t *testing.T, events []*controlv1.Event, tool, id, code string) {
	t.Helper()
	trail := trailOfTool(t, events, tool, id)
	for _, e := range trail {
		if e.GetKind() == kStarted {
			t.Errorf("the blocked call %s was handed to execution:\n%s", id, kinds(trail))
		}
	}
	last := trail[len(trail)-1]
	if last.GetKind() != kBlocked || !slices.Contains(last.GetDecision().GetReasonCodes(), code) {
		t.Errorf("the trail of %s ends %v with %v, want ACTION_BLOCKED with %s",
			id, last.GetKind(), last.GetDecision().GetReasonCodes(), code)
	}
}
