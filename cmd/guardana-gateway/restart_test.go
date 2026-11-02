package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/evidence"
)

// helperConfig turns this test binary into a plane the parent drives, and
// names the configuration it serves. The variable sits outside the product's
// prefix on purpose: a variable under that prefix naming no configuration key
// is refused at load.
const helperConfig = "INLINE_PLANE_HELPER_CONFIG"

// The material tool the agent calls, and how the operator classifies it.
const (
	toolTransfer = "transfer"
	accountArg   = "acct-1"
)

// approveDocument allows a read and a transfer. Under APPROVE an allowed
// material call is held for an approval, which is what these cases need.
const approveDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"gateway-fixture","version":"2026-09-20.2","serial":2,"maxStaleSeconds":600},
  "rules":[
    {"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}},
    {"id":"allow-transfers","effect":"ALLOW","when":{"action":{"effect":["TRANSACT"]}}}
  ]}`

// TestHelperServesAPlane is this binary as a gateway process. It runs only
// when the parent case starts it, and it is the same `run` the command line
// reaches, over a configuration the parent wrote.
func TestHelperServesAPlane(t *testing.T) {
	path := os.Getenv(helperConfig)
	if path == "" {
		t.Skip("this case is the plane a restart case starts; it runs in that child process alone")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if status := serve(ctx, path, "", os.Stdout, os.Stderr); status != exitOK {
		t.Fatalf("the plane answered %d", status)
	}
}

// TestAnApproverOutsideThePlaneAnswersAndALostHoldIsClosed crosses a real
// process boundary in both directions this round is about. One call is held,
// answered by an approver in another process and resumed; a second is held,
// its plane is killed, and an approver answers it while no plane is running.
// A new plane over the same directories closes that trail, and the chain of
// every trail validates over the records a collector accepted — which is the
// case a scan of the spool could never serve, because a collector that accepts
// everything has already released those segments.
func TestAnApproverOutsideThePlaneAnswersAndALostHoldIsClosed(t *testing.T) {
	tr := newTree(t)
	records, _ := tr.fileProvider(t)
	collector := newAcceptingCollector(t)
	upstream := tr.approveConfiguration(t, collector.url)

	first := tr.startPlane(t)
	agent := connectAgent(t, first.address(t))

	// The held call is answered by another process while this plane serves,
	// and the retry resumes it.
	answerFrom(t, records, pendingApproval(t, callTransfer(t, agent, "a")), true)
	if granted := callTransfer(t, agent, "a"); granted.IsError {
		t.Fatalf("the approved retry was refused: %+v", granted.StructuredContent)
	}
	// The next identical call may not run on the approval that call spent.
	// Whether it is refused as already used or held anew for a fresh answer
	// is the store's to say; that the upstream does not run twice is not.
	if again := callTransfer(t, agent, "a"); !again.IsError {
		t.Errorf("the call after the approved one ran: %+v", again.StructuredContent)
	}
	if ran := upstream.count(); ran != 1 {
		t.Fatalf("the upstream ran %d times; one approval is consumed once", ran)
	}

	// The second call is held and never retried: the plane is killed, and the
	// approver answers a directory no plane holds.
	lost := pendingApproval(t, callTransfer(t, agent, "b"))
	collector.waitUntil(t, "the held request reaches the collector", func(events []*controlv1.Event) bool {
		return requested(events, lost)
	})
	first.kill(t)
	answerFrom(t, records, lost, false)

	second := tr.startPlane(t)
	if line := second.waitFor(t, "lost holds:"); strings.Contains(line, "0 closed") {
		t.Fatalf("the restarted plane closed no lost hold: %q", line)
	}
	collector.waitUntil(t, "the lost hold's trail is closed", func(events []*controlv1.Event) bool {
		return notResumed(events) == 1 && standingAtRequest(events) == 0
	})
	second.stop(t)
	if ran := upstream.count(); ran != 1 {
		t.Errorf("the upstream ran %d times; a lost hold is closed and never run", ran)
	}
	expectValidChains(t, collector.events(t))
}

// The reason code a closing of a lost hold carries.
const codeNotResumed = "APPROVAL_NOT_RESUMED"

// approveConfiguration points the tree at the material upstream, classifies
// its one tool from the fingerprint `doctor` prints, and moves the plane to
// APPROVE over a bundle that allows the call.
func (tr tree) approveConfiguration(t *testing.T, collector string) *counted {
	t.Helper()
	writeBundle(t, tr.dir+"/approve.bundle", approveDocument)
	setEnv(t, "policy.bundle_file", tr.dir+"/approve.bundle")
	writeStatement(t, filepath.Join(tr.dir, "policy.statement"), tr.dir+"/approve.bundle", time.Now().Truncate(time.Second))
	up := materialUpstream(t)
	setEnv(t, "upstreams.0.endpoint", up.url)
	setEnv(t, "upstreams.0.tenant_id", "acme")
	setEnv(t, "upstreams.0.environment", "dev")
	setEnv(t, "export.endpoint", collector)
	setEnv(t, "export.in_flight", "1")
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	var out strings.Builder
	if status := doctor(context.Background(), tr.config, &out, &out); status != exitOK {
		t.Fatalf("doctor refused the configuration these cases run on:\n%s", out.String())
	}
	withTransferOverride(t, tr, fingerprintOf(t, out.String(), toolTransfer))
	setEnv(t, "mode", "APPROVE")
	return up
}

// withTransferOverride classifies the material tool, which is what an
// operator does with the fingerprint `doctor` printed.
func withTransferOverride(t *testing.T, tr tree, fingerprint string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(tr.config))
	if err != nil {
		t.Fatalf("reading the configuration: %v", err)
	}
	override := "\noverrides:\n  - upstream: orders\n    tool: " + toolTransfer +
		"\n    fingerprint: " + fingerprint +
		"\n    effect: TRANSACT\n    resource_type: account\n    resource_from: /account\n"
	if err := os.WriteFile(filepath.Clean(tr.config), append(raw, override...), 0o600); err != nil { //nolint:gosec // G703: the configuration copy under this test's own temporary tree
		t.Fatalf("writing the configuration: %v", err)
	}
}

// counted is the upstream server, with how many times its tool actually ran.
// It lives in this process, so it counts what the plane in the other one sent.
type counted struct {
	url string

	mu  sync.Mutex
	ran int
}

func (c *counted) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ran
}

// materialUpstream serves one tool that moves money, so a call to it is a
// material call the policy allows and the mode holds.
func materialUpstream(t *testing.T) *counted {
	t.Helper()
	up := &counted{}
	server := sdk.NewServer(&sdk.Implementation{Name: "fixture-upstream", Version: "0"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"account": map[string]any{"type": "string"},
		"tag":     map[string]any{"type": "string"},
	}}
	server.AddTool(&sdk.Tool{Name: toolTransfer, Description: "moves money", InputSchema: schema},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			up.mu.Lock()
			up.ran++
			up.mu.Unlock()
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "the transfer ran"}}}, nil
		})
	handler := sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	up.url = ts.URL
	return up
}

// child is one gateway process the parent started, read through its own
// standard output.
type child struct {
	cmd  *exec.Cmd
	out  *syncBuffer
	done bool
}

// startPlane runs this test binary as a plane over the tree's configuration.
// It is a process of its own: the parent kills it, and what it wrote to the
// directories is all that survives.
func (tr tree) startPlane(t *testing.T) *child {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperServesAPlane", "-test.timeout=5m") //nolint:gosec // G204: the test binary's own path and its own flags
	cmd.Env = append(os.Environ(), helperConfig+"="+tr.config)
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the plane: %v", err)
	}
	c := &child{cmd: cmd, out: out}
	t.Cleanup(func() { c.kill(t) })
	return c
}

// address is where the started plane listens for agents.
func (c *child) address(t *testing.T) string {
	t.Helper()
	const says = "listening for agents on "
	line := c.waitFor(t, says)
	return strings.TrimSpace(line[strings.Index(line, says)+len(says):])
}

func (c *child) waitFor(t *testing.T, prefix string) string {
	t.Helper()
	return waitFor(t, c.out, prefix)
}

// kill ends the process the way a machine losing power does: nothing is
// flushed, no lock is released by the process itself.
func (c *child) kill(t *testing.T) {
	t.Helper()
	if c.done {
		return
	}
	c.done = true
	if err := c.cmd.Process.Kill(); err != nil {
		t.Errorf("killing the plane: %v", err)
	}
	_ = c.cmd.Wait()
}

// stop asks the process to stop as a service manager would, and fails when it
// does not end cleanly.
func (c *child) stop(t *testing.T) {
	t.Helper()
	c.done = true
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stopping the plane: %v", err)
	}
	if err := c.cmd.Wait(); err != nil {
		t.Fatalf("the plane did not stop cleanly: %v\n%s", err, c.out.String())
	}
}

// connectAgent is an agent on the protocol library, talking to the address the
// plane bound.
func connectAgent(t *testing.T, address string) *sdk.ClientSession {
	t.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "agent-a", Version: "0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cs, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: "http://" + address},
		&sdk.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatalf("connecting to the plane: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// callTransfer makes one material call. tag changes the arguments, and with
// them the digest and the binding, so two calls are two held requests.
func callTransfer(t *testing.T, cs *sdk.ClientSession, tag string) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{
		Name: toolTransfer, Arguments: map[string]any{"account": accountArg, "tag": tag},
	})
	if err != nil {
		t.Fatalf("the plane answered an error instead of a result: %v", err)
	}
	return res
}

// pendingApproval reads the approval id out of a pending answer, which is
// what an approver is given to answer.
func pendingApproval(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	body := planeFields(res.Meta)
	if len(body) == 0 || !res.IsError {
		t.Fatalf("a held call came back as %+v", res)
	}
	id, _ := body["approval_id"].(string)
	if body["reason_code"] != "APPROVAL_PENDING" || id == "" {
		t.Fatalf("the pending answer is %v", body)
	}
	return id
}

// answerFrom approves a record from this process, which is not the one that
// holds it. wantPlane is whether a plane should be holding the directory at
// that moment: an answer filed while none is is written all the same, and the
// reconciliation is what reads it.
func answerFrom(t *testing.T, dir, approvalID string, wantPlane bool) {
	t.Helper()
	answerFromAt(t, dir, approvalID, wantPlane, time.Now())
}

// answerFromAt is answerFrom with the answer dated at.
func answerFromAt(t *testing.T, dir, approvalID string, wantPlane bool, at time.Time) {
	t.Helper()
	approver, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	answered, err := approver.Answer(context.Background(), approvalID,
		controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "ok", at)
	if closeErr := approver.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("answering %s: %v", approvalID, err)
	}
	if answered.PlaneRunning != wantPlane {
		t.Errorf("the answer to %s reports a plane running: %t, want %t",
			approvalID, answered.PlaneRunning, wantPlane)
	}
}

// acceptingCollector accepts every record it is sent, so every segment is
// acknowledged and unlinked: nothing a trail needs can be read back off the
// spool afterwards.
type acceptingCollector struct {
	url string

	mu    sync.Mutex
	lines []string
}

func newAcceptingCollector(t *testing.T) *acceptingCollector {
	t.Helper()
	c := &acceptingCollector{}
	ts := httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(ts.Close)
	c.url = ts.URL + "/v1/logs"
	return c
}

func (c *acceptingCollector) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Body struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if json.NewDecoder(r.Body).Decode(&req) == nil {
		c.mu.Lock()
		for _, rl := range req.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					c.lines = append(c.lines, lr.Body.StringValue)
				}
			}
		}
		c.mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

// waitUntil blocks until what the collector accepted satisfies ok, so a case
// that goes on knows the spool released those records to it.
func (c *acceptingCollector) waitUntil(t *testing.T, what string, ok func([]*controlv1.Event) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ok(c.events(t)) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("within the bound, the collector never held %s", what)
}

// requested reports whether the collector holds the request for approvalID.
func requested(events []*controlv1.Event, approvalID string) bool {
	for _, e := range events {
		if e.GetKind() == controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED &&
			e.GetApproval().GetApprovalId() == approvalID {
			return true
		}
	}
	return false
}

// notResumed counts the trails closed as a hold a plane lost: the approver's
// answer recorded, and the call named as one that never ran.
func notResumed(events []*controlv1.Event) int {
	n := 0
	for _, trail := range byRequest(events) {
		if crossesProcesses(trail) {
			n++
		}
	}
	return n
}

// standingAtRequest counts the trails whose last event is a request for an
// approval: the state a hold lost to a restart stays in unless its trail is
// closed.
func standingAtRequest(events []*controlv1.Event) int {
	n := 0
	for _, trail := range byRequest(events) {
		if trail[len(trail)-1].GetKind() == controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED {
			n++
		}
	}
	return n
}

// byRequest groups records by the request they belong to, in the order the
// collector took them.
func byRequest(events []*controlv1.Event) map[string][]*controlv1.Event {
	out := map[string][]*controlv1.Event{}
	for _, e := range events {
		out[e.GetRequestId()] = append(out[e.GetRequestId()], e)
	}
	return out
}

// events decodes every record the collector accepted, in the order it took
// them, keeping the first of each event id. Delivery is at least once: a plane
// killed between the collector's answer and its own acknowledgement sends
// those records again when it comes back, and a collector tells the copies
// apart by their event id as this one does.
func (c *acceptingCollector) events(t *testing.T) []*controlv1.Event {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*controlv1.Event
	seen := map[string]bool{}
	for _, line := range c.lines {
		events, err := evidence.DecodeJSONL(strings.NewReader(line), evidence.MaxLineBytes)
		if err != nil {
			t.Fatalf("decoding an exported record: %v: %s", err, line)
		}
		for _, e := range events {
			if seen[e.GetEventId()] {
				continue
			}
			seen[e.GetEventId()] = true
			out = append(out, e)
		}
	}
	return out
}

// expectValidChains groups the exported records by request and validates each
// trail: the links, the identifiers and the grammar of what may follow what.
// One trail is the lost hold's, whose last two events were written by another
// process than the first three.
func expectValidChains(t *testing.T, events []*controlv1.Event) {
	t.Helper()
	trails := byRequest(events)
	if len(trails) < 3 {
		t.Fatalf("the collector holds %d trail(s), and these cases made calls that record more", len(trails))
	}
	for id, trail := range trails {
		if err := evidence.ValidateChain(trail); err != nil {
			t.Errorf("ValidateChain over the trail of %s: %v\n%s", id, err, kinds(trail))
		}
	}
	if closed := notResumed(events); closed != 1 {
		t.Errorf("%d trail(s) were closed as a hold this plane lost, want exactly the one", closed)
	}
	if open := standingAtRequest(events); open != 0 {
		t.Errorf("%d trail(s) stand at a request for an approval after the restart", open)
	}
}

// crossesProcesses reports whether a trail is the lost hold's: held by one
// plane and closed by another, with the approver's answer recorded and the
// call named as one that never ran.
func crossesProcesses(trail []*controlv1.Event) bool {
	var requested, decided, blocked bool
	for _, e := range trail {
		switch e.GetKind() {
		case controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED:
			requested = true
		case controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED:
			decided = true
		case controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
			for _, code := range e.GetDecision().GetReasonCodes() {
				blocked = blocked || code == codeNotResumed
			}
		default:
		}
	}
	return requested && decided && blocked
}

// kinds is a trail's event kinds, for a failure to name what it saw.
func kinds(trail []*controlv1.Event) string {
	var b strings.Builder
	for _, e := range trail {
		b.WriteString(e.GetKind().String() + "\n")
	}
	return b.String()
}
