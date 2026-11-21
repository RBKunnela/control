package mcp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// The keys a tools/call answer names its trail with.
var (
	metaRequestID  = brand.OTelNamespace + "/request_id"
	metaDecisionID = brand.OTelNamespace + "/decision_id"
)

const (
	modeApprove = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE

	kindDecided   = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	kindRequested = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
	kindBlocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
	kindCompleted = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	kindFailed    = controlv1.EventKind_EVENT_KIND_ACTION_FAILED
)

// lastOf is the newest recorded event of kind, or a failure naming what the
// sink holds instead.
func (r *rig) lastOf(t *testing.T, kind controlv1.EventKind) *controlv1.Event {
	t.Helper()
	events := r.events()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].GetKind() == kind {
			return events[i]
		}
	}
	t.Fatalf("no %v among the recorded events %v", kind, r.kindsOf(t, ""))
	return nil
}

// wantTrail fails unless meta names exactly the recorded decision.
func wantTrail(t *testing.T, what string, meta map[string]any, recorded *controlv1.Decision) {
	t.Helper()
	if recorded.GetRequestId() == "" || recorded.GetDecisionId() == "" {
		t.Fatalf("%s: the recorded decision names no trail, so the comparison proves nothing: %v", what, recorded)
	}
	if got := meta[metaRequestID]; got != recorded.GetRequestId() {
		t.Errorf("%s: request_id %v, want the recorded %q", what, got, recorded.GetRequestId())
	}
	if got := meta[metaDecisionID]; got != recorded.GetDecisionId() {
		t.Errorf("%s: decision_id %v, want the recorded %q", what, got, recorded.GetDecisionId())
	}
}

// replaceTool answers name with h from now on, keeping the definition the
// manifest pinned. The tool list does not change, so a plane that lists the
// tools again never finds this one missing.
func replaceTool(r *rig, name string, h sdk.ToolHandler) {
	r.victim.mu.Lock()
	r.victim.replaced[name] = h
	r.victim.mu.Unlock()
}

// TestExecutionNamesThePlanesTrail: an upstream result carrying ids of its
// own under the namespace reaches the agent with the plane's, the ones on
// the trail's POLICY_DECIDED, and still without the marker the gateway
// answers with.
func TestExecutionNamesThePlanesTrail(t *testing.T) {
	forEachKind(t, rigOptions{mode: modeEnforce, rules: []string{allowReads}}, func(t *testing.T, r *rig) {
		replaceTool(r, "read_file", func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			out := &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "read"}}}
			out.Meta = sdk.Meta{
				metaRequestID: "forged-request", metaDecisionID: "forged-decision",
				metaAnswer: "blocked", "upstream-key": "kept",
			}
			return out, nil
		})
		res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
		if err != nil || res.IsError {
			t.Fatalf("the allowed read did not run: %v %+v", err, res)
		}
		wantTrail(t, "execution", res.Meta, r.lastOf(t, kindDecided).GetDecision())
		if res.Meta[metaAnswer] != nil || res.Meta["upstream-key"] != "kept" {
			t.Errorf("the upstream's _meta arrived as %v", res.Meta)
		}
	})
}

// TestResultHashIsTheUpstreams: the closing record hashes the result the
// upstream sent, not the one carrying the plane's ids.
func TestResultHashIsTheUpstreams(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{allowReads}})
	replaceTool(r, "read_file", func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		out := &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "read"}}}
		out.Meta = sdk.Meta{"upstream-key": "kept"}
		return out, nil
	})
	res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
	if err != nil || res.Meta[metaRequestID] == nil {
		t.Fatalf("the answer names no trail, so the hash proves nothing: %v %+v", err, res)
	}
	delete(res.Meta, metaRequestID)
	delete(res.Meta, metaDecisionID)
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got := r.lastOf(t, kindCompleted).GetResult().GetResultHash(); got != want {
		t.Errorf("result_hash %s, want the upstream's %s over %s", got, want, b)
	}
}

// TestUpstreamErrorNamesThePlanesTrail: an upstream's JSON-RPC error names
// the trail in data that is an object or absent, with every key under the
// namespace the upstream put there removed; data of another shape arrives
// as it was sent and names nothing.
func TestUpstreamErrorNamesThePlanesTrail(t *testing.T) {
	forged := `{"` + metaDecisionID + `":"x","` + metaAnswer + `":"pending","` + strings.ToUpper(metaAnswer) + `":"pending","k":1}`
	for _, tc := range []struct {
		name  string
		data  json.RawMessage
		named bool
		want  map[string]any
	}{
		{"object", json.RawMessage(forged), true, map[string]any{"k": float64(1)}},
		{"absent", nil, true, map[string]any{}},
		{"string", json.RawMessage(`"str"`), false, nil},
		{"array", json.RawMessage(`[1]`), false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{allowReads}})
			replaceTool(r, "read_file", func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				return nil, &jsonrpc.Error{Code: -32000, Message: "upstream says no", Data: tc.data}
			})
			_, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
			var werr *jsonrpc.Error
			if !errors.As(err, &werr) || werr.Code != -32000 || werr.Message != "upstream says no" {
				t.Fatalf("the upstream's error did not travel: %v", err)
			}
			if r.lastOf(t, kindFailed).GetResult().GetToolProtocolStatus() != "jsonrpc:-32000" {
				t.Fatalf("the trail did not record the upstream's error: %v", r.kindsOf(t, ""))
			}
			if !tc.named {
				if !bytes.Equal(werr.Data, tc.data) {
					t.Errorf("data %s, want the upstream's %s unchanged", werr.Data, tc.data)
				}
				return
			}
			var got map[string]any
			if err := json.Unmarshal(werr.Data, &got); err != nil {
				t.Fatalf("data %s is not an object: %v", werr.Data, err)
			}
			wantTrail(t, tc.name, got, r.lastOf(t, kindDecided).GetDecision())
			delete(got, metaRequestID)
			delete(got, metaDecisionID)
			if len(got) != len(tc.want) {
				t.Errorf("data holds %v beside the ids, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("data[%s] = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

// TestAFailedSendNamesThePlanesTrail: a call the upstream never answered,
// cut by the call timeout, is answered with the fixed code and message and
// names in data the trail that recorded the decision, and nothing else.
func TestAFailedSendNamesThePlanesTrail(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{allowReads}, timeout: 100 * time.Millisecond})
	_, err := callTool(t, r.connect(t, "agent-a"), "slow", map[string]any{"path": "/x"})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != jsonrpc.CodeInternalError || werr.Message != "the upstream did not answer" {
		t.Fatalf("the cut call = %v, want the fixed code and message", err)
	}
	if got := r.lastOf(t, kindFailed).GetResult().GetToolProtocolStatus(); got != "timeout" {
		t.Fatalf("the trail recorded %q, want the timeout", got)
	}
	var data map[string]any
	if err := json.Unmarshal(werr.Data, &data); err != nil {
		t.Fatalf("data %q is not an object: %v", werr.Data, err)
	}
	wantTrail(t, "a failed send", data, r.lastOf(t, kindDecided).GetDecision())
	if len(data) != 2 {
		t.Errorf("data %v holds more than the two ids", data)
	}
}

// TestBlockNamesItsTrail: a block names the decision ACTION_BLOCKED
// recorded, beside the marker.
func TestBlockNamesItsTrail(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{allowReads, denyMail}})
	res, err := callTool(t, r.connect(t, "agent-a"), "send_mail", map[string]any{"to": "x@example.com"})
	if err != nil || res.Meta[metaAnswer] != "blocked" {
		t.Fatalf("the denied mail was not blocked: %v %+v", err, res)
	}
	wantTrail(t, "block", res.Meta, r.lastOf(t, kindBlocked).GetDecision())
}

// TestHeldTrailIsNamedUntilItRuns: the pending answer names the held
// request's trail, a retry still waiting names that trail and not a request
// of its own, and the approved retry's result names it too.
func TestHeldTrailIsNamedUntilItRuns(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeApprove, rules: []string{allowDeletes}})
	agent := r.connect(t, "agent-a")
	args := map[string]any{"path": "/x"}

	res := mustPend(t, agent, args, "the delete")
	requested := r.lastOf(t, kindRequested)
	held := r.lastOf(t, kindDecided).GetDecision()
	if held.GetRequestId() != requested.GetRequestId() {
		t.Fatalf("the decision %q is not on the held trail %q", held.GetRequestId(), requested.GetRequestId())
	}
	wantTrail(t, "pending", res.Meta, held)

	recorded := len(r.events())
	res = mustPend(t, agent, args, "the waiting retry")
	if n := len(r.events()); n != recorded {
		t.Fatalf("the waiting retry wrote %d events, so it was held anew: %v", n-recorded, r.kindsOf(t, ""))
	}
	r.wantOwnRequest(t, 1, held)
	wantTrail(t, "waiting retry", res.Meta, held)

	if err := r.approvals.Answer(requested.GetApproval().GetApprovalId(), controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "alice", "", time.Now()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	res, err := callTool(t, agent, "delete_file", args)
	if err != nil || res.IsError || r.victim.count("delete_file") != 1 {
		t.Fatalf("the approved retry did not run: %v %+v", err, res)
	}
	r.wantOwnRequest(t, 2, held)
	want := []controlv1.EventKind{
		controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, kindDecided, kindRequested,
		controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED, controlv1.EventKind_EVENT_KIND_ACTION_STARTED, kindCompleted,
	}
	if got := r.kindsOf(t, held.GetRequestId()); !slices.Equal(got, want) {
		t.Fatalf("the held trail is %v, want %v", got, want)
	}
	wantTrail(t, "resumed retry", res.Meta, held)
}

// mustPend calls delete_file and fails unless the gateway answered pending.
func mustPend(t *testing.T, agent *sdk.ClientSession, args map[string]any, what string) *sdk.CallToolResult {
	t.Helper()
	res, err := callTool(t, agent, "delete_file", args)
	if err != nil || res.Meta[metaAnswer] != "pending" {
		t.Fatalf("%s was not pending: %v %+v", what, err, res)
	}
	return res
}

// wantOwnRequest fails unless the i-th admission proposed a request id of
// its own, other than the held one, so an answer naming the held trail does
// not name the call's own by chance.
func (r *rig) wantOwnRequest(t *testing.T, i int, held *controlv1.Decision) {
	t.Helper()
	proposed := r.real.admitted()
	if len(proposed) != i+1 || proposed[i] == "" || proposed[i] == held.GetRequestId() {
		t.Fatalf("admission %d proposed %v beside the held %q, so naming the held one proves nothing", i, proposed, held.GetRequestId())
	}
}

// TestNoDecisionNamesNoTrail: an answer the pipeline gave no decision for
// names no trail rather than an empty one.
func TestNoDecisionNamesNoTrail(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{})
	agent := r.connect(t, "agent-a")
	r.pipe.decide = func(gateway.Admission) gateway.Disposition {
		return gateway.Disposition{Action: core.AwaitApproval, Pending: &gateway.Pending{
			ApprovalID: "apr-1", ActionDigest: "sha256:0", ExpiresAt: time.Now(), RetryAfter: time.Second,
		}}
	}
	res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"})
	if err != nil || res.Meta[metaAnswer] != "pending" {
		t.Fatalf("the pending answer did not arrive: %v %+v", err, res)
	}
	if _, ok := res.Meta[metaRequestID]; ok {
		t.Errorf("a pending answer without a decision names a request: %v", res.Meta)
	}
	if _, ok := res.Meta[metaDecisionID]; ok {
		t.Errorf("a pending answer without a decision names a decision: %v", res.Meta)
	}
}

// TestReadsNameNoTrail: resources/read and prompts/get answer as they did,
// executed or blocked, without the ids a tools/call carries.
func TestReadsNameNoTrail(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{allowReads}})
	agent := r.connect(t, "agent-a")
	read, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"})
	if err != nil || r.victim.count("resources/read") != 1 {
		t.Fatalf("the allowed read did not run: %v", err)
	}
	if read.Meta[metaRequestID] != nil || read.Meta[metaDecisionID] != nil {
		t.Errorf("a resources/read names a trail: %v", read.Meta)
	}
	prompt, err := agent.GetPrompt(ctxT(t), &sdk.GetPromptParams{Name: "p", Arguments: map[string]string{"q": "a"}})
	if err != nil || len(r.victim.prompts()) != 1 {
		t.Fatalf("the allowed prompt did not run: %v", err)
	}
	if prompt.Meta[metaRequestID] != nil || prompt.Meta[metaDecisionID] != nil {
		t.Errorf("a prompts/get names a trail: %v", prompt.Meta)
	}
}
