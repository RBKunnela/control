package mcp_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// TestAllowSendsTheAuthorizedBytes: ObserveRequest and ObserveResult. The
// pipeline is asked before the victim runs, the victim receives exactly the
// authorized bytes once, and Close gets the bytes that were sent and a
// SUCCESS result for the same request.
func TestAllowSendsTheAuthorizedBytes(t *testing.T) {
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		agent := r.connect(t, "agent-a")
		res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"})
		if err != nil || res.IsError {
			t.Fatalf("CallTool: %v %+v", err, res)
		}
		env := assertAdmittedFirst(t, r, "read_file", `{"path":"/x"}`)
		if got := r.victim.args("read_file"); len(got) != 1 || string(got[0]) != `{"path":"/x"}` {
			t.Errorf("victim received %s", got)
		}
		assertClosedSuccess(t, r, env, `{"path":"/x"}`)
	})
}

// assertAdmittedFirst checks the one admission names the tool with the
// agent's bytes and was made while the victim had run nothing.
func assertAdmittedFirst(t *testing.T, r *rig, tool, args string) *controlv1.ActionEnvelope {
	t.Helper()
	adm := r.pipe.admitted()
	if len(adm) != 1 || adm[0].victimCalls != 0 {
		t.Fatalf("admissions %d, victim calls at Admit %v; want 1 and 0", len(adm), adm)
	}
	env := adm[0].a.Envelope
	if env.GetAction().GetName() != tool || env.GetAction().GetEffect() != effectRead || env.GetAction().GetProvider() != "victim" {
		t.Errorf("action = %v", env.GetAction())
	}
	if got := string(adm[0].a.Arguments); got != args {
		t.Errorf("Admit saw arguments %s", got)
	}
	return env
}

// assertClosedSuccess checks Close got the sent bytes, a SUCCESS result for
// the same request and the disposition Admit minted for the same digest.
func assertClosedSuccess(t *testing.T, r *rig, env *controlv1.ActionEnvelope, sent string) {
	t.Helper()
	closes := r.pipe.closed()
	if len(closes) != 1 || string(closes[0].sent) != sent {
		t.Fatalf("Close calls %+v", closes)
	}
	result := closes[0].result
	if result.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_SUCCESS || result.GetResultHash() == "" {
		t.Errorf("Close result %v", result)
	}
	// The identifiers are the pipeline's, never one the adapter minted.
	if result.GetRequestId() != pipelineRequestID || result.GetExecutionId() != pipelineExecutionID {
		t.Errorf("Close result names %s/%s, want the pipeline's %s/%s",
			result.GetRequestId(), result.GetExecutionId(), pipelineRequestID, pipelineExecutionID)
	}
	if env.GetRequestId() == pipelineRequestID {
		t.Fatal("the adapter's own request id is the fake's, so this proves nothing")
	}
	if closes[0].d.AuthorizedDigest != env.GetArguments().GetCanonicalHash() {
		t.Errorf("Close got a disposition for another digest")
	}
}

// TestBlockNeverReachesUpstream: Block. A denied call is an isError tool
// result carrying the decision's codes and id, never a JSON-RPC error, and
// the victim ran zero times.
func TestBlockNeverReachesUpstream(t *testing.T) {
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		r.pipe.decide = deny
		agent := r.connect(t, "agent-a")
		res, err := callTool(t, agent, "delete_file", map[string]any{"path": "/x"})
		if err != nil {
			t.Fatalf("a block came back as an error: %v", err)
		}
		if !res.IsError || !slices.Equal(codesOf(t, res), []string{"RULE_DENY"}) || structured(t, res)["decision_id"] != "dec-1" {
			t.Fatalf("block on the wire: %+v", res)
		}
		if n := r.victim.count("delete_file"); n != 0 {
			t.Fatalf("victim ran %d times", n)
		}
		if len(r.pipe.closed()) != 0 {
			t.Errorf("a block was closed as an execution")
		}
		if s := r.adapter.Stats(); s.Blocked != 1 || s.Sent != 0 {
			t.Errorf("stats %+v", s)
		}
	})
}

// TestZeroDispositionBlocks: a pipeline that answers nothing blocks.
func TestZeroDispositionBlocks(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	r.pipe.decide = func(gateway.Admission) gateway.Disposition { return gateway.Disposition{} }
	res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
	if err != nil || !res.IsError || !slices.Equal(codesOf(t, res), []string{"POLICY_UNAVAILABLE"}) {
		t.Fatalf("zero disposition on the wire: %v %+v", err, res)
	}
	if n := r.victim.count("read_file"); n != 0 {
		t.Fatalf("victim ran %d times", n)
	}
}

// TestPendingIsAToolResult: AwaitApproval answers at once with the pending
// payload, on every revision, and nothing is sent.
func TestPendingIsAToolResult(t *testing.T) {
	expires := time.Date(2026, 9, 19, 20, 0, 0, 0, time.UTC)
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		r.pipe.decide = func(gateway.Admission) gateway.Disposition {
			return gateway.Disposition{Action: core.AwaitApproval, Pending: &gateway.Pending{
				ApprovalID: "apr-1", ActionDigest: "sha256:" + string(bytes.Repeat([]byte("a"), 64)), ExpiresAt: expires, RetryAfter: 5 * time.Second,
			}}
		}
		res, err := callTool(t, r.connect(t, "agent-a"), "transfer", map[string]any{"amount": 5, "account": "acc-1"})
		if err != nil || !res.IsError {
			t.Fatalf("pending on the wire: %v %+v", err, res)
		}
		sc := structured(t, res)
		if sc["reason_code"] != "APPROVAL_PENDING" || sc["approval_id"] != "apr-1" || sc["expires_at"] != "2026-09-19T20:00:00Z" || sc["retry_after"] != float64(5) {
			t.Fatalf("pending payload %v", sc)
		}
		if sc["action_digest"] != "sha256:"+string(bytes.Repeat([]byte("a"), 64)) {
			t.Fatalf("pending payload %v", sc)
		}
		if n := r.victim.count("transfer"); n != 0 {
			t.Fatalf("victim ran %d times", n)
		}
	})
}

// TestPendingRetryAfterRoundsUp: the hint is whole seconds, and a fraction
// rounds up, so a sub-second setting never tells the agent to retry at once.
func TestPendingRetryAfterRoundsUp(t *testing.T) {
	for _, tc := range []struct {
		after time.Duration
		want  float64
	}{{500 * time.Millisecond, 1}, {1500 * time.Millisecond, 2}, {2 * time.Second, 2}} {
		t.Run(tc.after.String(), func(t *testing.T) {
			r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
			r.pipe.decide = func(gateway.Admission) gateway.Disposition {
				return gateway.Disposition{Action: core.AwaitApproval, Pending: &gateway.Pending{
					ApprovalID: "apr-1", ActionDigest: "sha256:" + string(bytes.Repeat([]byte("a"), 64)), ExpiresAt: time.Now(), RetryAfter: tc.after,
				}}
			}
			res, err := callTool(t, r.connect(t, "agent-a"), "transfer", map[string]any{"amount": 5, "account": "acc-1"})
			if err != nil || !res.IsError {
				t.Fatalf("pending on the wire: %v %+v", err, res)
			}
			if got := structured(t, res)["retry_after"]; got != tc.want {
				t.Fatalf("retry_after %v for %v, want %v", got, tc.after, tc.want)
			}
		})
	}
}

// TestMismatchNeverSends: a disposition whose digest is not the digest of
// its bytes is refused before the send, answered as EXECUTED_ARGS_MISMATCH,
// and aborted, never closed with bytes nothing sent.
func TestMismatchNeverSends(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	other, err := canon.ArgumentsHashV1([]byte(`{"path":"/other"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.pipe.decide = func(a gateway.Admission) gateway.Disposition {
		d := execute(a)
		d.AuthorizedDigest = other
		return d
	}
	res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
	if err != nil || !res.IsError || !slices.Equal(codesOf(t, res), []string{"EXECUTED_ARGS_MISMATCH"}) {
		t.Fatalf("mismatch on the wire: %v %+v", err, res)
	}
	if n := r.victim.count("read_file"); n != 0 {
		t.Fatalf("victim ran %d times", n)
	}
	if closes := r.pipe.closed(); len(closes) != 0 {
		t.Fatalf("a call nothing sent was closed: %+v", closes)
	}
	aborts := r.pipe.aborted()
	if len(aborts) != 1 || aborts[0].cause != gateway.AbortArgsMismatch {
		t.Fatalf("Abort calls %+v, want one AbortArgsMismatch", aborts)
	}
	// The same bytes under their own digest are sent: the check is the
	// comparison, not the shape.
	r.pipe.decide = execute
	if res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("matching digest: %v %+v", err, res)
	}
	if n := r.victim.count("read_file"); n != 1 {
		t.Fatalf("victim ran %d times, want 1", n)
	}
}

// TestUnclassifiedIsThePipelinesToDecide: a tool the manifest holds no
// entry for reaches the pipeline as the envelope the adapter could build
// beside a refusal wrapping gateway.ErrUnclassified. The adapter overrides
// nothing: under ENFORCE the pipeline blocks it and the upstream never runs
// it; under OBSERVE the pipeline lets it through and the adapter sends it.
func TestUnclassifiedIsThePipelinesToDecide(t *testing.T) {
	for _, tc := range []struct {
		mode  controlv1.EnforcementMode
		sent  int
		codes []string
	}{
		{modeEnforce, 0, []string{"ACTION_UNCLASSIFIED"}},
		{modeObserve, 1, nil},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			r := newRig(t, mcp.KindStdio, rigOptions{mode: tc.mode, rules: []string{allowEverything}})
			res, err := callTool(t, r.connect(t, "agent-a"), "unlisted", map[string]any{"path": "/x"})
			if err != nil {
				t.Fatalf("unlisted: %v", err)
			}
			if tc.codes != nil && (!res.IsError || !slices.Equal(codesOf(t, res), tc.codes)) {
				t.Fatalf("unlisted under %s: %+v", tc.mode, res)
			}
			if tc.codes == nil && res.IsError {
				t.Fatalf("unlisted under %s: %+v", tc.mode, res)
			}
			if n := r.victim.count("unlisted"); n != tc.sent {
				t.Fatalf("victim ran %d times under %s, want %d", n, tc.mode, tc.sent)
			}
		})
	}
}

// TestRefusedTranslationIsNeverSent: a call the adapter could not translate
// into an envelope the contract accepts is blocked by the pipeline under
// OBSERVE as under ENFORCE, with the kernel's code for the refusal, and its
// trail never says it started.
func TestRefusedTranslationIsNeverSent(t *testing.T) {
	// delete_file is a DELETE, which needs a resource id; an argument
	// document that names none leaves the envelope invalid.
	for _, mode := range []controlv1.EnforcementMode{modeObserve, modeEnforce} {
		t.Run(mode.String(), func(t *testing.T) {
			r := newRig(t, mcp.KindStdio, rigOptions{mode: mode, rules: []string{allowEverything}})
			res, err := callTool(t, r.connect(t, "agent-a"), "delete_file", map[string]any{"other": "/x"})
			if err != nil || !res.IsError {
				t.Fatalf("a refused translation: %v %+v", err, res)
			}
			if got := codesOf(t, res); !slices.Equal(got, []string{"REQUIRED_FIELD_ABSENT"}) {
				t.Errorf("the block names %v, want the kernel's REQUIRED_FIELD_ABSENT alone", got)
			}
			if n := r.victim.count("delete_file"); n != 0 {
				t.Fatalf("victim ran %d times", n)
			}
			want := []controlv1.EventKind{controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, controlv1.EventKind_EVENT_KIND_POLICY_DECIDED, controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED}
			if kinds := r.kindsOf(t, ""); !slices.Equal(kinds, want) {
				t.Fatalf("trail %v, want %v", kinds, want)
			}
		})
	}
}

// TestClientInfoNeverReachesTheDigest: two clients with one credential and
// two names produce one digest; the name is a run-context tag.
func TestClientInfoNeverReachesTheDigest(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	for _, name := range []string{"agent-a", "agent-b"} {
		if _, err := callTool(t, r.connect(t, name), "read_file", map[string]any{"path": "/x"}); err != nil {
			t.Fatal(err)
		}
	}
	adm := r.pipe.admitted()
	if len(adm) != 2 {
		t.Fatalf("admissions %d", len(adm))
	}
	var digests []string
	for _, a := range adm {
		d, err := canon.DigestV1(a.a.Envelope, a.a.Arguments)
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, d)
		if a.a.Envelope.GetAgent().GetId() != "agent-1" || a.a.Envelope.GetPrincipal().GetId() != "svc-agent" {
			t.Errorf("identity came from the client: %v %v", a.a.Envelope.GetAgent(), a.a.Envelope.GetPrincipal())
		}
	}
	if digests[0] != digests[1] {
		t.Errorf("two clientInfo names gave two digests: %v", digests)
	}
	tags := [][]string{adm[0].a.Envelope.GetContext().GetTags(), adm[1].a.Envelope.GetContext().GetTags()}
	if !slices.Contains(tags[0], "mcp.client=agent-a/0") || !slices.Contains(tags[1], "mcp.client=agent-b/0") {
		t.Errorf("tags %v", tags)
	}
}

// TestUpstreamErrorPassesThrough: a wire error from the victim keeps its
// code across the hop, and Close records a FAILURE.
func TestUpstreamErrorPassesThrough(t *testing.T) {
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		agent := r.connect(t, "agent-a")
		_, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///missing"})
		var werr *jsonrpc.Error
		if !errors.As(err, &werr) || werr.Code != jsonrpcCodeInvalidParams {
			t.Fatalf("want the victim's -32602, got %v", err)
		}
		closes := r.pipe.closed()
		if len(closes) != 1 || closes[0].result.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_FAILURE || closes[0].result.GetToolProtocolStatus() != "jsonrpc:-32602" {
			t.Fatalf("Close calls %+v", closes)
		}
	})
}

// TestReadsAreForwardedAsReads: resources/read and prompts/get reach the
// pipeline as READ envelopes naming the resource, and a block on them is
// the adapter's own JSON-RPC code, outside the reserved range.
func TestReadsAreForwardedAsReads(t *testing.T) {
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		agent := r.connect(t, "agent-a")
		if _, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"}); err != nil {
			t.Fatal(err)
		}
		if _, err := agent.GetPrompt(ctxT(t), &sdk.GetPromptParams{Name: "p"}); err != nil {
			t.Fatal(err)
		}
		adm := r.pipe.admitted()
		if len(adm) != 2 {
			t.Fatalf("admissions %d", len(adm))
		}
		assertReadEnvelope(t, adm[0].a.Envelope, "resource", "file:///r")
		assertReadEnvelope(t, adm[1].a.Envelope, "prompt", "p")
		if r.victim.count("resources/read") != 1 || r.victim.count("prompts/get") != 1 {
			t.Errorf("victim counts: read %d get %d", r.victim.count("resources/read"), r.victim.count("prompts/get"))
		}
		r.pipe.decide = deny
		_, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"})
		var werr *jsonrpc.Error
		if !errors.As(err, &werr) || werr.Code != mcp.CodeBlocked || !bytes.Contains(werr.Data, []byte(`"RULE_DENY"`)) {
			t.Fatalf("blocked read on the wire: %v", err)
		}
		if n := r.victim.count("resources/read"); n != 1 {
			t.Errorf("victim read %d times, want 1", n)
		}
	})
}

// TestOwnCodesAreOutsideTheReservedRange: the adapter's JSON-RPC codes sit
// outside what the protocol reserves, away from the library's own and apart
// from each other.
func TestOwnCodesAreOutsideTheReservedRange(t *testing.T) {
	codes := map[string]int64{"CodeBlocked": mcp.CodeBlocked, "CodePending": mcp.CodePending, "CodeRunRefused": mcp.CodeRunRefused}
	seen := map[int64]string{}
	for name, code := range codes {
		if code >= -32768 && code <= -32000 || code == -31001 {
			t.Errorf("%s %d is in a reserved range", name, code)
		}
		if other, ok := seen[code]; ok {
			t.Errorf("%s and %s are one code", name, other)
		}
		seen[code] = name
	}
}

func assertReadEnvelope(t *testing.T, env *controlv1.ActionEnvelope, kind, name string) {
	t.Helper()
	act, res := env.GetAction(), env.GetResource()
	if act.GetKind() != kind || act.GetName() != name || act.GetEffect() != effectRead || res.GetId() != name || res.GetType() != "mcp."+kind {
		t.Errorf("%s: action %v resource %v", kind, act, res)
	}
}

// TestCloseFailureDeliversAndCounts: a Close that fails still delivers the
// upstream result; the failure is counted so nothing reads it as durable.
func TestCloseFailureDeliversAndCounts(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	r.pipe.closeErr = gateway.ErrExecutedArgsMismatch
	res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
	if err != nil || res.IsError {
		t.Fatalf("the result was not delivered: %v %+v", err, res)
	}
	if s := r.adapter.Stats(); s.CloseFailures != 1 {
		t.Errorf("stats %+v, want one close failure", s)
	}
}

const jsonrpcCodeInvalidParams = -32602
