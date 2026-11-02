package mcp_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/gateway"
)

// digestOf is the canonical action digest of one admission, computed from
// the envelope and the bytes, never taken from the adapter.
func digestOf(t *testing.T, a gateway.Admission) string {
	t.Helper()
	d, err := canon.DigestV1(a.Envelope, a.Arguments)
	if err != nil {
		t.Fatalf("DigestV1: %v", err)
	}
	return d
}

// TestPromptArgumentsAreBoundAndAuthorized: two prompts/get differing only
// in their arguments are two actions with two digests, and the upstream
// receives the arguments the pipeline authorized, not the agent's.
func TestPromptArgumentsAreBoundAndAuthorized(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{})
	agent := r.connect(t, "agent-a")
	for _, q := range []string{"ls", "rm -rf /"} {
		if _, err := agent.GetPrompt(ctxT(t), &sdk.GetPromptParams{Name: "p", Arguments: map[string]string{"q": q}}); err != nil {
			t.Fatal(err)
		}
	}
	assertTwoPromptsDiffer(t, r)
	// What the pipeline authorized is what goes, whatever the agent asked.
	r.pipe.decide = authorize(`{"q":"redacted"}`)
	if _, err := agent.GetPrompt(ctxT(t), &sdk.GetPromptParams{Name: "p", Arguments: map[string]string{"q": "rm -rf /"}}); err != nil {
		t.Fatal(err)
	}
	got := r.victim.prompts()
	if len(got) != 3 || got[2]["q"] != "redacted" {
		t.Fatalf("the upstream received %v, want the authorized arguments", got)
	}
	closes := r.pipe.closed()
	if len(closes) != 3 || string(closes[2].sent) != `{"q":"redacted"}` {
		t.Fatalf("Close got %s as the bytes that were sent", closes[2].sent)
	}
}

// assertTwoPromptsDiffer checks the two prompts/get were two actions, and
// that each reached the upstream with the arguments it asked with.
func assertTwoPromptsDiffer(t *testing.T, r *rig) {
	t.Helper()
	adm := r.pipe.admitted()
	if len(adm) != 2 {
		t.Fatalf("admissions %d", len(adm))
	}
	if string(adm[0].a.Arguments) != `{"q":"ls"}` || string(adm[1].a.Arguments) != `{"q":"rm -rf /"}` {
		t.Fatalf("the arguments the pipeline saw: %s and %s", adm[0].a.Arguments, adm[1].a.Arguments)
	}
	if first, second := digestOf(t, adm[0].a), digestOf(t, adm[1].a); first == second {
		t.Errorf("two prompts/get with different arguments share the digest %s", first)
	}
	if got := r.victim.prompts(); len(got) != 2 || got[0]["q"] != "ls" || got[1]["q"] != "rm -rf /" {
		t.Errorf("the upstream received %v", got)
	}
}

// TestReadsSendFreshParams: a resources/read and a prompts/get reach the
// upstream in params the adapter built from what was authorized; the agent's
// own _meta and request state stay with the gateway.
func TestReadsSendFreshParams(t *testing.T) {
	const agentOnly = "the agent's own header"
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		agent := r.connect(t, "agent-a")
		if _, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{
			URI: "file:///r", Meta: sdk.Meta{"x-agent-only": agentOnly}, RequestState: "state-1",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := agent.GetPrompt(ctxT(t), &sdk.GetPromptParams{
			Name: "p", Arguments: map[string]string{"q": "x"}, Meta: sdk.Meta{"x-agent-only": agentOnly}, RequestState: "state-2",
		}); err != nil {
			t.Fatal(err)
		}
		assertFreshParams(t, r.victim.received())
	})
}

// assertFreshParams checks the two reads reached the upstream in params the
// adapter built: the name it authorized, and nothing of the agent's own.
func assertFreshParams(t *testing.T, received []sdk.Params) {
	t.Helper()
	if len(received) != 2 {
		t.Fatalf("the upstream served %d reads", len(received))
	}
	for _, p := range received {
		if got := p.GetMeta()["x-agent-only"]; got != nil {
			t.Errorf("the agent's _meta reached the upstream: %v", got)
		}
	}
	read, ok := received[0].(*sdk.ReadResourceParams)
	if !ok || read.URI != "file:///r" || read.RequestState != "" || len(read.InputResponses) != 0 {
		t.Errorf("resources/read params %+v", received[0])
	}
	prompt, ok := received[1].(*sdk.GetPromptParams)
	if !ok || prompt.Name != "p" || prompt.RequestState != "" || len(prompt.InputResponses) != 0 {
		t.Errorf("prompts/get params %+v", received[1])
	}
}

// TestAbsentArgumentsAreTheEmptyDocument: a call with no arguments, and one
// whose arguments are null, are decided and sent as the empty document; the
// wire never carries null, and Close gets the bytes that were sent.
func TestAbsentArgumentsAreTheEmptyDocument(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	bodies := map[string]string{
		"absent": rawCall(t, 1, map[string]any{"name": "read_file", "_meta": meta()}),
		"null":   rawCall(t, 2, map[string]any{"name": "read_file", "arguments": nil, "_meta": meta()}),
	}
	for _, name := range slices.Sorted(maps.Keys(bodies)) {
		if status, body := rawPostWith(t, r.url, nil, bodies[name], "read_file"); status != 200 {
			t.Fatalf("%s arguments: HTTP %d %s", name, status, body)
		}
	}
	adm := r.pipe.admitted()
	if len(adm) != 2 {
		t.Fatalf("admissions %d", len(adm))
	}
	for i, a := range adm {
		if got := string(a.a.Arguments); got != "{}" {
			t.Errorf("admission %d saw arguments %q, want {}", i, got)
		}
	}
	for i, got := range r.victim.args("read_file") {
		if string(got) != "{}" {
			t.Errorf("the upstream received %q as the arguments of call %d", got, i)
		}
	}
	for i, c := range r.pipe.closed() {
		if string(c.sent) != "{}" {
			t.Errorf("Close %d got %q as the bytes that were sent", i, c.sent)
		}
	}
}

// rawCall is one tools/call body with exactly the params given.
func rawCall(t *testing.T, id int, params map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
	if err != nil {
		t.Fatalf("marshalling the body: %v", err)
	}
	return string(b)
}

// TestReadsCarryTheEmptyDocument: a resources/read carries no arguments, so
// it is decided and closed about the empty document, and an authorized
// document that is not empty is never sent.
func TestReadsCarryTheEmptyDocument(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{})
	agent := r.connect(t, "agent-a")
	if _, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"}); err != nil {
		t.Fatal(err)
	}
	adm := r.pipe.admitted()
	if len(adm) != 1 || string(adm[0].a.Arguments) != "{}" {
		t.Fatalf("admissions %+v", adm)
	}
	if closes := r.pipe.closed(); len(closes) != 1 || string(closes[0].sent) != "{}" {
		t.Fatalf("Close calls %+v", closes)
	}
	r.pipe.decide = authorize(`{"uri":"file:///other"}`)
	_, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"})
	assertUncarryable(t, r, err)
}

// assertUncarryable: the authorized bytes are not what the method sends, so
// nothing went, the execution is aborted as untranslatable, and the agent is
// told a field is wrong rather than that the bytes disagreed.
func assertUncarryable(t *testing.T, r *rig, err error) {
	t.Helper()
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != mcp.CodeBlocked {
		t.Fatalf("a read whose authorized arguments it cannot carry: %v", err)
	}
	if !bytes.Contains(werr.Data, []byte(`"INVALID_FIELD_VALUE"`)) || bytes.Contains(werr.Data, []byte("EXECUTED_ARGS_MISMATCH")) {
		t.Errorf("the block says %s", werr.Data)
	}
	if n := r.victim.count("resources/read"); n != 1 {
		t.Errorf("the upstream served %d reads, want 1", n)
	}
	aborts := r.pipe.aborted()
	if len(aborts) != 1 || aborts[0].cause != gateway.AbortUntranslatable {
		t.Fatalf("Abort calls %+v, want one AbortUntranslatable", aborts)
	}
}

// TestAbortedExecutionIsNeverClosed: every execution the adapter does not
// send is aborted with the cause, and none is closed with bytes nothing
// sent.
func TestAbortedExecutionIsNeverClosed(t *testing.T) {
	cases := []struct {
		name   string
		decide func(gateway.Admission) gateway.Disposition
		tool   string
		cause  gateway.AbortCause
		codes  []string
	}{
		{"digest mismatch", authorizeWithWrongDigest(), "read_file", gateway.AbortArgsMismatch, []string{"EXECUTED_ARGS_MISMATCH"}},
		{"obligation refuses", executeWith(obligation("read_only", nil)), "delete_file", gateway.AbortObligation, []string{"OBLIGATIONS_ATTACHED", "OBLIGATION_NOT_UNDERSTOOD"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, mcp.KindStdio, rigOptions{})
			r.pipe.decide = tc.decide
			res, err := callTool(t, r.connect(t, "agent-a"), tc.tool, map[string]any{"path": "/x"})
			if err != nil || !res.IsError || !slices.Equal(codesOf(t, res), tc.codes) {
				t.Fatalf("%s on the wire: %v %+v", tc.name, err, res)
			}
			if n := r.victim.count(tc.tool); n != 0 {
				t.Errorf("the upstream ran %s %d times", tc.tool, n)
			}
			if closes := r.pipe.closed(); len(closes) != 0 {
				t.Errorf("an execution nothing sent was closed: %+v", closes)
			}
			aborts := r.pipe.aborted()
			if len(aborts) != 1 || aborts[0].cause != tc.cause {
				t.Fatalf("Abort calls %+v, want one %d", aborts, tc.cause)
			}
			if aborts[0].d.ExecutionID != pipelineExecutionID {
				t.Errorf("Abort got a disposition naming execution %q", aborts[0].d.ExecutionID)
			}
			// The agent is told the code the plane records the cause as.
			recorded, ok := tc.cause.Code()
			if codes := codesOf(t, res); !ok || codes[len(codes)-1] != recorded {
				t.Errorf("the answer ends %q; the plane records %s as %q", codes, tc.name, recorded)
			}
		})
	}
}

// authorizeWithWrongDigest hands out bytes under another document's digest.
func authorizeWithWrongDigest() func(gateway.Admission) gateway.Disposition {
	return func(a gateway.Admission) gateway.Disposition {
		d := execute(a)
		other, err := canon.ArgumentsHashV1([]byte(`{"path":"/other"}`))
		if err != nil {
			return gateway.Disposition{Decision: decision(controlv1.Verdict_VERDICT_INDETERMINATE, "INVALID_FIELD_VALUE")}
		}
		d.AuthorizedDigest = other
		return d
	}
}

// TestAuthenticatedListenerConfiguresNoUser: on a listener with an
// authenticator the operator configures the tenant and the type; an id, a
// strength or attributes are a claim about a user nobody authenticated and
// New refuses them.
func TestAuthenticatedListenerConfiguresNoUser(t *testing.T) {
	v := newVictim()
	ct, _ := sdk.NewInMemoryTransports()
	cases := []struct {
		name string
		mut  func(*controlv1.Principal)
		want error
	}{
		{"tenant and type only", func(*controlv1.Principal) {}, nil},
		{"an id", func(p *controlv1.Principal) { p.Id = "alice" }, mcp.ErrIdentity},
		{"a strength", func(p *controlv1.Principal) { p.AuthnStrength = "bearer" }, mcp.ErrIdentity},
		{"attributes", func(p *controlv1.Principal) { p.Attributes = map[string]string{"role": "admin"} }, mcp.ErrIdentity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig(t, v, mcp.KindStatelessHTTP, ct, rigOptions{auth: bearer()})
			tc.mut(cfg.Listener.Identity.Principal)
			a, err := mcp.New(cfg)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("New = %v, want an adapter", err)
			case tc.want != nil && (a != nil || !errors.Is(err, tc.want)):
				t.Fatalf("New = %v, %v; want nil, %v", a, err, tc.want)
			}
		})
	}
}
