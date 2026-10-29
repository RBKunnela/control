package mcp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

// queryMarker stands for a credential an operator put in an upstream's
// endpoint query; nothing the agent or the log sees may carry it.
const queryMarker = "query-credential-marker"

// lockedBuffer is a log destination the notification goroutine writes while
// the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestATransportFailureNeverQuotesTheEndpoint: with the upstream gone, every
// method that reaches it fails, and no answer quotes the endpoint the
// transport dialled, whose query holds a credential.
func TestATransportFailureNeverQuotesTheEndpoint(t *testing.T) {
	v := newVictim()
	upstream := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return v.server }, &sdk.StreamableHTTPOptions{Stateless: true}))
	transport := &sdk.StreamableClientTransport{Endpoint: upstream.URL + "/mcp?token=" + queryMarker}
	a, err := mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, transport, rigOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctxT(t), &fakePipeline{decide: execute}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	agent := connectHTTP(t, serveHTTP(t, h), "agent-a", v20260728, nil)
	upstream.CloseClientConnections()
	upstream.Close()

	ctx := ctxT(t)
	for method, call := range map[string]func() error{
		"tools/call": func() error {
			_, err := agent.CallTool(ctx, &sdk.CallToolParams{Name: "read_file", Arguments: map[string]any{"path": "/x"}})
			return err
		},
		"resources/read": func() error {
			_, err := agent.ReadResource(ctx, &sdk.ReadResourceParams{URI: "file:///r"})
			return err
		},
		"prompts/get": func() error {
			_, err := agent.GetPrompt(ctx, &sdk.GetPromptParams{Name: "p"})
			return err
		},
		"resources/list":           func() error { _, err := agent.ListResources(ctx, nil); return err },
		"resources/templates/list": func() error { _, err := agent.ListResourceTemplates(ctx, nil); return err },
		"prompts/list":             func() error { _, err := agent.ListPrompts(ctx, nil); return err },
	} {
		err := call()
		var werr *jsonrpc.Error
		if !errors.As(err, &werr) {
			t.Errorf("%s with the upstream gone = %v, want a JSON-RPC error", method, err)
			continue
		}
		if strings.Contains(err.Error(), queryMarker) || strings.Contains(err.Error(), upstream.URL) {
			t.Errorf("%s answered %q, which quotes the endpoint", method, err)
		}
	}
}

// TestARefreshFailureIsLoggedWithoutTheUpstreamsWords: an upstream that
// announces a changed list and refuses to give it with an error whose
// message reflects a credential is logged by the error's code, never by that
// message.
func TestARefreshFailureIsLoggedWithoutTheUpstreamsWords(t *testing.T) {
	v := newVictim()
	refusing := make(chan struct{})
	v.server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, m string, req sdk.Request) (sdk.Result, error) {
			select {
			case <-refusing:
				if m == "tools/list" {
					return nil, &jsonrpc.Error{Code: -32042, Message: "reflected " + queryMarker}
				}
			default:
			}
			return next(ctx, m, req)
		}
	})
	ct, st := sdk.NewInMemoryTransports()
	ss, err := v.server.Connect(ctxT(t), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	logs := &lockedBuffer{}
	cfg := newConfig(t, v, mcp.KindStatelessHTTP, ct, rigOptions{})
	cfg.Logger = slog.New(slog.NewTextHandler(logs, nil))
	a, err := mcp.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctxT(t), &fakePipeline{decide: execute}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	close(refusing)
	v.server.AddTool(&sdk.Tool{Name: "added", InputSchema: objectSchema(nil)}, v.handler("added"))
	waitFor(t, "the refresh to fail", func() bool { return a.Stats().RefreshFailures > 0 })
	waitFor(t, "the failure to be logged", func() bool { return strings.Contains(logs.String(), "manifest refresh failed") })
	if got := logs.String(); strings.Contains(got, queryMarker) || !strings.Contains(got, "-32042") {
		t.Errorf("the log says %q; want the code and nothing of the upstream's message", got)
	}
}

// TestAnOverlongNameStaysOffTheTrail: a tool no entry classifies, named past
// the contract's bound on a string, is refused as too large rather than as
// unclassified, and its name stays off the envelope, so the trail can record
// the call; at the bound the name is kept and the call is unclassified. A
// client naming itself past the bound is refused the same way on a classified
// tool.
func TestAnOverlongNameStaysOffTheTrail(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{})
	agent := r.connect(t, "agent-a")
	at := strings.Repeat("n", contract.MaxStringBytes)
	for i, name := range []string{at, at + "n", strings.Repeat("n", evidence.MaxLineBytes)} {
		// The fake pipeline sends what it admits, and the upstream knows no
		// such tool; what matters is what the adapter admitted.
		_, _ = callTool(t, agent, name, nil)
		got := r.pipe.admitted()
		if len(got) != i+1 {
			t.Fatalf("a call named %d bytes: %d admission(s), want %d", len(name), len(got), i+1)
		}
		a := got[i].a
		if len(name) == contract.MaxStringBytes {
			if !errors.Is(a.Refusal, gateway.ErrUnclassified) || a.Envelope.GetAction().GetName() != name {
				t.Errorf("a name at the bound: refusal %v, name of %d bytes; want unclassified, name kept", a.Refusal, len(a.Envelope.GetAction().GetName()))
			}
			continue
		}
		expectOffTheTrail(t, a, "a name of "+strconv.Itoa(len(name))+" bytes")
	}
	client := r.connect(t, strings.Repeat("c", evidence.MaxLineBytes))
	if _, err := callTool(t, client, "read_file", map[string]any{"path": "/x"}); err != nil {
		t.Fatal(err)
	}
	got := r.pipe.admitted()
	expectOffTheTrail(t, got[len(got)-1].a, "an overlong client name")
}

// TestAnOverlongClientNameIsNotSent: on the real pipeline, a call from a
// client that names itself past the contract's bound is blocked as too large
// in OBSERVE as in ENFORCE, and the upstream is never called.
func TestAnOverlongClientNameIsNotSent(t *testing.T) {
	for _, mode := range []controlv1.EnforcementMode{modeObserve, modeEnforce} {
		t.Run(mode.String(), func(t *testing.T) {
			r := newRig(t, mcp.KindStdio, rigOptions{mode: mode, rules: []string{allowEverything}})
			res, err := callTool(t, r.connect(t, strings.Repeat("c", evidence.MaxLineBytes)), "read_file", map[string]any{"path": "/x"})
			if err != nil || !res.IsError {
				t.Fatalf("a call from an overlong client name: %v %+v", err, res)
			}
			if got := codesOf(t, res); !slices.Equal(got, []string{"LIMIT_EXCEEDED"}) {
				t.Errorf("the block names %v, want the kernel's LIMIT_EXCEEDED alone", got)
			}
			if n := r.victim.count("read_file"); n != 0 {
				t.Errorf("the victim ran read_file %d time(s) for an overlong client name", n)
			}
		})
	}
}

// expectOffTheTrail asserts a is refused as too large and carries an envelope
// a trail line holds.
func expectOffTheTrail(t *testing.T, a gateway.Admission, what string) {
	t.Helper()
	if !errors.Is(a.Refusal, contract.ErrTooLarge) || errors.Is(a.Refusal, gateway.ErrUnclassified) {
		t.Errorf("%s: refusal %v, want too large and nothing else", what, a.Refusal)
	}
	if size := proto.Size(a.Envelope); size > contract.MaxEnvelopeBytes {
		t.Errorf("%s: the envelope is %d bytes, past the contract's %d", what, size, contract.MaxEnvelopeBytes)
	}
	event := &controlv1.Event{EventId: "evt-1", Payload: &controlv1.Event_Proposed{Proposed: a.Envelope}}
	if err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{event}); err != nil {
		t.Errorf("%s: the proposal cannot be recorded: %v", what, err)
	}
}

// TestARewriteThatMovesTheResourceIsNotSent: the pipeline refuses rewritten
// bytes whose member at the classification's pointer no longer names the
// decided resource, so nothing is sent and nothing started; a rewrite that
// leaves the member alone is sent.
func TestARewriteThatMovesTheResourceIsNotSent(t *testing.T) {
	redact := func(field string) string {
		return `{"id":"redact","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"redact_fields","params":{"fields":"` + field +
			`"}}],"when":{"action":{"name":["read_file"]}}}`
	}
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{redact("path")}})
	res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x", "note": "n"})
	if err != nil || !res.IsError || !slices.Equal(codesOf(t, res), []string{"OBLIGATION_NOT_UNDERSTOOD"}) {
		t.Fatalf("a call whose resource moved: %v %+v", err, res)
	}
	if n := r.victim.count("read_file"); n != 0 {
		t.Errorf("the victim ran read_file %d time(s) on a moved resource", n)
	}
	for _, e := range r.events() {
		if e.GetKind() == controlv1.EventKind_EVENT_KIND_ACTION_STARTED {
			t.Errorf("a call whose resource moved was recorded as started")
		}
	}
	r = newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{redact("note")}})
	if res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x", "note": "n"}); err != nil || res.IsError {
		t.Fatalf("a rewrite that keeps the resource: %v %+v", err, res)
	}
	if got := r.victim.args("read_file"); len(got) != 1 || string(got[0]) != `{"path":"/x"}` {
		t.Errorf("the victim received %s, want the rewritten bytes once", got)
	}
}

// TestForwardedListsLoseTheGatewaysKeys: a resource, a template and a prompt
// an upstream lists under the gateway's _meta namespace reach the agent
// without those keys and with the upstream's own.
func TestForwardedListsLoseTheGatewaysKeys(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{})
	meta := func() sdk.Meta { return sdk.Meta{metaAnswer: "blocked", "upstream-key": "kept"} }
	r.victim.server.AddResource(&sdk.Resource{URI: "file:///m", Name: "m", Meta: meta()}, nil)
	r.victim.server.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: "file:///t/{id}", Name: "t", Meta: meta()}, nil)
	r.victim.server.AddPrompt(&sdk.Prompt{Name: "m", Meta: meta()}, nil)
	agent := r.connect(t, "agent-a")
	ctx := ctxT(t)
	resources, err := agent.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	templates, err := agent.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	prompts, err := agent.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]sdk.Meta{}
	for _, res := range resources.Resources {
		found["resource "+res.Name] = res.Meta
	}
	for _, tmpl := range templates.ResourceTemplates {
		found["template "+tmpl.Name] = tmpl.Meta
	}
	for _, p := range prompts.Prompts {
		found["prompt "+p.Name] = p.Meta
	}
	for _, item := range []string{"resource m", "template t", "prompt m"} {
		got, listed := found[item]
		if !listed || got[metaAnswer] != nil || got["upstream-key"] != "kept" {
			t.Errorf("%s: listed %v with _meta %v; want the upstream's key and none of the gateway's", item, listed, got)
		}
	}
}

// TestAnUnansweredCallIsOneFixedError: a call the upstream never answered,
// cut by the call timeout, is answered with one fixed code and message,
// whatever the method, rather than with the error's own text.
func TestAnUnansweredCallIsOneFixedError(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{timeout: 100 * time.Millisecond})
	blockMethod(t, r.victim, "resources/read")
	agent := r.connect(t, "agent-a")
	_, callErr := callTool(t, agent, "slow", map[string]any{"path": "/x"})
	_, readErr := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"})
	for method, err := range map[string]error{"tools/call": callErr, "resources/read": readErr} {
		var werr *jsonrpc.Error
		if !errors.As(err, &werr) || werr.Code != jsonrpc.CodeInternalError || werr.Message != "the upstream did not answer" {
			t.Errorf("%s past its timeout = %v, want code %d and the fixed message", method, err, jsonrpc.CodeInternalError)
		}
	}
}

// TestStartNamesTheUpstreamAndNeverItsEndpoint: an upstream Start cannot
// reach, through a query or a username holding a credential, and one whose
// tools/list answers a wire error reflecting a credential, fail Start with an
// error that names the upstream and what failed, and holds neither the
// endpoint nor the upstream's message.
func TestStartNamesTheUpstreamAndNeverItsEndpoint(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	host := strings.TrimPrefix(gone.URL, "http://")
	gone.Close()
	v := newVictim()
	v.server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, m string, req sdk.Request) (sdk.Result, error) {
			if m == "tools/list" {
				return nil, &jsonrpc.Error{Code: -32042, Message: "reflected " + queryMarker}
			}
			return next(ctx, m, req)
		}
	})
	listing := serveHTTP(t, sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return v.server }, &sdk.StreamableHTTPOptions{Stateless: true}))
	for endpoint, want := range map[string]string{
		"http://" + host + "/mcp?token=" + queryMarker:   "mcp: connect victim: Post: dial tcp",
		"http://" + queryMarker + ":pw@" + host + "/mcp": "mcp: connect victim: Post: dial tcp",
		listing + "/mcp": "mcp: tools/list from victim: JSON-RPC error -32042",
	} {
		transport := &sdk.StreamableClientTransport{Endpoint: endpoint}
		a, err := mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, transport, rigOptions{}))
		if err != nil {
			t.Fatal(err)
		}
		err = a.Start(ctxT(t), &fakePipeline{decide: execute})
		if err == nil || strings.Contains(err.Error(), queryMarker) || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("Start over %s = %v; want it to begin %q and hold no credential", endpoint, err, want)
		}
	}
}

// TestCloseNamesTheUpstreamAndNeverItsEndpoint: a stateful upstream gone by
// the time the plane closes its session fails the session's DELETE, and the
// close error names the upstream and the cause, never the endpoint's query.
func TestCloseNamesTheUpstreamAndNeverItsEndpoint(t *testing.T) {
	v := newVictim()
	up := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return v.server }, nil))
	t.Cleanup(up.Close)
	transport := &sdk.StreamableClientTransport{Endpoint: up.URL + "/mcp?token=" + queryMarker}
	a, err := mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, transport, rigOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctxT(t), &fakePipeline{decide: execute}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	up.CloseClientConnections()
	up.Close()
	err = a.Close()
	if err == nil || strings.Contains(err.Error(), queryMarker) || !strings.HasPrefix(err.Error(), "mcp: close victim: ") {
		t.Errorf("Close = %v; want it to begin %q and hold no credential", err, "mcp: close victim: ")
	}
}

// TestStartGivesUpOnAnUpstreamThatNeverAnswers: an upstream that takes the
// connection and never answers it fails Start within the list timeout, plus
// the library's own close, rather than holding it until a signal.
func TestStartGivesUpOnAnUpstreamThatNeverAnswers(t *testing.T) {
	release := make(chan struct{})
	silent := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); silent.Close() })
	v := newVictim()
	a, err := mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, &sdk.StreamableClientTransport{Endpoint: silent.URL + "/mcp"},
		rigOptions{timeout: 200 * time.Millisecond, listTimeout: 200 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Start(ctx, &fakePipeline{decide: execute}) }()
	select {
	case err := <-done:
		if err == nil || !strings.HasPrefix(err.Error(), "mcp: connect victim:") {
			t.Fatalf("Start = %v, want a failure to connect victim", err)
		}
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatalf("Start was still connecting 30s in with a 200ms list timeout; it returned %v only when cancelled", <-done)
	}
}
