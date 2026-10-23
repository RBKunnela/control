package mcp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/secretscan"
)

const (
	v20260728 = "2026-07-28"
	v20251125 = "2025-11-25"

	effectRead     = controlv1.EffectClass_EFFECT_CLASS_READ
	effectDelete   = controlv1.EffectClass_EFFECT_CLASS_DELETE
	effectTransact = controlv1.EffectClass_EFFECT_CLASS_TRANSACT
	effectComm     = controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE
	zoneInternal   = controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL
	zoneExternal   = controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL
)

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// victim is the upstream server. Every tool records the raw argument bytes
// it received; slow waits for its context or two seconds. A read and a
// prompt record what reached them beside the name, so a test can see what
// the adapter forwarded and what it did not.
type victim struct {
	server *sdk.Server
	tools  map[string]*sdk.Tool

	mu         sync.Mutex
	calls      map[string][]json.RawMessage
	replaced   map[string]sdk.ToolHandler
	promptArgs []map[string]string
	params     []sdk.Params
}

func objectSchema(props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props}
}

// upstreamMark is in every answer the victim gives, and random per test binary,
// so an agent cannot put it in a request for the gateway to echo back: its
// presence in a response is an upstream answer that reached the agent.
var upstreamMark = "upstream-" + rand.Text()

func newVictim() *victim {
	v := &victim{calls: map[string][]json.RawMessage{}, replaced: map[string]sdk.ToolHandler{}, tools: map[string]*sdk.Tool{}}
	v.server = sdk.NewServer(&sdk.Implementation{Name: "victim", Version: "0"}, nil)
	falseHint, trueHint := false, true
	path := objectSchema(map[string]any{"path": map[string]any{"type": "string"}})
	for _, t := range []*sdk.Tool{
		{Name: "read_file", Description: "reads a file", InputSchema: path, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &falseHint}},
		{Name: "delete_file", Description: "deletes a file", InputSchema: path, Annotations: &sdk.ToolAnnotations{DestructiveHint: &trueHint}},
		{Name: "transfer", InputSchema: objectSchema(map[string]any{"amount": map[string]any{"type": "integer"}, "account": map[string]any{"type": "string"}})},
		{Name: "send_mail", InputSchema: objectSchema(map[string]any{"to": map[string]any{"type": "string"}})},
		{Name: "slow", InputSchema: path},
		{Name: "unlisted", InputSchema: path},
	} {
		v.tools[t.Name] = t
		v.server.AddTool(t, v.handler(t.Name))
	}
	v.server.AddResource(&sdk.Resource{URI: "file:///r", Name: "r", MIMEType: "text/plain"}, func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
		v.record("resources/read", nil)
		v.recordParams(req.Params)
		return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: "file:///r", MIMEType: "text/plain", Text: "r " + upstreamMark}}}, nil
	})
	v.server.AddPrompt(&sdk.Prompt{Name: "p", Arguments: []*sdk.PromptArgument{{Name: "q"}}}, func(_ context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		v.record("prompts/get", nil)
		v.recordParams(req.Params)
		v.mu.Lock()
		v.promptArgs = append(v.promptArgs, req.Params.Arguments)
		v.mu.Unlock()
		return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{{Role: "user", Content: &sdk.TextContent{Text: "p " + upstreamMark}}}}, nil
	})
	return v
}

func (v *victim) handler(name string) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		v.mu.Lock()
		h := v.replaced[name]
		v.mu.Unlock()
		if h != nil {
			return h(ctx, req)
		}
		v.record(name, req.Params.Arguments)
		if name == "slow" {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: name + " ran " + upstreamMark}}}, nil
	}
}

func (v *victim) record(name string, args json.RawMessage) {
	v.mu.Lock()
	v.calls[name] = append(v.calls[name], bytes.Clone(args))
	v.mu.Unlock()
}

func (v *victim) recordParams(p sdk.Params) {
	v.mu.Lock()
	v.params = append(v.params, p)
	v.mu.Unlock()
}

// received returns the params of every read and prompt the victim served.
func (v *victim) received() []sdk.Params {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]sdk.Params(nil), v.params...)
}

// prompts returns the arguments of every prompts/get the victim served.
func (v *victim) prompts() []map[string]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]map[string]string(nil), v.promptArgs...)
}

func (v *victim) count(name string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.calls[name])
}

func (v *victim) args(name string) []json.RawMessage {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]json.RawMessage(nil), v.calls[name]...)
}

// fingerprint is the victim's definition of name as the operator would pin
// it; a test that needs a wrong one writes its own literal.
func (v *victim) fingerprint(t *testing.T, name string) string {
	t.Helper()
	fp, err := mcp.Fingerprint(v.tools[name])
	if err != nil {
		t.Fatalf("Fingerprint(%s): %v", name, err)
	}
	return fp
}

// overrides classifies the victim's tools; unlisted stays unclassified.
func (v *victim) overrides(t *testing.T) []mcp.Override {
	t.Helper()
	return []mcp.Override{
		{Upstream: "victim", Tool: "read_file", Fingerprint: v.fingerprint(t, "read_file"), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}},
		{Upstream: "victim", Tool: "delete_file", Fingerprint: v.fingerprint(t, "delete_file"), Classification: classify.Classification{Effect: effectDelete, ResourceType: "file", ResourceFrom: "/path"}},
		{Upstream: "victim", Tool: "transfer", Fingerprint: v.fingerprint(t, "transfer"), Classification: classify.Classification{Effect: effectTransact, ResourceType: "account", ResourceFrom: "/account"}},
		{Upstream: "victim", Tool: "send_mail", Fingerprint: v.fingerprint(t, "send_mail"), Classification: classify.Classification{Effect: effectComm, ResourceType: "mailbox", ResourceFrom: "/to", TrustZone: zoneExternal}},
		{Upstream: "victim", Tool: "slow", Fingerprint: v.fingerprint(t, "slow"), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}},
	}
}

// admitted is one Admit as the fake saw it, with the victim's tool call
// count at that moment: the proof that the pipeline is asked first.
type admitted struct {
	a           gateway.Admission
	victimCalls int
}

type closed struct {
	d      gateway.Disposition
	sent   []byte
	result *controlv1.ActionResult
}

// aborted is one Abort as the fake saw it: an execution the adapter was
// handed and did not send.
type aborted struct {
	d     gateway.Disposition
	cause gateway.AbortCause
}

// fakePipeline is the shape the adapter drives, for the dispositions a real
// pipeline never hands out: decide is what Admit answers, preview what
// Preview answers. Shaping and the modes are tested against the real
// pipeline.
type fakePipeline struct {
	decide   func(gateway.Admission) gateway.Disposition
	preview  func(gateway.Admission) *controlv1.Decision
	probe    func() int
	closeErr error
	abortErr error
	// onAdmit, when set, is handed the context of every Admit before the fake
	// answers it.
	onAdmit func(context.Context)

	mu         sync.Mutex
	admissions []admitted
	closes     []closed
	aborts     []aborted
}

func (f *fakePipeline) Admit(ctx context.Context, a gateway.Admission) gateway.Disposition {
	if f.onAdmit != nil {
		f.onAdmit(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := 0
	if f.probe != nil {
		calls = f.probe()
	}
	f.admissions = append(f.admissions, admitted{a: a, victimCalls: calls})
	return f.decide(a)
}

func (f *fakePipeline) Close(_ context.Context, d gateway.Disposition, sent []byte, result *controlv1.ActionResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes = append(f.closes, closed{d: d, sent: bytes.Clone(sent), result: result})
	return f.closeErr
}

func (f *fakePipeline) Abort(_ context.Context, d gateway.Disposition, cause gateway.AbortCause) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aborts = append(f.aborts, aborted{d: d, cause: cause})
	return f.abortErr
}

func (f *fakePipeline) Preview(_ context.Context, a gateway.Admission) *controlv1.Decision {
	if f.preview != nil {
		return f.preview(a)
	}
	return f.decide(a).Decision
}

func (f *fakePipeline) aborted() []aborted {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]aborted(nil), f.aborts...)
}

func (f *fakePipeline) admitted() []admitted {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]admitted(nil), f.admissions...)
}

func (f *fakePipeline) closed() []closed {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]closed(nil), f.closes...)
}

func decision(verdict controlv1.Verdict, codes ...string) *controlv1.Decision {
	return &controlv1.Decision{DecisionId: "dec-1", RequestId: pipelineRequestID, Verdict: verdict, ReasonCodes: codes}
}

// The identifiers the fake pipeline mints, which the adapter has to carry
// into the closing record instead of any of its own.
const (
	pipelineRequestID   = "pipeline-req-1"
	pipelineExecutionID = "pipeline-exe-1"
)

// execute authorizes the proposed bytes as they came.
func execute(a gateway.Admission) gateway.Disposition {
	digest, err := canon.ArgumentsHashV1(a.Arguments)
	if err != nil {
		return gateway.Disposition{Decision: decision(controlv1.Verdict_VERDICT_INDETERMINATE, "INVALID_FIELD_VALUE")}
	}
	return gateway.Disposition{
		Action:           core.Execute,
		Decision:         decision(controlv1.Verdict_VERDICT_ALLOW, "RULE_ALLOW"),
		AuthorizedArgs:   bytes.Clone(a.Arguments),
		AuthorizedDigest: digest,
		ExecutionID:      pipelineExecutionID,
	}
}

// authorize is execute with other bytes than the agent proposed, as a
// rewriting obligation leaves them.
func authorize(args string) func(gateway.Admission) gateway.Disposition {
	return func(a gateway.Admission) gateway.Disposition {
		d := execute(a)
		digest, err := canon.ArgumentsHashV1([]byte(args))
		if err != nil {
			return gateway.Disposition{Decision: decision(controlv1.Verdict_VERDICT_INDETERMINATE, "INVALID_FIELD_VALUE")}
		}
		d.AuthorizedArgs, d.AuthorizedDigest = []byte(args), digest
		return d
	}
}

// executeWith is execute under obligations.
func executeWith(obligations ...*controlv1.Obligation) func(gateway.Admission) gateway.Disposition {
	return func(a gateway.Admission) gateway.Disposition {
		d := execute(a)
		d.Action = core.ExecuteWithObligations
		d.Decision = decision(controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS, "OBLIGATIONS_ATTACHED")
		d.Obligations = obligations
		return d
	}
}

func deny(gateway.Admission) gateway.Disposition {
	return gateway.Disposition{Action: core.Block, Decision: decision(controlv1.Verdict_VERDICT_DENY, "RULE_DENY")}
}

// rig is one agent -> adapter -> victim arrangement.
type rig struct {
	kind    mcp.Kind
	version string
	victim  *victim
	adapter *mcp.Adapter
	pipe    *fakePipeline
	// real, sink and approvals are set when the rig runs on the real
	// pipeline.
	real      *realPipeline
	sink      *evidence.MemorySink
	approvals *gateway.MemoryApprovals
	url       string // "" on stdio
	connect   func(t *testing.T, clientName string) *sdk.ClientSession
}

type rigOptions struct {
	shaping mcp.Shaping
	listTTL time.Duration
	auth    func(http.Handler) http.Handler
	// mode, when set, runs the rig on the real pipeline in that mode over a
	// bundle of rules; without it the rig runs on the fake.
	mode  controlv1.EnforcementMode
	rules []string
	// policy, when set, serves the real pipeline's snapshot in place of one
	// built from rules.
	policy      gateway.PolicySource
	overrides   func(*victim, *testing.T) []mcp.Override
	timeout     time.Duration
	listTimeout time.Duration
	// runs and runToken configure the listener's run resolver and a stdio
	// listener's token; headers go on every request an HTTP agent sends; a
	// nil clock is time.Now.
	runs     gateway.RunResolver
	runToken string
	headers  http.Header
	clock    func() time.Time
	// sessionIdle bounds a stateful session's idle time and bodyTimeout an
	// HTTP request's body; zero is each one's default.
	sessionIdle time.Duration
	bodyTimeout time.Duration
	// maxSessions caps a stateful listener's live sessions; zero is the
	// default. forceSessionCap sets a cap past New's checks.
	maxSessions     int
	forceSessionCap int
	// connState, when set, is told of every state an agent's connection to
	// an HTTP listener reaches.
	connState func(net.Conn, http.ConnState)
	// secrets are what answers are scanned for, an empty set when nil;
	// logger takes the adapter's log, which a nil one discards.
	secrets *secretscan.Set
	logger  *slog.Logger
	// rewrite, on stdio, edits the members of every result the upstream
	// answers before the adapter reads it, as an upstream speaking for
	// itself on the wire would write them.
	rewrite func(map[string]json.RawMessage)
}

// identity is what an unauthenticated listener calls for. An authenticated
// one configures the tenant and the type only; the token names the user.
func identity(authenticated bool) mcp.Identity {
	id := mcp.Identity{
		Principal: &controlv1.Principal{Id: "svc-agent", Type: "service", TenantId: "t1"},
		Agent:     &controlv1.Agent{Id: "agent-1", Framework: "test"},
	}
	if authenticated {
		id.Principal = &controlv1.Principal{Type: "user", TenantId: "t1"}
	}
	return id
}

func newConfig(t *testing.T, v *victim, kind mcp.Kind, upstream sdk.Transport, o rigOptions) mcp.Config {
	t.Helper()
	var n atomic.Int64
	overrides := v.overrides(t)
	if o.overrides != nil {
		overrides = o.overrides(v, t)
	}
	clock := o.clock
	if clock == nil {
		clock = time.Now
	}
	secrets := o.secrets
	if secrets == nil {
		secrets = noSecrets(t)
	}
	return mcp.Config{
		Listener: mcp.Listener{
			Kind: kind, Authenticator: o.auth, AuthnStrength: "bearer", Identity: identity(o.auth != nil),
			Runs: o.runs, RunToken: o.runToken, SessionIdle: o.sessionIdle, BodyTimeout: o.bodyTimeout,
			MaxSessions: o.maxSessions,
		},
		Upstreams:   []mcp.Upstream{{Name: "victim", Transport: upstream, TenantID: "t1", Environment: "prod"}},
		Overrides:   overrides,
		Shaping:     o.shaping,
		ListTTL:     o.listTTL,
		CallTimeout: o.timeout,
		ListTimeout: o.listTimeout,
		ProjectID:   "p1", TenantID: "t1", Environment: "prod",
		Clock:   clock,
		NewID:   func() string { return "id-" + strconv.FormatInt(n.Add(1), 10) },
		Secrets: secrets,
		Logger:  o.logger,
	}
}

// noSecrets is the empty set, which scans every answer and finds nothing.
func noSecrets(t testing.TB) *secretscan.Set {
	t.Helper()
	set, err := secretscan.New(nil)
	if err != nil {
		t.Fatalf("secretscan.New(nil): %v", err)
	}
	return set
}

func serveHTTP(t *testing.T, h http.Handler) string {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

// serveHTTPWatched serves h as serveHTTP does, telling connState of every
// change of a connection's state, as the server sees it.
func serveHTTPWatched(t *testing.T, h http.Handler, connState func(net.Conn, http.ConnState)) string {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	ts.Config.ConnState = connState
	ts.Start()
	t.Cleanup(ts.Close)
	return ts.URL
}

func connectHTTP(t *testing.T, url, clientName, version string, headers http.Header) *sdk.ClientSession {
	t.Helper()
	c := sdk.NewClient(&sdk.Implementation{Name: clientName, Version: "0"}, nil)
	transport := &sdk.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: headerTransport{headers: headers, next: http.DefaultTransport}}}
	cs, err := c.Connect(ctxT(t), transport, &sdk.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("connect %s as %s at %s: %v", url, clientName, version, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// headerTransport adds fixed headers, such as a bearer token, to every
// request the agent sends.
type headerTransport struct {
	headers http.Header
	next    http.RoundTripper
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	for k, vs := range h.headers {
		for _, v := range vs {
			r.Header.Set(k, v)
		}
	}
	return h.next.RoundTrip(r)
}

// newRig builds the arrangement for kind over a fresh upstream.
func newRig(t *testing.T, kind mcp.Kind, o rigOptions) *rig {
	t.Helper()
	return newRigOver(t, newVictim(), kind, o)
}

// newAdapter builds the adapter of a rig, with a session cap forced past
// New's checks when the options ask for one.
func newAdapter(t *testing.T, v *victim, kind mcp.Kind, upstream sdk.Transport, o rigOptions) *mcp.Adapter {
	t.Helper()
	a, err := mcp.New(newConfig(t, v, kind, upstream, o))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if o.forceSessionCap > 0 {
		mcp.ForceSessionCap(a, o.forceSessionCap)
	}
	return a
}

// newRigOver builds the arrangement for kind over v: HTTP on both hops for
// the two HTTP listeners, a pipe toward the agent and an in-memory hop
// upstream on stdio.
func newRigOver(t *testing.T, v *victim, kind mcp.Kind, o rigOptions) *rig {
	t.Helper()
	r := &rig{kind: kind, victim: v}
	r.pipe = &fakePipeline{decide: execute, probe: func() int {
		return r.victim.count("read_file") + r.victim.count("delete_file") + r.victim.count("transfer") + r.victim.count("send_mail") + r.victim.count("slow") + r.victim.count("unlisted")
	}}
	var upstream sdk.Transport
	switch kind {
	case mcp.KindStatelessHTTP:
		r.version = v20260728
		upstream = &sdk.StreamableClientTransport{Endpoint: serveHTTP(t, sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return r.victim.server }, &sdk.StreamableHTTPOptions{Stateless: true}))}
	case mcp.KindStatefulHTTP:
		r.version = v20251125
		upstream = &sdk.StreamableClientTransport{Endpoint: serveHTTP(t, sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return r.victim.server }, &sdk.StreamableHTTPOptions{Stateless: false}))}
	case mcp.KindStdio:
		r.version = v20260728
		ct, st := sdk.NewInMemoryTransports()
		ss, err := r.victim.server.Connect(ctxT(t), st, nil)
		if err != nil {
			t.Fatalf("victim connect: %v", err)
		}
		t.Cleanup(func() { _ = ss.Close() })
		upstream = ct
		if o.rewrite != nil {
			upstream = rewritingTransport{Transport: ct, rewrite: o.rewrite}
		}
	}
	a := newAdapter(t, r.victim, kind, upstream, o)
	pipeline := r.plan(t, a, o)
	if err := a.Start(ctxT(t), pipeline); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	r.adapter = a
	if kind == mcp.KindStdio {
		r.connect = func(t *testing.T, clientName string) *sdk.ClientSession {
			t.Helper()
			toServer, fromAgent := io.Pipe()
			toAgent, fromServer := io.Pipe()
			ctx, cancel := context.WithCancel(ctxT(t))
			t.Cleanup(cancel)
			go func() { _ = a.ServeStdio(ctx, toServer, fromServer) }()
			c := sdk.NewClient(&sdk.Implementation{Name: clientName, Version: "0"}, nil)
			cs, err := c.Connect(ctx, &sdk.IOTransport{Reader: toAgent, Writer: fromAgent}, nil)
			if err != nil {
				t.Fatalf("stdio connect: %v", err)
			}
			t.Cleanup(func() { _ = cs.Close() })
			return cs
		}
		return r
	}
	h, err := a.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	r.url = serveHTTPWatched(t, h, o.connState)
	r.connect = func(t *testing.T, clientName string) *sdk.ClientSession {
		t.Helper()
		headers := o.headers.Clone()
		if o.auth != nil {
			if headers == nil {
				headers = http.Header{}
			}
			headers.Set("Authorization", "Bearer alice-token")
		}
		return connectHTTP(t, r.url, clientName, r.version, headers)
	}
	return r
}

var kinds = []struct {
	name string
	kind mcp.Kind
}{
	{"stateless", mcp.KindStatelessHTTP},
	{"stateful", mcp.KindStatefulHTTP},
	{"stdio", mcp.KindStdio},
}

// forEachKind runs fn once per listener kind, each with a fresh rig.
func forEachKind(t *testing.T, o rigOptions, fn func(t *testing.T, r *rig)) {
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) { fn(t, newRig(t, k.kind, o)) })
	}
}

func callTool(t *testing.T, cs *sdk.ClientSession, name string, args map[string]any) (*sdk.CallToolResult, error) {
	t.Helper()
	return cs.CallTool(ctxT(t), &sdk.CallToolParams{Name: name, Arguments: args})
}

// structured is a plane answer's fields, read from _meta under the
// namespace, which is the one place the plane puts them.
func structured(t *testing.T, res *sdk.CallToolResult) map[string]any {
	t.Helper()
	m := map[string]any{}
	for k, v := range res.Meta {
		if rest, ok := strings.CutPrefix(k, strings.TrimSuffix(metaAnswer, "answer")); ok {
			m[rest] = v
		}
	}
	if len(m) == 0 {
		t.Fatalf("no field of the plane's in _meta: %+v", res)
	}
	return m
}

// codesOf reads a block's codes from _meta, where every answer the plane
// makes carries them, whatever the tool declares.
func codesOf(t *testing.T, res *sdk.CallToolResult) []string {
	t.Helper()
	raw, ok := res.Meta[metaReasonCodes].([]any)
	if !ok {
		t.Fatalf("no reason_codes in %v", res.Meta)
	}
	var out []string
	for _, c := range raw {
		out = append(out, c.(string))
	}
	return out
}
