package mcp_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
)

type noPolicy struct{}

func (noPolicy) Current() *policy.Snapshot { return nil }

func pipelineConfig(a gateway.Adapter, mode controlv1.EnforcementMode) gateway.Config {
	var n atomic.Int64
	store := &gateway.MemoryApprovals{}
	return gateway.Config{
		Mode: mode, Adapter: a,
		KernelOptions: core.Options{MaxStale: time.Minute}, Policy: noPolicy{}, Pause: gateway.PauseDisabled(), Stops: gateway.StopsDisabled(), Sink: &evidence.MemorySink{},
		Approvals: store, Authority: store, AuthorityKind: gateway.AuthorityDirectory, Ledger: &gateway.MemoryLedger{}, Clock: time.Now,
		NewID:       func() string { return "id-" + strconv.FormatInt(n.Add(1), 10) },
		ApprovalTTL: time.Minute, RetryAfter: time.Second, MaxHeld: 16, MaxOpen: 16, MaxRuns: 16,
	}
}

// TestPipelineAcceptsTheAdapter: what the adapter declares is what the
// blocking modes need, so the real pipeline starts with it; and the real
// pipeline is the Pipeline shape the adapter drives.
func TestPipelineAcceptsTheAdapter(t *testing.T) {
	v := newVictim()
	ct, _ := sdk.NewInMemoryTransports()
	a, err := mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, ct, rigOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "mcp" {
		t.Errorf("Name() = %q", a.Name())
	}
	accepted := 0
	values := controlv1.EnforcementMode(0).Descriptor().Values()
	for i := range values.Len() {
		mode := controlv1.EnforcementMode(values.Get(i).Number())
		p, err := gateway.New(pipelineConfig(a, mode))
		switch {
		case errors.Is(err, gateway.ErrCapability):
			t.Errorf("the pipeline refuses the adapter under %s: %v", mode, err)
		case err == nil:
			accepted++
			var _ mcp.Pipeline = p
		}
	}
	if accepted == 0 {
		t.Fatal("no mode accepted the adapter")
	}
}

// TestHeaderMismatchNeverRunsTheMiddleware: a request whose Mcp-Name
// disagrees with the body is the library's -32020, before the pipeline is
// asked anything; a request with no routing headers is decided from the
// body, and the headers never turn a deny into anything else.
func TestHeaderMismatchNeverRunsTheMiddleware(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	r.pipe.decide = deny
	status, body := rawPostWith(t, r.url, nil, callBody(7, "delete_file", map[string]any{"path": "/x"}), "read_file")
	w := decodeWire(t, body)
	if status != http.StatusBadRequest || w.Error == nil || w.Error.Code != sdk.CodeHeaderMismatch {
		t.Fatalf("mismatch: HTTP %d %s", status, body)
	}
	if n := len(r.pipe.admitted()); n != 0 {
		t.Fatalf("the middleware ran %d times on a mismatched request", n)
	}
	// Agreeing headers reach the body-level verdict, which is a deny.
	status, body = rawPostWith(t, r.url, nil, callBody(8, "delete_file", map[string]any{"path": "/x"}), "delete_file")
	w = decodeWire(t, body)
	if status != http.StatusOK || w.Error != nil || !bytes.Contains(w.Result, []byte(`"RULE_DENY"`)) {
		t.Fatalf("agreeing headers: HTTP %d %s", status, body)
	}
	// No routing headers at all, a 2025-11-25-shaped body on the stateless
	// listener: the same verdict from the body.
	legacy, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": map[string]any{"name": "delete_file", "arguments": map[string]any{"path": "/x"}}})
	req, _ := http.NewRequestWithContext(ctxT(t), http.MethodPost, r.url, bytes.NewReader(legacy))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", v20251125)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(raw, []byte(`"RULE_DENY"`)) {
		t.Fatalf("headerless request: HTTP %d %s", resp.StatusCode, raw)
	}
	if n := r.victim.count("delete_file"); n != 0 {
		t.Fatalf("victim ran %d times", n)
	}
}

// TestStatefulListenerRefusesTheNewRevision: a 2026-07-28 tools/call on a
// stateful listener is -32022 with the supported versions, the pipeline is
// never asked, and the library's client falls back to 2025-11-25.
func TestStatefulListenerRefusesTheNewRevision(t *testing.T) {
	r := newRig(t, mcp.KindStatefulHTTP, rigOptions{})
	status, body := rawPostWith(t, r.url, nil, callBody(2, "read_file", map[string]any{"path": "/x"}), "read_file")
	assertUnsupportedVersion(t, status, body)
	if n := len(r.pipe.admitted()); n != 0 || r.victim.count("read_file") != 0 {
		t.Fatalf("a refused revision reached the pipeline %d times", n)
	}
	agent := connectHTTP(t, r.url, "agent-a", v20260728, nil)
	if got := agent.InitializeResult().ProtocolVersion; got != v20251125 {
		t.Fatalf("agent negotiated %q, want the fallback", got)
	}
	if res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("call over the fallback: %v %+v", err, res)
	}
	adm := r.pipe.admitted()
	if len(adm) != 1 || !containsTag(adm[0].a.Envelope, "mcp.protocol_version="+v20251125) {
		t.Fatalf("admission tags %v", adm)
	}
}

// assertUnsupportedVersion checks a -32022 with a supported list holding
// nothing at or past 2026-07-28.
func assertUnsupportedVersion(t *testing.T, status int, body []byte) {
	t.Helper()
	w := decodeWire(t, body)
	if status != http.StatusBadRequest || w.Error == nil || w.Error.Code != sdk.CodeUnsupportedProtocolVersion {
		t.Fatalf("2026-07-28 on stateful: HTTP %d %s", status, body)
	}
	var data sdk.UnsupportedProtocolVersionData
	if err := json.Unmarshal(w.Error.Data, &data); err != nil || len(data.Supported) == 0 {
		t.Fatalf("error data %s", w.Error.Data)
	}
	for _, v := range data.Supported {
		if v >= v20260728 {
			t.Errorf("the stateful listener advertises %s", v)
		}
	}
}

func containsTag(env *controlv1.ActionEnvelope, tag string) bool {
	for _, t := range env.GetContext().GetTags() {
		if t == tag {
			return true
		}
	}
	return false
}

// TestOriginIsValidated: a browser origin the operator did not list is
// refused before anything reads the body, a loopback origin included: only
// what the operator listed passes, and a request with no Origin is not a
// browser's while one with the opaque origin "null" is.
func TestOriginIsValidated(t *testing.T) {
	v := newVictim()
	ct, st := sdk.NewInMemoryTransports()
	ss, err := v.server.Connect(ctxT(t), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cfg := newConfig(t, v, mcp.KindStatelessHTTP, ct, rigOptions{})
	cfg.Listener.Origins = []string{"https://app.example", "http://localhost:3000"}
	a, err := mcp.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctxT(t), &fakePipeline{decide: execute}); err != nil {
		t.Fatal(err)
	}
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		origin string
		status int
	}{
		{"", http.StatusOK},
		{"http://localhost:3000", http.StatusOK},
		{"https://app.example", http.StatusOK},
		{"http://localhost:3001", http.StatusForbidden},
		{"http://127.0.0.1", http.StatusForbidden},
		{"http://[::1]:8080", http.StatusForbidden},
		{"https://evil.example", http.StatusForbidden},
		{"http://localhost.evil.example", http.StatusForbidden},
		{"localhost", http.StatusForbidden},
		// A sandboxed frame or a file: page sends the opaque origin.
		{"null", http.StatusForbidden},
	}
	url := serveHTTP(t, h)
	for _, tc := range cases {
		req, err := http.NewRequestWithContext(ctxT(t), http.MethodPost, url, bytes.NewReader([]byte(listBody(1))))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Protocol-Version", v20260728)
		req.Header.Set("Mcp-Method", "tools/list")
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Origin %q: %v", tc.origin, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("Origin %q: reading the answer: %v", tc.origin, err)
		}
		if resp.StatusCode != tc.status {
			t.Errorf("Origin %q: HTTP %d, want %d: %s", tc.origin, resp.StatusCode, tc.status, body)
		}
	}
}

// TestListenerKindsAreExclusive: an HTTP listener serves no stdio and a
// stdio listener no HTTP.
func TestListenerKindsAreExclusive(t *testing.T) {
	v := newVictim()
	ct, _ := sdk.NewInMemoryTransports()
	a, err := mcp.New(newConfig(t, v, mcp.KindStdio, ct, rigOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Handler(); !errors.Is(err, mcp.ErrListener) {
		t.Errorf("Handler on stdio = %v, want ErrListener", err)
	}
	a, err = mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, ct, rigOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	if err := a.ServeStdio(ctxT(t), r, w); !errors.Is(err, mcp.ErrListener) {
		t.Errorf("ServeStdio on HTTP = %v, want ErrListener", err)
	}
}

type wireResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int64           `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func decodeWire(t *testing.T, body []byte) wireResponse {
	t.Helper()
	var w wireResponse
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatalf("body %s is not a JSON-RPC response: %v", body, err)
	}
	return w
}

func callBody(id int, name string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{
		"name": name, "arguments": args, "_meta": meta(),
	}})
	return string(b)
}
