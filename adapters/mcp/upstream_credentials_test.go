package mcp_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
)

// seenRequest is one request an upstream received: its header and body.
type seenRequest struct {
	header http.Header
	body   []byte
}

// echoingUpstream records every request before the MCP server behind it
// reads it.
type echoingUpstream struct {
	mu   sync.Mutex
	seen []seenRequest
}

func (u *echoingUpstream) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		u.mu.Lock()
		u.seen = append(u.seen, seenRequest{header: r.Header.Clone(), body: body})
		u.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func (u *echoingUpstream) requests() []seenRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seenRequest(nil), u.seen...)
}

// rigOverUpstream is newRigOver's HTTP arrangement over an upstream the
// caller made, so the test sees what that upstream receives.
func rigOverUpstream(t *testing.T, v *victim, kind mcp.Kind, version string, upstream sdk.Transport, o rigOptions) *rig {
	t.Helper()
	r := &rig{kind: kind, victim: v, version: version}
	r.pipe = &fakePipeline{decide: execute, probe: func() int { return r.victim.count("read_file") }}
	a := newAdapter(t, v, kind, upstream, o)
	if err := a.Start(ctxT(t), r.plan(t, a, o)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	r.adapter = a
	h, err := a.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	r.url = serveHTTP(t, h)
	return r
}

// TestInboundCredentialsNeverReachTheUpstream: an agent's call carrying a
// run token, an Authorization header and a cookie is admitted under the run
// and reaches an HTTP upstream, which receives none of the three, in no
// header and in no body, on any request; the one header the upstream's own
// client sets reaches it on every request.
func TestInboundCredentialsNeverReachTheUpstream(t *testing.T) {
	const (
		authorization = "Bearer agent-side-credential"
		cookie        = "session=agent-side-cookie"
		configured    = "configured-for-the-upstream"
	)
	for _, k := range []struct {
		name    string
		kind    mcp.Kind
		version string
	}{{"stateless", mcp.KindStatelessHTTP, v20260728}, {"stateful", mcp.KindStatefulHTTP, v20251125}} {
		t.Run(k.name, func(t *testing.T) {
			v := newVictim()
			echo := &echoingUpstream{}
			handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return v.server },
				&sdk.StreamableHTTPOptions{Stateless: k.kind == mcp.KindStatelessHTTP})
			upstream := &sdk.StreamableClientTransport{Endpoint: serveHTTP(t, echo.wrap(handler)),
				HTTPClient: &http.Client{Transport: headerTransport{headers: http.Header{"X-Upstream-Key": {configured}}, next: http.DefaultTransport}}}
			runs := &fakeRuns{}
			r := rigOverUpstream(t, v, k.kind, k.version, upstream, rigOptions{runs: runs, clock: runClock})
			agent := connectHTTP(t, r.url, "agent-a", r.version, http.Header{
				mcp.RunTokenHeader: {testRunToken}, "Authorization": {authorization}, "Cookie": {cookie},
			})
			if _, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"}); err != nil {
				t.Fatalf("tools/call: %v", err)
			}
			if v.count("read_file") != 1 || len(runs.asked()) == 0 {
				t.Fatalf("the upstream ran read_file %d times and the token was resolved %d times; want one call under the run",
					v.count("read_file"), len(runs.asked()))
			}
			assertRunOnEach(t, r.pipe.admitted(), 1)
			seen := echo.requests()
			if len(seen) == 0 {
				t.Fatal("the upstream recorded no request")
			}
			for i, req := range seen {
				if got := req.header.Get("X-Upstream-Key"); got != configured {
					t.Errorf("upstream request %d carries X-Upstream-Key %q, want the upstream client's %q", i, got, configured)
				}
				assertNoInboundCredential(t, i, req, testRunToken, "agent-side-credential", "agent-side-cookie")
			}
		})
	}
}

// assertNoInboundCredential fails t when request i carries a header an agent
// authenticates with, or any of secrets in a header or its body.
func assertNoInboundCredential(t *testing.T, i int, req seenRequest, secrets ...string) {
	t.Helper()
	for _, name := range []string{mcp.RunTokenHeader, "Authorization", "Cookie"} {
		if got := req.header.Values(name); len(got) > 0 {
			t.Errorf("upstream request %d carries %s: %q", i, name, got)
		}
	}
	for _, secret := range secrets {
		for name, values := range req.header {
			if strings.Contains(strings.Join(values, "\n"), secret) {
				t.Errorf("upstream request %d carries %q in its %s header", i, secret, name)
			}
		}
		if bytes.Contains(req.body, []byte(secret)) {
			t.Errorf("upstream request %d carries %q in its body: %s", i, secret, req.body)
		}
	}
}
