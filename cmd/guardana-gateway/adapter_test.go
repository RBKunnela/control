package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestAnUpstreamRedirectIsNotFollowed: an upstream that lists its tools and
// answers the call with a 307 to a second server fails the call, and the
// second server, which would have run it, sees no request.
func TestAnUpstreamRedirectIsNotFollowed(t *testing.T) {
	var reached atomic.Int32
	elsewhere := upstreamHandler()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		elsewhere.ServeHTTP(w, r)
	}))
	t.Cleanup(target.Close)

	front := upstreamHandler()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var msg struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(raw, &msg) == nil && msg.Method == "tools/call" {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		front.ServeHTTP(w, r)
	}))
	t.Cleanup(redirector.Close)

	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", redirector.URL)
	exportTo(t, collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	agent, _ := serveInProcess(t, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := agent.CallTool(ctx, &sdk.CallToolParams{Name: "read_order", Arguments: map[string]any{"id": "ord-1"}})
	if err == nil && (!res.IsError || strings.Contains(resultText(res), upstreamAnswer)) {
		t.Errorf("the call through a redirecting upstream came back as %+v, want a failed call", res)
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("the server the upstream redirected to saw %d request(s), want none", n)
	}
}

// TestTheSessionIdleBoundReachesTheAdapter: the configured idle bound of a
// stateful listener is the one the adapter's session reaper runs with.
func TestTheSessionIdleBoundReachesTheAdapter(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "listener.kind", "stateful_http")
	setEnv(t, "listener.session_idle", "7m")
	cfg, err := adapterConfig(tr.load(t), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Listener.SessionIdle; got != 7*time.Minute {
		t.Errorf("the adapter's session idle bound is %v, want 7m", got)
	}
}

// TestTheSessionCapReachesTheAdapter: the configured cap on a stateful
// listener's live sessions is the one the adapter enforces.
func TestTheSessionCapReachesTheAdapter(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "listener.kind", "stateful_http")
	setEnv(t, "listener.max_sessions", "37")
	cfg, err := adapterConfig(tr.load(t), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Listener.MaxSessions; got != 37 {
		t.Errorf("the adapter's session cap is %d, want 37", got)
	}
}

// TestOnlyAStatefulListenerCarriesASessionCap: the cap the configuration
// holds by default reaches no listener that keeps no session, which the
// adapter would refuse.
func TestOnlyAStatefulListenerCarriesASessionCap(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "listener.kind", "stateless_http")
	cfg, err := adapterConfig(tr.load(t), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Listener.MaxSessions; got != 0 {
		t.Errorf("a stateless listener's adapter carries a session cap of %d, want none", got)
	}
}

// resultText joins the text content of a result.
func resultText(res *sdk.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// oversizeAnswer is how long the hostile upstream's answer to a call is: four
// times the bound the library puts on one event of a stream.
const oversizeAnswer = 4 * sdk.DefaultMaxEventSize

// TestAnOversizeUpstreamAnswerFailsTheCallInBoundedMemory: an upstream that
// answers a call with one JSON document four times the bound fails the call,
// whose trail closes as ACTION_FAILED, and the plane allocates in proportion
// to the bound rather than to the answer.
func TestAnOversizeUpstreamAnswerFailsTheCallInBoundedMemory(t *testing.T) {
	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", oversizeUpstream(t))
	exportTo(t, collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	agent, _ := serveInProcess(t, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res, err := agent.CallTool(ctx, &sdk.CallToolParams{Name: "read_order", Arguments: map[string]any{"id": "ord-1"}})
	runtime.ReadMemStats(&after)
	if err == nil && !res.IsError {
		t.Errorf("a call answered past the bound came back as a result of %d bytes", len(resultText(res)))
	}
	// Reading up to the bound costs a few times the bound, through append's
	// doublings; reading the whole answer costs many times the answer.
	if allocated, limit := after.TotalAlloc-before.TotalAlloc, uint64(8*sdk.DefaultMaxEventSize); allocated > limit {
		t.Errorf("the call allocated %d bytes; want at most %d", allocated, limit)
	}
	collector.waitUntil(t, "the call's closed trail", func(events []*controlv1.Event) bool {
		for _, trail := range byRequest(events) {
			if closedTrail(trail) {
				return true
			}
		}
		return false
	})
	for id, trail := range byRequest(collector.events(t)) {
		if last := trail[len(trail)-1].GetKind(); last != controlv1.EventKind_EVENT_KIND_ACTION_FAILED {
			t.Errorf("the trail of %s ends in %s, want ACTION_FAILED", id, last)
		}
	}
}

// oversizeUpstream serves the fixture upstream, but for a tools/call, which
// it answers with one JSON document of oversizeAnswer bytes and more, and
// returns its URL.
func oversizeUpstream(t *testing.T) string {
	t.Helper()
	front := upstreamHandler()
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(raw, &msg) != nil || msg.Method != "tools/call" {
			r.Body = io.NopCloser(bytes.NewReader(raw))
			front.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(msg.ID)+`,"result":{"content":[{"type":"text","text":"`)
		chunk := bytes.Repeat([]byte("x"), 1<<20)
		for written := 0; written < oversizeAnswer; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `"}]}}`)
	}))
	t.Cleanup(hostile.Close)
	return hostile.URL
}

// TestTheUpstreamAnswerBound: an answer of exactly the bound is read whole and
// one byte more fails, a refusal and a stream under an error status included;
// an event stream under a success status is the library's to bound per event.
func TestTheUpstreamAnswerBound(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		size        int
		fails       bool
	}{
		{"a document at the bound", http.StatusOK, "application/json", sdk.DefaultMaxEventSize, false},
		{"a document past the bound", http.StatusOK, "application/json", sdk.DefaultMaxEventSize + 1, true},
		{"a refusal past the bound", http.StatusBadRequest, "application/json", sdk.DefaultMaxEventSize + 1, true},
		{"a stream past the bound under an error", http.StatusBadRequest, "text/event-stream", sdk.DefaultMaxEventSize + 1, true},
		{"a stream past the bound", http.StatusOK, "text/event-stream; charset=utf-8", sdk.DefaultMaxEventSize + 1, false},
	}
	for _, c := range cases {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", c.contentType)
			w.WriteHeader(c.status)
			_, _ = w.Write(bytes.Repeat([]byte(" "), c.size))
		}))
		tr := newTree(t)
		setEnv(t, "upstreams.0.endpoint", upstream.URL)
		ups, err := upstreams(tr.load(t))
		if err != nil {
			t.Fatal(err)
		}
		client := ups[0].Transport.(*sdk.StreamableClientTransport).HTTPClient
		resp, err := client.Post(upstream.URL, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		upstream.Close()
		want := c.size
		if c.fails {
			want = sdk.DefaultMaxEventSize
		}
		if c.fails != errors.Is(err, errUpstreamAnswerTooLong) || len(body) != want {
			t.Errorf("%s: read %d bytes and %v; want %d bytes, failing %v", c.name, len(body), err, want, c.fails)
		}
	}
}
