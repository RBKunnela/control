//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/gateway"
)

// sendBuffer is the send buffer the kernel reports for c.
func sendBuffer(c net.Conn) (int, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return 0, errors.New("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var size int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		size, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil {
		return 0, err
	}
	return size, sockErr
}

// acceptedSendBuffer is what the kernel reports for an accepted loopback
// connection whose send buffer set is called with size, or left alone where
// size is zero: the reading a plane's connection is held to.
func acceptedSendBuffer(t *testing.T, size int) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	if size > 0 {
		if err := server.(*net.TCPConn).SetWriteBuffer(size); err != nil {
			t.Fatal(err)
		}
	}
	got, err := sendBuffer(server)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// servedAgents binds the plane's listeners on free ports and serves the
// agents' one with the plane's own server, reporting on accepted the send
// buffer of each connection it accepts once the plane's own connection hook
// has run. The others are released unserved.
func servedAgents(t *testing.T, p *plane, accepted chan<- int) string {
	t.Helper()
	bound, err := p.bind(io.Discard, listenTCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := closeListeners(bound[1:]); err != nil {
		t.Fatal(err)
	}
	agents := bound[0]
	if accepted != nil {
		hook := agents.server.ConnState
		agents.server.ConnState = func(c net.Conn, state http.ConnState) {
			if hook != nil {
				hook(c, state)
			}
			if state == http.StateNew {
				size, err := sendBuffer(c)
				if err != nil {
					size = -1
				}
				accepted <- size
			}
		}
	}
	go func() { _ = agents.server.Serve(agents.listener) }()
	t.Cleanup(func() { _ = agents.server.Close() })
	return agents.listener.Addr().String()
}

// TestAnAgentConnectionKeepsASmallSendBuffer: the connection the plane's
// agent listener accepts reports the send buffer the kernel gives one set to
// 64 KiB, and not the one it gives a connection left alone.
func TestAnAgentConnectionKeepsASmallSendBuffer(t *testing.T) {
	want, untouched := acceptedSendBuffer(t, 64<<10), acceptedSendBuffer(t, 0)
	if want == untouched {
		t.Fatalf("this kernel reports %d for a connection set to 64 KiB and for one left alone, so nothing here can tell them apart", want)
	}
	tr := newTree(t)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "127.0.0.1:0")
	accepted := make(chan int, 1)
	addr := servedAgents(t, tr.plane(t), accepted)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	select {
	case got := <-accepted:
		if got != want {
			t.Errorf("an agent's connection reports a send buffer of %d, want %d, what one set to 64 KiB reports (left alone: %d)", got, want, untouched)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the plane accepted no connection")
	}
}

// slowAnswerBound is the answer bound the steady reader runs under. A slice
// is cut only when more than bound times pacedAgentRate, 1.25 MiB, must drain
// before it is taken: a stall of the whole process for ten seconds, or a send
// buffer grown to megabytes, which the 64 KiB one forbids.
const slowAnswerBound = 10 * time.Second

// pacedAgentRate is how fast the steady agent reads: every read sleeps for its
// bytes at this rate, so the answer takes at least 24 seconds, more than twice
// the bound.
const pacedAgentRate = 128 << 10

// bigAnswerBytes is the upstream's answer, far past every socket buffer.
const bigAnswerBytes = 3 << 20

// pacedConn reads no faster than pacedAgentRate bytes a second, each read
// waiting as long as its bytes take at that rate.
type pacedConn struct{ net.Conn }

func (p pacedConn) Read(b []byte) (int, error) {
	n, err := p.Conn.Read(b[:min(len(b), 32<<10)])
	time.Sleep(time.Duration(n) * time.Second / pacedAgentRate)
	return n, err
}

// TestASlowSteadyAgentGetsTheWholeAnswerThroughThePlane: an agent that reads
// a large answer steadily, far slower than the answer's size over the bound,
// gets all of it through the plane's own server, which sets every socket
// option the plane relies on: the test sets none on the plane's side. The
// agent's receive buffer is its own choice, kept small so the plane's writes
// wait on its reading.
func TestASlowSteadyAgentGetsTheWholeAnswerThroughThePlane(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", bigUpstream(t))
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "127.0.0.1:0")
	p := withAnswerBound(t, tr.plane(t), slowAnswerBound)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := p.startUpstreams(ctx); err != nil {
		t.Fatalf("connecting the upstream: %v", err)
	}
	addr := servedAgents(t, p, nil)

	dialer := &net.Dialer{}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err := c.(*net.TCPConn).SetReadBuffer(256 << 10); err != nil {
			return nil, errors.Join(err, c.Close())
		}
		return pacedConn{c}, nil
	}}}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "agent-a", Version: "0"}, nil).Connect(ctx,
		&sdk.StreamableClientTransport{Endpoint: "http://" + addr, HTTPClient: client},
		&sdk.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatalf("connecting to the plane: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	start := time.Now()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "read_order", Arguments: map[string]any{"id": "ord-1"}})
	took := time.Since(start)
	if err != nil {
		t.Fatalf("after %v the call failed: %v", took, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("the answer holds %d content item(s), want one", len(res.Content))
	}
	text, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("the answer is %T, want text", res.Content[0])
	}
	if len(text.Text) != bigAnswerBytes || !strings.HasSuffix(text.Text, "END-OF-ANSWER") {
		t.Fatalf("the agent got an answer of %d byte(s), want the whole %d", len(text.Text), bigAnswerBytes)
	}
	if took <= 2*slowAnswerBound {
		t.Errorf("the answer was read in %v, within twice the bound of %v: no slice's deadline was at stake", took, slowAnswerBound)
	}
}

// withAnswerBound rebuilds p's adapter and pipeline as wire builds them, with
// bound as the answer bound in place of the default the configuration leaves.
func withAnswerBound(t *testing.T, p *plane, bound time.Duration) *plane {
	t.Helper()
	cfg, err := adapterConfig(p.cfg, p.logger)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listener.BodyTimeout = bound
	adapter, err := adaptermcp.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mode, err := p.cfg.Mode()
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := gateway.New(p.pipelineConfig(adapter, mode, p.pdp))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.adapter.Close(); err != nil {
		t.Fatal(err)
	}
	p.adapter, p.pipeline = adapter, pipeline
	return p
}

// bigUpstream serves the fixture's one tool with an answer of bigAnswerBytes.
func bigUpstream(t *testing.T) string {
	t.Helper()
	answer := strings.Repeat("x", bigAnswerBytes-len("END-OF-ANSWER")) + "END-OF-ANSWER"
	server := sdk.NewServer(&sdk.Implementation{Name: "fixture-upstream", Version: "0"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}}
	server.AddTool(&sdk.Tool{Name: "read_order", Description: "reads an order", InputSchema: schema},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: answer}}}, nil
		})
	ts := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: true}))
	t.Cleanup(ts.Close)
	return ts.URL
}
