package enforce_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
)

// pipeListener is a listener that is not a Unix socket's: it accepts nothing
// until it is closed.
type pipeListener struct {
	once   sync.Once
	closed chan struct{}
}

func (p *pipeListener) Accept() (net.Conn, error) { <-p.closed; return nil, net.ErrClosed }
func (p *pipeListener) Close() error              { p.once.Do(func() { close(p.closed) }); return nil }
func (p *pipeListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestServeRefusesAListenerThatIsNotAUnixSocket(t *testing.T) {
	cfg := validConfig()
	cfg.Socket = socketPath(t)
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln := &pipeListener{closed: make(chan struct{})}
	defer func() { _ = ln.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := a.Serve(ctx, ln); !errors.Is(err, enforce.ErrListener) {
		t.Fatalf("Serve on a listener that is not a Unix socket's = %v, want ErrListener", err)
	}
}

// A request whose headers pass the bound is refused before any handler runs;
// one under it is served.
func TestTheHeaderBoundIsEnforced(t *testing.T) {
	r := newRig(t, defaults())
	send := func(pad int) int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://enforce"+enforce.PathAdmit, strings.NewReader(admitBody("read_file", `{"path":"a"}`)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(enforce.RunTokenHeader, runA)
		req.Header.Set("X-Pad", strings.Repeat("p", pad))
		resp, err := r.http.Do(req)
		if err != nil {
			t.Fatalf("POST with %d bytes of header: %v", pad, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if status := send(8 << 10); status != http.StatusOK {
		t.Fatalf("8 KiB of headers answered %d", status)
	}
	if status := send(64 << 10); status != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("64 KiB of headers answered %d", status)
	}
}
