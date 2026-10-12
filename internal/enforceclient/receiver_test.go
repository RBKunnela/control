package enforceclient_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/enforceclient"
)

type gotRequest struct {
	path, token string
	body        []byte
}

// receiver answers each request with the next scripted answer, whatever the
// request holds, and records what it was sent.
type receiver struct {
	mu         sync.Mutex
	answers    []scripted
	next       int
	got        []gotRequest
	cancel     context.CancelFunc
	expire     func()
	callerDone <-chan struct{}
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.got = append(r.got, gotRequest{path: req.URL.Path, token: req.Header.Get(enforceclient.RunTokenHeader), body: body})
	var a *scripted
	if r.next < len(r.answers) {
		a = &r.answers[r.next]
		r.next++
	}
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if a == nil || a.For != req.URL.Path || req.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"ERROR_CODE_MALFORMED","message":"unscripted request"}`))
		return
	}
	switch a.Then {
	case "cancel_caller":
		r.cancel()
	case "await_caller":
		r.expire()
		select {
		case <-r.callerDone:
		case <-time.After(5 * time.Second):
		}
	}
	w.WriteHeader(a.Status)
	if a.Raw != nil {
		_, _ = w.Write([]byte(*a.Raw))
		return
	}
	_, _ = w.Write(a.Body)
}

func (r *receiver) requests() []gotRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.got)
}

// serve starts r on a fresh Unix socket and returns its path. The directory
// is short because a socket path is bounded at about 104 bytes.
func serve(t *testing.T, r http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ecl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socket
}

// expiring is a caller's context whose deadline passes when expire is called.
type expiring struct {
	context.Context
	deadline time.Time
	done     chan struct{}
	once     sync.Once
}

func newExpiring(parent context.Context, d time.Duration) *expiring {
	return &expiring{Context: parent, deadline: time.Now().Add(d), done: make(chan struct{})}
}

func (e *expiring) Deadline() (time.Time, bool) { return e.deadline, true }

func (e *expiring) Done() <-chan struct{} { return e.done }

func (e *expiring) Err() error {
	select {
	case <-e.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (e *expiring) expire() { e.once.Do(func() { close(e.done) }) }
