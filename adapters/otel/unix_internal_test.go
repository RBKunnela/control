//go:build linux || darwin

package otel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/internal/spool"
)

// collectorSocket is a Unix socket a test collector listens on, in a
// directory short enough for the platform's bound on a socket's name.
func collectorSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "otel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

// unixSpool is a spool holding n sample events and a reader over it.
func unixSpool(t *testing.T, n int) (*spool.Spool, *spool.Reader) {
	t.Helper()
	s, r, _ := spoolOf(t, n)
	return s, r
}

// unixExporter is an exporter over r to the socket at path, sending the
// credential to account uid, logging to log.
func unixExporter(t *testing.T, r *spool.Reader, path string, uid uint32, log io.Writer) *Exporter {
	t.Helper()
	e, err := New(Options{
		Endpoint: "unix://" + path, CollectorUID: &uid, InFlight: 1, Timeout: 2 * time.Second,
		Backoff: time.Millisecond, MaxBackoff: time.Millisecond,
		Headers: map[string]string{"Authorization": "Bearer unix-fixture-credential"},
		Logger:  slog.New(slog.NewTextHandler(log, nil)),
	}, r)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// runExporterUntil runs e until cond holds or ten seconds pass.
func runExporterUntil(t *testing.T, e *Exporter, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Error("the condition did not hold within 10s")
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run = %v", err)
	}
}

// TestAUnixCollectorOfThisAccountReceivesTheRecords: over a real socket the
// peer is this process's account, which the exporter was told to expect, so
// every record arrives at the logs path with the credential and is released.
func TestAUnixCollectorOfThisAccountReceivesTheRecords(t *testing.T) {
	path := collectorSocket(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, r := unixSpool(t, 3)
	e := unixExporter(t, r, path, uint32(os.Geteuid()), io.Discard) //nolint:gosec // G115: a uid fits 32 bits
	runExporterUntil(t, e, func() bool { return e.Stats().Acknowledged == 3 })
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || seen[0] != "/v1/logs Bearer unix-fixture-credential" {
		t.Errorf("the collector saw %q", seen)
	}
	if st := e.Stats(); st.RetriedPeer != 0 || st.Acknowledged != 3 {
		t.Errorf("stats %+v", st)
	}
}

// rawCollector accepts connections on a socket and counts them and every
// byte any of them carried, answering nothing.
type rawCollector struct {
	conns, bytes atomic.Int64
}

func listenRaw(t *testing.T, path string) *rawCollector {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c := &rawCollector{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.conns.Add(1)
			go func() {
				n, _ := io.Copy(io.Discard, conn)
				c.bytes.Add(n)
				_ = conn.Close()
			}()
		}
	}()
	return c
}

// TestACollectorOfAnotherAccountIsSentNothing: the peer of the socket is
// another account, so each connection is closed before a byte is written,
// the credential included; the refusal is counted on every attempt, logged
// once, and the records stay in the spool.
func TestACollectorOfAnotherAccountIsSentNothing(t *testing.T) {
	for name, peer := range map[string]func(net.Conn) (uint32, error){
		"another account": func(net.Conn) (uint32, error) { return 4242, nil },
		"no account named": func(net.Conn) (uint32, error) {
			return 0, errors.New("fixture: the kernel answered nothing")
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := collectorSocket(t)
			raw := listenRaw(t, path)
			s, r := unixSpool(t, 2)
			var log bytes.Buffer
			e := unixExporter(t, r, path, 0, &log)
			e.peerUID = peer
			runExporterUntil(t, e, func() bool { return e.Stats().RetriedPeer >= 3 })
			time.Sleep(20 * time.Millisecond)
			st := e.Stats()
			switch {
			case raw.conns.Load() < 3:
				t.Errorf("the socket took %d connections, want one per attempt", raw.conns.Load())
			case raw.bytes.Load() != 0:
				t.Errorf("%d bytes reached a peer of another account", raw.bytes.Load())
			case st.Acknowledged != 0 || st.RetriedTransport != 0 || st.Retries != st.RetriedPeer:
				t.Errorf("stats %+v", st)
			}
			if n := strings.Count(log.String(), "nothing was sent to the collector socket"); n != 1 {
				t.Errorf("the refusal was logged %d times over %d attempts, want once:\n%s", n, st.RetriedPeer, log.String())
			}
			if strings.Contains(log.String(), "unix-fixture-credential") {
				t.Errorf("the log carries the credential:\n%s", log.String())
			}
			if spoolStats, err := s.Stats(); err != nil || spoolStats.Unacknowledged == 0 || spoolStats.Unacknowledged != spoolStats.Bytes {
				t.Errorf("the spool holds %+v, %v; want every byte unacknowledged", spoolStats, err)
			}
		})
	}
}

// TestAUnixEndpointNeedsItsCollectorsAccount: each options value breaks one
// rule of a unix endpoint and is refused.
func TestAUnixEndpointNeedsItsCollectorsAccount(t *testing.T) {
	_, r := unixSpool(t, 0)
	uid := uint32(7)
	base := Options{Endpoint: "unix:///run/c.sock", CollectorUID: &uid, InFlight: 1, Timeout: time.Second}
	if _, err := New(base, r); err != nil {
		t.Fatalf("a unix endpoint with its account: %v", err)
	}
	for name, edit := range map[string]func(*Options){
		"no account":             func(o *Options) { o.CollectorUID = nil },
		"plaintext set":          func(o *Options) { o.AllowPlaintext = true },
		"a client of the caller": func(o *Options) { o.Client = &http.Client{} },
		"a host":                 func(o *Options) { o.Endpoint = "unix://host/run/c.sock" },
		"a relative path":        func(o *Options) { o.Endpoint = "unix:run/c.sock" },
		"a path not clean":       func(o *Options) { o.Endpoint = "unix:///run/./c.sock" },
		"a query":                func(o *Options) { o.Endpoint = "unix:///run/c.sock?k=v" },
		"an account on https":    func(o *Options) { o.Endpoint = "https://collector.example/v1/logs" },
	} {
		o := base
		edit(&o)
		if _, err := New(o, r); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("%s: New = %v, want ErrInvalidOptions", name, err)
		}
	}
}
