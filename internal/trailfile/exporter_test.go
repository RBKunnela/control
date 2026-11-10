package trailfile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/spool"
)

// statuses counts what a handler answered, by status.
type statuses struct {
	mu   sync.Mutex
	seen map[int]int
}

func (s *statuses) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		s.mu.Lock()
		s.seen[rec.Code]++
		s.mu.Unlock()
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

func (s *statuses) count(status int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[status]
}

// TestAFailedSyncReleasesNothing drives the plane's real exporter against the
// receiver over this writer: while the file's sync fails the collector
// answers 503, the exporter acknowledges nothing, the spool keeps every
// record and the file holds none of them; once the sync works, each record is
// in the file once.
func TestAFailedSyncReleasesNothing(t *testing.T) {
	path := trailPath(t)
	w := openWriter(t, path)
	var failing atomic.Bool
	failing.Store(true)
	w.ops = fileOps{write: osOps.write, sync: func(f *os.File) error {
		if failing.Load() {
			return errors.New("the disk went away")
		}
		return f.Sync()
	}}
	st, url := serveReceiver(t, w)
	events := append(chain("p1", "a", kindProposed, kindDecided, kindBlocked),
		chain("p1", "b", kindProposed, kindDecided, kindStarted, kindCompleted)...)
	sp := spoolHolding(t, events)
	e, stop := runExporter(t, sp, url)

	within(t, func() bool { return st.count(http.StatusServiceUnavailable) >= 3 })
	expectNothingReleased(t, e, sp, path)

	failing.Store(false)
	within(t, func() bool { return e.Stats().Acknowledged == uint64(len(events)) })
	stop()
	if got := contents(t, path); got != lines(t, events...) {
		t.Errorf("the file holds\n%s\nwant each record once, in order", got)
	}
	rep, err := ReadFile(path, DefaultMaxLines)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Duplicates != 0 || len(rep.Trails) != 2 || rep.Trails[0].Verdict != Passed || rep.Trails[1].Verdict != Passed {
		t.Errorf("the trail reads as %+v", rep)
	}
}

// expectNothingReleased checks that the exporter acknowledged nothing, the
// spool still holds the records and the file holds none of them.
func expectNothingReleased(t *testing.T, e *otel.Exporter, sp *spool.Spool, path string) {
	t.Helper()
	if ex := e.Stats(); ex.Acknowledged != 0 || ex.Quarantined != 0 || ex.RetriedServer == 0 {
		t.Fatalf("while the sync failed the exporter reports %+v", ex)
	}
	if stats, err := sp.Stats(); err != nil || stats.Unacknowledged == 0 {
		t.Fatalf("while the sync failed the spool reports %+v, %v", stats, err)
	}
	if got := contents(t, path); got != "" {
		t.Fatalf("records the collector refused are in the file: %q", got)
	}
}

// testToken is the credential the receivers under test require and the
// exporters under test send.
var testToken = strings.Repeat("c", otel.MinCredentialBytes)

// receiverClient trusts the certificate every httptest server serves with:
// a plane exports over no plaintext, so the receivers here serve TLS.
var receiverClient = sync.OnceValue(func() *http.Client {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	return srv.Client()
})

// serveReceiver serves the OTLP receiver over w and returns its logs URL.
func serveReceiver(t *testing.T, w otel.Sink) (*statuses, string) {
	t.Helper()
	cred, err := otel.NewCredential(testToken)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := otel.NewReceiver(w, slog.New(slog.DiscardHandler), cred)
	if err != nil {
		t.Fatal(err)
	}
	st := &statuses{seen: map[int]int{}}
	srv := httptest.NewTLSServer(st.wrap(receiver))
	t.Cleanup(srv.Close)
	return st, srv.URL + "/v1/logs"
}

func spoolHolding(t *testing.T, events []*controlv1.Event) *spool.Spool {
	t.Helper()
	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	for _, ev := range events {
		if err := sp.Append(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	return sp
}

// runExporter runs the real exporter over sp toward url, and returns what
// stops it and requires a clean end.
func runExporter(t *testing.T, sp *spool.Spool, url string) (*otel.Exporter, func()) {
	t.Helper()
	r, err := sp.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := otel.New(otel.Options{Endpoint: url, Client: receiverClient(), InFlight: 1,
		Headers: map[string]string{"Authorization": "Bearer " + testToken},
		Timeout: 5 * time.Second, MaxBatch: 16, Linger: 10 * time.Millisecond, Backoff: 10 * time.Millisecond,
		MaxBackoff: 20 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run = %v", err)
		}
		_ = r.Close()
	}
	t.Cleanup(stop)
	return e, stop
}

func within(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within ten seconds")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var _ otel.Sink = (*Writer)(nil)
