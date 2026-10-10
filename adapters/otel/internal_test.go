package otel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/spool"
)

func sample(n int) *controlv1.Event {
	return &controlv1.Event{
		EventId: "evt-" + strconv.Itoa(n), Kind: controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED,
		RequestId: "req-1", SchemaVersion: evidence.SchemaVersion,
	}
}

// spoolOf opens a spool holding n sample events and a reader that delivered
// them all, and returns the reader and the cursor after each.
func spoolOf(t *testing.T, n int) (*spool.Spool, *spool.Reader, []spool.Cursor) {
	t.Helper()
	s, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 1; i <= n; i++ {
		if err := s.Append(context.Background(), sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	var cursors []spool.Cursor
	for range n {
		_, c, err := r.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		cursors = append(cursors, c)
	}
	return s, r, cursors
}

func exporterOver(t *testing.T, r *spool.Reader, endpoint string) *Exporter {
	t.Helper()
	e, err := New(Options{Endpoint: endpoint, AllowPlaintext: true, InFlight: 1, Timeout: 2 * time.Second, Backoff: time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, r)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestARecordTheEncoderRefusesIsQuarantinedAtOnce: the batch is split until
// the record stands alone, and that record is quarantined without a request.
func TestARecordTheEncoderRefusesIsQuarantinedAtOnce(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		mu.Lock()
		bodies = append(bodies, b.String())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s, r, _ := spoolOf(t, 3)
	e := exporterOver(t, r, srv.URL)
	e.encode = func(events []*controlv1.Event) ([]byte, error) {
		for _, ev := range events {
			if ev.GetEventId() == "evt-2" {
				return nil, errors.New("not encodable")
			}
		}
		return encode(events)
	}
	if err := e.deliver(context.Background(), []*controlv1.Event{sample(1), sample(2), sample(3)}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(bodies, "\n")
	if strings.Contains(joined, `evt-2\"`) || !strings.Contains(joined, `evt-1\"`) || !strings.Contains(joined, `evt-3\"`) {
		t.Errorf("requests %q; want evt-1 and evt-3 sent and evt-2 not", bodies)
	}
	st, err := s.Stats()
	if err != nil || st.QuarantinedRecords != 1 || e.Stats().Quarantined != 1 {
		t.Errorf("spool %+v, %v, exporter %+v; want one record quarantined", st, err, e.Stats())
	}
}

// TestAQuarantineThatFailsIsNotDelivered: deliver reports it, so nothing is
// acknowledged past a record that is neither exported nor kept.
func TestAQuarantineThatFailsIsNotDelivered(t *testing.T) {
	s, r, _ := spoolOf(t, 1)
	e := exporterOver(t, r, "http://127.0.0.1:1/v1/logs")
	e.encode = func([]*controlv1.Event) ([]byte, error) { return nil, errors.New("not encodable") }
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.deliver(context.Background(), []*controlv1.Event{sample(1)}); !errors.Is(err, spool.ErrClosed) {
		t.Errorf("deliver with a quarantine that fails = %v, want the quarantine's error", err)
	}
}

// TestAcknowledgementStopsAtTheFirstBatchNotDelivered: whatever the batches
// after it did, the cursor does not pass one that was not delivered.
func TestAcknowledgementStopsAtTheFirstBatchNotDelivered(t *testing.T) {
	boom := errors.New("quarantine failed")
	for name, tc := range map[string]struct {
		cause, want error
	}{
		"stopped by the context": {context.Canceled, nil},
		"a failure":              {boom, boom},
	} {
		t.Run(name, func(t *testing.T) {
			s, r, cursors := spoolOf(t, 3)
			e := exporterOver(t, r, "http://127.0.0.1:1/v1/logs")
			queue := make(chan *pending, 3)
			slots := make(chan struct{}, 3)
			for i, err := range []error{nil, tc.cause, nil} {
				p := &pending{batch: &batch{events: []*controlv1.Event{sample(i + 1)}, cursor: cursors[i]}, done: make(chan error, 1)}
				p.done <- err
				queue <- p
				slots <- struct{}{}
			}
			close(queue)
			stopped := false
			if err := e.acknowledge(queue, slots, func() { stopped = true }); !errors.Is(err, tc.want) {
				t.Errorf("acknowledge = %v, want %v", err, tc.want)
			}
			if stopped != (tc.want != nil) {
				t.Errorf("the Run was stopped: %v, want %v", stopped, tc.want != nil)
			}
			st, err := s.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if st.Oldest != cursors[0] || e.Stats().Acknowledged != 1 {
				t.Errorf("spool %+v, exporter %+v; want only the first batch acknowledged", st, e.Stats())
			}
			if len(slots) != 0 {
				t.Errorf("%d in-flight slots left held", len(slots))
			}
		})
	}
}

// TestAReplayAfterAQuarantineWritesNoSecondCopy: a run stopped between
// quarantining a record and acknowledging past it repeats both on the next
// run, and the quarantine holds the record once.
func TestAReplayAfterAQuarantineWritesNoSecondCopy(t *testing.T) {
	var refusals atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refusals.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	s, r, _ := spoolOf(t, 1)
	e := exporterOver(t, r, srv.URL)
	for range 2 {
		if err := e.deliver(context.Background(), []*controlv1.Event{sample(1)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := refusals.Load(); got != 2*maxRefusals {
		t.Errorf("the collector refused %d times, want %d: each delivery tries the record itself", got, 2*maxRefusals)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.QuarantinedRecords != 1 {
		t.Errorf("the quarantine holds %d records, want one", st.QuarantinedRecords)
	}
	if es := e.Stats(); es.Quarantined != 1 || es.QuarantineHeld != 1 {
		t.Errorf("Stats = %+v; want one record quarantined and one already held", es)
	}
}

// TestStatsWaitsForAReleaseUnderWay: a reader of the spool's counters who saw
// a batch released must then read it counted, so Stats waits while a release
// holds its lock and answers the count the release left.
func TestStatsWaitsForAReleaseUnderWay(t *testing.T) {
	_, r, cursors := spoolOf(t, 2)
	e := exporterOver(t, r, "http://127.0.0.1:1/v1/logs")
	e.ackMu.Lock()
	got := make(chan uint64, 1)
	go func() { got <- e.Stats().Acknowledged }()
	select {
	case n := <-got:
		e.ackMu.Unlock()
		t.Fatalf("Stats answered %d while a release was under way", n)
	case <-time.After(100 * time.Millisecond):
	}
	e.ackMu.Unlock()
	if n := <-got; n != 0 {
		t.Fatalf("Stats = %d before any release, want 0", n)
	}
	if err := e.release(&batch{events: []*controlv1.Event{sample(1), sample(2)}, cursor: cursors[1]}); err != nil {
		t.Fatal(err)
	}
	if n := e.Stats().Acknowledged; n != 2 {
		t.Fatalf("Stats = %d after releasing two records, want 2", n)
	}
}
