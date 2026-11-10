package otel_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/spool"
)

// memorySink keeps what a receiver hands it, and refuses while failing is set.
type memorySink struct {
	failing atomic.Bool
	mu      sync.Mutex
	calls   int
	kept    []*controlv1.Event
}

func (s *memorySink) Append(_ context.Context, events []*controlv1.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failing.Load() {
		return errors.New("the disk is full")
	}
	s.kept = append(s.kept, events...)
	return nil
}

func (s *memorySink) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.kept))
	for _, ev := range s.kept {
		out = append(out, ev.GetEventId())
	}
	return out
}

func (s *memorySink) appends() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// testToken is the credential every receiver under test requires.
var testToken = strings.Repeat("k", otel.MinCredentialBytes)

func testCredential(t *testing.T) otel.Credential {
	t.Helper()
	cred, err := otel.NewCredential(testToken)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// carrying hands every request to h with the credential, as a sender
// configured with it sends each one.
func carrying(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+testToken)
		h.ServeHTTP(w, r)
	})
}

func newReceiver(t *testing.T, sink otel.Sink) http.Handler {
	t.Helper()
	h, err := otel.NewReceiver(sink, slog.New(slog.DiscardHandler), testCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	return carrying(h)
}

func TestAReceiverNeedsASink(t *testing.T) {
	if h, err := otel.NewReceiver(nil, nil, testCredential(t)); h != nil || !errors.Is(err, otel.ErrNoSink) {
		t.Errorf("NewReceiver(nil) = %v, %v; want nil, ErrNoSink", h, err)
	}
}

// TestTheReceiverAnswersAsTheProtocolSays: 200 with an empty body once the
// sink holds the records, 400 for a request it refuses, 413 over the bound,
// 405 for a method other than POST, 415 for a body that is not JSON as sent,
// and 503 when the sink fails. The sink is reached only by a request read
// whole and accepted.
func TestTheReceiverAnswersAsTheProtocolSays(t *testing.T) {
	type c struct {
		method, contentType, encoding, body string
		failSink                            bool
		status, appended                    int
	}
	over := base() + strings.Repeat(" ", otel.MaxRequestBytes-len(base())+1)
	cases := map[string]c{
		"a request it reads":              {body: base(), status: http.StatusOK, appended: 1},
		"a charset of UTF-8":              {contentType: "application/json; charset=utf-8", body: base(), status: http.StatusOK, appended: 1},
		"a media type in capitals":        {contentType: "Application/JSON", body: base(), status: http.StatusOK, appended: 1},
		"the identity encoding":           {encoding: "identity", body: base(), status: http.StatusOK, appended: 1},
		"no records":                      {body: `{}`, status: http.StatusOK},
		"a GET":                           {method: http.MethodGet, body: base(), status: http.StatusMethodNotAllowed},
		"a PUT":                           {method: http.MethodPut, body: base(), status: http.StatusMethodNotAllowed},
		"no content type":                 {contentType: "-", body: base(), status: http.StatusUnsupportedMediaType},
		"protobuf":                        {contentType: "application/x-protobuf", body: base(), status: http.StatusUnsupportedMediaType},
		"plain text":                      {contentType: "text/plain", body: base(), status: http.StatusUnsupportedMediaType},
		"another charset":                 {contentType: "application/json; charset=latin1", body: base(), status: http.StatusUnsupportedMediaType},
		"a content type that won't parse": {contentType: "application/json; charset", body: base(), status: http.StatusUnsupportedMediaType},
		"gzip":                            {encoding: "gzip", body: base(), status: http.StatusUnsupportedMediaType},
		"a request it refuses":            {body: variant(t, `"resourceLogs"`, `"resource_logs"`), status: http.StatusBadRequest},
		"a body that is not an event":     {body: requestWithBody(`"{}x"`), status: http.StatusBadRequest},
		"an event of another major":       {body: variant(t, `\"schemaVersion\":\"1.0\"`, `\"schemaVersion\":\"2.0\"`), status: http.StatusBadRequest},
		"an event with no version":        {body: variant(t, `,\"schemaVersion\":\"1.0\"`, ``), status: http.StatusBadRequest},
		"a request over the bound":        {body: over, status: http.StatusRequestEntityTooLarge},
		"a sink that fails":               {body: base(), failSink: true, status: http.StatusServiceUnavailable},
	}
	for name, c := range cases {
		rec, sink := serveOne(t, c.method, c.contentType, c.encoding, c.body, c.failSink)
		if rec.Code != c.status || rec.Body.Len() != 0 {
			t.Errorf("%s: answered %d with %q, want %d and no body", name, rec.Code, rec.Body.String(), c.status)
		}
		if got := len(sink.ids()); got != c.appended {
			t.Errorf("%s: the sink holds %d events, want %d", name, got, c.appended)
		}
		wantCalls := c.appended
		if c.failSink {
			wantCalls = 1
		}
		if sink.appends() != wantCalls {
			t.Errorf("%s: the sink was called %d times, want %d", name, sink.appends(), wantCalls)
		}
		if c.status == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
			t.Errorf("%s: Allow = %q, want POST", name, rec.Header().Get("Allow"))
		}
	}
}

// refusingSink refuses every append with err.
type refusingSink struct{ err error }

func (s refusingSink) Append(context.Context, []*controlv1.Event) error { return s.err }

// TestASinkThatRefusesForGoodIsAnswered400: a sink's error matching
// ErrSinkRefused is answered 400, which the exporter quarantines on, and any
// other error beside it 503, which it retries.
func TestASinkThatRefusesForGoodIsAnswered400(t *testing.T) {
	for err, want := range map[error]int{
		fmt.Errorf("an id with other content: %w", otel.ErrSinkRefused): http.StatusBadRequest,
		errors.New("an id with other content"):                          http.StatusServiceUnavailable,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(base()))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		newReceiver(t, refusingSink{err: err}).ServeHTTP(rec, req)
		if rec.Code != want || rec.Body.Len() != 0 {
			t.Errorf("a sink failing with %q: answered %d with %q, want %d and no body", err, rec.Code, rec.Body.String(), want)
		}
	}
}

// countingReader counts what is read of it.
type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

// TestTheReceiverStopsReadingAtTheBound: a body twice the bound is answered
// 413 after at most one byte past the bound was read, so a request's size
// never sets what the receiver holds.
func TestTheReceiverStopsReadingAtTheBound(t *testing.T) {
	body := &countingReader{r: strings.NewReader(base() + strings.Repeat(" ", 2*otel.MaxRequestBytes))}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	sink := &memorySink{}
	newReceiver(t, sink).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || body.read > otel.MaxRequestBytes+1 || sink.appends() != 0 {
		t.Errorf("answered %d after reading %d bytes, bound %d", rec.Code, body.read, otel.MaxRequestBytes)
	}
}

// TestABodyThatCannotBeReadIsAnswered503: a body whose read fails short of
// the bound, as a read timeout or a reset connection fails it, is answered
// 503, which the exporter sends again, and the sink is not reached; a body
// read whole that does not parse is still 400.
func TestABodyThatCannotBeReadIsAnswered503(t *testing.T) {
	body := io.MultiReader(strings.NewReader(base()[:20]), iotest.ErrReader(errors.New("read tcp: i/o timeout")))
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	sink := &memorySink{}
	newReceiver(t, sink).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.Len() != 0 || sink.appends() != 0 {
		t.Errorf("a body whose read failed: answered %d with %q, %d append(s); want 503, no body and none", rec.Code, rec.Body.String(), sink.appends())
	}
	if rec, sink := serveOne(t, "", "", "", base()[:20], false); rec.Code != http.StatusBadRequest || sink.appends() != 0 {
		t.Errorf("the same bytes read whole: answered %d, %d append(s); want 400 and none", rec.Code, sink.appends())
	}
}

// serveOne hands one request to a receiver over a sink of its own. An empty
// method is POST, an empty content type is JSON and "-" is none.
func serveOne(t *testing.T, method, contentType, encoding, body string, failSink bool) (*httptest.ResponseRecorder, *memorySink) {
	t.Helper()
	sink := &memorySink{}
	sink.failing.Store(failSink)
	if method == "" {
		method = http.MethodPost
	}
	req := httptest.NewRequest(method, "/v1/logs", strings.NewReader(body))
	switch contentType {
	case "":
		req.Header.Set("Content-Type", "application/json")
	case "-":
	default:
		req.Header.Set("Content-Type", contentType)
	}
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	rec := httptest.NewRecorder()
	newReceiver(t, sink).ServeHTTP(rec, req)
	return rec, sink
}

// TestASinkThatFailsReleasesNothing drives the real exporter against the
// receiver: while the sink fails, the collector answers 503, the exporter
// retries and acknowledges nothing, and the spool keeps every record; once it
// holds them, each arrives once.
func TestASinkThatFailsReleasesNothing(t *testing.T) {
	sink := &memorySink{}
	sink.failing.Store(true)
	srv := httptest.NewTLSServer(newReceiver(t, sink))
	t.Cleanup(srv.Close)

	s := openSpool(t, 1<<20)
	events := fixtureEvents(t)
	for _, ev := range events {
		mustAppend(t, s, ev)
	}
	e := exporterTo(t, s, srv, otel.Options{InFlight: 1, MaxBatch: 16, Linger: 10 * time.Millisecond,
		Backoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), runDeadline)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	waitFor(t, func() bool { return e.Stats().RetriedServer >= 3 })
	if st := e.Stats(); st.Acknowledged != 0 || st.Quarantined != 0 {
		t.Fatalf("the exporter released records the sink never kept: %+v", st)
	}
	if st := spoolStats(t, s); st.Unacknowledged == 0 {
		t.Fatal("the spool released records the sink never kept")
	}
	sink.failing.Store(false)
	waitFor(t, func() bool { return e.Stats().Acknowledged == uint64(len(events)) })
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Errorf("Run = %v", err)
	}
	if got := strings.Join(sink.ids(), ","); got != "evt-1,evt-2,evt-3,evt-4" {
		t.Errorf("the sink holds %s, want each event once, in order", got)
	}
	if st := spoolStats(t, s); st.Unacknowledged != 0 {
		t.Errorf("the spool still holds %d unacknowledged bytes", st.Unacknowledged)
	}
}

// statusCounter counts the answers a handler gives, by status.
type statusCounter struct {
	mu   sync.Mutex
	seen map[int]int
}

func (c *statusCounter) count(status int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[status]
}

func (c *statusCounter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		c.mu.Lock()
		c.seen[rec.Code]++
		c.mu.Unlock()
		w.WriteHeader(rec.Code)
	})
}

// TestABatchOverTheBoundIsHalvedAndDelivered: the exporter answers a 413 by
// halving the request, so a batch over the receiver's bound still arrives
// whole, in more than one request, and nothing goes to the quarantine. The
// bound is lowered so that records of about 2 KiB in their request go over it
// together and fit it alone, which keeps the test cheap.
func TestABatchOverTheBoundIsHalvedAndDelivered(t *testing.T) {
	const records, bound = 16, 16 << 10
	sink := &memorySink{}
	h, err := otel.NewReceiverWithin(sink, slog.New(slog.DiscardHandler), testCredential(t), bound)
	if err != nil {
		t.Fatal(err)
	}
	answers := &statusCounter{seen: map[int]int{}}
	srv := httptest.NewTLSServer(answers.wrap(carrying(h)))
	t.Cleanup(srv.Close)
	s := openSpool(t, 1<<20)
	run := strings.Repeat("x", 1<<10)
	for i := range records {
		ev := event(i)
		ev.RunId = run
		mustAppend(t, s, ev)
	}
	e := exporterTo(t, s, srv, otel.Options{InFlight: 1, MaxBatch: records, Linger: 200 * time.Millisecond,
		Backoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond})
	runUntil(t, e, func() bool { return e.Stats().Acknowledged == records })
	st := e.Stats()
	if st.Refused == 0 || st.Quarantined != 0 || answers.count(http.StatusRequestEntityTooLarge) == 0 || answers.count(http.StatusOK) < 2 {
		t.Errorf("stats %+v, 413 answered %d times, 200 %d times: want the batch refused over the bound, delivered in parts, nothing quarantined",
			st, answers.count(http.StatusRequestEntityTooLarge), answers.count(http.StatusOK))
	}
	if got := strings.Join(sink.ids(), ","); got != "evt-0,evt-1,evt-2,evt-3,evt-4,evt-5,evt-6,evt-7,evt-8,evt-9,evt-10,evt-11,evt-12,evt-13,evt-14,evt-15" {
		t.Errorf("the sink holds %s, want every event once, in order", got)
	}
}

func exporterTo(t *testing.T, s *spool.Spool, srv *httptest.Server, opts otel.Options) *otel.Exporter {
	t.Helper()
	opts.Endpoint = srv.URL + "/v1/logs"
	opts.Client = srv.Client()
	opts.Timeout = 5 * time.Second
	opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err := otel.New(opts, reader(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
