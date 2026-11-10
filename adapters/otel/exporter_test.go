package otel_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/spool"
)

// TestZeroValueAndBadOptionsRefuse: an exporter nobody built, or one that
// cannot reach a collector, exports nothing and says so.
func TestZeroValueAndBadOptionsRefuse(t *testing.T) {
	good := otel.Options{Endpoint: "https://collector.example:4318/v1/logs", InFlight: 1, Timeout: time.Second}
	if e, err := otel.New(good, nil); e != nil || !errors.Is(err, otel.ErrNoReader) {
		t.Errorf("New with no reader = %v, %v; want nil, ErrNoReader", e, err)
	}
	var e otel.Exporter
	if err := e.Run(contextWithin(t, 10*time.Second)); !errors.Is(err, otel.ErrNoReader) {
		t.Errorf("Run on the zero value = %v, want ErrNoReader", err)
	}
	r := reader(t, openSpool(t, 1<<20))
	bad := map[string]otel.Options{
		"no endpoint":     {InFlight: 1, Timeout: time.Second},
		"no host":         {Endpoint: "https:///v1/logs", InFlight: 1, Timeout: time.Second},
		"not http":        {Endpoint: "ftp://collector/v1/logs", InFlight: 1, Timeout: time.Second},
		"zero InFlight":   {Endpoint: good.Endpoint, Timeout: time.Second},
		"zero Timeout":    {Endpoint: good.Endpoint, InFlight: 1},
		"negative linger": {Endpoint: good.Endpoint, InFlight: 1, Timeout: time.Second, Linger: -1},
		"plaintext":       {Endpoint: "http://collector.example:4318/v1/logs", InFlight: 1, Timeout: time.Second},
	}
	for name, opts := range bad {
		if e, err := otel.New(opts, r); e != nil || !errors.Is(err, otel.ErrInvalidOptions) {
			t.Errorf("New with %s = %v, %v; want nil, ErrInvalidOptions", name, e, err)
		}
	}
	if _, err := otel.New(good, r); err != nil {
		t.Errorf("New with good options: %v", err)
	}
}

// TestHeadersAreCheckedAtNew: a header name that is not an HTTP token, or a
// value that could end the header, is refused before any request, and the
// refusal does not quote the value, which is usually a credential.
func TestHeadersAreCheckedAtNew(t *testing.T) {
	r := reader(t, openSpool(t, 1<<20))
	opts := func(h map[string]string) otel.Options {
		return otel.Options{Endpoint: "https://collector.example:4318/v1/logs", InFlight: 1, Timeout: time.Second, Headers: h}
	}
	bad := map[string]map[string]string{
		"an empty name":         {"": "v"},
		"a space in the name":   {"X Token": "v"},
		"a colon in the name":   {"X-Token:": "v"},
		"a non-ASCII name":      {"X-T\u00f6ken": "v"},
		"a CR in the value":     {"Authorization": "Bearer secret-one\r"},
		"an LF in the value":    {"Authorization": "Bearer secret-one\nX-Injected: 1"},
		"a NUL in the value":    {"Authorization": "Bearer secret-one\x00"},
		"a CR in a later value": {"X-A": "fine", "X-B": "secret-one\r"},
	}
	for name, h := range bad {
		e, err := otel.New(opts(h), r)
		if e != nil || !errors.Is(err, otel.ErrInvalidOptions) {
			t.Errorf("New with %s = %v, %v; want nil, ErrInvalidOptions", name, e, err)
			continue
		}
		if strings.Contains(err.Error(), "secret-one") {
			t.Errorf("the refusal of %s quotes the value: %v", name, err)
		}
	}
	good := map[string]string{"Authorization": "Bearer a\tb", "X-Token_1.~!#$%&'*+-^`|": "v"}
	if _, err := otel.New(opts(good), r); err != nil {
		t.Errorf("New with token names and a tab in a value = %v", err)
	}
	if _, err := otel.New(otel.Options{Endpoint: "https://user:secret-two@[::1", InFlight: 1, Timeout: time.Second}, r); !errors.Is(err, otel.ErrInvalidOptions) || strings.Contains(err.Error(), "secret-two") {
		t.Errorf("New with an endpoint that does not parse = %v; want ErrInvalidOptions without the password", err)
	}
}

// TestTheRequestMatchesTheGolden: the events in testdata/otlp/events.jsonl
// go through a spool and the exporter, and the one request the collector
// sees equals export_logs_request.json once both are parsed.
func TestTheRequestMatchesTheGolden(t *testing.T) {
	events := fixtureEvents(t)
	want := readFixture(t, "export_logs_request.json")

	c := newCollector(t, func(int) int { return http.StatusOK })
	s := openSpool(t, 1<<20)
	for _, ev := range events {
		mustAppend(t, s, ev)
	}
	e := newExporter(t, s, c, otel.Options{InFlight: 1, MaxBatch: 16, Linger: 200 * time.Millisecond,
		Headers: map[string]string{"Authorization": "Bearer token-for-a-test"}})
	runUntil(t, e, func() bool { return e.Stats().Acknowledged == 4 })

	got := c.requests()
	if len(got) != 1 {
		t.Fatalf("the collector saw %d requests, want one batch", len(got))
	}
	if ct := got[0].header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if auth := got[0].header.Get("Authorization"); auth != "Bearer token-for-a-test" {
		t.Errorf("Authorization = %q, want the configured header", auth)
	}
	var wantDoc, gotDoc any
	if err := json.Unmarshal(want, &wantDoc); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got[0].body, &gotDoc); err != nil {
		t.Fatalf("the request is not JSON: %v\n%s", err, got[0].body)
	}
	if !reflect.DeepEqual(gotDoc, wantDoc) {
		t.Errorf("the request differs from the golden\n got: %s\nwant: %s", got[0].body, want)
	}
	if st := spoolStats(t, s); st.Unacknowledged != 0 {
		t.Errorf("the spool still holds %d unacknowledged bytes after the collector accepted", st.Unacknowledged)
	}
}

// TestInFlightBoundsTheUnacknowledgedRequests: with the collector holding
// every request, no more than InFlight are open at once, and all are
// acknowledged once it lets go.
func TestInFlightBoundsTheUnacknowledgedRequests(t *testing.T) {
	release := make(chan struct{})
	var open, peak atomic.Int32
	c := newCollectorFunc(t, func(w http.ResponseWriter, r *http.Request) {
		n := open.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		open.Add(-1)
		w.WriteHeader(http.StatusOK)
	})
	s := openSpool(t, 1<<20)
	const records = 6
	for i := range records {
		mustAppend(t, s, event(i))
	}
	e := newExporter(t, s, c, otel.Options{InFlight: 2, MaxBatch: 1, Linger: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), runDeadline)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	waitFor(t, func() bool { return open.Load() == 2 })
	time.Sleep(50 * time.Millisecond)
	if got := peak.Load(); got != 2 {
		t.Errorf("peak open requests = %d, want InFlight = 2", got)
	}
	close(release)
	waitFor(t, func() bool { return e.Stats().Acknowledged == records })
	if got := peak.Load(); got > 2 {
		t.Errorf("peak open requests = %d after the release, want at most 2", got)
	}
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Errorf("Run = %v, want nil after the context ended", err)
	}
	if sst := spoolStats(t, s); sst.Unacknowledged != 0 {
		t.Errorf("spool after all acknowledgements: %+v", sst)
	}
}

// TestACollectorOutageFillsTheSpoolAndBlocksNothingHere: with the collector
// down the exporter keeps retrying, appends are the spool's business until
// its budget, and the depth is visible in Stats.
func TestACollectorOutageFillsTheSpoolAndBlocksNothingHere(t *testing.T) {
	c := newCollector(t, func(int) int { return http.StatusServiceUnavailable })
	ev := event(1)
	size := recordSize(t, ev)
	s := openSpool(t, 4*size)
	e := newExporter(t, s, c, otel.Options{InFlight: 1, MaxBatch: 1, Linger: time.Millisecond, Backoff: 10 * time.Millisecond, MaxBackoff: 10 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), runDeadline)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	var last spool.Stats
	for i := range 4 {
		if err := s.Append(context.Background(), event(i)); err != nil {
			t.Fatalf("Append %d with the collector down: %v", i, err)
		}
		st := spoolStats(t, s)
		if st.Unacknowledged <= last.Unacknowledged {
			t.Errorf("Unacknowledged did not grow: %d then %d", last.Unacknowledged, st.Unacknowledged)
		}
		last = st
	}
	if err := s.Append(context.Background(), ev); !errors.Is(err, spool.ErrFull) {
		t.Errorf("Append past the budget = %v, want ErrFull: the spool's rule, not the exporter's", err)
	}
	waitFor(t, func() bool { return e.Stats().Retries >= 2 })
	if st := e.Stats(); st.Acknowledged != 0 {
		t.Errorf("Stats = %+v, want nothing accepted while the collector is down", st)
	}
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Errorf("Run = %v, want nil after the context ended", err)
	}
}

// TestRunStopsWhenTheSpoolCloses: a reader that fails ends Run with its
// error rather than a silent exit.
func TestRunStopsWhenTheSpoolCloses(t *testing.T) {
	c := newCollector(t, func(int) int { return http.StatusOK })
	s := openSpool(t, 1<<20)
	e := newExporter(t, s, c, otel.Options{InFlight: 1})
	done := make(chan error, 1)
	go func() { done <- e.Run(contextWithin(t, 10*time.Second)) }()
	time.Sleep(20 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, spool.ErrClosed) {
			t.Errorf("Run after the spool closed = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the spool closed")
	}
}

// Helpers.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "otlp", filepath.Base(name)))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixtureEvents(t *testing.T) []*controlv1.Event {
	t.Helper()
	events, err := evidence.DecodeJSONL(bytes.NewReader(readFixture(t, "events.jsonl")), 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("the fixture holds %d events, want 4", len(events))
	}
	return events
}

type request struct {
	header http.Header
	body   []byte
	// status and answer are what the collector wrote back.
	status int
	answer []byte
}

// accepted is whether the collector answered the way OTLP accepts a request
// whole: 200 or 202 and an empty body.
func (r request) accepted() bool {
	return (r.status == http.StatusOK || r.status == http.StatusAccepted) && len(bytes.TrimSpace(r.answer)) == 0
}

// recorder keeps what a handler wrote back.
type recorder struct {
	http.ResponseWriter
	status int
	answer bytes.Buffer
}

func (w *recorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.answer.Write(b)
	return w.ResponseWriter.Write(b)
}

type collector struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []request
}

// newCollector answers each request with the status the function gives for
// its ordinal.
func newCollector(t *testing.T, status func(n int) int) *collector {
	t.Helper()
	var n atomic.Int32
	return newCollectorFunc(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status(int(n.Add(1) - 1)))
	})
}

func newCollectorFunc(t *testing.T, handle http.HandlerFunc) *collector {
	t.Helper()
	c := &collector{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the request: %v", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := &recorder{ResponseWriter: w}
		handle(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		c.mu.Lock()
		c.seen = append(c.seen, request{header: r.Header.Clone(), body: body, status: rec.status, answer: rec.answer.Bytes()})
		c.mu.Unlock()
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *collector) requests() []request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]request(nil), c.seen...)
}

// delivered is the event ids of every request the collector accepted whole.
func (c *collector) delivered(t *testing.T) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, r := range c.requests() {
		if r.accepted() {
			for _, id := range eventIDs(t, r.body) {
				ids[id] = true
			}
		}
	}
	return ids
}

// eventIDs reads a request the way a collector would and returns the
// event_id of each log record's body, decoded as the evidence line it is.
func eventIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var req struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Body struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("the request is not JSON: %v", err)
	}
	var ids []string
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				events, err := evidence.DecodeJSONL(strings.NewReader(lr.Body.StringValue+"\n"), 1)
				if err != nil {
					t.Fatalf("a log record's body is not an evidence line: %v", err)
				}
				ids = append(ids, events[0].GetEventId())
			}
		}
	}
	return ids
}

func openSpool(t *testing.T, maxBytes int64) *spool.Spool {
	t.Helper()
	s, _ := openSpoolIn(t, maxBytes)
	return s
}

// openSpoolIn opens a spool and returns its directory too.
func openSpoolIn(t *testing.T, maxBytes int64) (*spool.Spool, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := spool.Open(spool.Options{Dir: dir, MaxBytes: maxBytes, SegmentBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func reader(t *testing.T, s *spool.Spool) *spool.Reader {
	t.Helper()
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newExporter(t *testing.T, s *spool.Spool, c *collector, opts otel.Options) *otel.Exporter {
	t.Helper()
	opts.Endpoint = c.srv.URL + "/v1/logs"
	if opts.Client == nil {
		opts.Client = c.srv.Client()
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	e, err := otel.New(opts, reader(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// runUntil runs the exporter until cond holds, then stops it and requires a
// clean return.
func runUntil(t *testing.T, e *otel.Exporter, cond func() bool) {
	t.Helper()
	// The context has a deadline of its own, so a Run that ignores its
	// cancellation ends the test with a failure rather than a hang.
	ctx, cancel := context.WithTimeout(context.Background(), runDeadline)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	waitFor(t, cond)
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Errorf("Run = %v, want nil after the context ended", err)
	}
}

// runDeadline bounds a Run a test starts, so no test can wait on one for ever.
const runDeadline = 30 * time.Second

// waitRun takes the result of a Run a test started, and fails the test when it
// does not come.
func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(runDeadline):
		t.Fatal("Run did not return within the deadline")
		return nil
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within ten seconds")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func mustAppend(t *testing.T, s *spool.Spool, ev *controlv1.Event) {
	t.Helper()
	if err := s.Append(context.Background(), ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

func spoolStats(t *testing.T, s *spool.Spool) spool.Stats {
	t.Helper()
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func event(n int) *controlv1.Event {
	return &controlv1.Event{
		EventId: "evt-" + strconv.Itoa(n), Kind: controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED,
		RequestId: "req-1", ProjectId: "proj-1", TenantId: "tenant-1", SchemaVersion: evidence.SchemaVersion,
	}
}

func recordSize(t *testing.T, ev *controlv1.Event) int64 {
	t.Helper()
	var line bytes.Buffer
	if err := evidence.EncodeJSONL(&line, []*controlv1.Event{ev}); err != nil {
		t.Fatal(err)
	}
	return int64(line.Len()) + 8
}

// contextWithin is a context that ends after d.
func contextWithin(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// storedLines is every record the spool's segments hold, as the line the
// framing checksummed, read by the format itself.
func storedLines(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".seg") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // G304: the spool's segment under the test's temp dir
		if err != nil {
			t.Fatal(err)
		}
		for len(raw) > 8 {
			length := binary.BigEndian.Uint32(raw[0:4])
			sum := binary.BigEndian.Uint32(raw[4:8])
			line := raw[8 : 8+length]
			if crc32.Checksum(line, crc32.MakeTable(crc32.Castagnoli)) != sum {
				t.Fatal("a stored record does not check")
			}
			lines = append(lines, string(line))
			raw = raw[8+length:]
		}
	}
	return lines
}

// bodyLines is every log record's body in a request, as the evidence line it
// has to be: the stringValue and the newline the codec writes.
func bodyLines(t *testing.T, body []byte) []string {
	t.Helper()
	var req struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Body struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("the request is not JSON: %v", err)
	}
	var lines []string
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				lines = append(lines, lr.Body.StringValue+"\n")
			}
		}
	}
	return lines
}
