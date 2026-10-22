package otel_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
	"github.com/guardana/control/internal/spool"
)

// fast is the retry pacing of a test: short enough to see several attempts.
func fast(opts otel.Options) otel.Options {
	opts.Backoff, opts.MaxBackoff = 5*time.Millisecond, 5*time.Millisecond
	if opts.Linger == 0 {
		opts.Linger = 5 * time.Millisecond
	}
	return opts
}

// TestNoAnswerButAcceptancePassesARecordOver: an outage of any status that
// is not an acceptance and not a refusal of the records, three answers long,
// is retried until the collector accepts, and every record is delivered.
func TestNoAnswerButAcceptancePassesARecordOver(t *testing.T) {
	for _, tc := range []struct {
		status  int
		counter func(otel.Stats) uint64
	}{
		{http.StatusUnauthorized, func(s otel.Stats) uint64 { return s.RetriedAuth }},
		{http.StatusForbidden, func(s otel.Stats) uint64 { return s.RetriedAuth }},
		{http.StatusProxyAuthRequired, func(s otel.Stats) uint64 { return s.RetriedAuth }},
		{http.StatusNotFound, func(s otel.Stats) uint64 { return s.RetriedStatus }},
		{http.StatusMethodNotAllowed, func(s otel.Stats) uint64 { return s.RetriedStatus }},
		{http.StatusNoContent, func(s otel.Stats) uint64 { return s.RetriedStatus }},
		{http.StatusRequestTimeout, func(s otel.Stats) uint64 { return s.RetriedThrottled }},
		{http.StatusTooManyRequests, func(s otel.Stats) uint64 { return s.RetriedThrottled }},
		{http.StatusInternalServerError, func(s otel.Stats) uint64 { return s.RetriedServer }},
		{http.StatusBadGateway, func(s otel.Stats) uint64 { return s.RetriedServer }},
		{http.StatusServiceUnavailable, func(s otel.Stats) uint64 { return s.RetriedServer }},
		{http.StatusNotModified, func(s otel.Stats) uint64 { return s.RetriedRedirect }},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			c := newCollector(t, func(n int) int {
				if n < 3 {
					return tc.status
				}
				return http.StatusOK
			})
			s := openSpool(t, 1<<20)
			mustAppend(t, s, event(1))
			mustAppend(t, s, event(2))
			e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 1}))
			runUntil(t, e, func() bool { return e.Stats().Acknowledged == 2 })
			if got := c.delivered(t); !got["evt-1"] || !got["evt-2"] {
				t.Errorf("accepted requests carried %v, want evt-1 and evt-2", got)
			}
			st := e.Stats()
			if tc.counter(st) != 3 || st.Retries != 3 || st.Quarantined != 0 || st.Refused != 0 {
				t.Errorf("Stats = %+v; want three retries of this class and nothing quarantined", st)
			}
			if sst := spoolStats(t, s); sst.Unacknowledged != 0 || sst.QuarantinedRecords != 0 {
				t.Errorf("spool after delivery = %+v", sst)
			}
		})
	}
}

// TestATimeoutIsRetried: a collector that hangs past Timeout gets the request
// again, and the batch is acknowledged when it finally answers.
func TestATimeoutIsRetried(t *testing.T) {
	var calls atomic.Int32
	c := newCollectorFunc(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s := openSpool(t, 1<<20)
	mustAppend(t, s, event(1))
	e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, Timeout: 50 * time.Millisecond}))
	runUntil(t, e, func() bool { return e.Stats().Acknowledged == 1 })
	if st := e.Stats(); st.RetriedTransport < 1 {
		t.Errorf("Stats = %+v, want the timeout counted as no answer", st)
	}
	if sst := spoolStats(t, s); sst.Unacknowledged != 0 {
		t.Errorf("spool after the answer: %+v", sst)
	}
}

// TestARedirectIsNeverFollowed: a collector that points elsewhere has not
// accepted anything, and the place it points to sees nothing, with the
// exporter's own client and with a caller's, which is left as it was.
func TestARedirectIsNeverFollowed(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		for _, own := range []bool{true, false} {
			t.Run(http.StatusText(status), func(t *testing.T) {
				var elsewhere atomic.Int32
				b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					elsewhere.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(b.Close)
				a := newCollectorFunc(t, func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, b.URL+"/v1/logs", status)
				})
				s := openSpool(t, 1<<20)
				ev := event(1)
				mustAppend(t, s, ev)
				opts := fast(otel.Options{InFlight: 1})
				var callers *http.Client
				if !own {
					callers = &http.Client{}
					opts.Client = callers
				}
				e := newExporter(t, s, a, opts)
				runUntil(t, e, func() bool { return e.Stats().RetriedRedirect >= 3 })
				if n := elsewhere.Load(); n != 0 {
					t.Errorf("the redirect target saw %d requests", n)
				}
				if st := e.Stats(); st.Acknowledged != 0 {
					t.Errorf("Stats = %+v, want nothing acknowledged", st)
				}
				if sst := spoolStats(t, s); sst.Unacknowledged != recordSize(t, ev) {
					t.Errorf("spool after the redirects = %+v, want the record kept", sst)
				}
				if callers != nil && callers.CheckRedirect != nil {
					t.Error("New changed the caller's client")
				}
			})
		}
	}
}

// TestOnlyTheProtocolsAnswerAccepts: a 200 or 202 whose body is not an
// ExportLogsServiceResponse, such as a login page, accepts nothing; the
// request is sent again until an answer that is the protocol's.
func TestOnlyTheProtocolsAnswerAccepts(t *testing.T) {
	type answer struct {
		status int
		body   string
	}
	for name, bad := range map[string]answer{
		"a login page":             {http.StatusOK, "<html>login</html>"},
		"a login page on 202":      {http.StatusAccepted, "<html>login</html>"},
		"JSON null":                {http.StatusOK, "null"},
		"a JSON array":             {http.StatusOK, "[]"},
		"another member":           {http.StatusOK, `{"unexpected":1}`},
		"a member beside it":       {http.StatusOK, `{"partialSuccess":{},"unexpected":1}`},
		"an unknown inner member":  {http.StatusOK, `{"partialSuccess":{"other":1}}`},
		"a count that is no count": {http.StatusOK, `{"partialSuccess":{"rejectedLogRecords":"many"}}`},
		"a negative count":         {http.StatusOK, `{"partialSuccess":{"rejectedLogRecords":"-1"}}`},
		"a cut object":             {http.StatusOK, `{"partialSuccess":`},
		// Its first 64 KiB alone would read as an empty object.
		"an answer past the bound": {http.StatusOK, "{}" + strings.Repeat(" ", 64<<10)},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			c := newCollectorFunc(t, func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) <= 3 {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(bad.status)
					_, _ = w.Write([]byte(bad.body))
					return
				}
				w.WriteHeader(http.StatusOK)
			})
			s := openSpool(t, 1<<20)
			mustAppend(t, s, event(1))
			e := newExporter(t, s, c, fast(otel.Options{InFlight: 1}))
			runUntil(t, e, func() bool { return e.Stats().Acknowledged == 1 })
			if n := len(c.requests()); n != 4 {
				t.Errorf("the collector saw %d requests, want the three answered %q and one accepted", n, bad.body)
			}
			if st := e.Stats(); st.RetriedAnswer != 3 {
				t.Errorf("Stats = %+v, want three unreadable answers", st)
			}
		})
	}
	for name, good := range map[string]answer{
		"an empty body":            {http.StatusOK, ""},
		"an empty body on 202":     {http.StatusAccepted, ""},
		"an empty object":          {http.StatusOK, " {} "},
		"an empty partial success": {http.StatusOK, `{"partialSuccess":{}}`},
		"a null partial success":   {http.StatusOK, `{"partialSuccess":null}`},
		"nothing rejected":         {http.StatusOK, `{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":""}}`},
		"a null message":           {http.StatusOK, `{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":null}}`},
		"a surrogate pair":         {http.StatusOK, `{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":"\\\ud83d\ude00\\u"}}`},
		"an answer at the bound":   {http.StatusOK, "{}" + strings.Repeat(" ", 64<<10-2)},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCollectorFunc(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(good.status)
				_, _ = w.Write([]byte(good.body))
			})
			s := openSpool(t, 1<<20)
			mustAppend(t, s, event(1))
			e := newExporter(t, s, c, fast(otel.Options{InFlight: 1}))
			runUntil(t, e, func() bool { return e.Stats().Acknowledged == 1 })
			if n := len(c.requests()); n != 1 {
				t.Errorf("the collector saw %d requests, want one", n)
			}
			if st := e.Stats(); st.Retries != 0 || st.Quarantined != 0 {
				t.Errorf("Stats = %+v, want the first answer to accept", st)
			}
		})
	}
}

// TestARefusedRecordIsIsolatedAndQuarantined: a collector that refuses one
// record of four makes the exporter split the request until that record
// stands alone; refused three times running, it goes to the quarantine, and
// the other three are delivered.
func TestARefusedRecordIsIsolatedAndQuarantined(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var alone atomic.Int32
			c := newCollectorFunc(t, refusing("evt-2", status, &alone))
			s := openSpool(t, 1<<20)
			for i := 1; i <= 4; i++ {
				mustAppend(t, s, event(i))
			}
			e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 4, Linger: 200 * time.Millisecond}))
			runUntil(t, e, func() bool { return e.Stats().Acknowledged == 4 })
			if got := c.delivered(t); len(got) != 3 || !got["evt-1"] || !got["evt-3"] || !got["evt-4"] {
				t.Errorf("accepted requests carried %v, want evt-1, evt-3 and evt-4", got)
			}
			if n := alone.Load(); n != 3 {
				t.Errorf("evt-2 was sent alone %d times, want three", n)
			}
			if st := e.Stats(); st.Quarantined != 1 || st.Refused != 5 {
				t.Errorf("Stats = %+v; want one record quarantined after five refusals: two splits and three alone", st)
			}
			if sst := spoolStats(t, s); sst.QuarantinedRecords != 1 || sst.Unacknowledged != 0 {
				t.Errorf("spool = %+v, want evt-2 in the quarantine and the rest released", sst)
			}
		})
	}
}

// refusing answers status to every request that carries the event id, and
// counts those in which it is the only record; it accepts every other.
func refusing(id string, status int, alone *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		if !strings.Contains(body.String(), id+`\"`) {
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Count(body.String(), `"body"`) == 1 {
			alone.Add(1)
		}
		w.WriteHeader(status)
	}
}

// TestAPartialSuccessQuarantinesTheWholeRequest: which records a collector
// dropped is unknown, so all of them are kept before the cursor passes them.
func TestAPartialSuccessQuarantinesTheWholeRequest(t *testing.T) {
	c := newCollectorFunc(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"one record over the size limit"}}`))
	})
	var logged bytes.Buffer
	s := openSpool(t, 1<<20)
	mustAppend(t, s, event(1))
	mustAppend(t, s, event(2))
	e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 2, Linger: 200 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(&logged, nil))}))
	runUntil(t, e, func() bool { return e.Stats().Acknowledged == 2 })
	if st := e.Stats(); st.Quarantined != 2 || st.PartialRejected != 1 {
		t.Errorf("Stats = %+v; want both records quarantined and one reported dropped", st)
	}
	if sst := spoolStats(t, s); sst.QuarantinedRecords != 2 || sst.Unacknowledged != 0 {
		t.Errorf("spool = %+v, want both in the quarantine", sst)
	}
	// The collector's own text never reaches the log; its length and digest do.
	out := logged.String()
	if strings.Contains(out, "one record over the size limit") {
		t.Errorf("the collector's message reached the log: %q", out)
	}
	for _, want := range []string{"answer_bytes=93", "answer_sha256=", "rejected=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log does not carry %q: %q", want, out)
		}
	}
}

// TestARestartedRunSendsWhatTheStoppedOneTook: a Run stopped with a batch in
// flight left it unacknowledged, and the next Run starts from the
// acknowledged position, so that batch goes out again before anything later
// is acknowledged.
func TestARestartedRunSendsWhatTheStoppedOneTook(t *testing.T) {
	var up atomic.Bool
	c := newCollectorFunc(t, func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s := openSpool(t, 1<<20)
	mustAppend(t, s, event(1))
	e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 8}))
	runUntil(t, e, func() bool { return len(c.requests()) >= 1 })
	up.Store(true)
	mustAppend(t, s, event(2))
	runUntil(t, e, func() bool { return e.Stats().Acknowledged >= 1 && spoolStats(t, s).Unacknowledged == 0 })
	if got := c.delivered(t); !got["evt-1"] || !got["evt-2"] {
		t.Errorf("accepted requests carried %v, want evt-1 and evt-2", got)
	}
}

// TestAReadErrorMidBatchLosesNothing: a Run that read a record, then failed
// on the next, dropped the batch it was collecting; the next Run reads the
// first record again rather than acknowledging past it.
func TestAReadErrorMidBatchLosesNothing(t *testing.T) {
	c := newCollector(t, func(int) int { return http.StatusOK })
	s, dir := openSpoolIn(t, 1<<20)
	first := event(1)
	mustAppend(t, s, first)
	mustAppend(t, s, event(2))
	segment := filepath.Join(dir, "00000000000000000001.seg")
	flip := func() {
		f, err := os.OpenFile(segment, os.O_RDWR, 0) //nolint:gosec // G304: the spool's segment under the test's temp dir
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1)
		at := recordSize(t, first) + 20
		if _, err := f.ReadAt(b, at); err != nil {
			t.Fatal(err)
		}
		b[0] ^= 0x01
		if _, err := f.WriteAt(b, at); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	flip()
	e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 8, Linger: 200 * time.Millisecond}))
	// Bounded: a Run that does not stop on the record that does not check is
	// a failure here, not a test that hangs until the whole package times out.
	if err := e.Run(contextWithin(t, 5*time.Second)); !errors.Is(err, spool.ErrCorrupt) {
		t.Fatalf("Run over a record that does not check = %v, want ErrCorrupt", err)
	}
	if n := len(c.requests()); n != 0 {
		t.Fatalf("the collector saw %d requests from a batch that was never completed", n)
	}
	flip()
	runUntil(t, e, func() bool { return spoolStats(t, s).Unacknowledged == 0 })
	if got := c.delivered(t); !got["evt-1"] || !got["evt-2"] {
		t.Errorf("accepted requests carried %v, want evt-1 and evt-2", got)
	}
}

// TestNothingIsAcknowledgedPastABatchNotDelivered: with two requests in
// flight, a later one accepted does not move the cursor past an earlier one
// the Run stopped before its answer.
func TestNothingIsAcknowledgedPastABatchNotDelivered(t *testing.T) {
	c := newCollectorFunc(t, func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		if strings.Contains(body.String(), `evt-1\"`) {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s := openSpool(t, 1<<20)
	mustAppend(t, s, event(1))
	mustAppend(t, s, event(2))
	e := newExporter(t, s, c, fast(otel.Options{InFlight: 2, MaxBatch: 1, Timeout: 10 * time.Second}))
	runUntil(t, e, func() bool {
		for _, r := range c.requests() {
			if r.accepted() {
				return true
			}
		}
		return false
	})
	if st := e.Stats(); st.Acknowledged != 0 {
		t.Errorf("Stats = %+v, want nothing acknowledged past the unanswered evt-1", st)
	}
	if sst := spoolStats(t, s); sst.Unacknowledged != recordSize(t, event(1))+recordSize(t, event(2)) {
		t.Errorf("spool = %+v, want both records kept", sst)
	}
}

// TestLogsNeverCarryTheEndpointsSecrets: the HTTP client's errors quote the
// URL, and the exporter's log lines leave out its userinfo and query.
func TestLogsNeverCarryTheEndpointsSecrets(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	addr := gone.Listener.Addr().String()
	gone.Close()
	var logged bytes.Buffer
	s := openSpool(t, 1<<20)
	mustAppend(t, s, event(1))
	e, err := otel.New(fast(otel.Options{
		Endpoint:       "http://collector-user:secret-password@" + addr + "/v1/logs/secret-path?token=secret-query",
		AllowPlaintext: true,
		InFlight:       1, Timeout: time.Second,
		Logger: slog.New(slog.NewTextHandler(&logged, nil)),
	}), reader(t, s))
	if err != nil {
		t.Fatal(err)
	}
	runUntil(t, e, func() bool { return e.Stats().RetriedTransport >= 2 })
	out := logged.String()
	if !strings.Contains(out, addr) {
		t.Fatalf("the log does not name the endpoint at all: %q", out)
	}
	for _, secret := range []string{"collector-user", "secret-password", "secret-path", "secret-query", "token="} {
		if strings.Contains(out, secret) {
			t.Errorf("the log carries %q: %q", secret, out)
		}
	}
}

// echoingCollector answers every request with a status line that is not one,
// spelled from the request line and every header it was sent, and
// returns its host:port.
func echoingCollector(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck // the answer is written; nothing reads the close
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				var echo strings.Builder
				echo.WriteString(req.Method + " " + req.RequestURI + " " + req.Proto + " ")
				_ = req.Header.Write(&echo)
				_, _ = io.WriteString(conn, strings.NewReplacer(" ", "_", "\r\n", "_").Replace(echo.String())+"\r\n\r\n")
			}()
		}
	}()
	return ln.Addr().String()
}

// TestLogsNeverCarryWhatTheCollectorEchoes: a collector that answers with a
// malformed status line quoting the request line and the Authorization header
// gets the HTTP client to quote them back in its error; the log line names
// the operation, the endpoint without its secrets and a fixed cause, and
// neither the query, the configured header nor the userinfo as the client
// encodes it.
func TestLogsNeverCarryWhatTheCollectorEchoes(t *testing.T) {
	addr := echoingCollector(t)
	var logged bytes.Buffer
	s := openSpool(t, 1<<20)
	mustAppend(t, s, event(1))
	e, err := otel.New(fast(otel.Options{
		Endpoint:       "http://collector-user:userinfo-marker@" + addr + "/v1/logs?token=query-marker",
		Headers:        map[string]string{"X-Collector-Key": "header-marker"},
		AllowPlaintext: true,
		InFlight:       1, Timeout: time.Second,
		Logger: slog.New(slog.NewTextHandler(&logged, nil)),
	}), reader(t, s))
	if err != nil {
		t.Fatal(err)
	}
	runUntil(t, e, func() bool { return e.Stats().RetriedTransport >= 2 })
	out := logged.String()
	if want := "Post http://" + addr + ": " + otel.CauseWithheld; !strings.Contains(out, want) {
		t.Errorf("the log does not name the operation, the endpoint and the fixed cause %q: %q", want, out)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("collector-user:userinfo-marker"))
	for _, secret := range []string{"userinfo-marker", "query-marker", "token=", "header-marker", basic, "Authorization"} {
		if strings.Contains(out, secret) {
			t.Errorf("the log carries %q: %q", secret, out)
		}
	}
}

// TestOneRunDrainsOneReader: two runs share one reader, so each takes records
// the other does not see and each one's acknowledgement is over the whole log.
// The second run is refused, and the record the collector never accepted stays
// in the spool.
func TestOneRunDrainsOneReader(t *testing.T) {
	const records = 6
	var accepted sync.Map
	c := newCollectorFunc(t, func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		if strings.Contains(body.String(), `evt-1\"`) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		for i := 1; i <= records; i++ {
			if strings.Contains(body.String(), fmt.Sprintf(`evt-%d\"`, i)) {
				accepted.Store(i, true)
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	ev := event(1)
	s, _ := openSpoolIn(t, 1<<20)
	for i := 1; i <= records; i++ {
		mustAppend(t, s, event(i))
	}
	e := newExporter(t, s, c, fast(otel.Options{InFlight: 4, MaxBatch: 1}))
	ctx, cancel := context.WithTimeout(context.Background(), runDeadline)
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- e.Run(ctx) }()
	waitFor(t, func() bool { return len(c.requests()) >= 2 })
	// Bounded, so a second run that is wrongly allowed ends the test rather
	// than draining beside the first for ever.
	if err := e.Run(contextWithin(t, 500*time.Millisecond)); !errors.Is(err, otel.ErrRunning) {
		t.Errorf("a second Run while the first is going = %v, want ErrRunning", err)
	}
	// The first run keeps retrying evt-1 and acknowledges nothing past it.
	waitFor(t, func() bool { return e.Stats().RetriedServer >= 3 })
	cancel()
	if err := waitRun(t, first); err != nil {
		t.Errorf("Run = %v, want nil after the context ended", err)
	}
	if _, held := accepted.Load(1); held {
		t.Fatal("the collector accepted evt-1, which it was told to refuse")
	}
	st, sst := e.Stats(), spoolStats(t, s)
	if st.Acknowledged != 0 || sst.Unacknowledged < recordSize(t, ev) || sst.QuarantinedRecords != 0 {
		t.Errorf("exporter %+v, spool %+v; want evt-1 still in the spool and nothing acknowledged", st, sst)
	}
	// A run after this one is allowed again.
	if err := e.Run(contextWithin(t, 20*time.Millisecond)); err != nil {
		t.Errorf("Run after the first returned = %v", err)
	}
}

// TestAnAnswerIsTheProtocolsOrItIsNotAnAnswer: protojson refuses a member
// that appears twice, and the exporter reads the answer as strictly, in either
// spelling, because a duplicate member read loosely turns a refusal into an
// acceptance; so is an error message that is not a string.
func TestAnAnswerIsTheProtocolsOrItIsNotAnAnswer(t *testing.T) {
	for name, body := range map[string]string{
		"partialSuccess twice":       `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"both dropped"},"partialSuccess":null}`,
		"the count twice":            `{"partialSuccess":{"rejectedLogRecords":"2","rejectedLogRecords":"0"}}`,
		"both spellings of a member": `{"partialSuccess":{},"partial_success":{}}`,
		"both spellings of a count":  `{"partialSuccess":{"rejectedLogRecords":"0","rejected_log_records":"0"}}`,
		"a count past the batch":     `{"partialSuccess":{"rejectedLogRecords":"3"}}`,
		"a count past every batch":   `{"partialSuccess":{"rejectedLogRecords":"9223372036854775807"}}`,
		"an unknown member":          `{"partialSuccess":{"rejectedLogRecords":0,"unknown":1}}`,
		"two documents":              `{} {}`,
		"an object for the message":  `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":{}}}`,
		"an array for the message":   `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":["dropped"]}}`,
		"a number for the message":   `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":2}}`,
		"a boolean for the message":  `{"partialSuccess":{"rejected_log_records":"2","error_message":true}}`,
		"a message not UTF-8":        "{\"partialSuccess\":{\"rejectedLogRecords\":\"2\",\"errorMessage\":\"\xff\"}}",
		"a lone high surrogate":      `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"a\ud800"}}`,
		"a lone low surrogate":       `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"\udc00b"}}`,
		"a high surrogate unpaired":  `{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"\uD800\u0041"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var answers atomic.Int32
			c := newCollectorFunc(t, func(w http.ResponseWriter, _ *http.Request) {
				if answers.Add(1) <= 3 {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(body))
					return
				}
				w.WriteHeader(http.StatusOK)
			})
			s := openSpool(t, 1<<20)
			mustAppend(t, s, event(1))
			mustAppend(t, s, event(2))
			e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 2, Linger: 200 * time.Millisecond}))
			runUntil(t, e, func() bool { return e.Stats().Acknowledged == 2 })
			st := e.Stats()
			if st.RetriedAnswer != 3 {
				t.Errorf("Stats = %+v, want the three answers retried, not taken for an acceptance", st)
			}
			if st.PartialRejected != 0 || st.Quarantined != 0 {
				t.Errorf("Stats = %+v, want nothing counted from an answer that is not the protocol's", st)
			}
		})
	}
	// The proto spelling is the protobuf JSON mapping's too, and a count
	// inside the batch is read as it stands.
	for name, tc := range map[string]struct {
		body     string
		rejected uint64
	}{
		"the proto spelling of the member": {`{"partial_success":{"rejectedLogRecords":"0"}}`, 0},
		"the proto spelling of the count":  {`{"partialSuccess":{"rejected_log_records":"1"}}`, 1},
		"the proto spelling of both":       {`{"partial_success":{"rejected_log_records":"2","error_message":"both"}}`, 2},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCollectorFunc(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			})
			s := openSpool(t, 1<<20)
			mustAppend(t, s, event(1))
			mustAppend(t, s, event(2))
			e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 2, Linger: 200 * time.Millisecond}))
			runUntil(t, e, func() bool { return e.Stats().Acknowledged == 2 })
			st := e.Stats()
			if st.RetriedAnswer != 0 || len(c.requests()) != 1 {
				t.Errorf("Stats = %+v over %d requests, want the answer accepted at once", st, len(c.requests()))
			}
			if st.PartialRejected != tc.rejected {
				t.Errorf("PartialRejected = %d, want %d", st.PartialRejected, tc.rejected)
			}
		})
	}
}

// TestAPlaintextCollectorNeedsTheRiskSetting: over plaintext anyone on the
// path can forge the empty 200 that releases the evidence, so an http endpoint
// is refused unless the operator named the risk.
func TestAPlaintextCollectorNeedsTheRiskSetting(t *testing.T) {
	r := reader(t, openSpool(t, 1<<20))
	plain := otel.Options{Endpoint: "http://127.0.0.1:4318/v1/logs", InFlight: 1, Timeout: time.Second,
		Headers: map[string]string{"Authorization": "Bearer s3cret"}}
	if e, err := otel.New(plain, r); e != nil || !errors.Is(err, otel.ErrInvalidOptions) {
		t.Errorf("New over plaintext = %v, %v; want nil, ErrInvalidOptions", e, err)
	}
	plain.AllowPlaintext = true
	if _, err := otel.New(plain, r); err != nil {
		t.Errorf("New over plaintext with the risk setting = %v", err)
	}
	secure := otel.Options{Endpoint: "https://collector.example:4318/v1/logs", InFlight: 1, Timeout: time.Second}
	if _, err := otel.New(secure, r); err != nil {
		t.Errorf("New over https = %v", err)
	}
}

// TestAPlaintextCollectorIsOnTheLoopback: the risk setting admits plaintext
// to a loopback IP literal and nowhere else, a name that resolves there
// included.
func TestAPlaintextCollectorIsOnTheLoopback(t *testing.T) {
	r := reader(t, openSpool(t, 1<<20))
	cases := map[string]bool{
		"http://127.0.0.1:4318/v1/logs":    true,
		"http://127.0.0.2:4318/v1/logs":    true,
		"http://[::1]:4318/v1/logs":        true,
		"http://localhost:4318/v1/logs":    false,
		"http://10.0.0.5:4318/v1/logs":     false,
		"http://collector.example/v1/logs": false,
		"http://[::ffff:10.0.0.5]:4318/":   false,
	}
	for endpoint, admitted := range cases {
		o := otel.Options{Endpoint: endpoint, AllowPlaintext: true, InFlight: 1, Timeout: time.Second}
		_, err := otel.New(o, r)
		switch {
		case admitted && err != nil:
			t.Errorf("New with %s = %v; want admitted", endpoint, err)
		case !admitted && !errors.Is(err, otel.ErrInvalidOptions):
			t.Errorf("New with %s = %v; want ErrInvalidOptions", endpoint, err)
		}
	}
	o := otel.Options{Endpoint: "http://secret-x@10.0.0.5:4318/v1/logs", AllowPlaintext: true, InFlight: 1, Timeout: time.Second}
	if _, err := otel.New(o, r); err == nil || strings.Contains(err.Error(), "secret-x") || strings.Contains(err.Error(), "10.0.0.5") {
		t.Errorf("the refusal of a plaintext endpoint off the loopback quotes it: %v", err)
	}
}

// TestTheBodyCarriesTheLineTheSpoolChecksummed: exported evidence is the
// stored evidence, byte for byte, so nothing can read a different record from
// the collector than from the spool.
func TestTheBodyCarriesTheLineTheSpoolChecksummed(t *testing.T) {
	c := newCollector(t, func(int) int { return http.StatusOK })
	s, dir := openSpoolIn(t, 1<<20)
	for i := 1; i <= 3; i++ {
		mustAppend(t, s, event(i))
	}
	// Read what the spool checksummed before the acknowledgement releases it.
	stored := storedLines(t, dir)
	e := newExporter(t, s, c, fast(otel.Options{InFlight: 1, MaxBatch: 3, Linger: 200 * time.Millisecond}))
	runUntil(t, e, func() bool { return e.Stats().Acknowledged == 3 })
	var sent []string
	for _, r := range c.requests() {
		sent = append(sent, bodyLines(t, r.body)...)
	}
	if len(sent) != len(stored) {
		t.Fatalf("the collector saw %d records, the spool holds %d", len(sent), len(stored))
	}
	for i := range stored {
		if sent[i] != stored[i] {
			t.Errorf("record %d: the request carries %q, the spool checksummed %q", i, sent[i], stored[i])
		}
	}
}
