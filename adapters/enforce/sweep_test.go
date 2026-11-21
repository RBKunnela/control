package enforce_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

const codeUnavailable = enforcev1alpha1.ErrorCode_ERROR_CODE_UNAVAILABLE

func (r *rig) abandoned(t *testing.T) int {
	t.Helper()
	var n int
	for _, e := range r.sink.Events() {
		res := e.GetResult()
		if e.GetKind() != kindFailed || res.GetToolProtocolStatus() != "EXECUTION_ABANDONED" {
			continue
		}
		if res.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_UNKNOWN || res.GetRetryable() || res.GetExecutedActionDigest() != "" {
			t.Fatalf("an abandoned execution recorded as %v", res)
		}
		n++
	}
	return n
}

func TestAClientThatNeverCompletesIsAbandonedAtItsExpiry(t *testing.T) {
	r := newRig(t, defaults())
	handle := r.executed(t, runA, "refund", refund)
	r.settle(t)
	expiry := base().Add(time.Minute)
	if n := r.a.Sweep(t.Context(), expiry.Add(-time.Nanosecond)); n != 0 || r.abandoned(t) != 0 {
		t.Fatalf("a sweep before the expiry abandoned %d", n)
	}
	if n := r.a.Sweep(t.Context(), expiry); n != 1 || r.abandoned(t) != 1 {
		t.Fatalf("a sweep at the expiry abandoned %d, recorded %d", n, r.abandoned(t))
	}
	if n := r.a.Sweep(t.Context(), expiry); n != 0 || r.abandoned(t) != 1 {
		t.Fatalf("a second sweep abandoned %d", n)
	}
	r.clock.advance(time.Minute)
	r.refused(t, runA, enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusNotFound, codeUnknown)
	if s := r.a.Stats(); s.Abandoned != 1 || s.Open != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func TestASweepIsBoundedPerPass(t *testing.T) {
	o := defaults()
	o.adapter = func(c *enforce.Config) { c.SweepMax = 2 }
	r := newRig(t, o)
	for range 3 {
		r.executed(t, runA, "refund", refund)
	}
	r.settle(t)
	at := base().Add(time.Minute)
	for i, want := range []int{2, 1, 0} {
		if n := r.a.Sweep(t.Context(), at); n != want {
			t.Fatalf("pass %d abandoned %d, want %d", i, n, want)
		}
	}
}

func TestAnAbandonedExecutionFreesItsKey(t *testing.T) {
	r := newRig(t, defaults())
	key := `,"requestKey":"once"`
	r.admit(t, runA, "read_file", `{"path":"a"}`, key)
	r.settle(t)
	r.clock.advance(time.Minute)
	r.a.Sweep(t.Context(), r.clock.read())
	if resp := r.admit(t, runA, "read_file", `{"path":"a"}`, key); resp.GetOutcome() != outcomeExecute {
		t.Fatalf("the key stayed taken: %s", resp.GetOutcome())
	}
}

func TestShutdownAbandonsEveryOpenExecutionAndRefusesWhatComesAfter(t *testing.T) {
	r := newRig(t, defaults())
	first := r.executed(t, runA, "refund", refund)
	spent := r.executed(t, runB, "refund", refund)
	r.executed(t, runB, "read_file", `{"path":"a"}`)
	r.complete(t, runB, spent, refund, "COMPLETION_STATUS_SUCCESS")
	if err := r.a.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if n := r.abandoned(t); n != 2 {
		t.Fatalf("Shutdown abandoned %d of 2 open executions", n)
	}
	r.refused(t, runA, enforce.PathAdmit, admitBody("read_file", `{"path":"a"}`), http.StatusServiceUnavailable, codeUnavailable)
	r.refused(t, runA, enforce.PathComplete, completeBody(first, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusServiceUnavailable, codeUnavailable)
	if s := r.a.Stats(); s.Open != 0 || s.Abandoned != 2 {
		t.Fatalf("stats %+v", s)
	}
}

// gate holds every Admit until it is opened, so a test can act while one is
// in flight.
type gate struct {
	enforce.Pipeline
	entered chan struct{}
	open    chan struct{}
	once    sync.Once
}

func (g *gate) Admit(ctx context.Context, a gateway.Admission) gateway.Disposition {
	g.once.Do(func() { close(g.entered) })
	<-g.open
	return g.Pipeline.Admit(ctx, a)
}

func gated(o *options) *gate {
	g := &gate{entered: make(chan struct{}), open: make(chan struct{})}
	o.pipeline = func(p enforce.Pipeline) enforce.Pipeline { g.Pipeline = p; return g }
	return g
}

func TestShutdownWaitsForTheAdmitInFlight(t *testing.T) {
	o := defaults()
	g := gated(&o)
	r := newRig(t, o)
	answered := make(chan int, 1)
	go func() {
		status, _ := r.post(t, runA, enforce.PathAdmit, admitBody("refund", refund))
		answered <- status
	}()
	<-g.entered
	shut := make(chan error, 1)
	go func() { shut <- r.a.Shutdown(context.Background()) }()
	select {
	case err := <-shut:
		t.Fatalf("Shutdown returned %v with an admit in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(g.open)
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if status := <-answered; status != http.StatusOK {
		t.Fatalf("the admit in flight answered %d", status)
	}
	if n := r.abandoned(t); n != 1 {
		t.Fatalf("the execution handed out during Shutdown was abandoned %d times", n)
	}
}

func TestAnExecutionMintedAfterShutdownGaveUpWaitingIsAbandonedAtOnce(t *testing.T) {
	o := defaults()
	g := gated(&o)
	r := newRig(t, o)
	answered := make(chan []byte, 1)
	statuses := make(chan int, 1)
	go func() {
		status, body := r.post(t, runA, enforce.PathAdmit, admitBody("refund", refund))
		statuses <- status
		answered <- body
	}()
	<-g.entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.a.Shutdown(ctx); !errors.Is(err, enforce.ErrDraining) {
		t.Fatalf("Shutdown = %v, want ErrDraining", err)
	}
	close(g.open)
	refusal(t, <-statuses, <-answered, http.StatusServiceUnavailable, codeUnavailable)
	if n := r.abandoned(t); n != 1 || r.a.Stats().Open != 0 {
		t.Fatalf("abandoned %d, open %d", n, r.a.Stats().Open)
	}
}

// An abandon whose record the sink refused is counted apart, since no client
// is told of it.
func TestAnAbandonTheSinkRefusesIsCounted(t *testing.T) {
	sink := &switchSink{}
	o := defaults()
	o.plane = func(c *gateway.Config) { c.Sink = sink }
	r := newRig(t, o)
	r.executed(t, runA, "refund", refund)
	r.executed(t, runB, "refund", refund)
	r.settle(t)
	if n := r.a.Sweep(t.Context(), base().Add(time.Minute)); n != 2 {
		t.Fatalf("the sweep abandoned %d", n)
	}
	if s := r.a.Stats(); s.RecordsFailed != 0 || s.Abandoned != 2 {
		t.Fatalf("stats after landed abandons %+v", s)
	}
	r.executed(t, runA, "refund", refund)
	r.settle(t)
	sink.failing.Store(true)
	if n := r.a.Sweep(t.Context(), base().Add(time.Minute)); n != 1 {
		t.Fatalf("the sweep abandoned %d", n)
	}
	if s := r.a.Stats(); s.RecordsFailed != 1 || s.Abandoned != 3 || s.Open != 0 {
		t.Fatalf("stats after a refused abandon %+v", s)
	}
}

// shutter is a ResponseWriter that shuts the adapter down as the answer
// starts, which is the last moment an execution handed out could be
// abandoned before its client hears of it.
type shutter struct {
	http.ResponseWriter
	once         sync.Once
	a            *enforce.Adapter
	abandonedAt  uint64
	shutdownSeen error
}

func (s *shutter) Header() http.Header {
	s.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s.shutdownSeen = s.a.Shutdown(ctx)
		s.abandonedAt = s.a.Stats().Abandoned
	})
	return s.ResponseWriter.Header()
}

// No execution is abandoned before its EXECUTE is written: a shutdown that
// comes while the answer is being written leaves it to the request, which
// abandons it once the answer is out, so nothing is left open either.
func TestAnExecuteIsNeverAnsweredForAnExecutionAlreadyAbandoned(t *testing.T) {
	r := newRig(t, defaults())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, enforce.PathAdmit, strings.NewReader(admitBody("refund", refund)))
	req.Header.Set(enforce.RunTokenHeader, runA)
	rec := httptest.NewRecorder()
	w := &shutter{ResponseWriter: rec, a: r.a}
	r.a.Handler().ServeHTTP(w, req)
	if !errors.Is(w.shutdownSeen, enforce.ErrDraining) {
		t.Fatalf("Shutdown with the admit in flight = %v", w.shutdownSeen)
	}
	resp := outcome(t, rec.Code, rec.Body.Bytes())
	if resp.GetOutcome() == outcomeExecute && w.abandonedAt != 0 {
		t.Fatalf("EXECUTE was answered for an execution abandoned before the answer (%d abandoned)", w.abandonedAt)
	}
	if s := r.a.Stats(); s.Open != 0 || s.Abandoned != 1 || r.abandoned(t) != 1 {
		t.Fatalf("after the request: stats %+v, %d abandoned on the trail", s, r.abandoned(t))
	}
}

// shutOnWrite shuts the adapter down once the answer's body is handed to the
// connection, while the handler still runs.
type shutOnWrite struct {
	http.ResponseWriter
	once sync.Once
	a    *enforce.Adapter
}

func (s *shutOnWrite) Write(p []byte) (int, error) {
	n, err := s.ResponseWriter.Write(p)
	s.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = s.a.Shutdown(ctx) // ErrDraining: the admit writing this answer is in flight
	})
	return n, err
}

func (s *shutOnWrite) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// awaitClient holds an abandon until the client has read its answer, or a
// bound passed, and notes which came first.
type awaitClient struct {
	enforce.Pipeline
	received  chan struct{}
	heard     atomic.Bool
	abandoned chan struct{}
}

func (p *awaitClient) Abandon(ctx context.Context, d gateway.Disposition) error {
	select {
	case <-p.received:
		p.heard.Store(true)
	case <-time.After(3 * time.Second):
	}
	err := p.Pipeline.Abandon(ctx, d)
	close(p.abandoned)
	return err
}

// Over a real connection, an EXECUTE a shutdown overtakes reaches its client
// before the plane records the execution abandoned: the server would
// otherwise keep the answer buffered until the handler returned, after the
// abandon.
func TestAnExecuteReachesItsClientBeforeAShutdownAbandonsIt(t *testing.T) {
	await := &awaitClient{received: make(chan struct{}), abandoned: make(chan struct{})}
	o := defaults()
	o.pipeline = func(p enforce.Pipeline) enforce.Pipeline { await.Pipeline = p; return await }
	r := newRig(t, o)
	socket := socketPath(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.a.Handler().ServeHTTP(&shutOnWrite{ResponseWriter: w, a: r.a}, req)
	})}
	go func() { _ = srv.Serve(ln) }() // ErrServerClosed once the test closes it
	t.Cleanup(func() { _ = srv.Close() })
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://enforce"+enforce.PathAdmit, strings.NewReader(admitBody("refund", refund)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(enforce.RunTokenHeader, runA)
	resp, err := unixClient(socket).Do(req)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	close(await.received)
	if got := outcome(t, resp.StatusCode, body); got.GetOutcome() != outcomeExecute {
		t.Fatalf("outcome %s, want the EXECUTE the shutdown overtook", got.GetOutcome())
	}
	select {
	case <-await.abandoned:
	case <-time.After(10 * time.Second):
		t.Fatal("the execution was never abandoned")
	}
	if !await.heard.Load() {
		t.Fatal("the plane recorded the execution abandoned before its client had the EXECUTE")
	}
	s := r.countsWithin(settleBound, 0, 1)
	if s.Open != 0 || s.Abandoned != 1 || r.abandoned(t) != 1 {
		t.Fatalf("after the request: stats %+v, %d abandoned on the trail", s, r.abandoned(t))
	}
}

// holdFlush keeps an admit between writing its EXECUTE and opening the
// execution until released.
type holdFlush struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
}

func (h *holdFlush) Flush() {
	close(h.entered)
	<-h.release
	h.ResponseRecorder.Flush()
}

// The wait a sweeping step makes is bounded both ways: it gives up on an
// admit still writing its EXECUTE, and returns once that admit opened it.
func TestTheSettleWaitSeesAnAdmitStillWritingItsExecute(t *testing.T) {
	r := newRig(t, defaults())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, enforce.PathAdmit, strings.NewReader(admitBody("refund", refund)))
	req.Header.Set(enforce.RunTokenHeader, runA)
	w := &holdFlush{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.a.Handler().ServeHTTP(w, req)
	}()
	<-w.entered
	if n := enforce.Minting(r.a); n != 1 {
		t.Fatalf("%d minting while the EXECUTE is written, want 1", n)
	}
	if r.settledWithin(20 * time.Millisecond) {
		t.Fatal("the wait passed with an admit still writing its EXECUTE")
	}
	close(w.release)
	<-done
	if !r.settledWithin(settleBound) || enforce.Minting(r.a) != 0 {
		t.Fatal("the wait still saw an admit minting after it returned")
	}
	if n := r.a.Sweep(t.Context(), base().Add(time.Minute)); n != 1 {
		t.Fatalf("the sweep after the wait abandoned %d, want 1", n)
	}
}
