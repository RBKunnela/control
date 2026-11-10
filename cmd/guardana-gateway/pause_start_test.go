package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/pause"
)

// slowUpstream is the fixture upstream behind a proxy that holds every request
// for delay, so a start that lists its tools takes several poll intervals.
func slowUpstream(t *testing.T, delay time.Duration) string {
	t.Helper()
	target, err := url.Parse(upstream(t))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestAFirstCallAfterASlowStartIsDecidedUnderAFreshRead: the start reads the
// pause file, and connecting an upstream then takes longer than the three
// intervals that read answers for. The first call is still decided under a
// read of the clear file, not blocked as unreadable.
func TestAFirstCallAfterASlowStartIsDecidedUnderAFreshRead(t *testing.T) {
	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", slowUpstream(t, 4*servePoll))
	exportTo(t, collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	tr.withPauseFile(t, pauseClear, servePoll)
	agent, _ := serveInProcess(t, tr)
	res := callReadOrder(t, agent)
	if res.IsError {
		t.Errorf("the first call under a clear, readable pause file was refused: %v", planeFields(res.Meta)["reason_codes"])
	}
}

// ticking is a clock that moves on by a tick each time it is read.
type ticking struct {
	mu  sync.Mutex
	now time.Time
}

func (c *ticking) tick() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(time.Nanosecond)
	return c.now
}

func (c *ticking) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// pollingSource polls on every read: a poll that lands between /healthz
// reading the clock and reading the state.
type pollingSource struct{ poller *pause.Poller }

func (s pollingSource) Current() pause.Snapshot { return s.poller.Poll() }

// TestHealthTakesTheStateBeforeTheClock: a read published just before the
// answer reads the clock is never dated ahead of it.
func TestHealthTakesTheStateBeforeTheClock(t *testing.T) {
	tr := newTree(t)
	path := tr.withPauseFile(t, pauseClear, time.Second)
	p := tr.plane(t)
	clock := &ticking{now: time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)}
	poller, err := pause.Open(pause.Options{Path: path, Interval: time.Second, Clock: clock.tick})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		answer, ok := p.health(pollingSource{poller}, clock.read)
		if !ok || answer.Pause.State != "clear" {
			t.Errorf("a clear state read just now answers %v, pause %+v", ok, answer.Pause)
		}
	}
}

// Scopes of tools the fixture upstream orders does and does not list.
const (
	scopeListedTool   = `{"kind":"action","action":"tool","provider":"orders","name":"read_order"}`
	scopeUnlistedTool = `{"kind":"action","action":"tool","provider":"orders","name":"refund_order"}`
)

// TestAnEntryNamingAnUnlistedToolIsNamed: once the upstreams answered, an
// entry naming a tool its upstream does not list is named by doctor, by
// /healthz and in the plane's log at warn, beside one naming an upstream the
// configuration lacks. An entry naming a listed tool is not.
func TestAnEntryNamingAnUnlistedToolIsNamed(t *testing.T) {
	document := pauseDocument(pauseEntry("listed", scopeListedTool), pauseEntry("unlisted", scopeUnlistedTool),
		pauseEntry("billing", scopeElsewhere))

	t.Run("doctor", func(t *testing.T) {
		tr := newTree(t)
		setEnv(t, "upstreams.0.endpoint", upstream(t))
		tr.withPauseFile(t, document, time.Second)
		var stdout, stderr bytes.Buffer
		doctor(context.Background(), tr.config, &stdout, &stderr)
		out := tr.output(stdout.String())
		want := `       pause entry unlisted names tool "refund_order", which upstream "orders" does not list: ` +
			"it pauses only calls to that name that carry no provider, which are calls when no upstream lists it\n"
		if !strings.Contains(out, want) || strings.Contains(out, "pause entry listed ") {
			t.Errorf("doctor does not name the unlisted tool alone:\n%s", out)
		}
		if line := reportLine(out, "upstreams"); !strings.HasSuffix(line, "; 1 pause entry(ies) name a tool its upstream does not list") {
			t.Errorf("the upstreams line is %q", line)
		}
	})

	t.Run("healthz", func(t *testing.T) {
		tr := newTree(t)
		setEnv(t, "upstreams.0.endpoint", upstream(t))
		tr.withPauseFile(t, document, time.Second)
		p := tr.plane(t)
		at := p.poller.Current().ReadAt()
		_, body := p.healthAt(at)
		if unlisted, _ := pauseMember(t, body)["unlisted_only"].([]any); !slices.Equal(unlisted, []any{"billing"}) {
			t.Errorf("before the upstreams answered, unlisted_only = %v; want the upstream alone", unlisted)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := p.startUpstreams(ctx); err != nil {
			t.Fatalf("startUpstreams: %v", err)
		}
		_, body = p.healthAt(at)
		if unlisted, _ := pauseMember(t, body)["unlisted_only"].([]any); !slices.Equal(unlisted, []any{"unlisted", "billing"}) {
			t.Errorf("unlisted_only = %v, want [unlisted billing]", unlisted)
		}
	})

	t.Run("log", func(t *testing.T) {
		tr := newTree(t)
		collector := newAcceptingCollector(t)
		setEnv(t, "upstreams.0.endpoint", upstream(t))
		exportTo(t, collector.url)
		setEnv(t, "listener.address", "127.0.0.1:0")
		setEnv(t, "health.address", "")
		path := tr.withPauseFile(t, document, servePoll)
		_, stderr := serveInProcess(t, tr)
		if warned := lastWarning(stderr.String()); !strings.Contains(warned, "unlisted_only=\"[unlisted billing]\"") {
			t.Errorf("the plane did not warn at start naming both entries:\n%s", stderr.String())
		}
		later := pause.Entry{
			ID: "later", CreatedAt: time.Now(),
			Scope: pause.Scope{Kind: pause.ScopeAction, Action: pause.ActionTool, Provider: "orders", Name: "void_order"},
		}
		changes := strings.Count(stderr.String(), "pause state changed")
		if err := pause.Add(context.Background(), path, later); err != nil {
			t.Fatalf("Add: %v", err)
		}
		waitForChange(t, stderr, changes+1, "added=[later]")
		if warned := lastWarning(stderr.String()); !strings.Contains(warned, "pause state changed") ||
			!strings.Contains(warned, "unlisted_only=\"[unlisted billing later]\"") {
			t.Errorf("the change did not warn naming the three entries:\n%s", stderr.String())
		}
	})
}

// lastWarning is the last line logged at warn that names unlisted_only.
func lastWarning(log string) string {
	var warned string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "unlisted_only=") {
			warned = line
		}
	}
	return warned
}

// pollsAtListen records how many reads the poller had made when the plane
// said it listens, which it says before any goroutine of run starts.
type pollsAtListen struct {
	mu     sync.Mutex
	poller *pause.Poller
	polls  uint64
	said   bool
}

func (w *pollsAtListen) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.said && strings.Contains(string(b), "listening for agents on ") {
		w.polls, w.said = w.poller.Stats().Polls, true
	}
	return len(b), nil
}

// TestRunReadsThePauseFileBeforeItListens: the start's read is the first, and
// run reads once more before it binds, so no call is admitted under the
// start's read alone.
func TestRunReadsThePauseFileBeforeItListens(t *testing.T) {
	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	exportTo(t, collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	tr.withPauseFile(t, pauseClear, time.Minute)
	p := tr.plane(t)
	ctx, cancel := context.WithCancel(context.Background())
	if err := p.startUpstreams(ctx); err != nil {
		t.Fatalf("startUpstreams: %v", err)
	}
	w := &pollsAtListen{poller: p.poller}
	done := make(chan error, 1)
	go func() { done <- p.run(ctx, w, listenTCP, 0) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		w.mu.Lock()
		said, polls := w.said, w.polls
		w.mu.Unlock()
		if said {
			if polls != 2 {
				t.Errorf("the plane listened after %d read(s) of the pause file, want the start's and one more", polls)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the plane never said it listens")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("run: %v", err)
	}
}
