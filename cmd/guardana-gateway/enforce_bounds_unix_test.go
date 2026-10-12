//go:build unix

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// servedEnforcer builds the enforcement API plane of tr to serve and starts
// its adapter, without binding the socket.
func servedEnforcer(t *testing.T, tr enforceTree) *plane {
	t.Helper()
	p, err := build(loadEnforce(t, tr), slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.close() })
	if err := p.enforce.Start(p.pipeline); err != nil {
		t.Fatal(err)
	}
	return p
}

// operate posts body to path through the adapter's handler under token.
func operate(t *testing.T, p *plane, token, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(enforce.RunTokenHeader, token)
	rec := httptest.NewRecorder()
	p.enforce.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// admitBody is an admit of tool with args, padded to pad more bytes.
func admitBody(tool, args string, pad int) string {
	return `{"tool":"` + tool + `","arguments":"` + base64.StdEncoding.EncodeToString([]byte(args)) + `"` +
		strings.Repeat(" ", pad) + `}`
}

// executedHandle admits tool with args and returns the handle it was
// handed.
func executedHandle(t *testing.T, p *plane, token, tool, args string) string {
	t.Helper()
	status, body := operate(t, p, token, enforce.PathAdmit, admitBody(tool, args, 0))
	resp := &enforcev1alpha1.AdmitResponse{}
	if status != http.StatusOK || protojson.Unmarshal([]byte(body), resp) != nil || resp.GetOutcome() != enforcev1alpha1.Outcome_OUTCOME_EXECUTE {
		t.Fatalf("admit %s: %d %s", tool, status, body)
	}
	return resp.GetExecution().GetHandle()
}

func TestSweepEveryIsAQuarterOfTheLifetimeAndAtMostASecond(t *testing.T) {
	for lifetime, want := range map[time.Duration]time.Duration{
		time.Second:     250 * time.Millisecond,
		2 * time.Second: 500 * time.Millisecond,
		4 * time.Second: time.Second,
		5 * time.Second: time.Second,
		time.Hour:       time.Second,
	} {
		if got := sweepEvery(lifetime); got != want {
			t.Errorf("sweepEvery(%v) = %v, want %v", lifetime, got, want)
		}
	}
}

// TestTheListenerBoundsReachTheAdapter: listener.max_open_per_run and
// listener.max_body_bytes, at values that are not the adapter's defaults,
// are the bounds the plane's adapter holds a request to.
func TestTheListenerBoundsReachTheAdapter(t *testing.T) {
	tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
	setEnv(t, "listener.max_open_per_run", "1")
	setEnv(t, "listener.max_body_bytes", "1024")
	p := servedEnforcer(t, tr)
	runA, runB := tr.openRun(t), tr.openRun(t)

	executedHandle(t, p, runA, enforceRead, `{"id":"1"}`)
	if status, body := operate(t, p, runA, enforce.PathAdmit, admitBody(enforceRead, `{"id":"2"}`, 0)); !strings.Contains(body, "ERROR_CODE_UNAVAILABLE") {
		t.Errorf("a second open execution of a run bound to one answered %d %s", status, body)
	}

	small := admitBody(enforceRead, `{"id":"3"}`, 0)
	if status, body := operate(t, p, runB, enforce.PathAdmit, admitBody(enforceRead, `{"id":"3"}`, 1025-len(small))); !strings.Contains(body, "ERROR_CODE_MALFORMED") {
		t.Errorf("a body of 1025 bytes under a bound of 1024 answered %d %s", status, body)
	}
	if status, body := operate(t, p, runB, enforce.PathAdmit, admitBody(enforceRead, `{"id":"3"}`, 1024-len(small))); !strings.Contains(body, "OUTCOME_EXECUTE") {
		t.Errorf("a body of 1024 bytes under a bound of 1024 answered %d %s", status, body)
	}
}

// failingSink refuses every append once failing is set.
type failingSink struct {
	evidence.Sink
	failing atomic.Bool
}

func (s *failingSink) Append(ctx context.Context, e *controlv1.Event) error {
	if s.failing.Load() {
		return errors.New("sink: refused")
	}
	return s.Sink.Append(ctx, e)
}

// TestALostCompletionAndALostAbortAreBothLost: once the sink refuses, a
// completion and a client's abort each leave a trail open, and each is an
// error of lostClosings, which makes run exit 1.
func TestALostCompletionAndALostAbortAreBothLost(t *testing.T) {
	tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
	p, err := build(loadEnforce(t, tr), slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.close() })
	mode, err := p.cfg.Mode()
	if err != nil {
		t.Fatal(err)
	}
	sink := &failingSink{Sink: p.spool}
	cfg := p.pipelineConfig(p.enforce, mode, p.pdp)
	cfg.Sink = sink
	if p.pipeline, err = gateway.New(cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.enforce.Start(p.pipeline); err != nil {
		t.Fatal(err)
	}
	token := tr.openRun(t)
	completed := executedHandle(t, p, token, enforceNote, `{"id":"n1"}`)
	aborted := executedHandle(t, p, token, enforceNote, `{"id":"n2"}`)
	if err := p.lostClosings(); err != nil {
		t.Fatalf("before the sink refused: %v", err)
	}
	sink.failing.Store(true)

	sent := base64.StdEncoding.EncodeToString([]byte(`{"id":"n1"}`))
	if _, body := operate(t, p, token, enforce.PathComplete, `{"handle":"`+completed+`","sentArguments":"`+sent+`","status":"COMPLETION_STATUS_SUCCESS"}`); !strings.Contains(body, "ENDING_RECORD_FAILED") {
		t.Fatalf("complete answered %s", body)
	}
	if err := p.lostClosings(); err == nil || !strings.Contains(err.Error(), "1 call(s)") {
		t.Errorf("after a lost completion lostClosings = %v, want one lost call", err)
	}
	if _, body := operate(t, p, token, enforce.PathAbort, `{"handle":"`+aborted+`","cause":"ABORT_CAUSE_NOT_SENT"}`); !strings.Contains(body, "ENDING_RECORD_FAILED") {
		t.Fatalf("abort answered %s", body)
	}
	if err := p.lostClosings(); err == nil || !strings.Contains(err.Error(), "1 call(s)") {
		t.Errorf("after a lost abort lostClosings = %v, want one lost call", err)
	}
}
