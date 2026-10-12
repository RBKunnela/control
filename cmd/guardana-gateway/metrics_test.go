package main

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/metrics"
	"github.com/guardana/control/internal/metrics/metricstest"
)

// scrape puts GET /metrics through the health mux.
func scrape(t *testing.T, p *plane) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	p.healthMux().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return recorder
}

// scraped is the answer of a plane whose every statistic can be read, by the
// strict reader.
func scraped(t *testing.T, p *plane) []metricstest.Family {
	t.Helper()
	answer := scrape(t, p)
	if answer.Code != http.StatusOK {
		t.Fatalf("/metrics answered %d", answer.Code)
	}
	media, params, err := mime.ParseMediaType(answer.Header().Get("Content-Type"))
	if err != nil || media != "text/plain" || params["version"] != "0.0.4" {
		t.Fatalf("/metrics answered content type %q", answer.Header().Get("Content-Type"))
	}
	families, err := metricstest.Parse(answer.Body.Bytes())
	if err != nil {
		t.Fatalf("the strict reader refused /metrics: %v\n%s", err, answer.Body.String())
	}
	other := "Enforce."
	if p.enforce != nil {
		other = "Adapter."
	}
	want := 0
	for _, m := range metrics.Table() {
		if !strings.HasPrefix(m.Reads, other) {
			want++
		}
	}
	if len(families) != want {
		t.Fatalf("/metrics holds %d families, want the %d rows of the table this plane's adapter writes", len(families), want)
	}
	return families
}

// value is the one sample of name under labels, as the text spells it.
func value(t *testing.T, families []metricstest.Family, name string, labels map[string]string) string {
	t.Helper()
	f, ok := metricstest.Find(families, metrics.Prefix()+name)
	if !ok {
		t.Fatalf("/metrics has no %s", name)
	}
	s, ok := f.One(labels)
	if !ok {
		t.Fatalf("%s has no sample %v: %+v", name, labels, f.Samples)
	}
	return s.Raw
}

// TestMetricsCountWhatThePlaneDid: each seam's statistics reach the text
// live, not as a copy taken at start. A read run and a read blocked by a
// pause move their counters, the pause state says why, and the spool's size
// grows by what the trails wrote.
func TestMetricsCountWhatThePlaneDid(t *testing.T) {
	tr := newTree(t)
	path := tr.withPauseFile(t, pauseClear, time.Minute)
	p := tr.plane(t)
	before := scraped(t, p)
	for name, want := range map[string]string{
		"pipeline_executed_total": "0", "pause_polls_total": "1", "pause_entries": "0", "spool_bytes": "0",
	} {
		if got := value(t, before, name, map[string]string{}); got != want {
			t.Errorf("before any call %s is %s, want %s", name, got, want)
		}
	}
	if got := value(t, before, "pause_state", map[string]string{"state": "clear"}); got != "1" {
		t.Errorf("a clear pause file reads pause_state{clear} %s", got)
	}

	d := p.pipeline.Admit(context.Background(), gateway.Admission{Envelope: readEnvelope(), Arguments: []byte(`{"id":"ord-1"}`)})
	if d.Action != core.Execute {
		t.Fatalf("the fixture policy did not allow a read: %v", d.Decision)
	}
	if err := p.pipeline.Close(context.Background(), d, []byte(`{"id":"ord-1"}`),
		&controlv1.ActionResult{Status: controlv1.ResultStatus_RESULT_STATUS_SUCCESS}); err != nil {
		t.Fatalf("closing the read: %v", err)
	}
	writePauseFile(t, path, pauseDocument(pauseEntry("all", scopeGlobal)))
	p.poller.Poll()
	paused := readEnvelope()
	paused.RequestId = "req-2"
	if d := p.pipeline.Admit(context.Background(), gateway.Admission{Envelope: paused, Arguments: []byte(`{}`)}); d.Action != core.Block {
		t.Fatalf("a global pause let a read through: %v", d.Action)
	}

	after := scraped(t, p)
	for name, want := range map[string]string{
		"pipeline_executed_total": "1", "pause_polls_total": "2", "pause_changes_total": "2", "pause_entries": "1",
	} {
		if got := value(t, after, name, map[string]string{}); got != want {
			t.Errorf("after the calls %s is %s, want %s", name, got, want)
		}
	}
	if got := value(t, after, "pipeline_blocks_total", map[string]string{"code": "PAUSED"}); got != "1" {
		t.Errorf("pipeline_blocks_total{code=PAUSED} is %s, want 1", got)
	}
	if got := value(t, after, "pause_state", map[string]string{"state": "paused"}); got != "1" {
		t.Errorf("a global pause reads pause_state{paused} %s", got)
	}
	if got := value(t, after, "spool_bytes", map[string]string{}); got == "0" {
		t.Error("two trails were written and the spool reads 0 bytes")
	}
}

// TestMetricsReportAHaltAndAStoppedExport: a halted plane and an export
// that stopped are states the text reports with 200, since both are what an
// operator scrapes for.
func TestMetricsReportAHaltAndAStoppedExport(t *testing.T) {
	p := newTree(t).plane(t)
	families := scraped(t, p)
	for _, name := range []string{"pipeline_halted", "exporter_stopped"} {
		if got := value(t, families, name, map[string]string{}); got != "0" {
			t.Errorf("a sound plane reads %s %s", name, got)
		}
	}
	if got := value(t, families, "pause_state", map[string]string{"state": "disabled"}); got != "1" {
		t.Errorf("a plane without a pause file reads pause_state{disabled} %s", got)
	}

	d := p.pipeline.Admit(context.Background(), gateway.Admission{Envelope: readEnvelope(), Arguments: []byte(`{"id":"ord-1"}`)})
	if err := p.pipeline.Close(context.Background(), d, []byte(`{"id":"ord-2"}`),
		&controlv1.ActionResult{Status: controlv1.ResultStatus_RESULT_STATUS_SUCCESS}); err == nil {
		t.Fatal("Close accepted bytes that were not the authorized ones")
	}
	stopped := errors.New("the collector went away")
	p.stopped.Store(&stopped)

	families = scraped(t, p)
	for _, name := range []string{"pipeline_halted", "exporter_stopped", "pipeline_mismatches_total"} {
		if got := value(t, families, name, map[string]string{}); got != "1" {
			t.Errorf("after the mismatch and the stop %s is %s, want 1", name, got)
		}
	}
}

// TestMetricsReportASpoolThatCannotAnswer: a plane whose spool reports an
// error still answers 200 with everything else it can read, sets
// spool_broken and leaves out the spool's metrics rather than writing them as
// zero, and keeps doing so on every later scrape.
func TestMetricsReportASpoolThatCannotAnswer(t *testing.T) {
	p := newTree(t).plane(t)
	families := scraped(t, p)
	if got := value(t, families, "spool_broken", map[string]string{}); got != "0" {
		t.Errorf("a sound spool reads spool_broken %s", got)
	}
	value(t, families, "spool_bytes", map[string]string{})
	if err := p.spool.Close(); err != nil {
		t.Fatalf("closing the spool: %v", err)
	}
	for range 2 {
		answer := scrape(t, p)
		if answer.Code != http.StatusOK || answer.Header().Get("Content-Type") != metrics.ContentType {
			t.Fatalf("a plane with no usable spool answered %d %q", answer.Code, answer.Header().Get("Content-Type"))
		}
		families, err := metricstest.Parse(answer.Body.Bytes())
		if err != nil {
			t.Fatalf("the strict reader refused /metrics: %v", err)
		}
		if got := value(t, families, "spool_broken", map[string]string{}); got != "1" {
			t.Errorf("a closed spool reads spool_broken %s", got)
		}
		for _, name := range []string{"spool_bytes", "spool_segments", "spool_unacknowledged_bytes"} {
			if _, ok := metricstest.Find(families, metrics.Prefix()+name); ok {
				t.Errorf("a closed spool still writes %s", name)
			}
		}
		for _, name := range []string{"pipeline_executed_total", "pipeline_halted", "exporter_stopped"} {
			value(t, families, name, map[string]string{})
		}
	}
}

// TestMetricsOfAServingPlane scrapes the health listener of the command's
// own serve: the adapter's call reaches its counters, and the exporter's
// acknowledgements reach the text once the collector took the trail.
func TestMetricsOfAServingPlane(t *testing.T) {
	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "export.endpoint", collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "127.0.0.1:0")
	ctx, stop := context.WithCancel(context.Background())
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	status := make(chan int, 1)
	go func() { status <- serve(ctx, tr.config, "", stdout, stderr) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-status:
		case <-time.After(15 * time.Second):
			t.Error("the plane did not stop within its bound")
		}
	})
	agentLine := waitFor(t, stdout, "listening for agents on ")
	healthLine := waitFor(t, stdout, "answering /healthz")
	agent := connectAgent(t, agentLine[strings.LastIndex(agentLine, " ")+1:])
	url := "http://" + healthLine[strings.LastIndex(healthLine, " ")+1:] + "/metrics"

	if res := callReadOrder(t, agent); res.IsError {
		t.Fatalf("the fixture's read was refused: %+v", res.StructuredContent)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		families := get(t, url)
		acked := value(t, families, "exporter_acknowledged_records_total", map[string]string{})
		if acked != "0" {
			for _, name := range []string{"adapter_admitted_total", "adapter_sent_total", "pipeline_executed_total"} {
				if got := value(t, families, name, map[string]string{}); got != "1" {
					t.Errorf("after one call %s is %s, want 1", name, got)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the exporter acknowledged nothing within its bound:\n%s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// get scrapes url over the network and reads the answer strictly.
func get(t *testing.T, url string) []metricstest.Family {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != metrics.ContentType {
		t.Fatalf("GET %s answered %d %q (%v)", url, res.StatusCode, res.Header.Get("Content-Type"), err)
	}
	families, err := metricstest.Parse(body)
	if err != nil {
		t.Fatalf("the strict reader refused the scrape: %v", err)
	}
	return families
}

// TestMetricsReadThePauseStateAsACallWould: a read older than three poll
// intervals is unknown to a call admitted now, and so to the text, which
// still answers since an unknown pause state is a state it reports.
func TestMetricsReadThePauseStateAsACallWould(t *testing.T) {
	tr := newTree(t)
	tr.withPauseFile(t, pauseClear, time.Second)
	p := tr.plane(t)
	readAt := p.poller.Current().ReadAt()
	for after, want := range map[time.Duration]string{3 * time.Second: "clear", 3*time.Second + time.Nanosecond: "unknown"} {
		text, err := p.metrics(p.pauseSource(), func() time.Time { return readAt.Add(after) })
		if err != nil {
			t.Fatalf("%v after the read: %v", after, err)
		}
		families, err := metricstest.Parse(text)
		if err != nil {
			t.Fatalf("the strict reader refused the text: %v", err)
		}
		if got := value(t, families, "pause_state", map[string]string{"state": want}); got != "1" {
			t.Errorf("%v after the read pause_state{%s} is %s, want 1", after, want, got)
		}
	}
}

func TestMetricsAnswersOnlyGet(t *testing.T) {
	p := newTree(t).plane(t)
	recorder := httptest.NewRecorder()
	p.healthMux().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics answered %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}
