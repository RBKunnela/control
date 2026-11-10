package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/spool"
	"github.com/guardana/control/internal/trailfile"
)

const denyMail = `{"id":"deny-mail","effect":"DENY","when":{"action":{"effect":["COMMUNICATE"]}}}`

// collectorToken is the credential the collectors under test require and
// the exporters under test send.
var collectorToken = strings.Repeat("e", otel.MinCredentialBytes)

// collectorTLS is the certificate httptest serves with and a client that
// trusts it: a plane exports over no plaintext, so the collectors here serve
// TLS.
var collectorTLS = sync.OnceValues(func() (*tls.Config, *http.Client) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	defer srv.Close()
	return srv.TLS.Clone(), srv.Client()
})

// fileCollector is the collector this repository ships, in-process: the OTLP
// receiver over a trail file, on a loopback port over TLS.
type fileCollector struct {
	addr string
	srv  *http.Server
	w    io.Closer
}

func startFileCollector(t *testing.T, path, addr string) *fileCollector {
	t.Helper()
	w, err := trailfile.Open(path)
	if err != nil {
		t.Fatalf("trailfile.Open: %v", err)
	}
	return serveCollector(t, w, w, addr)
}

// serveCollector serves the OTLP receiver over sink on addr, requiring the
// credential, and closes the listener, every connection and then w.
func serveCollector(t *testing.T, sink otel.Sink, w io.Closer, addr string) *fileCollector {
	t.Helper()
	cred, err := otel.NewCredential(collectorToken)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := otel.NewReceiver(sink, slog.New(slog.DiscardHandler), cred)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		_ = w.Close()
		t.Fatalf("listening on %s: %v", addr, err)
	}
	config, _ := collectorTLS()
	ln := tls.NewListener(raw, config)
	mux := http.NewServeMux()
	mux.Handle("/v1/logs", receiver)
	c := &fileCollector{addr: ln.Addr().String(), srv: &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}, w: w}
	go func() { _ = c.srv.Serve(ln) }()
	t.Cleanup(c.stop)
	return c
}

func (c *fileCollector) url() string { return "https://" + c.addr + "/v1/logs" }

// stop closes the listener and every connection, then the file.
func (c *fileCollector) stop() {
	_ = c.srv.Close()
	_ = c.w.Close()
}

// exportTo starts the plane's real exporter over its spool toward url,
// sending the collector's credential.
func exportTo(t *testing.T, p *plane, url string) *otel.Exporter {
	t.Helper()
	return exportWith(t, p, url, "Bearer "+collectorToken)
}

// exportWith starts the plane's real exporter over its spool toward url,
// sending authorization as its Authorization header.
func exportWith(t *testing.T, p *plane, url, authorization string) *otel.Exporter {
	t.Helper()
	reader, err := p.spool.Reader(spool.Cursor{})
	if err != nil {
		t.Fatalf("spool.Reader: %v", err)
	}
	_, client := collectorTLS()
	exporter, err := otel.New(otel.Options{
		Endpoint: url, Client: client, InFlight: 2, Timeout: 2 * time.Second, MaxBatch: 8,
		Linger: 10 * time.Millisecond, Backoff: 20 * time.Millisecond, MaxBackoff: 40 * time.Millisecond,
		Logger: slog.New(slog.DiscardHandler), Headers: map[string]string{"Authorization": authorization},
	}, reader)
	if err != nil {
		t.Fatalf("otel.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exporter.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the exporter stopped with %v", err)
		}
		_ = reader.Close()
	})
	return exporter
}

// fileEvents counts, by event id, the events the trail file holds.
func fileEvents(t *testing.T, path string) map[string]int {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own trail file
	if err != nil {
		t.Fatal(err)
	}
	// A line the collector is still writing is not read, as the trail reader
	// does not read it.
	raw = raw[:bytes.LastIndexByte(raw, '\n')+1]
	events, err := evidence.DecodeJSONL(bytes.NewReader(raw), 10_000)
	if err != nil {
		t.Fatalf("the trail file does not decode: %v", err)
	}
	ids := map[string]int{}
	for _, ev := range events {
		ids[ev.GetEventId()]++
	}
	return ids
}

// everyEventOnce reports whether the file holds each recorded event once and
// nothing else.
func everyEventOnce(t *testing.T, path string, recorded []*controlv1.Event) bool {
	t.Helper()
	ids := fileEvents(t, path)
	if len(ids) != len(recorded) {
		return false
	}
	for _, ev := range recorded {
		if ids[ev.GetEventId()] != 1 {
			return false
		}
	}
	return true
}

// TestAPlaneExportsToTheCollectorItShips: a plane exporting to the collector,
// one call of each outcome, and every trail in the file whole or still open;
// the collector stopped, the spool reaching its budget and a material call
// blocked; the collector back on the same file, and every record in it once.
func TestAPlaneExportsToTheCollectorItShips(t *testing.T) {
	p := newPlane(t, options{
		kind: mcp.KindStatelessHTTP, mode: modeEnforce,
		rules:      []string{allowReads, allowDeletes, denyMail, approveTransfers},
		spoolBytes: spoolBudget, closingReserve: closingBytes, noExport: true,
		callTimeout: 300 * time.Millisecond,
	})
	path := filepath.Join(t.TempDir(), "trail.jsonl")
	c := startFileCollector(t, path, "127.0.0.1:0")
	exporter := exportTo(t, p, c.url())
	agent := p.connect(t, "agent-a")

	callEachOutcome(t, agent)
	recorded := p.sink.events()
	eventually(t, func() bool { return everyEventOnce(t, path, recorded) })
	if rep, verdicts := verdictsOf(t, path); len(rep.Trails) != 5 || verdicts[trailfile.Passed] != 4 || verdicts[trailfile.StillOpen] != 1 {
		t.Fatalf("the file's trails: %+v", rep.Trails)
	}
	eventually(t, func() bool { return exporter.Stats().Acknowledged == uint64(len(recorded)) })

	// The collector stops with nothing in flight, so nothing it wrote goes
	// unanswered.
	c.stop()
	fillUntilBlocked(t, p, agent)
	if st := exporter.Stats(); st.RetriedTransport == 0 || st.Acknowledged != uint64(len(recorded)) {
		t.Fatalf("while the collector was stopped the exporter reports %+v", st)
	}

	startFileCollector(t, path, c.addr)
	recorded = p.sink.events()
	eventually(t, func() bool { return everyEventOnce(t, path, recorded) })
	eventually(t, func() bool { return exporter.Stats().Acknowledged == uint64(len(recorded)) })
	rep, verdicts := verdictsOf(t, path)
	if rep.Duplicates != 0 || rep.Lines != len(recorded) {
		t.Errorf("the file holds %d lines and %d repeats for %d records", rep.Lines, rep.Duplicates, len(recorded))
	}
	if verdicts[trailfile.Failed]+verdicts[trailfile.Indeterminate] != 0 {
		t.Errorf("the file's trails: %+v", rep.Trails)
	}
	if st, err := p.spool.Stats(); err != nil || st.Unacknowledged != 0 {
		t.Errorf("the spool still holds %+v, %v", st, err)
	}
}

// callEachOutcome makes one call that completes, one material call that
// completes, one denied, one held for an approval and one the upstream never
// answers.
func callEachOutcome(t *testing.T, agent *sdk.ClientSession) {
	t.Helper()
	allowed(t, agent, toolRead, map[string]any{"path": "/r"})
	allowed(t, agent, toolDelete, map[string]any{"path": "/d"})
	blockedWith(t, call(t, agent, toolMail, map[string]any{"to": "x@example.com"}), codeRuleDeny)
	expectPending(t, call(t, agent, toolTransfer, map[string]any{"account": "a1", "amount": 250}))
	if res, err := callTool(t, agent, toolSlow, map[string]any{"path": "/s"}); err == nil {
		t.Fatalf("a call the upstream never answered came back as %+v", res)
	}
}

// fillUntilBlocked makes material calls until one is blocked with
// EVIDENCE_UNAVAILABLE, and checks the blocked one never reached the upstream.
func fillUntilBlocked(t *testing.T, p *plane, agent *sdk.ClientSession) {
	t.Helper()
	ran := p.victim.count(toolDelete)
	for i := range fillBound {
		res := call(t, agent, toolDelete, map[string]any{"path": "/fill" + strconv.Itoa(i)})
		if !res.IsError {
			ran++
			continue
		}
		blockedWith(t, res, codeEvidenceUnavailable)
		if n := p.victim.count(toolDelete); n != ran {
			t.Fatalf("the upstream ran %d deletes, want %d: the blocked call ran", n, ran)
		}
		return
	}
	t.Fatalf("%d calls did not reach the budget of %d bytes", fillBound, spoolBudget)
}

// verdictsOf reads the trail file as the trail command does, and counts its
// trails by verdict.
func verdictsOf(t *testing.T, path string) (trailfile.Report, map[trailfile.Verdict]int) {
	t.Helper()
	rep, err := trailfile.ReadFile(path, trailfile.DefaultMaxLines)
	if err != nil {
		t.Fatalf("reading the trail file: %v", err)
	}
	verdicts := map[trailfile.Verdict]int{}
	for _, tr := range rep.Trails {
		verdicts[tr.Verdict]++
	}
	return rep, verdicts
}
