//go:build twoaccounts && unix

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/spool"
)

// exportCredential is the header value the exporter sends a collector.
const exportCredential = "Bearer two-account-export-fixture" //nolint:gosec // G101: a fixture, no credential of any system

// TestTheExportSocketSendsOnlyToTheCollectorsAccount: an exporter run as
// root over a unix endpoint whose export.collector_uid names the other
// account connects to a collector the third account runs and sends it not a
// byte, the credential included, and the records stay in the spool; a
// collector the other account runs receives every record with the
// credential.
func TestTheExportSocketSendsOnlyToTheCollectorsAccount(t *testing.T) {
	other, third := twoAccounts(t)

	wrong, wrongSocket := collectorAs(t, third)
	e, s := exporterTo(t, wrongSocket, other.uid, 2)
	runExporter(t, e, func() bool { return e.Stats().RetriedPeer >= 2 })
	if strings.Contains(wrong.String(), "request ") || !strings.Contains(wrong.String(), "connection") {
		t.Errorf("the third account's collector saw %q; want connections and no request", wrong.String())
	}
	if st, err := s.Stats(); err != nil || st.Unacknowledged == 0 {
		t.Errorf("the spool after a refused collector holds %+v, %v; want its records unacknowledged", st, err)
	}
	if st := e.Stats(); st.Acknowledged != 0 {
		t.Errorf("the exporter counted %d acknowledged by the third account's collector", st.Acknowledged)
	}

	right, rightSocket := collectorAs(t, other)
	e, _ = exporterTo(t, rightSocket, other.uid, 2)
	runExporter(t, e, func() bool { return e.Stats().Acknowledged == 2 })
	if !strings.Contains(right.String(), "request "+otel.UnixLogsPath+" "+exportCredential+"\n") {
		t.Errorf("the other account's collector saw %q; want the records with the credential", right.String())
	}
	if st := e.Stats(); st.RetriedPeer != 0 {
		t.Errorf("the exporter refused the collector's account %d times", st.RetriedPeer)
	}
}

// collectorAs starts a collector as a on a socket in a directory a owns,
// and returns its output and the socket's path.
func collectorAs(t *testing.T, a account) (*lockedBuffer, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ex")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	chownTo(t, dir, a)
	setMode(t, dir, 0o755)
	socket := filepath.Join(dir, "c.sock")
	return a.startAs(t, "collector", socket, "listening"), socket
}

// exporterTo is an exporter of a new spool holding n records to the socket,
// sending the credential only to a collector running as uid.
func exporterTo(t *testing.T, socket string, uid uint32, n int) (*otel.Exporter, *spool.Spool) {
	t.Helper()
	s, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 1; i <= n; i++ {
		if err := s.Append(context.Background(), &controlv1.Event{
			EventId: "evt-" + strconv.Itoa(i), Kind: controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED,
			RequestId: "req-1", SchemaVersion: evidence.SchemaVersion,
		}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Reader(spool.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := otel.New(otel.Options{
		Endpoint: "unix://" + socket, CollectorUID: &uid, InFlight: 1, Timeout: 2 * time.Second,
		Backoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond,
		Headers: map[string]string{"Authorization": exportCredential},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, r)
	if err != nil {
		t.Fatal(err)
	}
	return e, s
}

// runExporter runs e until cond holds, for ten seconds at most.
func runExporter(t *testing.T, e *otel.Exporter, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Errorf("the condition did not hold within 10s: %+v", e.Stats())
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run = %v", err)
	}
}
