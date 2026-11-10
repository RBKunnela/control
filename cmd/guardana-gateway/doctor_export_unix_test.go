//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// TestDoctorNamesTheCollectorItExportsTo: an https endpoint's line names it
// and TLS, a unix endpoint's names the socket and the account the credential
// goes to, neither carries a warning, and an http endpoint is refused before
// doctor reads anything else, naming the release that removed it.
func TestDoctorNamesTheCollectorItExportsTo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	doctor(context.Background(), newTree(t).config, &stdout, &stderr)
	out := stdout.String()
	if line := reportLine(out, "export"); !strings.HasPrefix(line, "ok ") ||
		!strings.Contains(line, "over TLS to https://127.0.0.1:4318/v1/logs") || strings.Contains(out, "warning: TCP") {
		t.Errorf("doctor over an https collector:\n%s", out)
	}

	tr := newTree(t)
	setEnv(t, "export.endpoint", "unix:///run/collector/logs.sock")
	setEnv(t, "export.collector_uid", "4242")
	stdout.Reset()
	doctor(context.Background(), tr.config, &stdout, &stderr)
	out = stdout.String()
	if strings.Contains(out, "warning: TCP") {
		t.Errorf("doctor warns of a unix collector:\n%s", out)
	}
	if line := reportLine(out, "export"); !strings.HasPrefix(line, "ok ") ||
		!strings.Contains(line, "to the unix socket /run/collector/logs.sock, sent only to a collector running as uid 4242") {
		t.Errorf("the export line is %q", line)
	}
	if line := reportLine(out, "seams"); !strings.HasPrefix(line, "ok ") {
		t.Errorf("the seams line over a unix collector is %q", line)
	}

	plain := newTree(t)
	setEnv(t, "export.endpoint", "http://127.0.0.1:4318/v1/logs")
	stdout.Reset()
	stderr.Reset()
	status := doctor(context.Background(), plain.config, &stdout, &stderr)
	if both := stdout.String() + stderr.String(); status == exitOK || !strings.Contains(both, "plaintext export was removed in 0.17") {
		t.Errorf("doctor over an http collector answered %d:\n%s", status, both)
	}
}

// TestAPlaneExportsToACollectorOnASocket: a plane configured with a unix
// endpoint and this account as the collector's delivers its records to
// collect on that socket, which keeps them.
func TestAPlaneExportsToACollectorOnASocket(t *testing.T) {
	socket := shortSocketPath(t)
	out := filepath.Join(t.TempDir(), "trail")
	c := startUnixCollect(t, socket, out, "acme", "orders")
	defer c.stop(t)
	tr := newTree(t)
	setEnv(t, "export.endpoint", "unix://"+socket)
	setEnv(t, "export.collector_uid", strconv.Itoa(os.Geteuid()))
	setEnv(t, "export.headers.Authorization", "Bearer "+collectToken)
	p := tr.plane(t)
	if d := p.pipeline.Admit(context.Background(), gateway.Admission{Envelope: readEnvelope(), Arguments: []byte(`{"id":"ord-1"}`)}); d.Action != core.Execute {
		t.Fatalf("the fixture policy did not allow a read: %v", d.Decision)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.exporter.Run(ctx) }()
	for p.exporter.Stats().Acknowledged == 0 && ctx.Err() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run = %v", err)
	}
	if st := p.exporter.Stats(); st.Acknowledged == 0 || st.Quarantined != 0 || st.RetriedPeer != 0 {
		t.Fatalf("the exporter counted %+v", st)
	}
	if got := liveSegment(t, out); !bytes.Contains(got, []byte("ACTION_PROPOSED")) {
		t.Errorf("the trail holds %q", got)
	}
}
