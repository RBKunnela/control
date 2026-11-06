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

const (
	tcpWarning       = "warning: TCP export goes in 0.17; export.endpoint: unix:///path with export.collector_uid sends the credential only to the collector's account" //nolint:gosec // G101: a warning's text, which holds no credential
	plaintextWarning = ", and a plaintext TCP collector hands it to whoever holds "
)

// TestDoctorWarnsOfATCPCollector: a plaintext loopback endpoint and an
// https one are warned of, naming the unix form, the plaintext one with its
// port; a unix endpoint is not, and its line names the socket and the
// account the credential goes to.
func TestDoctorWarnsOfATCPCollector(t *testing.T) {
	var stdout, stderr bytes.Buffer
	doctor(context.Background(), newTree(t).config, &stdout, &stderr)
	if out := stdout.String(); !strings.Contains(out, tcpWarning+plaintextWarning+"127.0.0.1:4318 while it is down") {
		t.Errorf("doctor does not warn of the plaintext collector:\n%s", out)
	}

	secure := newTree(t)
	setEnv(t, "export.endpoint", "https://collector.example/v1/logs")
	setEnv(t, "export.allow_plaintext", "false")
	stdout.Reset()
	doctor(context.Background(), secure.config, &stdout, &stderr)
	if out := stdout.String(); !strings.Contains(out, tcpWarning+"\n") || strings.Contains(out, plaintextWarning) ||
		!strings.Contains(reportLine(out, "export"), "https://collector.example") {
		t.Errorf("doctor over an https collector:\n%s", out)
	}

	tr := newTree(t)
	setEnv(t, "export.endpoint", "unix:///run/collector/logs.sock")
	setEnv(t, "export.allow_plaintext", "false")
	setEnv(t, "export.collector_uid", "4242")
	stdout.Reset()
	doctor(context.Background(), tr.config, &stdout, &stderr)
	out := stdout.String()
	if strings.Contains(out, "warning: TCP export") {
		t.Errorf("doctor warns of a unix collector:\n%s", out)
	}
	if line := reportLine(out, "export"); !strings.HasPrefix(line, "ok ") ||
		!strings.Contains(line, "to the unix socket /run/collector/logs.sock, sent only to a collector running as uid 4242") {
		t.Errorf("the export line is %q", line)
	}
	if line := reportLine(out, "seams"); !strings.HasPrefix(line, "ok ") {
		t.Errorf("the seams line over a unix collector is %q", line)
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
	setEnv(t, "export.allow_plaintext", "false")
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
