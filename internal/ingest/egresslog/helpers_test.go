package egresslog_test

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/observe"
)

const descSHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

var received = time.Date(2026, 10, 4, 10, 5, 0, 0, time.UTC)

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS("testdata"), name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return b
}

// loadDescriptor reads a descriptor the way a caller of this package does:
// the neutral checks, then this kind's.
func loadDescriptor(t testing.TB, name string) *observev1.SourceDescriptor {
	t.Helper()
	d, err := observe.ReadNeutral(readTestdata(t, name))
	if err != nil {
		t.Fatalf("%s: ReadNeutral: %v", name, err)
	}
	if err := egresslog.Check(d); err != nil {
		t.Fatalf("%s: Check: %v", name, err)
	}
	return d
}

// envoy is the descriptor of an Envoy TLS listener, whose destination is the
// SNI host alone: the importer's rules are tested under it, and the
// authority form beside it.
func envoy(t testing.TB) *observev1.SourceDescriptor {
	t.Helper()
	return loadDescriptor(t, "envoy-sni.descriptor.json")
}

// forwardProxy is the descriptor of an Envoy forward proxy, whose destination
// is the request's authority.
func forwardProxy(t testing.TB) *observev1.SourceDescriptor {
	t.Helper()
	return loadDescriptor(t, "envoy.descriptor.json")
}

func importBytes(t testing.TB, in []byte, desc *observev1.SourceDescriptor) egresslog.Batch {
	t.Helper()
	b, err := egresslog.Import(bytes.NewReader(in), desc, descSHA, received)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	checkBatch(t, in, b)
	return b
}

// checkBatch holds a batch to what every import owes: each record is one the
// log's codec writes, which recomputes a connection's id from its content,
// and every complete line of the input lands in exactly one of observed and
// refused, the refusals summing by reason.
func checkBatch(t testing.TB, in []byte, b egresslog.Batch) {
	t.Helper()
	if b.Report == nil {
		t.Fatal("no report")
	}
	for i, o := range b.Observations {
		if _, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_Observation{Observation: o}}); err != nil {
			t.Fatalf("observation %d: %v", i, err)
		}
	}
	if _, err := observe.MarshalLine(&observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: b.Report}}); err != nil {
		t.Fatalf("report: %v", err)
	}
	c := b.Report.GetCounts()
	var lines uint64
	for _, c := range in {
		if c == '\n' {
			lines++
		}
	}
	var refused uint64
	for _, n := range c.GetRefusedBy() {
		refused += n
	}
	switch {
	case c.GetRead() != lines:
		t.Fatalf("read %d, the input holds %d complete lines", c.GetRead(), lines)
	case c.GetObserved()+c.GetRefused() != c.GetRead():
		t.Fatalf("observed %d + refused %d != read %d", c.GetObserved(), c.GetRefused(), c.GetRead())
	case refused != c.GetRefused():
		t.Fatalf("refused_by sums to %d, refused %d", refused, c.GetRefused())
	case uint64(len(b.Observations)) != c.GetObserved():
		t.Fatalf("%d observations, observed %d", len(b.Observations), c.GetObserved())
	}
}

// member is one member of an Envoy line: its name and its value as JSON.
type member struct{ name, raw string }

// envoyBase is a line as envoy-sni.descriptor.json maps it, member by member.
var envoyBase = []member{
	{"start_time", `"2026-10-04T10:00:00.250Z"`},
	{"server_name", `"api.example.com"`},
	{"upstream_remote_port", `443`},
	{"method", `"CONNECT"`},
	{"response_code", `200`},
	{"bytes_sent", `52011`},
	{"bytes_received", `1834`},
	{"downstream_remote_address", `"10.0.0.7"`},
}

// envoyLine is envoyBase with name's value replaced by raw, or the member
// left out when raw is "", and a newline.
func envoyLine(name, raw string) string {
	parts := make([]string, 0, len(envoyBase))
	for _, m := range envoyBase {
		v := m.raw
		if m.name == name {
			if raw == "" {
				continue
			}
			v = raw
		}
		parts = append(parts, `"`+m.name+`":`+v)
	}
	return "{" + strings.Join(parts, ",") + "}\n"
}

// one imports a single line under the Envoy TLS listener's descriptor.
func one(t *testing.T, line string) egresslog.Batch {
	t.Helper()
	return importBytes(t, []byte(line), envoy(t))
}

// refusedFor names the one reason a single-line batch was refused for, or "".
func refusedFor(t *testing.T, b egresslog.Batch) string {
	t.Helper()
	by := b.Report.GetCounts().GetRefusedBy()
	if len(by) > 1 {
		t.Fatalf("refused for more than one reason: %v", by)
	}
	for reason := range by {
		return reason
	}
	return ""
}

// conn is what a test reads of one connection observation.
type conn struct {
	host, method, caller string
	port, status         uint32
	sent, received       uint64
	basis                observev1.CallerBasis
	at                   string
}

func connOf(o *observev1.Observation) conn {
	c := o.GetConnection()
	return conn{
		host: o.GetSubject().GetName(), method: c.GetMethod(), caller: c.GetCaller(),
		port: c.GetPort(), status: c.GetHttpStatus(), sent: c.GetBytesSent(), received: c.GetBytesReceived(),
		basis: c.GetCallerBasis(), at: o.GetEventTime().AsTime().UTC().Format(time.RFC3339Nano),
	}
}

// only returns the one observation a batch holds.
func only(t *testing.T, b egresslog.Batch) conn {
	t.Helper()
	if len(b.Observations) != 1 {
		t.Fatalf("%d observations, want 1; counts %v", len(b.Observations), b.Report.GetCounts())
	}
	return connOf(b.Observations[0])
}
