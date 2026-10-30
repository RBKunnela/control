package egresslog_test

import (
	"maps"
	"slices"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
)

const (
	address       = observev1.CallerBasis_CALLER_BASIS_ADDRESS
	authenticated = observev1.CallerBasis_CALLER_BASIS_AUTHENTICATED
	none          = observev1.CallerBasis_CALLER_BASIS_NONE
)

// The forward proxy's lines name an authority: its port is taken when the
// port member is null, a plain HTTP request's host alone takes the port
// member's, and a port the authority contradicts is refused as a port.
func TestEnvoyFixture(t *testing.T) {
	b := importBytes(t, readTestdata(t, "envoy.jsonl"), forwardProxy(t))
	want := []conn{
		{host: "api.example.com", port: 443, method: "CONNECT", status: 200, sent: 52011, received: 1834,
			caller: "10.0.0.7", basis: address, at: "2026-10-04T10:00:00.25Z"},
		{host: "2001:db8::1", port: 8443, method: "CONNECT", status: 503, sent: 91,
			caller: "10.0.0.8", basis: address, at: "2026-10-04T10:00:01.5Z"},
		{host: "registry.example.org", port: 80, method: "GET", status: 304,
			caller: "10.0.0.8", basis: address, at: "2026-10-04T10:00:02Z"},
	}
	checkConns(t, b.Observations, want)
	c := b.Report.GetCounts()
	if c.GetRead() != 4 || c.GetObserved() != 3 || c.GetRefused() != 1 || c.GetStringsDropped() != 0 || c.GetCallersDropped() != 0 {
		t.Fatalf("counts %v", c)
	}
	if !maps.Equal(c.GetRefusedBy(), map[string]uint64{"port": 1}) {
		t.Fatalf("refused_by %v", c.GetRefusedBy())
	}
	checkEnvoyReport(t, b.Report, "egress-envoy", "envoy.jsonl", "10:00:02.000")
}

// A TLS listener's lines name the SNI host alone.
func TestEnvoySNIFixture(t *testing.T) {
	b := importBytes(t, readTestdata(t, "envoy-sni.jsonl"), envoy(t))
	want := []conn{
		{host: "api.example.com", port: 443, method: "GET", status: 200, sent: 52011, received: 1834,
			caller: "10.0.0.7", basis: address, at: "2026-10-04T10:00:00.25Z"},
		{host: "registry.example.org", port: 443, method: "GET", status: 304,
			caller: "10.0.0.8", basis: address, at: "2026-10-04T10:00:01.5Z"},
	}
	checkConns(t, b.Observations, want)
	c := b.Report.GetCounts()
	if c.GetRead() != 3 || c.GetObserved() != 2 || c.GetRefused() != 1 || c.GetStringsDropped() != 0 {
		t.Fatalf("counts %v", c)
	}
	if !maps.Equal(c.GetRefusedBy(), map[string]uint64{"destination": 1}) {
		t.Fatalf("refused_by %v", c.GetRefusedBy())
	}
	checkEnvoyReport(t, b.Report, "egress-envoy-sni", "envoy-sni.jsonl", "10:00:01.500")
}

func checkEnvoyReport(t *testing.T, r *observev1.ImportReport, source, input, latest string) {
	t.Helper()
	switch {
	case r.GetSchemaVersion() != "0.3":
		t.Fatalf("report schema %q", r.GetSchemaVersion())
	case r.GetEarliestEventTime().AsTime().Format("15:04:05.000") != "10:00:00.250",
		r.GetLatestEventTime().AsTime().Format("15:04:05.000") != latest:
		t.Fatalf("event times %v %v", r.GetEarliestEventTime(), r.GetLatestEventTime())
	case !r.GetEveryRunDoubted():
		t.Fatal("a refused line names no run, so it puts every run in doubt")
	case r.GetSource().GetSourceId() != source || r.GetSource().GetTrust() != observev1.Trust_TRUST_INDEPENDENT ||
		r.GetSource().GetDescriptorSha256() != descSHA || r.GetSource().GetConvention() != nil ||
		r.GetSource().GetKind() != "egress-access-log":
		t.Fatalf("source %v", r.GetSource())
	case r.GetInputBytes() != uint64(len(readTestdata(t, input))):
		t.Fatalf("input_bytes %d", r.GetInputBytes())
	}
}

// The report spans the earliest and latest connection whatever order the
// lines come in.
func TestEventTimeSpan(t *testing.T) {
	in := envoyLine("start_time", `"2026-10-04T10:00:02Z"`) +
		envoyLine("start_time", `"2026-10-04T10:00:01Z"`) +
		envoyLine("start_time", `"2026-10-04T10:00:03Z"`) +
		envoyLine("start_time", `"2026-10-04T10:00:01.5Z"`)
	r := importBytes(t, []byte(in), envoy(t)).Report
	if got := r.GetEarliestEventTime().AsTime().Format("15:04:05.0"); got != "10:00:01.0" {
		t.Fatalf("earliest %s", got)
	}
	if got := r.GetLatestEventTime().AsTime().Format("15:04:05.0"); got != "10:00:03.0" {
		t.Fatalf("latest %s", got)
	}
}

func TestSquidFixture(t *testing.T) {
	b := importBytes(t, readTestdata(t, "squid.jsonl"), loadDescriptor(t, "squid.descriptor.json"))
	want := []conn{
		{host: "api.example.com", port: 443, method: "CONNECT", status: 200, sent: 52011, received: 1834,
			caller: "alice", basis: authenticated, at: "2026-10-04T10:00:00.25Z"},
		{host: "registry.example.org", port: 80, method: "GET", status: 200, sent: 4096, received: 312,
			basis: none, at: "2026-10-04T10:00:01.5Z"},
		{host: "dav.example.net", port: 443, status: 207, sent: 610, received: 190,
			caller: "bob", basis: authenticated, at: "2026-10-04T10:00:02Z"},
	}
	checkConns(t, b.Observations, want)
	c := b.Report.GetCounts()
	if c.GetRead() != 3 || c.GetObserved() != 3 || c.GetRefused() != 0 || c.GetStringsDropped() != 1 || len(c.GetRefusedBy()) != 0 {
		t.Fatalf("counts %v", c)
	}
	if b.Report.GetEveryRunDoubted() || b.Report.GetSchemaVersion() != "0.3" || b.Report.GetSource().GetKind() != "egress-access-log" {
		t.Fatalf("a report that refused nothing: %v", b.Report)
	}
}

// checkConns holds observations to the connections want names and to the one
// form an importer writes them in.
func checkConns(t *testing.T, obs []*observev1.Observation, want []conn) {
	t.Helper()
	got := make([]conn, len(obs))
	for i, o := range obs {
		got[i] = connOf(o)
		switch {
		case o.GetSchemaVersion() != "0.3", o.GetStage() != observev1.Stage_STAGE_INDIRECT,
			o.GetSubject().GetKind() != observev1.SubjectKind_SUBJECT_KIND_CONNECTION,
			o.GetCorrelation().GetBasis() != observev1.Basis_BASIS_NONE, o.GetOutcome() != nil,
			o.GetTenantId() != "tenant-a", o.GetProjectId() != "project-a",
			o.GetSource().GetKind() != "egress-access-log",
			!o.GetReceivedTime().AsTime().Equal(received):
			t.Fatalf("observation %d: %v", i, o)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("connections\n got %+v\nwant %+v", got, want)
	}
	ids := map[string]bool{}
	for _, o := range obs {
		ids[o.GetObservationId()] = true
	}
	if len(ids) != len(obs) {
		t.Fatalf("%d ids for %d distinct connections", len(ids), len(obs))
	}
}
