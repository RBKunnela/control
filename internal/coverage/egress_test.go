package coverage_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/coverage"
)

const egressKind = "egress-access-log"

var connections int

// conn is a connection observation of host by source, a minute before now,
// with an id no other conn has.
func conn(source, host string, port uint32) *observev1.Record {
	connections++
	return &observev1.Record{Record: &observev1.Record_Observation{Observation: &observev1.Observation{
		SchemaVersion: "0.3", ObservationId: fmt.Sprintf("obs-%d", connections),
		TenantId: "t1", ProjectId: "p1",
		Source:       &observev1.SourceRef{SourceId: source, Trust: observev1.Trust_TRUST_INDEPENDENT, Kind: egressKind},
		ReceivedTime: at(-30 * time.Second), EventTime: at(-time.Minute),
		Subject:     &observev1.Subject{Kind: observev1.SubjectKind_SUBJECT_KIND_CONNECTION, Name: host},
		Correlation: &observev1.Correlation{Basis: observev1.Basis_BASIS_NONE},
		Stage:       observev1.Stage_STAGE_INDIRECT,
		Connection:  &observev1.Connection{Port: port},
	}}}
}

// egressSource is an egress source of kind egress-access-log at trust,
// sampling completely, last heard heardAgo before now.
func egressSource(id string, trust observev1.Trust, heardAgo time.Duration, records ...*observev1.Record) coverage.Source {
	d := descriptor(id, trust)
	d.SchemaVersion, d.Kind, d.Sampling = "0.2", egressKind, observev1.Sampling_SAMPLING_COMPLETE
	heard := report(id, at(-heardAgo), at(-heardAgo))
	heard.GetImportReport().Source.Kind = egressKind
	return coverage.Source{Descriptor: d, Records: append([]*observev1.Record{heard}, records...)}
}

func egressInventory(t testing.TB, host, sourceName string) *coverage.Inventory {
	t.Helper()
	return mustInventory(t, `{"schema_version":"0.1","paths":[{"id":"out","kind":"egress","host":"`+host+`",`+
		`"sources":[{"source_id":"e1","name":"`+sourceName+`"}]}]}`)
}

func joined(l []string) string { return strings.Join(l, "\n") }

func TestAnEgressPathIsObservedByAConnection(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: egressInventory(t, "api.example.com", "api.example.com"),
		Sources: []coverage.Source{egressSource("e1", independent, 10*time.Second, conn("e1", "api.example.com", 443))}})
	want := []string{
		"out observed, independent (unsigned descriptor): sources e1; no plane decides egress",
		"  source e1: observed, independent (unsigned descriptor): last heard 2026-10-05T11:59:50Z, heartbeat 300 s",
		"undeclared paths: unknown",
	}
	if got := r.Lines(); joined(got) != joined(want) {
		t.Errorf("lines:\n%s\nwant:\n%s", joined(got), joined(want))
	}
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitCovered {
		t.Errorf("exit %d, want %d", got, coverage.ExitCovered)
	}
}

// TestAnEgressPathIsNeverDecidedByAPlane: a LOCKDOWN plane whose upstream,
// and whose override's upstream, share the host's name stands in front of no
// egress path.
func TestAnEgressPathIsNeverDecidedByAPlane(t *testing.T) {
	const host = "api.example.com"
	lockdown := listing(plane("gw", modeLockdown, false,
		coverage.Override{Upstream: host, Tool: host, Fingerprint: "fp1", Effect: effectWrite}), host)
	for _, sources := range [][]coverage.Source{nil, {egressSource("e1", independent, 10*time.Second, conn("e1", host, 443))}} {
		r := mustMap(t, coverage.Input{Inventory: egressInventory(t, host, host), Planes: []coverage.Plane{lockdown}, Sources: sources})
		p := r.Paths[0]
		if p.State > coverage.Observed || len(p.Planes) != 0 || len(p.Joins) != 0 {
			t.Errorf("%d sources: %v with planes %+v and joins %+v, want at most observed and no plane", len(sources), p.State, p.Planes, p.Joins)
		}
		if !strings.HasSuffix(r.Lines()[0], "; no plane decides egress") {
			t.Errorf("%d sources: path line %q", len(sources), r.Lines()[0])
		}
	}
	r := mustMap(t, coverage.Input{Inventory: egressInventory(t, host, host), Planes: []coverage.Plane{lockdown}})
	if got, want := r.Lines()[0], "out not covered: no live source observed it; no plane decides egress"; got != want {
		t.Errorf("path line %q, want %q", got, want)
	}
	// An egress path names no upstream and no tool, so a plane that lists the
	// empty upstream and classifies the empty tool on it would stand in
	// front of every egress path if the kind did not keep planes away.
	blank := listing(plane("blank", modeLockdown, false,
		coverage.Override{Upstream: "", Tool: "", Fingerprint: "fp1", Effect: effectWrite}), "")
	r = mustMap(t, coverage.Input{Inventory: egressInventory(t, host, host), Planes: []coverage.Plane{blank}})
	if p := r.Paths[0]; p.State != coverage.NotCovered || len(p.Planes) != 0 {
		t.Errorf("a plane of the empty upstream: %v with planes %+v, want not covered and no plane", p.State, p.Planes)
	}
}

// TestAToolObservationNeverObservesAnEgressPath, and a connection never a
// tool path, whatever the names.
func TestAToolObservationNeverObservesAnEgressPath(t *testing.T) {
	tool := obs{source: "e1", name: "api.example.com"}.record()
	r := mustMap(t, coverage.Input{Inventory: egressInventory(t, "api.example.com", "api.example.com"),
		Sources: []coverage.Source{egressSource("e1", selfReported, 10*time.Second, tool)}})
	if p := r.Paths[0]; p.State != coverage.NotCovered || !strings.HasPrefix(p.Sources[0].Basis, "live, and no observation of the path") {
		t.Errorf("a tool observation: %v (%q), want not covered", p.State, p.Sources[0].Basis)
	}
	r = mustMap(t, coverage.Input{Inventory: toolInventory(t),
		Sources: []coverage.Source{liveSource(selfReported, conn("s1", "create_issue", 443))}})
	if p := r.Paths[0]; p.State != coverage.NotCovered {
		t.Errorf("a connection: %v, want not covered", p.State)
	}
}

// TestTheInventoryTakesTheOneSpelling: a host in another spelling is refused
// with the one to write, since read as written it would match no connection.
func TestTheInventoryTakesTheOneSpelling(t *testing.T) {
	doc := func(host, name string) string {
		return `{"schema_version":"0.1","paths":[{"id":"out","kind":"egress","host":"` + host + `",` +
			`"sources":[{"source_id":"e1","name":"` + name + `"}]}]}`
	}
	for _, c := range []struct{ host, name, write string }{
		{"Example.COM", "example.com", `write "example.com"`},
		{"example.com", "API.Example.com", `write "api.example.com"`},
		{"::ffff:203.0.113.7", "203.0.113.7", `write "203.0.113.7"`},
		{"2001:0db8::1", "2001:db8::1", `write "2001:db8::1"`},
		{"203.0.113.7", "::FFFF:cb00:7107", `write "203.0.113.7"`},
	} {
		_, err := coverage.ReadInventory([]byte(doc(c.host, c.name)))
		if !errors.Is(err, coverage.ErrInventory) || !strings.Contains(err.Error(), c.write) {
			t.Errorf("%s, %s: %v, want ErrInventory saying %s", c.host, c.name, err, c.write)
		}
	}
	inv := egressInventory(t, "2001:db8::1", "203.0.113.7")
	if p := inv.Paths[0]; p.Host != "2001:db8::1" || p.Sources[0].Name != "203.0.113.7" {
		t.Fatalf("read host %q and name %q", p.Host, p.Sources[0].Name)
	}
}

// TestALapsedSourcesOldConnectionIsStillUndeclared: the path the source is
// named on is unknown, a host no path declares is still a row, and so is the
// lapsed source.
func TestALapsedSourcesOldConnectionIsStillUndeclared(t *testing.T) {
	src := egressSource("e1", independent, time.Hour, conn("e1", "a.example", 443), conn("e1", "b.example", 80),
		conn("e1", "b.example", 0), conn("e1", "b.example", 80))
	r := mustMap(t, coverage.Input{Inventory: egressInventory(t, "a.example", "a.example"), Sources: []coverage.Source{src}})
	if r.Paths[0].State != coverage.Unknown {
		t.Errorf("path %v, want unknown", r.Paths[0].State)
	}
	want := []string{
		"out unknown: sources e1; no plane decides egress",
		"  source e1: unknown: past its heartbeat: last heard 2026-10-05T11:00:00Z, heartbeat 300 s",
		"undeclared egress b.example: observed by e1: independent (unsigned descriptor), past its heartbeat: " +
			"last heard 2026-10-05T11:00:00Z, heartbeat 300 s; 3 connections, ports unknown, 80; no plane decides egress",
		"unseen egress by e1: past its heartbeat: last heard 2026-10-05T11:00:00Z, heartbeat 300 s; " +
			"connections since its last import are unseen; no plane decides egress",
		"undeclared paths: unknown",
	}
	if got := r.Lines(); joined(got) != joined(want) {
		t.Errorf("lines:\n%s\nwant:\n%s", joined(got), joined(want))
	}
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
		t.Errorf("exit %d, want %d", got, coverage.ExitGaps)
	}
}

// TestAnUndeclaredRowMakesTheExitOne: every declared path observed, and one
// host besides.
func TestAnUndeclaredRowMakesTheExitOne(t *testing.T) {
	src := egressSource("e1", independent, 10*time.Second, conn("e1", "api.example.com", 443), conn("e1", "x.example", 443))
	r := mustMap(t, coverage.Input{Inventory: egressInventory(t, "api.example.com", "api.example.com"), Sources: []coverage.Source{src}})
	if r.Paths[0].State != coverage.Observed || len(r.Undeclared) != 1 || r.Undeclared[0].Host != "x.example" {
		t.Fatalf("%v, undeclared %+v", r.Paths[0].State, r.Undeclared)
	}
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
		t.Errorf("exit %d, want %d", got, coverage.ExitGaps)
	}
}

// TestAHostASourceNamesIsDeclared: the name a path gives its source for the
// host is declared too, but only for that source.
func TestAHostASourceNamesIsDeclared(t *testing.T) {
	inv := egressInventory(t, "api.example.com", "proxy-name.example")
	r := mustMap(t, coverage.Input{Inventory: inv, Sources: []coverage.Source{
		egressSource("e1", independent, 10*time.Second, conn("e1", "proxy-name.example", 443)),
		egressSource("e2", independent, 10*time.Second, conn("e2", "proxy-name.example", 443), conn("e2", "api.example.com", 443)),
	}})
	if len(r.Undeclared) != 1 || len(r.Undeclared[0].Sources) != 1 || r.Undeclared[0].Sources[0].SourceID != "e2" {
		t.Errorf("undeclared %+v, want proxy-name.example by e2 alone", r.Undeclared)
	}
}

// TestOnlyAnEgressSourcesOwnConnectionsAreUndeclared: a source of another
// kind, and a record of another tenant, make no row.
func TestOnlyAnEgressSourcesOwnConnectionsAreUndeclared(t *testing.T) {
	other := conn("e1", "y.example", 443)
	other.GetObservation().TenantId = "t2"
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{
		liveSource(selfReported, conn("s1", "x.example", 443)),
		egressSource("e1", independent, 10*time.Second, other),
	}})
	if len(r.Undeclared) != 0 || r.UndeclaredCut != 0 {
		t.Errorf("undeclared %+v, cut %d, want none", r.Undeclared, r.UndeclaredCut)
	}
}

func TestUndeclaredRowsNameEverySourceAndTheirTrust(t *testing.T) {
	sampled := egressSource("e2", selfReported, 10*time.Second, conn("e2", "x.example", 8443))
	sampled.Descriptor.Sampling = observev1.Sampling_SAMPLING_PARTIAL
	never := egressSource("e3", platform, 0, conn("e3", "x.example", 443))
	never.Records = never.Records[1:]
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{
		never, egressSource("e1", independent, 10*time.Second, conn("e1", "x.example", 443)), sampled,
	}})
	want := "undeclared egress x.example: observed by e1: independent (unsigned descriptor), last heard 2026-10-05T11:59:50Z, " +
		"heartbeat 300 s; 1 connection, port 443; by e2: self_reported, sampled, last heard 2026-10-05T11:59:50Z, heartbeat 300 s; " +
		"1 connection, port 8443; by e3: platform, never heard; 1 connection, port 443; no plane decides egress"
	if got := r.Lines(); len(got) < 3 || got[len(got)-3] != want {
		t.Errorf("lines:\n%s\nwant the row:\n%s", joined(got), want)
	}
}

// TestAnUndeclaredRowTakesTheWeakerTrust: a connection below its
// independent descriptor prints its own trust.
func TestAnUndeclaredRowTakesTheWeakerTrust(t *testing.T) {
	lowered := conn("e1", "x.example", 443)
	lowered.GetObservation().Source.Trust = selfReported
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{
		egressSource("e1", independent, 10*time.Second, conn("e1", "x.example", 443), lowered)}})
	if len(r.Undeclared) != 1 || r.Undeclared[0].Sources[0].Trust != selfReported {
		t.Fatalf("undeclared %+v, want x.example at self_reported", r.Undeclared)
	}
	if l := r.Lines(); !strings.HasPrefix(l[len(l)-2], "undeclared egress x.example: observed by e1: self_reported, last heard") {
		t.Errorf("row %q", l[len(l)-2])
	}
}

// TestUndeclaredRowsAreSortedAndCut: hosts given in reverse order come out
// by their bytes, the first 256 printed and the rest counted on one line
// before the standing row.
func TestUndeclaredRowsAreSortedAndCut(t *testing.T) {
	cases := []struct {
		hosts, cut int
		last       string
	}{
		{256, 0, "h255.example"},
		{257, 1, "h255.example"},
		{300, 44, "h255.example"},
	}
	for _, tc := range cases {
		var records []*observev1.Record
		for i := tc.hosts - 1; i >= 0; i-- {
			records = append(records, conn("e1", fmt.Sprintf("h%03d.example", i), 443))
		}
		r := mustMap(t, coverage.Input{Inventory: toolInventory(t),
			Sources: []coverage.Source{egressSource("e1", independent, 10*time.Second, records...)}})
		if len(r.Undeclared) != 256 || r.UndeclaredCut != tc.cut || r.Undeclared[0].Host != "h000.example" ||
			r.Undeclared[255].Host != tc.last {
			t.Fatalf("%d hosts: %d rows, cut %d", tc.hosts, len(r.Undeclared), r.UndeclaredCut)
		}
		l := r.Lines()
		if l[len(l)-1] != coverage.UndeclaredRow {
			t.Errorf("%d hosts: last line %q", tc.hosts, l[len(l)-1])
		}
		cutLine := fmt.Sprintf("undeclared egress: %d more hosts not printed", tc.cut)
		if has := l[len(l)-2] == cutLine; has != (tc.cut > 0) {
			t.Errorf("%d hosts: line before the standing row %q", tc.hosts, l[len(l)-2])
		}
		if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
			t.Errorf("%d hosts: exit %d, want %d", tc.hosts, got, coverage.ExitGaps)
		}
	}
}

// TestACutAloneMakesTheExitOne: a report a caller holds with only a cut
// still has hosts it did not print.
func TestACutAloneMakesTheExitOne(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{liveSource(selfReported, observedA.record())}})
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitCovered {
		t.Fatalf("before the cut: exit %d", got)
	}
	r.UndeclaredCut = 1
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
		t.Errorf("exit %d, want %d", got, coverage.ExitGaps)
	}
}

// TestUndeclaredPortsAreBounded: a row names at most 16 ports and counts
// the rest.
func TestUndeclaredPortsAreBounded(t *testing.T) {
	for _, tc := range []struct {
		ports uint32
		tail  string
	}{
		{16, "ports 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16; no plane decides egress"},
		{17, "ports 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 and 1 more; no plane decides egress"},
	} {
		var records []*observev1.Record
		for p := tc.ports; p >= 1; p-- {
			records = append(records, conn("e1", "x.example", p))
		}
		r := mustMap(t, coverage.Input{Inventory: toolInventory(t),
			Sources: []coverage.Source{egressSource("e1", independent, 10*time.Second, records...)}})
		l := r.Lines()
		if row := l[len(l)-2]; !strings.HasSuffix(row, tc.tail) {
			t.Errorf("%d ports: row %q, want it to end %q", tc.ports, row, tc.tail)
		}
	}
}

func TestReadInventoryHoldsEgressToHosts(t *testing.T) {
	doc := func(host, source string) string {
		return `{"schema_version":"0.1","paths":[{"id":"out","kind":"egress","host":"` + host + `","sources":[` + source + `]}]}`
	}
	long := strings.Repeat("a.", 126) + "a"
	if _, err := coverage.ReadInventory([]byte(doc(long, `{"source_id":"e1","name":"`+long+`"}`))); err != nil {
		t.Errorf("a host of 253 bytes: %v", err)
	}
	cases := map[string]string{
		"a URL as host":                    doc("https://x/", ""),
		"a path after the host":            doc("x.example/a", ""),
		"a port after the host":            doc("x.example:443", ""),
		"a Kelvin sign that folds to k":    doc("K.example", ""),
		"a host of 254 bytes":              doc(long+"a", ""),
		"a trailing dot":                   doc("x.example.", ""),
		"server_address on a source":       doc("x.example", `{"source_id":"e1","name":"x.example","server_address":"x.example"}`),
		"a source name that is not host":   doc("x.example", `{"source_id":"e1","name":"https://x.example/"}`),
		"a source name of 254 bytes":       doc("x.example", `{"source_id":"e1","name":"`+long+`a"}`),
		"a source name with a Kelvin sign": doc("x.example", `{"source_id":"e1","name":"K.example"}`),
	}
	for name, d := range cases {
		if _, err := coverage.ReadInventory([]byte(d)); !errors.Is(err, coverage.ErrInventory) {
			t.Errorf("%s: %v, want ErrInventory", name, err)
		}
	}
}
