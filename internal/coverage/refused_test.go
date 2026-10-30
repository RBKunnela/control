package coverage_test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/coverage"
	"github.com/guardana/control/internal/ingest"
	"github.com/guardana/control/internal/observe"
)

// imported is source e1 as the Envoy TLS listener's fixture descriptor
// declares it, holding what the importer made of log, each record through
// the log's codec.
func imported(t *testing.T, log string) coverage.Source {
	t.Helper()
	raw, err := os.ReadFile("../ingest/egresslog/testdata/envoy-sni.descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{`"tenant-a"`: `"t1"`, `"project-a"`: `"p1"`, `"egress-envoy-sni"`: `"e1"`} {
		raw = bytes.ReplaceAll(raw, []byte(from), []byte(to))
	}
	d, err := ingest.ReadDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	kind, _ := ingest.Lookup(d.GetKind())
	b, err := kind.Import(strings.NewReader(log), d, observe.DescriptorSHA256(raw), now)
	if err != nil {
		t.Fatal(err)
	}
	var records []*observev1.Record
	for _, o := range b.Observations {
		records = append(records, &observev1.Record{Record: &observev1.Record_Observation{Observation: o}})
	}
	records = append(records, &observev1.Record{Record: &observev1.Record_ImportReport{ImportReport: b.Report}})
	for _, r := range records {
		if _, err := observe.MarshalLine(r); err != nil {
			t.Fatalf("a record the log would refuse: %v", err)
		}
	}
	return coverage.Source{Descriptor: d, Records: records}
}

// sniLine is a TLS listener's line whose SNI is server, raw JSON.
func sniLine(server string) string {
	return fmt.Sprintf(`{"start_time":%q,"server_name":%s,"upstream_remote_port":443,"method":"GET","response_code":200,`+
		`"bytes_sent":9999999,"bytes_received":1,"downstream_remote_address":"10.0.0.7"}`+"\n", rfc(-time.Minute), server)
}

// TestRefusedLinesAreARowOfTheirOwn: a connection whose destination the
// importer refused is one nobody can say a path covers. Every declared path
// observed, the refusals still make a row before the standing one, and the
// exit 1.
func TestRefusedLinesAreARowOfTheirOwn(t *testing.T) {
	inv := egressInventory(t, "api.example.com", "api.example.com")
	clean := mustMap(t, coverage.Input{Inventory: inv, Sources: []coverage.Source{imported(t, sniLine(`"api.example.com"`))}})
	if got := coverage.ExitStatus(clean, nil); got != coverage.ExitCovered || len(clean.Refused) != 0 {
		t.Fatalf("the declared host alone: exit %d, refused %+v", got, clean.Refused)
	}
	log := sniLine(`"api.example.com"`) + sniLine(`"-"`) + sniLine(`"exfil.example.net."`) +
		sniLine(`"my_host.exfil.example.net"`) + sniLine(`"[2001:db8::1]"`) + sniLine(`null`) + "not json\n"
	r := mustMap(t, coverage.Input{Inventory: inv, Sources: []coverage.Source{imported(t, log)}})
	want := []string{
		"out observed, independent (unsigned descriptor): sources e1; no plane decides egress",
		"  source e1: observed, independent (unsigned descriptor): last heard 2026-10-05T11:59:00Z, heartbeat 300 s",
		"refused egress by e1: 6 lines refused, so their connections are unknown: destination 5, not_an_object 1; no plane decides egress",
		"undeclared paths: unknown",
	}
	if got := r.Lines(); joined(got) != joined(want) {
		t.Errorf("lines:\n%s\nwant:\n%s", joined(got), joined(want))
	}
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
		t.Errorf("exit %d, want %d", got, coverage.ExitGaps)
	}
}

// refusing is an import report of source e1, of kind, counting refused
// lines by the reasons given.
func refusing(tenant, kind string, refused uint64, by map[string]uint64) *observev1.Record {
	r := report("e1", at(-10*time.Second), at(-10*time.Second))
	rep := r.GetImportReport()
	rep.TenantId, rep.Source.Kind, rep.Counts = tenant, kind, &observev1.ImportCounts{Refused: refused, RefusedBy: by}
	return r
}

// TestARefusedRowAddsTheSourcesOwnReports: every report of the source counts,
// by reason, a refusal no reason names among them; a report of another
// tenant or kind, and a source of another kind, count none.
func TestARefusedRowAddsTheSourcesOwnReports(t *testing.T) {
	src := egressSource("e1", independent, 10*time.Second,
		refusing("t1", egressKind, 3, map[string]uint64{"time": 1, "destination": 2}),
		refusing("t1", egressKind, 2, nil),
		refusing("t1", egressKind, 0, nil),
		refusing("t2", egressKind, 7, map[string]uint64{"destination": 7}),
		refusing("t1", "", 11, nil),
	)
	spans := refusing("t1", "", 5, nil)
	spans.GetImportReport().Source.SourceId = "s1"
	tool := liveSource(selfReported, spans)
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{tool, src}})
	want := "refused egress by e1: 5 lines refused, so their connections are unknown: destination 2, no reason given 2, time 1; no plane decides egress"
	if l := r.Lines(); len(r.Refused) != 1 || l[len(l)-2] != want {
		t.Errorf("rows %+v, lines:\n%s\nwant the row:\n%s", r.Refused, joined(l), want)
	}
}

// TestARefusedRowNamesAtMostSixteenReasons and counts the rest.
func TestARefusedRowNamesAtMostSixteenReasons(t *testing.T) {
	for _, tc := range []struct {
		reasons int
		tail    string
	}{
		{16, "r15 1; no plane decides egress"},
		{17, "r15 1 and 1 more reasons; no plane decides egress"},
	} {
		by := map[string]uint64{}
		for i := range tc.reasons {
			by[fmt.Sprintf("r%02d", i)] = 1
		}
		src := egressSource("e1", independent, 10*time.Second, refusing("t1", egressKind, uint64(tc.reasons), by)) //nolint:gosec // G115: a small count
		r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{src}})
		if l := r.Lines(); !strings.HasSuffix(l[len(l)-2], tc.tail) {
			t.Errorf("%d reasons: row %q, want it to end %q", tc.reasons, l[len(l)-2], tc.tail)
		}
	}
}

// TestARefusedRowAloneMakesTheExitOne: a report a caller holds with only a
// refused source has connections nobody read.
func TestARefusedRowAloneMakesTheExitOne(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{liveSource(selfReported, observedA.record())}})
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitCovered {
		t.Fatalf("before the row: exit %d", got)
	}
	r.Refused = []coverage.RefusedSource{{SourceID: "e1", Refused: 1, By: map[string]uint64{"destination": 1}}}
	if got := coverage.ExitStatus(r, nil); got != coverage.ExitGaps {
		t.Errorf("exit %d, want %d", got, coverage.ExitGaps)
	}
}

// TestAnEgressReportNeverMakesAnotherKindLive: an OpenTelemetry source and an
// egress import under its id share a log; the egress report is not that
// source heard.
func TestAnEgressReportNeverMakesAnotherKindLive(t *testing.T) {
	egress := imported(t, sniLine(`"api.example.com"`))
	src := coverage.Source{Descriptor: descriptor("s1", selfReported), Records: nil}
	for _, r := range egress.Records {
		if rep := r.GetImportReport(); rep != nil {
			rep.Source.SourceId = "s1"
			src.Records = append(src.Records, r)
		}
	}
	src.Records = append(src.Records, observedA.record())
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{src}})
	if l := r.Paths[0].Sources[0]; l.State != coverage.Unknown || !strings.HasPrefix(l.Basis, "never heard") {
		t.Errorf("source line %v (%q), want unknown, never heard", l.State, l.Basis)
	}
}

// TestAMappedAddressMatchesItsIPv4Path: the importer writes an IPv4-mapped
// IPv6 destination as the IPv4 address the inventory declares.
func TestAMappedAddressMatchesItsIPv4Path(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: egressInventory(t, "203.0.113.7", "203.0.113.7"),
		Sources: []coverage.Source{imported(t, sniLine(`"::ffff:203.0.113.7"`))}})
	if r.Paths[0].State != coverage.Observed || len(r.Undeclared) != 0 {
		t.Errorf("%v with undeclared %+v, want observed and none", r.Paths[0].State, r.Undeclared)
	}
}
