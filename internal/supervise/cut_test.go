package supervise_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/supervise"
	"github.com/guardana/control/pkg/contract"
	"google.golang.org/protobuf/encoding/protojson"
)

// manyDenials is lookup and n denied refunds one second apart, request ids
// in the order made.
func manyDenials(n int) []call {
	calls := []call{{req: "r1", tool: "get_order", upstream: "shop"}}
	for i := range n {
		calls = append(calls, call{req: fmt.Sprintf("d%05d", i), tool: "issue_refund", upstream: "pay",
			at: time.Duration(i+1) * time.Second, outcome: "deny"})
	}
	return calls
}

// noDeadline is the 0.1 refund procedure with its deadline off, so a long
// run fires one finding.
func noDeadline(t *testing.T) *supervise.Procedure {
	return procWith(t, `"deadline_seconds":600,`, ``)
}

func lineOf(t *testing.T, f *findingv1alpha1.FindingRecord) []byte {
	t.Helper()
	b, err := findinglog.Line(&findingv1alpha1.Record{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: f}})
	if err != nil {
		t.Fatalf("the findings log refuses the record: %v", err)
	}
	return b
}

// cited is the request ids a finding's events name, in order.
func cited(f *findingv1alpha1.FindingRecord) []string {
	var out []string
	for _, r := range f.GetRefs() {
		out = append(out, r.GetEvent().GetRequestId())
	}
	return out
}

// TestTenThousandDenialsWriteOneRecordUnderTheBound: the record cites the
// first MaxFindingRefs denials and counts the rest, is "0.2" with each event
// naming its run, is confirmed as all its evidence is, and fits a log line.
func TestTenThousandDenialsWriteOneRecordUnderTheBound(t *testing.T) {
	res := evaluate(t, supervise.Input{Procedure: noDeadline(t), Exports: []supervise.Export{export(manyDenials(10000)...)}})
	if len(res.Findings) != 1 {
		t.Fatalf("%d findings", len(res.Findings))
	}
	f := res.Findings[0]
	if n := len(lineOf(t, f)); n > findinglog.MaxLineBytes {
		t.Fatalf("a line of %d bytes", n)
	}
	checkFirstCited(t, f, 10000)
	if f.GetSchemaVersion() != "0.2" || f.GetFinding().GetVerdict() != confirmed || f.GetFinding().GetRunId() != runID ||
		f.GetFinding().GetFindingId() != id("REPEATED_DENIAL", "issue_refund", "pay") {
		t.Fatalf("record %s", protojson.Format(f))
	}
}

// checkFirstCited holds f, a finding of n denials, to citing the first
// MaxFindingRefs of them, each naming runID, and counting the rest.
func checkFirstCited(t *testing.T, f *findingv1alpha1.FindingRecord, n uint64) {
	t.Helper()
	got := cited(f)
	if len(got) != supervise.MaxFindingRefs || f.GetRefsLeftOut() != n-supervise.MaxFindingRefs ||
		got[0] != "d00000" || got[len(got)-1] != fmt.Sprintf("d%05d", supervise.MaxFindingRefs-1) {
		t.Fatalf("cites %q and leaves out %d", got, f.GetRefsLeftOut())
	}
	for _, r := range f.GetRefs() {
		if r.GetEvent().GetRunId() != runID {
			t.Fatalf("an event of a 0.2 record names run %q", r.GetEvent().GetRunId())
		}
	}
}

// TestAFindingAtTheBoundCitesEveryRecord: MaxFindingRefs denials are cited
// whole in a 0.1 record, one more is cut.
func TestAFindingAtTheBoundCitesEveryRecord(t *testing.T) {
	at := evaluate(t, supervise.Input{Procedure: noDeadline(t), Exports: []supervise.Export{export(manyDenials(supervise.MaxFindingRefs)...)}}).Findings[0]
	if len(at.GetRefs()) != supervise.MaxFindingRefs || at.GetRefsLeftOut() != 0 || at.GetSchemaVersion() != "0.1" ||
		at.GetRefs()[0].GetEvent().GetRunId() != "" {
		t.Fatalf("at the bound: %s", protojson.Format(at))
	}
	past := evaluate(t, supervise.Input{Procedure: noDeadline(t), Exports: []supervise.Export{export(manyDenials(supervise.MaxFindingRefs + 1)...)}}).Findings[0]
	if len(past.GetRefs()) != supervise.MaxFindingRefs || past.GetRefsLeftOut() != 1 || past.GetSchemaVersion() != "0.2" {
		t.Fatalf("one past the bound: %s", protojson.Format(past))
	}
}

// TestADoubtfulReferencePastTheCutKeepsIndeterminate: the last of many
// denials, as many as max_denials, has a broken trail, so the clean ones do
// not reach the bound alone; it is cited first and the finding is
// indeterminate.
func TestADoubtfulReferencePastTheCutKeepsIndeterminate(t *testing.T) {
	n := supervise.MaxFindingRefs + 5
	p := procWith(t, `"deadline_seconds":600,`, ``, `"max_denials":4`, fmt.Sprintf(`"max_denials":%d`, n))
	x := export(manyDenials(n)...)
	last := fmt.Sprintf("d%05d", n-1)
	for _, ev := range x.Events {
		if ev.GetEventId() == last+"-e3" {
			ev.PrevEventId = last + "-e9"
		}
	}
	f := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{x}}).Findings[0]
	got := cited(f)
	if f.GetFinding().GetVerdict() != indetermin || got[0] != last || got[1] != "d00000" || f.GetRefsLeftOut() != 5 {
		t.Fatalf("verdict %s, cites %q, leaves out %d", f.GetFinding().GetVerdict(), got, f.GetRefsLeftOut())
	}
}

// TestTheBoundHoldsForTheLongestIdentifiers: every string the record
// carries at contract.MaxStringBytes, each byte one JSON escapes in two, and
// MaxFindingRefs events cited, through Evaluate: the line stays within seven
// eighths of findinglog.MaxLineBytes.
func TestTheBoundHoldsForTheLongestIdentifiers(t *testing.T) {
	long := func(suffix string) string { return strings.Repeat(`"`, contract.MaxStringBytes-len(suffix)) + suffix }
	doc := strings.Replace(strings.Replace(v02Doc(t), `"procedure_id": "refund"`, `"procedure_id": "`+strings.Repeat(`\"`, contract.MaxStringBytes)+`"`, 1),
		`"version": "2"`, `"version": "`+strings.Repeat(`\\`, contract.MaxStringBytes)+`"`, 1)
	p, err := supervise.ReadProcedure([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var calls []call
	for i := range supervise.MaxFindingRefs + 1 {
		calls = append(calls, call{req: long(fmt.Sprintf("%04d", i))[3:], tool: "issue_refund", upstream: "pay",
			at: time.Duration(i) * time.Second, outcome: "deny", tenant: long("t"), proj: long("p")})
	}
	x := export(calls...)
	for _, ev := range x.Events {
		if len(ev.GetEventId()) != contract.MaxStringBytes || len(ev.GetRequestId()) != contract.MaxStringBytes-3 {
			t.Fatalf("an event id of %d bytes", len(ev.GetEventId()))
		}
	}
	res, err := supervise.Evaluate(supervise.Input{Procedure: p, Run: supervise.Run{ID: runID, Tenant: long("t")},
		Exports: []supervise.Export{x}})
	if err != nil {
		t.Fatal(err)
	}
	f := only(res, supervise.RuleRepeatedDenial)
	if len(f) != 1 || len(f[0].GetRefs()) != supervise.MaxFindingRefs {
		t.Fatalf("findings:\n%s", dump(res.Findings))
	}
	// The longest rule id and enum names any finding carries, beyond this one's.
	const slack = 64
	n := len(lineOf(t, f[0])) + slack
	t.Logf("the line takes %d bytes with the slack, of %d", n, findinglog.MaxLineBytes)
	if n > findinglog.MaxLineBytes*7/8 {
		t.Fatalf("a line of %d bytes with the slack, more than seven eighths of %d", n, findinglog.MaxLineBytes)
	}
}

// BenchmarkDenialsOnAClosedRun applies every rule to runs of 5 000 and
// 20 000 denials; linear work keeps the second near four times the first.
func BenchmarkDenialsOnAClosedRun(b *testing.B) {
	p, err := supervise.ReadProcedure([]byte(strings.Replace(procJSON, `"deadline_seconds":600,`, ``, 1)))
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range []int{5000, 20000} {
		in := supervise.Input{Procedure: p, Run: supervise.Run{ID: runID, Tenant: tenant, Closed: true},
			Exports: []supervise.Export{export(manyDenials(n)...)}}
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			for b.Loop() {
				if res, err := supervise.Evaluate(in); err != nil || len(res.Findings) != 1 {
					b.Fatalf("Evaluate: %v", err)
				}
			}
			b.ReportMetric(float64(n), "denials/op")
		})
	}
}

// TestACutOfObservationsAloneIsSchema02: a source's reports of one name no
// plane call joins, one more than the bound, make a record that cites no
// event and still says "0.2", which the findings log takes.
func TestACutOfObservationsAloneIsSchema02(t *testing.T) {
	var obs []ob
	for i := range supervise.MaxFindingRefs + 1 {
		obs = append(obs, ob{id: fmt.Sprintf("obs-%032x", i), name: "wipe_disk", span: fmt.Sprintf("%016x", i+1)})
	}
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Exports: []supervise.Export{export(conforming()...)},
		Sources: []supervise.Source{source(obs...)}})
	f := only(res, supervise.RuleStepOutsideProcedure)
	if len(f) != 1 || f[0].GetSchemaVersion() != "0.2" || f[0].GetRefsLeftOut() != 1 ||
		f[0].GetRefs()[0].GetObservation().GetObservationId() != fmt.Sprintf("obs-%032x", 0) {
		t.Fatalf("findings:\n%s", dump(res.Findings))
	}
	lineOf(t, f[0])
}
