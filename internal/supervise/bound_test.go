package supervise_test

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/supervise"
	"github.com/guardana/control/pkg/contract"
)

// countVerdicts is how many findings of rule res holds at each verdict, as
// its name says it.
func countVerdicts(res *supervise.Result, rule string) map[string]int {
	out := map[string]int{}
	for _, f := range only(res, rule) {
		out[f.GetFinding().GetVerdict().String()]++
	}
	return out
}

// TestManyDenialsOfOneCallAreStillRetried: n denials of one refund, each
// with the same arguments, then the refund with other arguments and the
// order refunded by another tool. Each denial is retried in both forms, by
// the root, confirmed when the root was denied and suggested when its child
// was; no denial is left unjudged, however many there are.
func TestManyDenialsOfOneCallAreStillRetried(t *testing.T) {
	for _, n := range []int{1025, 4096} {
		for _, deniedIn := range []string{runID, childRun} {
			t.Run(fmt.Sprint(n, " in ", deniedIn), func(t *testing.T) {
				var as []act
				for i := range n {
					d := denial()
					d.req, d.run, d.at = fmt.Sprintf("d%04d", i), deniedIn, time.Duration(i)*time.Millisecond
					as = append(as, d)
				}
				retry, other := again(), manual()
				retry.at, other.at = 30*time.Second, 40*time.Second
				res := supervise02(t, siblings(), acts(append(as, retry, other)...))
				want := map[string]int{"FINDING_VERDICT_CONFIRMED": n}
				if deniedIn != runID {
					want = map[string]int{"FINDING_VERDICT_SUSPECTED": n}
				}
				for _, rule := range []string{ruleArgs, ruleRes} {
					if got := countVerdicts(res, rule); rules(res)[rule] != checked || fmt.Sprint(got) != fmt.Sprint(want) {
						t.Errorf("%s is %s with %v; want %v", rule, rules(res)[rule], got, want)
					}
					for _, f := range only(res, rule) {
						if f.GetFinding().GetRunId() != runID {
							t.Fatalf("%s names %s", rule, f.GetFinding().GetRunId())
						}
					}
				}
			})
		}
	}
}

// spacedDenials is n denials of the refund on order 42, each with its own
// arguments, two seconds apart, so each is proposed after the one before was
// decided.
func spacedDenials(n int) []act {
	var as []act
	for i := range n {
		as = append(as, act{call: call{req: fmt.Sprintf("d%04d", i), tool: "issue_refund", upstream: "pay",
			at: 2 * time.Duration(i) * time.Second, outcome: "deny"}, hash: "sha256:" + fmt.Sprintf("%064x", i), res: orderNo("42")})
	}
	return as
}

// TestEveryDenialIsJudgedHoweverMany: 1449 denials of one tool, each with
// its own arguments, are each retried by every denial after it, more than
// a million pairs; each but the last is confirmed. The first rests on 1448
// retries: it cites the first ten read and counts the other 1438.
func TestEveryDenialIsJudgedHoweverMany(t *testing.T) {
	res := retrySupervise(t, source(), acts(spacedDenials(1449)...))
	got := countVerdicts(res, ruleArgs)
	if rules(res)[ruleArgs] != checked || fmt.Sprint(got) != "map[FINDING_VERDICT_CONFIRMED:1448]" {
		t.Fatalf("%s with %v", rules(res)[ruleArgs], got)
	}
	for _, f := range only(res, ruleArgs) {
		if f.GetFinding().GetFindingId() != id02(ruleArgs, "d0000", runID) {
			continue
		}
		want := "d0000-e2 d0001-e1 d0002-e1 d0003-e1 d0004-e1 d0005-e1 d0006-e1 d0007-e1 d0008-e1 d0009-e1"
		if citedEvents(f) != want || f.GetRefsLeftOut() != 1439 {
			t.Errorf("the finding on d0000 cites %q and leaves out %d", citedEvents(f), f.GetRefsLeftOut())
		}
	}
}

// TestEveryReportAroundADenialIsWeighed: 1024 reports of the refund after
// 1025 denials of it on one order: each denial is retried around by all of
// them, citing ten of the reports and counting the rest with the denial,
// and in the plane forms each but the last is retried by
// the denials after it, while one tool on one order is no retry of itself.
func TestEveryReportAroundADenialIsWeighed(t *testing.T) {
	var reports []ob
	for i := range 1024 {
		reports = append(reports, ob{id: fmt.Sprintf("obs-%04d", i), name: "issue_refund", at: 5000 * time.Second})
	}
	res := retrySupervise(t, source(reports...), acts(spacedDenials(1025)...))
	want := map[string]string{
		ruleArgs:   "map[FINDING_VERDICT_CONFIRMED:1024]",
		ruleRes:    "map[]",
		ruleAround: "map[FINDING_VERDICT_SUSPECTED:1025]",
	}
	for _, rule := range retryRules {
		if got := countVerdicts(res, rule); rules(res)[rule] != checked || fmt.Sprint(got) != want[rule] {
			t.Errorf("%s is %s with %v; want %v", rule, rules(res)[rule], got, want[rule])
		}
	}
	for _, f := range only(res, ruleAround) {
		if f.GetFinding().GetFindingId() == id02(ruleAround, "d1024", runID) &&
			(citedEvents(f) != "obs-0000 obs-0001 obs-0002 obs-0003 obs-0004 obs-0005 obs-0006 obs-0007 obs-0008 obs-0009" ||
				f.GetRefsLeftOut() != 1015) {
			t.Errorf("the last denial cites %q and leaves out %d", citedEvents(f), f.GetRefsLeftOut())
		}
	}
}

// TestAReportAtTheTreeBoundIsWritten: a tree of MaxTreeRuns open runs, with
// the tenant, project, procedure id and version at contract.MaxStringBytes
// of a byte JSON escapes in two, and MaxSources sources never heard, each
// with the longest id a descriptor holds, makes a report the findings log
// writes within seven eighths of its line.
func TestAReportAtTheTreeBoundIsWritten(t *testing.T) {
	long := strings.Repeat(`"`, contract.MaxStringBytes)
	doc := v02With(t, `"procedure_id": "refund"`, `"procedure_id": "`+strings.Repeat(`\"`, contract.MaxStringBytes)+`"`,
		`"version": "2"`, `"version": "`+strings.Repeat(`\\`, contract.MaxStringBytes)+`"`)
	p, err := supervise.ReadProcedure([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	tree := []supervise.Run{{ID: runID, Tenant: long}}
	for i := 1; i < supervise.MaxTreeRuns; i++ {
		tree = append(tree, supervise.Run{ID: fmt.Sprintf("run-%032x", i), Tenant: long, Parent: tree[i-1].ID})
	}
	var sources []supervise.Source
	for i := range supervise.MaxSources {
		sources = append(sources, supervise.Source{SourceID: fmt.Sprintf("%0128d", i), Kind: otelKind, Tenant: long, Project: long,
			HeartbeatSeconds: math.MaxUint32})
	}
	lookup := call{req: "r1", tool: "get_order", upstream: "shop", tenant: long, proj: long}
	res, err := supervise.Evaluate(supervise.Input{Procedure: p, Run: tree[0], Tree: tree, Exports: []supervise.Export{export(lookup)}, Sources: sources})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.GetRunTree()) != supervise.MaxTreeRuns || res.Report.GetProjectId() != long || len(res.Report.GetSourcesInDoubt()) != supervise.MaxSources {
		t.Fatalf("the report names %d runs and %d sources", len(res.Report.GetRunTree()), len(res.Report.GetSourcesInDoubt()))
	}
	line, err := findinglog.Line(&findingv1alpha1.Record{Record: &findingv1alpha1.Record_SuperviseReport{SuperviseReport: res.Report}})
	if err != nil {
		t.Fatalf("the findings log refuses the report: %v", err)
	}
	t.Logf("the report takes %d bytes of %d", len(line), findinglog.MaxLineBytes)
	if len(line) > findinglog.MaxLineBytes*7/8 {
		t.Fatalf("a report of %d bytes, more than seven eighths of %d", len(line), findinglog.MaxLineBytes)
	}
}

// floodOf is a closed child's n denials of the refund on order 42, each with
// its own arguments and each followed by the order refunded by hand, all
// before the root's denial at ten seconds.
func floodOf(n int) []act {
	var as []act
	for i := range n {
		at := time.Duration(i) * time.Millisecond
		as = append(as,
			act{call: call{req: fmt.Sprintf("c%04d", i), tool: "issue_refund", upstream: "pay", at: at, outcome: "deny", run: childRun},
				res: orderNo("42"), hash: "sha256:" + fmt.Sprintf("%064x", i), effect: transact},
			act{call: call{req: fmt.Sprintf("c%04dm", i), tool: "refund_manual", upstream: "pay", at: at, run: childRun},
				res: orderNo("42"), hash: "sha256:" + fmt.Sprintf("%064x", n+i), effect: transact})
	}
	return as
}

// TestAnotherRunsFloodLeavesARetryJudged: a closed child's 4 096 denials and
// calls of the denied tool and of another on the order come first; the
// root's own denial and its retry in each form are still judged on the
// root's calls alone, confirmed by the plane and suggested by a source.
func TestAnotherRunsFloodLeavesARetryJudged(t *testing.T) {
	var reports []ob
	for i := range 512 {
		reports = append(reports, ob{id: fmt.Sprintf("obs-%04d", i), name: "issue_refund", at: 5000 * time.Second})
	}
	res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family(childRun),
		Exports: []supervise.Export{acts(append(floodOf(4096), denial(), again(), manual())...)}, Sources: []supervise.Source{source(reports...)}})
	for rule, want := range map[string]string{ruleArgs: "FINDING_VERDICT_CONFIRMED", ruleRes: "FINDING_VERDICT_CONFIRMED",
		ruleAround: "FINDING_VERDICT_SUSPECTED"} {
		var got []string
		for _, f := range only(res, rule) {
			if f.GetFinding().GetFindingId() == id02(rule, "d1", runID) {
				got = append(got, f.GetFinding().GetVerdict().String())
			}
		}
		if rules(res)[rule] != checked || len(got) != 1 || got[0] != want {
			t.Errorf("%s is %s; the root's finding on d1 is %q, want %s", rule, rules(res)[rule], got, want)
		}
	}
}
