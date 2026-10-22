package supervise_test

import (
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
)

const (
	low      = controlv1.FindingSeverity_FINDING_SEVERITY_LOW
	critical = controlv1.FindingSeverity_FINDING_SEVERITY_CRITICAL
	inform   = findingv1alpha1.Escalation_ESCALATION_INFORM
)

func id(rule string, anchor ...string) string {
	return handID(append([]string{tenant, proj, runID, "refund", "1", rule, ruleVersions[rule]}, anchor...)...)
}

// skipped is lookup and notify with no refund between them.
func skipped() []call {
	return []call{
		{req: "r1", tool: "get_order", upstream: "shop"},
		{req: "r4", tool: "send_mail", upstream: "mail", at: 30 * time.Second},
	}
}

func TestAbsenceIsJudgedOnlyOnAClosedRunWithWholeExports(t *testing.T) {
	p := procWith(t)
	closed := evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(skipped()...)}})
	sameFindings(t, closed.Findings,
		want(p, "REQUIRED_STEP_SKIPPED", high, alert, suspected, id("REQUIRED_STEP_SKIPPED", "refund")),
		want(p, "STEP_OUT_OF_ORDER", medium, inform, suspected, id("STEP_OUT_OF_ORDER", "notify"), evRef("r4-e1", "r4")))

	open := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(skipped()...)}})
	filtered := export(skipped()...)
	filtered.Whole, filtered.NotWhole = false, "a filter on the run"
	partial := evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{filtered}})
	for name, res := range map[string]*supervise.Result{"open": open, "not whole": partial} {
		sameFindings(t, res.Findings)
		why := map[string]string{"open": "the run is open", "not whole": "an export is not whole: a filter on the run"}[name]
		got := rules(res)
		for _, rule := range []string{"REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE"} {
			if got[rule] != "RULE_STATE_NOT_CHECKED:"+why {
				t.Errorf("%s: %s is %s", name, rule, got[rule])
			}
		}
		if got["REPEATED_DENIAL"] != checked || got["DEADLINE_EXCEEDED"] != checked {
			t.Errorf("%s: %v", name, got)
		}
	}
	if partial.Report.GetRead().GetExportsNotWhole() != 1 {
		t.Errorf("read %v", partial.Report.GetRead())
	}
}

func TestAnAbsenceWhileASourceIsSilentIsIndeterminate(t *testing.T) {
	p := procWith(t)
	src := source()
	src.Heard = false
	res := evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(skipped()...)}, Sources: []supervise.Source{src}})
	sameFindings(t, res.Findings,
		want(p, "REQUIRED_STEP_SKIPPED", high, alert, indetermin, id("REQUIRED_STEP_SKIPPED", "refund")),
		want(p, "STEP_OUT_OF_ORDER", medium, inform, indetermin, id("STEP_OUT_OF_ORDER", "notify"), evRef("r4-e1", "r4")))
}

// denials is lookup, then n refunds the policy denies, ten seconds apart.
func denials(n int, more ...call) []call {
	calls := []call{{req: "r1", tool: "get_order", upstream: "shop"}}
	for i := range n {
		calls = append(calls, call{req: "d" + string(rune('1'+i)), tool: "issue_refund", upstream: "pay",
			at: time.Duration(10*(i+1)) * time.Second, outcome: "deny"})
	}
	return append(calls, more...)
}

func TestDenialsFireAtMaxDenialsAndKeepTheirID(t *testing.T) {
	p := procWith(t)
	denialID := id("REPEATED_DENIAL", "issue_refund", "pay")
	four := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(denials(4)...)}})
	sameFindings(t, four.Findings, want(p, "REPEATED_DENIAL", high, alert, confirmed, denialID,
		evRef("d1-e3", "d1"), evRef("d2-e3", "d2"), evRef("d3-e3", "d3"), evRef("d4-e3", "d4")))

	atFive := procWith(t, `"max_denials":4`, `"max_denials":5`)
	sameFindings(t, evaluate(t, supervise.Input{Procedure: atFive, Exports: []supervise.Export{export(denials(4)...)}}).Findings)

	five := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(denials(5)...)}})
	sameFindings(t, five.Findings, want(p, "REPEATED_DENIAL", high, alert, confirmed, denialID,
		evRef("d1-e3", "d1"), evRef("d2-e3", "d2"), evRef("d3-e3", "d3"), evRef("d4-e3", "d4"), evRef("d5-e3", "d5")))
}

func TestAPlanesOwnBlockIsNotADenial(t *testing.T) {
	p := procWith(t)
	calls := denials(3,
		call{req: "x1", tool: "issue_refund", upstream: "pay", at: 50 * time.Second, outcome: "pause"},
		call{req: "x2", tool: "issue_refund", upstream: "pay", at: 60 * time.Second, outcome: "silent"},
		call{req: "x3", tool: "issue_refund", upstream: "pay", at: 70 * time.Second, outcome: "expired"},
		call{req: "x4", tool: "issue_refund", upstream: "pay", at: 80 * time.Second, outcome: "denied and paused"})
	res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(calls...)}})
	sameFindings(t, res.Findings)
	if want := map[string]uint64{"PAUSED": 1, "PDP_TIMEOUT": 1, "APPROVAL_EXPIRED": 1, "RULE_DENY": 1}; !maps.Equal(res.PlaneBlocks, want) {
		t.Fatalf("plane blocks %v, want %v", res.PlaneBlocks, want)
	}
	atThree := procWith(t, `"max_denials":4`, `"max_denials":3`)
	res = evaluate(t, supervise.Input{Procedure: atThree, Exports: []supervise.Export{export(calls...)}})
	sameFindings(t, res.Findings, want(atThree, "REPEATED_DENIAL", high, alert, confirmed, id("REPEATED_DENIAL", "issue_refund", "pay"),
		evRef("d1-e3", "d1"), evRef("d2-e3", "d2"), evRef("d3-e3", "d3")))
}

// TestABlockWithoutADecisionIDIsNotADenial: a block and a kernel decision
// that both carry no decision id are not told to be one decision, so four of
// them are four plane blocks and no REPEATED_DENIAL.
func TestABlockWithoutADecisionIDIsNotADenial(t *testing.T) {
	p := procWith(t)
	x := export(denials(4)...)
	for _, ev := range x.Events {
		if d := ev.GetDecision(); d != nil {
			d.DecisionId = ""
		}
	}
	res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{x}})
	sameFindings(t, res.Findings)
	if want := map[string]uint64{"RULE_DENY": 4}; !maps.Equal(res.PlaneBlocks, want) {
		t.Fatalf("plane blocks %v, want %v", res.PlaneBlocks, want)
	}
}

func TestABrokenChainOrAConflictingEventIsIndeterminate(t *testing.T) {
	p := procWith(t)
	broken := export(denials(4)...)
	broken.Events[len(broken.Events)-1].PrevEventId = "d4-e9"
	res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{broken}})
	if len(res.Findings) != 1 || res.Findings[0].GetFinding().GetVerdict() != indetermin {
		t.Fatalf("a broken chain: %s", dump(res.Findings))
	}

	again := export(call{req: "d2", tool: "issue_refund", upstream: "pay", at: 20 * time.Second, outcome: "deny"})
	res = evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(denials(4)...), again}})
	if len(res.Findings) != 1 || res.Findings[0].GetFinding().GetVerdict() != confirmed ||
		res.Report.GetRead().GetEventsLeftOut()["duplicate"] != 3 {
		t.Fatalf("an exact copy: %s %v", dump(res.Findings), res.Report.GetRead())
	}
	again.Events[0].GetProposed().Action.Name = "get_order"
	res = evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(denials(4)...), again}})
	if len(res.Findings) != 1 || res.Findings[0].GetFinding().GetVerdict() != indetermin ||
		res.Report.GetRead().GetEventsLeftOut()["conflicting id"] != 1 {
		t.Fatalf("a conflicting copy: %s %v", dump(res.Findings), res.Report.GetRead())
	}
}

// doubtOf is the ways a denial's trail falls into doubt: a broken chain, and
// a copy of one of its events read with other contents.
var doubtOf = map[string]func(x *supervise.Export, c call) []supervise.Export{
	"a broken chain": func(x *supervise.Export, c call) []supervise.Export {
		for _, ev := range x.Events {
			if ev.GetEventId() == c.req+"-e3" {
				ev.PrevEventId = c.req + "-e9"
			}
		}
		return nil
	},
	"a conflicting copy": func(_ *supervise.Export, c call) []supervise.Export {
		again := export(c)
		again.Events[0].GetProposed().Action.Name = "get_order"
		return []supervise.Export{again}
	},
}

// TestCleanDenialsAtMaxDenialsConfirmWithoutTheDoubtfulOne: four clean
// denials and one in doubt are confirmed on the four alone; three clean and
// one in doubt are indeterminate on all four, as one in doubt makes them.
func TestCleanDenialsAtMaxDenialsConfirmWithoutTheDoubtfulOne(t *testing.T) {
	p := procWith(t)
	denialID := id("REPEATED_DENIAL", "issue_refund", "pay")
	for name, doubt := range doubtOf {
		t.Run(name, func(t *testing.T) {
			calls := denials(5)
			x := export(calls...)
			res := evaluate(t, supervise.Input{Procedure: p, Exports: append([]supervise.Export{x}, doubt(&x, calls[5])...)})
			sameFindings(t, res.Findings, want(p, "REPEATED_DENIAL", high, alert, confirmed, denialID,
				evRef("d1-e3", "d1"), evRef("d2-e3", "d2"), evRef("d3-e3", "d3"), evRef("d4-e3", "d4")))

			calls = denials(4)
			x = export(calls...)
			res = evaluate(t, supervise.Input{Procedure: p, Exports: append([]supervise.Export{x}, doubt(&x, calls[4])...)})
			sameFindings(t, res.Findings, want(p, "REPEATED_DENIAL", high, alert, indetermin, denialID,
				evRef("d1-e3", "d1"), evRef("d2-e3", "d2"), evRef("d3-e3", "d3"), evRef("d4-e3", "d4")))
		})
	}
}

func closedRun(t *testing.T, p *supervise.Procedure, exports ...supervise.Export) *supervise.Result {
	t.Helper()
	return evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true}, Exports: exports})
}

func TestAStepBeforeTheStepsItFollowsIsOutOfOrderAndNotAlsoAContinuation(t *testing.T) {
	p := procWith(t)
	res := closedRun(t, p, export(
		call{req: "r1", tool: "issue_refund", upstream: "pay", outcome: "fail"},
		call{req: "r2", tool: "get_order", upstream: "shop", at: 10 * time.Second},
		call{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second},
		call{req: "r4", tool: "send_mail", upstream: "mail", at: 30 * time.Second}))
	sameFindings(t, res.Findings,
		want(p, "STEP_OUT_OF_ORDER", medium, inform, suspected, id("STEP_OUT_OF_ORDER", "refund"),
			evRef("r1-e1", "r1"), evRef("r2-e1", "r2")))

	res = closedRun(t, p, export(
		call{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
		call{req: "r4", tool: "send_mail", upstream: "mail", at: 10 * time.Second},
		call{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second}))
	sameFindings(t, res.Findings,
		want(p, "STEP_OUT_OF_ORDER", medium, inform, suspected, id("STEP_OUT_OF_ORDER", "notify"),
			evRef("r4-e1", "r4"), evRef("r3-e1", "r3")),
		want(p, "CONTINUED_AFTER_FAILURE", critical, alert, suspected, id("CONTINUED_AFTER_FAILURE", "r1"),
			evRef("r1-e4", "r1"), evRef("r3-e1", "r3")))
}

func TestADifferentStepAfterAFailureIsAContinuationAndARetryIsNot(t *testing.T) {
	p := procWith(t)
	res := closedRun(t, p, export(
		call{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
		call{req: "r2", tool: "search_docs", upstream: "docs", at: 5 * time.Second},
		call{req: "r3", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
		call{req: "r4", tool: "send_mail", upstream: "mail", at: 20 * time.Second}))
	continued := want(p, "CONTINUED_AFTER_FAILURE", critical, alert, suspected, id("CONTINUED_AFTER_FAILURE", "r1"),
		evRef("r1-e4", "r1"), evRef("r3-e1", "r3"))
	sameFindings(t, res.Findings, continued)

	for name, c := range map[string]struct {
		first []call
		want  []*findingv1alpha1.FindingRecord
	}{
		"a retry": {[]call{
			{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
			{req: "r2", tool: "get_order", upstream: "shop", at: 5 * time.Second},
		}, nil},
		"a retry at the failure's own time": {[]call{
			{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
			{req: "r2", tool: "get_order", upstream: "shop", at: 3 * time.Second},
		}, []*findingv1alpha1.FindingRecord{continued}},
		"a held request": {[]call{{req: "r1", tool: "get_order", upstream: "shop", outcome: "held"}}, nil},
	} {
		calls := append(c.first,
			call{req: "r3", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
			call{req: "r4", tool: "send_mail", upstream: "mail", at: 20 * time.Second})
		t.Run(name, func(t *testing.T) { sameFindings(t, closedRun(t, p, export(calls...)).Findings, c.want...) })
	}
}

// late is the refund done in order with the mail sent at 700 s: the run's
// events span 703 s.
func late() []call {
	return []call{
		{req: "r1", tool: "get_order", upstream: "shop"},
		{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second},
		{req: "r4", tool: "send_mail", upstream: "mail", at: 700 * time.Second},
	}
}

func TestADeadlineIsConfirmedOnOneExportAndSuspectedAcrossMore(t *testing.T) {
	at702 := procWith(t, `"deadline_seconds":600`, `"deadline_seconds":702`)
	deadlineID := handID(tenant, proj, runID, "refund", "1", "DEADLINE_EXCEEDED", "1")
	sameFindings(t, closedRun(t, at702, export(late()...)).Findings,
		want(at702, "DEADLINE_EXCEEDED", low, inform, confirmed, deadlineID, evRef("r1-e1", "r1"), evRef("r4-e4", "r4")))
	sameFindings(t, closedRun(t, at702, export(late()[:2]...), export(late()[2])).Findings,
		want(at702, "DEADLINE_EXCEEDED", low, inform, suspected, deadlineID, evRef("r1-e1", "r1"), evRef("r4-e4", "r4")))

	at703 := procWith(t, `"deadline_seconds":600`, `"deadline_seconds":703`)
	sameFindings(t, closedRun(t, at703, export(late()...)).Findings)
}

func TestARuleLeftOutIsOff(t *testing.T) {
	p := procWith(t, `"max_denials":4,"deadline_seconds":600,`, ``)
	res := evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(denials(5, call{req: "r9", tool: "send_mail", upstream: "mail", at: 900 * time.Second})...)}})
	got := rules(res)
	if got["REPEATED_DENIAL"] != "RULE_STATE_OFF:the procedure leaves max_denials out" ||
		got["DEADLINE_EXCEEDED"] != "RULE_STATE_OFF:the procedure leaves deadline_seconds out" {
		t.Fatalf("%v", got)
	}
	for _, f := range res.Findings {
		if r := f.GetFinding().GetRuleId(); r == "REPEATED_DENIAL" || r == "DEADLINE_EXCEEDED" {
			t.Fatalf("an off rule fired: %s", dump(res.Findings))
		}
	}
}

// untimed is x with the times of req's events taken away, or only of its
// event numbered n when n is not zero.
func untimed(x supervise.Export, req string, n int) supervise.Export {
	for i, ev := range x.Events {
		if ev.GetRequestId() == req && (n == 0 || ev.GetEventId() == req+"-e"+strconv.Itoa(n)) {
			x.Events[i].OccurredAt = nil
		}
	}
	return x
}

func TestAnOrderThatCannotBeToldIsIndeterminate(t *testing.T) {
	p := procWith(t)
	calls := []call{
		{req: "r1", tool: "get_order", upstream: "shop"},
		{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second},
		{req: "r4", tool: "send_mail", upstream: "mail", at: 30 * time.Second},
	}
	res := closedRun(t, p, untimed(export(calls...), "r1", 0))
	sameFindings(t, res.Findings,
		want(p, "STEP_OUT_OF_ORDER", medium, inform, indetermin, id("STEP_OUT_OF_ORDER", "refund"),
			evRef("r3-e1", "r3"), evRef("r1-e1", "r1")))
	if got := rules(res)["STEP_OUT_OF_ORDER"]; got != checked {
		t.Errorf("STEP_OUT_OF_ORDER %s", got)
	}

	res = closedRun(t, p, untimed(export(calls...), "r3", 0))
	sameFindings(t, res.Findings,
		want(p, "STEP_OUT_OF_ORDER", medium, inform, indetermin, id("STEP_OUT_OF_ORDER", "refund"),
			evRef("r3-e1", "r3"), evRef("r1-e1", "r1")),
		want(p, "STEP_OUT_OF_ORDER", medium, inform, indetermin, id("STEP_OUT_OF_ORDER", "notify"),
			evRef("r4-e1", "r4"), evRef("r3-e1", "r3")))
}

// TestAContinuationStartsAfterTheFailure: r1 fails at 3 s; r2 is proposed
// at 1 s, while r1 still runs, and is no continuation of it.
func TestAContinuationStartsAfterTheFailure(t *testing.T) {
	p := procWith(t)
	failed := []call{
		{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
		{req: "r2", tool: "issue_refund", upstream: "pay", at: time.Second},
	}
	mail := func(at time.Duration) call { return call{req: "r4", tool: "send_mail", upstream: "mail", at: at} }
	continued := func(v controlv1.FindingVerdict, next string) *findingv1alpha1.FindingRecord {
		return want(p, "CONTINUED_AFTER_FAILURE", critical, alert, v, id("CONTINUED_AFTER_FAILURE", "r1"),
			evRef("r1-e4", "r1"), evRef(next+"-e1", next))
	}
	for name, c := range map[string]struct {
		x    supervise.Export
		want []*findingv1alpha1.FindingRecord
	}{
		"a retry after the failure": {export(append(failed,
			call{req: "r5", tool: "get_order", upstream: "shop", at: 10 * time.Second}, mail(20*time.Second))...), nil},
		"another step after the failure": {export(append(failed, mail(10*time.Second))...),
			[]*findingv1alpha1.FindingRecord{continued(suspected, "r4")}},
		"another step a nanosecond after": {export(append(failed, mail(3*time.Second+1))...),
			[]*findingv1alpha1.FindingRecord{continued(suspected, "r4")}},
		"another step at the failure": {export(append(failed, mail(3*time.Second))...),
			[]*findingv1alpha1.FindingRecord{continued(indetermin, "r4")}},
		"a failure with no time": {untimed(export(failed...), "r1", 4),
			[]*findingv1alpha1.FindingRecord{continued(indetermin, "r2")}},
	} {
		t.Run(name, func(t *testing.T) { sameFindings(t, closedRun(t, p, c.x).Findings, c.want...) })
	}
}

// TestAContinuationDoesNotRestOnTheOrderRuleRunningFirst: the failed first
// refund, out of order, is no continuation whether or not STEP_OUT_OF_ORDER
// was applied before CONTINUED_AFTER_FAILURE; a failed lookup followed by a
// refund is one either way.
func TestAContinuationDoesNotRestOnTheOrderRuleRunningFirst(t *testing.T) {
	p := procWith(t)
	for _, c := range []struct {
		calls []call
		want  []string
	}{
		{[]call{
			{req: "r1", tool: "issue_refund", upstream: "pay", outcome: "fail"},
			{req: "r2", tool: "get_order", upstream: "shop", at: 10 * time.Second},
			{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second},
		}, nil},
		{[]call{
			{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
			{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second},
		}, []string{"r1"}},
	} {
		in := supervise.Input{Procedure: p, Run: supervise.Run{ID: runID, Tenant: tenant, Closed: true},
			Exports: []supervise.Export{export(c.calls...)}}
		alone, err := supervise.ApplyAlone(in, "CONTINUED_AFTER_FAILURE")
		if err != nil {
			t.Fatal(err)
		}
		var inTable []string
		for _, f := range evaluate(t, in).Findings {
			if f.GetFinding().GetRuleId() == "CONTINUED_AFTER_FAILURE" {
				inTable = append(inTable, f.GetRefs()[0].GetEvent().GetRequestId())
			}
		}
		if !slices.Equal(alone, c.want) || !slices.Equal(inTable, c.want) {
			t.Fatalf("failed %s first: alone %q, in the table %q; want %q", c.calls[0].tool, alone, inTable, c.want)
		}
	}
}
