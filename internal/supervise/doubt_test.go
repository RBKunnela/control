package supervise_test

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
)

// compliant is lookup r1 then refund r3, both completed.
func compliant() []call {
	return []call{
		{req: "r1", tool: "get_order", upstream: "shop"},
		{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second},
	}
}

// everyRuleIs is each 0.1 rule in state:why.
func everyRuleIs(state string) map[string]string {
	out := map[string]string{}
	for _, id := range []string{"REPEATED_DENIAL", "STEP_OUTSIDE_PROCEDURE", "DEADLINE_EXCEEDED",
		"REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE"} {
		out[id] = state
	}
	return out
}

// TestARequestInDoubtLeavesNoRuleCheckedOnItsTrail: a closed run that keeps
// to its procedure finds nothing whether or not refund's trail is in doubt,
// so only the rules' states tell the two apart. A trail in doubt may hide a
// failure, a denial, a tool or a time, so no rule that reads it is checked.
func TestARequestInDoubtLeavesNoRuleCheckedOnItsTrail(t *testing.T) {
	p := procWith(t)
	clean := closedRun(t, p, export(compliant()...))
	sameFindings(t, clean.Findings)
	if got, want := rules(clean), everyRuleIs(checked); !maps.Equal(got, want) {
		t.Fatalf("a clean run's rules %v, want %v", got, want)
	}
	brokenLast := func(x *supervise.Export, _ call) []supervise.Export {
		x.Events[len(x.Events)-1].PrevEventId = "r3-e9"
		return nil
	}
	for name, doubt := range map[string]func(*supervise.Export, call) []supervise.Export{
		"its last link broken": brokenLast, "a broken chain": doubtOf["a broken chain"],
		"a conflicting copy": doubtOf["a conflicting copy"],
	} {
		t.Run(name, func(t *testing.T) {
			calls := compliant()
			x := export(calls...)
			res := closedRun(t, p, append([]supervise.Export{x}, doubt(&x, calls[1])...)...)
			sameFindings(t, res.Findings)
			if got, want := rules(res), everyRuleIs(`RULE_STATE_NOT_CHECKED:request "r3" is in doubt`); !maps.Equal(got, want) {
				t.Fatalf("rules %v, want %v", got, want)
			}
		})
	}
}

// TestTheRequestInDoubtNamedIsTheLeastOfThem: which one the why names does
// not follow the order the evidence was read in.
func TestTheRequestInDoubtNamedIsTheLeastOfThem(t *testing.T) {
	p := procWith(t)
	for _, order := range [][]call{compliant(), {compliant()[1], compliant()[0]}} {
		x := export(order...)
		for _, ev := range x.Events {
			if ev.GetEventId() == "r1-e4" || ev.GetEventId() == "r3-e4" {
				ev.PrevEventId = "e9"
			}
		}
		want := everyRuleIs(`RULE_STATE_NOT_CHECKED:request "r1" and 1 more are in doubt`)
		if got := rules(closedRun(t, p, x)); !maps.Equal(got, want) {
			t.Fatalf("read %s first: rules %v, want %v", order[0].req, got, want)
		}
	}
}

// TestAFindingOnATrailInDoubtStands: the run's failed refund is followed by
// notify; the finding is written, indeterminate, and its rule not checked.
func TestAFindingOnATrailInDoubtStands(t *testing.T) {
	p := procWith(t)
	x := export(call{req: "r1", tool: "get_order", upstream: "shop"},
		call{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second, outcome: "fail"},
		call{req: "r4", tool: "send_mail", upstream: "mail", at: 30 * time.Second})
	x.Events[len(x.Events)-1].PrevEventId = "r4-e9"
	res := closedRun(t, p, x)
	sameFindings(t, res.Findings, want(p, "CONTINUED_AFTER_FAILURE", critical, alert, indetermin,
		id("CONTINUED_AFTER_FAILURE", "r3"), evRef("r3-e4", "r3"), evRef("r4-e1", "r4")))
	if got := rules(res)["CONTINUED_AFTER_FAILURE"]; got != `RULE_STATE_NOT_CHECKED:request "r4" is in doubt` {
		t.Fatalf("CONTINUED_AFTER_FAILURE is %s", got)
	}
}

// TestA02RuleOnATrailInDoubtIsNotChecked: the conforming 0.2 tree with the
// refund's last link broken checks none of the eleven rules, and
// EXCEPTION_TAKEN follows the rule its exceptions waive.
func TestA02RuleOnATrailInDoubtIsNotChecked(t *testing.T) {
	customer := orderNo("42")
	customer.Type = "crm_customer"
	customer.Id = "c1"
	x := acts(lookupOf("r1", 0, orderNo("42")), refundOf("r2", 10*time.Second, orderNo("42")).in(childRun),
		act{call: call{req: "r3", tool: "send_mail", upstream: "mail", at: 20 * time.Second}, res: customer})
	for _, ev := range x.Events {
		if ev.GetEventId() == "r2-e4" {
			ev.PrevEventId = "r2-e9"
		}
	}
	tree := closedFamily()
	res, err := supervise.Evaluate(supervise.Input{Procedure: inheritProc(t), Run: tree[0], Tree: tree,
		Exports: []supervise.Export{x}, Sources: []supervise.Source{source()}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	sameFindings(t, res.Findings)
	const doubt = `RULE_STATE_NOT_CHECKED:request "r2" is in doubt`
	want := everyRuleIs(doubt)
	for _, id := range []string{"RESOURCE_OUTSIDE_RUN", "DENIED_ACTION_RETRIED_ARGUMENTS",
		"DENIED_ACTION_RETRIED_RESOURCE", "DENIED_ACTION_RETRIED_AROUND"} {
		want[id] = doubt
	}
	want["EXCEPTION_TAKEN"] = `RULE_STATE_NOT_CHECKED:exceptions on STEP_OUTSIDE_PROCEDURE are not judged: request "r2" is in doubt`
	if got := rules(res); !maps.Equal(got, want) {
		t.Fatalf("rules %v, want %v", got, want)
	}
}

// TestADoubtLeavesARuleOffAndFollowsTheReasonItWasNotChecked: a rule the
// procedure turns off stays off, and one an open run leaves not checked
// names that reason first and the doubt after it.
func TestADoubtLeavesARuleOffAndFollowsTheReasonItWasNotChecked(t *testing.T) {
	const doubt = `RULE_STATE_NOT_CHECKED:request "r3" is in doubt`
	open := `RULE_STATE_NOT_CHECKED:the run is open; request "r3" is in doubt`
	for name, c := range map[string]struct {
		p      *supervise.Procedure
		closed bool
		want   map[string]string
	}{
		"max_denials left out": {procWith(t, `"max_denials":4,`, ""), true, map[string]string{
			"REPEATED_DENIAL": "RULE_STATE_OFF:the procedure leaves max_denials out", "STEP_OUTSIDE_PROCEDURE": doubt,
			"DEADLINE_EXCEEDED": doubt, "REQUIRED_STEP_SKIPPED": doubt, "STEP_OUT_OF_ORDER": doubt,
			"CONTINUED_AFTER_FAILURE": doubt}},
		"an open run": {procWith(t), false, map[string]string{
			"REPEATED_DENIAL": doubt, "STEP_OUTSIDE_PROCEDURE": doubt, "DEADLINE_EXCEEDED": doubt,
			"REQUIRED_STEP_SKIPPED": open, "STEP_OUT_OF_ORDER": open, "CONTINUED_AFTER_FAILURE": open}},
	} {
		t.Run(name, func(t *testing.T) {
			x := export(compliant()...)
			x.Events[len(x.Events)-1].PrevEventId = "r3-e9"
			res := evaluate(t, supervise.Input{Procedure: c.p, Run: supervise.Run{Closed: c.closed}, Exports: []supervise.Export{x}})
			if got := rules(res); !maps.Equal(got, c.want) {
				t.Fatalf("rules %v, want %v", got, c.want)
			}
		})
	}
}

// TestALongIDInDoubtIsQuotedAndCut: the why quotes at most 64 bytes of the
// request id, so a producer's id cannot grow the report past its line.
func TestALongIDInDoubtIsQuotedAndCut(t *testing.T) {
	long := "r" + strings.Repeat("x", 12000)
	x := export(append(compliant(), call{req: long, tool: "send_mail", upstream: "mail", at: 30 * time.Second})...)
	want := `RULE_STATE_NOT_CHECKED:request "r` + strings.Repeat("x", 63) + `" (truncated) is in doubt`
	if got := rules(closedRun(t, procWith(t), x)); !maps.Equal(got, everyRuleIs(want)) {
		t.Fatalf("rules %v, want each %q", got, want)
	}
}

// TestAnObservationInDoubtLeavesTheRulesThatReadReportsNotChecked: obs-9 is
// read with two contents, a step's name and a name outside the procedure.
// Whichever is read first, no rule that reads a source's reports is
// checked, so neither order passes.
func TestAnObservationInDoubtLeavesTheRulesThatReadReportsNotChecked(t *testing.T) {
	p := procWith(t)
	inside := ob{id: "obs-9", name: "get_order", span: "9999999999999999", at: 5 * time.Second}
	outside := inside
	outside.name = "drop_table"
	for name, order := range map[string][]ob{"outside first": {outside, inside}, "inside first": {inside, outside}} {
		t.Run(name, func(t *testing.T) {
			res := evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
				Exports: []supervise.Export{export(conforming()...)}, Sources: []supervise.Source{source(order...)}})
			want := everyRuleIs(checked)
			want["STEP_OUTSIDE_PROCEDURE"] = `RULE_STATE_NOT_CHECKED:observation "obs-9" is in doubt`
			if got := rules(res); !maps.Equal(got, want) {
				t.Fatalf("rules %v, want %v", got, want)
			}
		})
	}
}

// refusedTail is the why's tail for a source whose imports refused a copy
// that may be a call of a run judged.
const refusedTail = " is in doubt: an import refused a copy that may be a call of a run judged"

// doubtedIn is the conforming 0.2 tree, root, child and grandchild under
// inherit, supervised with sources s1 and s2 as given, and its rules.
func doubtedIn(t *testing.T, s1, s2 supervise.Source) map[string]string {
	t.Helper()
	customer := orderNo("42")
	customer.Type = "crm_customer"
	customer.Id = "c1"
	x := acts(lookupOf("r1", 0, orderNo("42")), refundOf("r2", 10*time.Second, orderNo("42")).in(childRun),
		act{call: call{req: "r3", tool: "send_mail", upstream: "mail", at: 20 * time.Second}, res: customer})
	s1.SourceID, s1.HeartbeatSeconds, s1.LastHeard, s1.Heard = "s1", 300, t0.Add(time.Hour), true
	s2.SourceID, s2.HeartbeatSeconds, s2.LastHeard, s2.Heard = "s2", 300, t0.Add(time.Hour), true
	tree := closedFamily()
	res, err := supervise.Evaluate(supervise.Input{Procedure: inheritProc(t), Run: tree[0], Tree: tree,
		Exports: []supervise.Export{x}, Sources: []supervise.Source{s1, s2}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	sameFindings(t, res.Findings)
	return rules(res)
}

func doubting(every bool, runs ...string) supervise.Source {
	return supervise.Source{Kind: otelKind, Tenant: tenant, Project: proj, EveryRunDoubted: every, DoubtedRuns: runs}
}

// TestARefusedCopyOfARunJudgedLeavesTheRulesThatReadReportsNotChecked: a
// copy an import refused, a span or an observation whose id the log held
// with other content, was never read and may be the call a rule that reads
// a source's reports looks for. It leaves those rules not checked when it
// claimed a run of the tree under inherit, or no run; one that claimed a
// run outside the tree changes nothing.
func TestARefusedCopyOfARunJudgedLeavesTheRulesThatReadReportsNotChecked(t *testing.T) {
	all := everyRuleIs(checked)
	for _, id := range []string{"RESOURCE_OUTSIDE_RUN", "DENIED_ACTION_RETRIED_ARGUMENTS",
		"DENIED_ACTION_RETRIED_RESOURCE", "DENIED_ACTION_RETRIED_AROUND", "EXCEPTION_TAKEN"} {
		all[id] = checked
	}
	for name, c := range map[string]struct {
		s1, s2 supervise.Source
		why    string
	}{
		"none":                     {doubting(false), doubting(false), ""},
		"a run outside the tree":   {doubting(false, outsiderRun, siblingRun), doubting(false), ""},
		"the root":                 {doubting(false), doubting(false, runID), `source "s2"` + refusedTail},
		"the grandchild":           {doubting(false, grandchildRun, outsiderRun), doubting(false), `source "s1"` + refusedTail},
		"every run":                {doubting(true), doubting(false), `source "s1"` + refusedTail},
		"every run and a child's":  {doubting(true), doubting(false, childRun), `source "s1" and 1 more are in doubt: an import refused a copy that may be a call of a run judged`},
		"every run and an outside": {doubting(false, outsiderRun), doubting(true), `source "s2"` + refusedTail},
	} {
		t.Run(name, func(t *testing.T) {
			want := maps.Clone(all)
			if c.why != "" {
				want["STEP_OUTSIDE_PROCEDURE"] = "RULE_STATE_NOT_CHECKED:" + c.why
				want["DENIED_ACTION_RETRIED_AROUND"] = "RULE_STATE_NOT_CHECKED:" + c.why
				want["EXCEPTION_TAKEN"] = "RULE_STATE_NOT_CHECKED:exceptions on STEP_OUTSIDE_PROCEDURE are not judged: " + c.why
			}
			if got := doubtedIn(t, c.s1, c.s2); !maps.Equal(got, want) {
				t.Fatalf("rules %v, want %v", got, want)
			}
		})
	}
}

// TestARefusedCopyOfAnotherRunLeavesThisRunChecked: under 0.1 the run is
// judged alone, so a copy that claimed run A is doubt for A and none for B.
func TestARefusedCopyOfAnotherRunLeavesThisRunChecked(t *testing.T) {
	for run, want := range map[string]string{
		runID:    `RULE_STATE_NOT_CHECKED:source "s1"` + refusedTail,
		childRun: checked,
	} {
		src := source()
		src.DoubtedRuns = []string{run}
		res := evaluate(t, supervise.Input{Procedure: procWith(t), Run: supervise.Run{Closed: true},
			Exports: []supervise.Export{export(conforming()...)}, Sources: []supervise.Source{src}})
		if got := rules(res)["STEP_OUTSIDE_PROCEDURE"]; got != want {
			t.Errorf("a refused copy of %s: STEP_OUTSIDE_PROCEDURE %s, want %s", run, got, want)
		}
	}
}

// TestALongSourceIDInDoubtIsQuotedAndCut: the why quotes at most 64 bytes of
// the source id, as it does a request's.
func TestALongSourceIDInDoubtIsQuotedAndCut(t *testing.T) {
	src := source()
	src.SourceID, src.EveryRunDoubted = "s"+strings.Repeat("x", 12000), true
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(conforming()...)}, Sources: []supervise.Source{src}})
	want := `RULE_STATE_NOT_CHECKED:source "s` + strings.Repeat("x", 63) + `" (truncated)` + refusedTail
	if got := rules(res)["STEP_OUTSIDE_PROCEDURE"]; got != want {
		t.Fatalf("STEP_OUTSIDE_PROCEDURE %s, want %s", got, want)
	}
}

// TestAnObservationAndASourceInDoubtAreBothNamed: obs-9 read with two
// contents and a source whose import refused a copy are two doubts, and the
// why names each.
func TestAnObservationAndASourceInDoubtAreBothNamed(t *testing.T) {
	inside := ob{id: "obs-9", name: "get_order", span: "9999999999999999", at: 5 * time.Second}
	outside := inside
	outside.name = "drop_table"
	src := source(inside, outside)
	src.EveryRunDoubted = true
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(conforming()...)}, Sources: []supervise.Source{src}})
	want := `RULE_STATE_NOT_CHECKED:observation "obs-9" is in doubt; source "s1"` + refusedTail
	if got := rules(res)["STEP_OUTSIDE_PROCEDURE"]; got != want {
		t.Fatalf("STEP_OUTSIDE_PROCEDURE %s, want %s", got, want)
	}
}

// TestAFindingOnARunInDoubtIsIndeterminate: drop_table, reported by s1 alone
// for the run, is a call outside the procedure. While s1's imports refused a
// copy of the run, or of no run, the finding stands, indeterminate, since
// the refused copy may be the call that was made; a refused copy of another
// run leaves it suspected.
func TestAFindingOnARunInDoubtIsIndeterminate(t *testing.T) {
	p := procWith(t)
	for name, c := range map[string]struct {
		src     supervise.Source
		verdict controlv1.FindingVerdict
	}{
		"nothing refused":        {doubting(false), suspected},
		"a copy of another run":  {doubting(false, childRun), suspected},
		"a copy of the run":      {doubting(false, childRun, runID), indetermin},
		"a copy claiming no run": {doubting(true), indetermin},
	} {
		t.Run(name, func(t *testing.T) {
			src := source(ob{id: "obs-1", name: "drop_table", span: "1000000000000001", at: 40 * time.Second})
			src.EveryRunDoubted, src.DoubtedRuns = c.src.EveryRunDoubted, c.src.DoubtedRuns
			res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(conforming()...)},
				Sources: []supervise.Source{src}})
			sameFindings(t, res.Findings, want(p, "STEP_OUTSIDE_PROCEDURE", medium, alert, c.verdict,
				handID(tenant, proj, runID, "refund", "1", "STEP_OUTSIDE_PROCEDURE", "1", "drop_table"), obsRef("s1", "obs-1")))
		})
	}
}

// TestADoubtCitesTheObservationsOfItsOwnRun: under inherit, drop_table is
// observed for the child alone. A refused copy of the child makes that
// finding indeterminate; one of the root leaves the rules that read reports
// not checked but the child's finding suspected, since no copy of the child
// was refused.
func TestADoubtCitesTheObservationsOfItsOwnRun(t *testing.T) {
	customer := orderNo("42")
	customer.Type = "crm_customer"
	customer.Id = "c1"
	x := acts(lookupOf("r1", 0, orderNo("42")), refundOf("r2", 10*time.Second, orderNo("42")).in(childRun),
		act{call: call{req: "r3", tool: "send_mail", upstream: "mail", at: 20 * time.Second}, res: customer})
	for run, want := range map[string]string{
		childRun: runID + " FINDING_VERDICT_INDETERMINATE",
		runID:    runID + " FINDING_VERDICT_SUSPECTED",
	} {
		src := source(ob{id: "obs-1", name: "drop_table", run: childRun, span: "1000000000000001", at: 40 * time.Second})
		src.DoubtedRuns = []string{run}
		tree := closedFamily()
		res, err := supervise.Evaluate(supervise.Input{Procedure: inheritProc(t), Run: tree[0], Tree: tree,
			Exports: []supervise.Export{x}, Sources: []supervise.Source{src}})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if got := verdicts(res, "STEP_OUTSIDE_PROCEDURE"); !slices.Equal(got, []string{want}) {
			t.Errorf("a refused copy of %s: STEP_OUTSIDE_PROCEDURE findings %v, want %s", run, got, want)
		}
	}
}

// TestEveryCauseThatCutsARuleIsNamed: a rule that reads reports and is cut
// for more than one cause names each, the reason it was already not checked
// first, then the request, observation and source in doubt and a walk cut
// short, joined by "; ".
func TestEveryCauseThatCutsARuleIsNamed(t *testing.T) {
	const walk = "a span walk ran out of steps, so a source's report may be a plane call"
	src := chain(supervise.MaxWalkSteps+1, ob{id: "obs-top", name: "search_docs"}, observev1.SubjectKind_SUBJECT_KIND_AGENT, "mcp_call")
	src.EveryRunDoubted = true
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Sources: []supervise.Source{src}, Exports: []supervise.Export{
		export(call{req: "r5", tool: "search_docs", upstream: "docs", span: spanAt(supervise.MaxWalkSteps)})}})
	want := `RULE_STATE_NOT_CHECKED:source "s1"` + refusedTail + "; " + walk
	if got := rules(res)["STEP_OUTSIDE_PROCEDURE"]; got != want {
		t.Errorf("a cut walk and a source in doubt: STEP_OUTSIDE_PROCEDURE %s, want %s", got, want)
	}

	silent, doubted := doubting(false), doubting(true)
	silent.SourceID, silent.HeartbeatSeconds, silent.LastHeard, silent.Heard = "s1", 300, t0.Add(-time.Hour), true
	doubted.SourceID, doubted.HeartbeatSeconds, doubted.LastHeard, doubted.Heard = "s2", 300, t0.Add(time.Hour), true
	tree := closedFamily()
	res, err := supervise.Evaluate(supervise.Input{Procedure: inheritProc(t), Run: tree[0], Tree: tree,
		Exports: []supervise.Export{acts(lookupOf("r1", 0, orderNo("42")))}, Sources: []supervise.Source{silent, doubted}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for rule, want := range map[string]string{
		"DENIED_ACTION_RETRIED_AROUND": `RULE_STATE_NOT_CHECKED:a source is silent, never heard or not read; source "s2"` + refusedTail,
		"STEP_OUTSIDE_PROCEDURE":       `RULE_STATE_NOT_CHECKED:source "s2"` + refusedTail,
	} {
		if got := rules(res)[rule]; got != want {
			t.Errorf("a silent source and a source in doubt: %s %s, want %s", rule, got, want)
		}
	}
}

// TestARequestInDoubtJoinsTheOtherCauses: a request in doubt cuts every rule,
// and a rule that reads reports names the source in doubt after it rather
// than the request alone.
func TestARequestInDoubtJoinsTheOtherCauses(t *testing.T) {
	x := export(compliant()...)
	x.Events[len(x.Events)-1].PrevEventId = "r3-e9"
	src := source()
	src.EveryRunDoubted = true
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{x}, Sources: []supervise.Source{src}})
	want := map[string]string{
		"STEP_OUTSIDE_PROCEDURE": `RULE_STATE_NOT_CHECKED:request "r3" is in doubt; source "s1"` + refusedTail,
		"REQUIRED_STEP_SKIPPED":  `RULE_STATE_NOT_CHECKED:request "r3" is in doubt`,
	}
	for rule, w := range want {
		if got := rules(res)[rule]; got != w {
			t.Errorf("%s %s, want %s", rule, got, w)
		}
	}
}

// TestARuleNotCheckedNamesEveryDoubtAfterItsReason: DENIED_ACTION_RETRIED_AROUND,
// not checked while s1 is silent, names after that reason both doubts, s2's
// refused copy and s1's cut walk, in order.
func TestARuleNotCheckedNamesEveryDoubtAfterItsReason(t *testing.T) {
	const walk = "a span walk ran out of steps, so a source's report may be a plane call"
	silent := chain(supervise.MaxWalkSteps+1, ob{id: "obs-top", name: "search_docs"}, observev1.SubjectKind_SUBJECT_KIND_AGENT, "mcp_call")
	silent.LastHeard = t0.Add(-time.Hour)
	doubted := doubting(true)
	doubted.SourceID, doubted.HeartbeatSeconds, doubted.LastHeard, doubted.Heard = "s2", 300, t0.Add(time.Hour), true
	tree := closedFamily()
	foot := act{call: call{req: "r5", tool: "search_docs", upstream: "docs", span: spanAt(supervise.MaxWalkSteps), at: 5 * time.Second}}
	res, err := supervise.Evaluate(supervise.Input{Procedure: inheritProc(t), Run: tree[0], Tree: tree,
		Exports: []supervise.Export{acts(lookupOf("r1", 0, orderNo("42")), foot)}, Sources: []supervise.Source{silent, doubted}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := `RULE_STATE_NOT_CHECKED:a source is silent, never heard or not read; source "s2"` + refusedTail + "; " + walk
	if got := rules(res)["DENIED_ACTION_RETRIED_AROUND"]; got != want {
		t.Errorf("DENIED_ACTION_RETRIED_AROUND %s, want %s", got, want)
	}
}
