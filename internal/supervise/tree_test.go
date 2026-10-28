package supervise_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	grandchildRun = "run-22222222222222222222222222222222"
	outsiderRun   = "run-ffffffffffffffffffffffffffffffff"
)

func inheritProc(t *testing.T) *supervise.Procedure {
	t.Helper()
	p, err := supervise.ReadProcedure([]byte(v02Doc(t)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func separateProc(t *testing.T) *supervise.Procedure {
	t.Helper()
	p, err := supervise.ReadProcedure([]byte(v02With(t, `"children": "inherit"`, `"children": "separate"`)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// family is the root runID, its child and the child's child, every one
// open unless closed names it.
func family(closed ...string) []supervise.Run {
	tree := []supervise.Run{
		{ID: runID, Tenant: tenant},
		{ID: childRun, Tenant: tenant, Parent: runID},
		{ID: grandchildRun, Tenant: tenant, Parent: childRun},
	}
	for i := range tree {
		for _, c := range closed {
			tree[i].Closed = tree[i].Closed || tree[i].ID == c
		}
	}
	return tree
}

// treeEvaluate is Evaluate with the tree's first run supervised.
func treeEvaluate(t *testing.T, in supervise.Input) *supervise.Result {
	t.Helper()
	if len(in.Tree) > 0 {
		in.Run = in.Tree[0]
	}
	res, err := supervise.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

// spread is lookup in the root, then a denied refund in each of the root, the
// child, the grandchild and a run outside the tree, ten seconds apart.
func spread() []call {
	return []call{
		{req: "r1", tool: "get_order", upstream: "shop"},
		{req: "d1", tool: "issue_refund", upstream: "pay", at: 10 * time.Second, outcome: "deny"},
		{req: "d2", tool: "issue_refund", upstream: "pay", at: 20 * time.Second, outcome: "deny", run: childRun},
		{req: "d3", tool: "issue_refund", upstream: "pay", at: 30 * time.Second, outcome: "deny", run: grandchildRun},
		{req: "d4", tool: "issue_refund", upstream: "pay", at: 40 * time.Second, outcome: "deny", run: outsiderRun},
	}
}

func deniedRequests(res *supervise.Result) string {
	var out []string
	for _, f := range res.Findings {
		if f.GetFinding().GetRuleId() != supervise.RuleRepeatedDenial {
			continue
		}
		for _, r := range f.GetRefs() {
			out = append(out, r.GetEvent().GetRequestId())
		}
	}
	return strings.Join(out, " ")
}

// TestAGrandchildsEventCountsUnderInherit: under inherit the denials of the
// root, its child and its grandchild are three, and at a bound of three they
// fire on the grandchild, whose denial is the third, citing its own first;
// the outside run's is left out. Under separate, and under 0.1, only the
// supervised run's own events are read.
func TestAGrandchildsEventCountsUnderInherit(t *testing.T) {
	x := export(spread()...)
	inherit := treeEvaluate(t, supervise.Input{Procedure: procAt3(t, inheritProc(t)), Tree: family(), Exports: []supervise.Export{x}})
	if got := inherit.Report.GetRead(); got.GetEventsTaken() != 13 || got.GetEventsLeftOut()["another run"] != 3 {
		t.Fatalf("inherit read %v; want 13 events taken and the outside run's 3 left out", got)
	}
	if got, run := deniedRequests(inherit), verdicts(inherit, supervise.RuleRepeatedDenial); got != "d3 d1 d2" ||
		!slices.Equal(run, []string{grandchildRun + " FINDING_VERDICT_SUSPECTED"}) {
		t.Fatalf("inherit: REPEATED_DENIAL is %q resting on %q, want the grandchild suspected on d3 d1 d2", run, got)
	}

	separate := treeEvaluate(t, supervise.Input{Procedure: procAt3(t, separateProc(t)), Tree: family()[:2],
		Exports: []supervise.Export{x}})
	if got := separate.Report.GetRead(); got.GetEventsTaken() != 7 || got.GetEventsLeftOut()["another run"] != 9 {
		t.Fatalf("separate read %v; want the root's 7 events taken and 9 left out", got)
	}
	if got := deniedRequests(separate); got != "" {
		t.Fatalf("separate: REPEATED_DENIAL rests on %q, want none", got)
	}

	old := evaluate(t, supervise.Input{Procedure: procWith(t, `"max_denials":4`, `"max_denials":3`), Exports: []supervise.Export{x}})
	if got := old.Report.GetRead(); got.GetEventsTaken() != 7 || deniedRequests(old) != "" {
		t.Fatalf("0.1 read %v, denials %q; want the root's 7 events and no finding", got, deniedRequests(old))
	}
}

// procAt3 is p with max_denials 3. The fixtures state 4, so a test that
// leaves this out fires nothing at three denials.
func procAt3(t *testing.T, p *supervise.Procedure) *supervise.Procedure {
	t.Helper()
	doc := v02Doc(t)
	if p.Children() == supervise.ChildrenSeparate {
		doc = v02With(t, `"children": "inherit"`, `"children": "separate"`)
	}
	at3, err := supervise.ReadProcedure([]byte(strings.Replace(doc, `"max_denials": 4`, `"max_denials": 3`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	return at3
}

// TestAnObservationOfAChildIsTheTreesUnderInherit: a source's report of a
// call it claims for the grandchild is read under inherit and left out
// under separate.
func TestAnObservationOfAChildIsTheTreesUnderInherit(t *testing.T) {
	src := source(ob{id: "obs-1", name: "search_docs", run: grandchildRun, span: "1111111111111111"})
	x := export(conforming()...)
	inherit := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family(), Exports: []supervise.Export{x},
		Sources: []supervise.Source{src}})
	separate := treeEvaluate(t, supervise.Input{Procedure: separateProc(t), Tree: family()[:2], Exports: []supervise.Export{x},
		Sources: []supervise.Source{src}})
	if got := inherit.Report.GetRead().GetObservationsTaken(); got != 1 {
		t.Errorf("inherit took %d observations, want 1", got)
	}
	if got := separate.Report.GetRead(); got.GetObservationsTaken() != 0 || got.GetObservationsLeftOut()["another run"] != 1 {
		t.Errorf("separate read %v, want the grandchild's observation left out", got)
	}
}

// TestARootClosedWithAnOpenChildKeepsTheTreeOpen: under inherit the rules
// that rest on what was not seen wait for every run of the tree; under
// separate the children are not judged, so the root's close is enough.
func TestARootClosedWithAnOpenChildKeepsTheTreeOpen(t *testing.T) {
	x := export(conforming()...)
	absence := []string{"REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE"}
	for name, c := range map[string]struct {
		p    *supervise.Procedure
		tree []supervise.Run
		want string
	}{
		"inherit, the root closed":     {inheritProc(t), family(runID), "RULE_STATE_NOT_CHECKED:run " + childRun + " of the tree is open"},
		"inherit, the grandchild open": {inheritProc(t), family(runID, childRun), "RULE_STATE_NOT_CHECKED:run " + grandchildRun + " of the tree is open"},
		"inherit, the root open":       {inheritProc(t), family(childRun, grandchildRun), "RULE_STATE_NOT_CHECKED:the run is open"},
		"inherit, every run closed":    {inheritProc(t), family(runID, childRun, grandchildRun), checked},
		"separate, the root closed":    {separateProc(t), family(runID)[:2], checked},
	} {
		t.Run(name, func(t *testing.T) {
			got := rules(treeEvaluate(t, supervise.Input{Procedure: c.p, Tree: c.tree, Exports: []supervise.Export{x}}))
			for _, rule := range absence {
				if got[rule] != c.want {
					t.Errorf("%s is %s, want %s", rule, got[rule], c.want)
				}
			}
		})
	}
}

// TestTheReportNamesTheTreeUnder02Only: a 0.2 report carries the children
// mode and the tree, the supervised run first; a 0.1 report carries neither.
func TestTheReportNamesTheTreeUnder02Only(t *testing.T) {
	x := export(conforming()...)
	member := func(id, parent string) *findingv1alpha1.RunTreeMember {
		return &findingv1alpha1.RunTreeMember{RunId: id, ParentRunId: parent}
	}
	inherit := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family(), Exports: []supervise.Export{x}}).Report
	wantInherit := []*findingv1alpha1.RunTreeMember{member(runID, ""), member(childRun, runID), member(grandchildRun, childRun)}
	sameTree(t, "inherit", inherit, "0.2", findingv1alpha1.ChildrenMode_CHILDREN_MODE_INHERIT, wantInherit)

	child := []supervise.Run{{ID: childRun, Tenant: tenant, Parent: runID}, {ID: grandchildRun, Tenant: tenant, Parent: childRun}}
	separate := treeEvaluate(t, supervise.Input{Procedure: separateProc(t), Tree: child, Exports: []supervise.Export{x}}).Report
	sameTree(t, "separate", separate, "0.2", findingv1alpha1.ChildrenMode_CHILDREN_MODE_SEPARATE,
		[]*findingv1alpha1.RunTreeMember{member(childRun, runID), member(grandchildRun, childRun)})

	old := evaluate(t, supervise.Input{Procedure: procWith(t), Exports: []supervise.Export{x}}).Report
	sameTree(t, "0.1", old, "0.1", findingv1alpha1.ChildrenMode_CHILDREN_MODE_UNSPECIFIED, nil)
}

func sameTree(t *testing.T, name string, r *findingv1alpha1.SuperviseReport, schema string,
	mode findingv1alpha1.ChildrenMode, tree []*findingv1alpha1.RunTreeMember) {
	t.Helper()
	if r.GetSchemaVersion() != schema || r.GetChildren() != mode || len(r.GetRunTree()) != len(tree) {
		t.Fatalf("%s: report %s; want schema %s, %s and %d members", name, protojson.Format(r), schema, mode, len(tree))
	}
	for i := range tree {
		if !proto.Equal(r.GetRunTree()[i], tree[i]) {
			t.Fatalf("%s: member %d is %v, want %v", name, i, r.GetRunTree()[i], tree[i])
		}
	}
}

// TestATreeItCannotJudgeIsRefused: each refusal against the same input with
// one thing changed, which the first case shows is accepted.
func TestATreeItCannotJudgeIsRefused(t *testing.T) {
	x := []supervise.Export{export(conforming()...)}
	edit := func(f func([]supervise.Run) []supervise.Run) []supervise.Run { return f(family()) }
	for name, c := range map[string]struct {
		p      *supervise.Procedure
		run    *supervise.Run
		tree   []supervise.Run
		refuse bool
	}{
		"the tree as given": {inheritProc(t), nil, family(), false},
		"a member of another tenant": {inheritProc(t), nil,
			edit(func(r []supervise.Run) []supervise.Run { r[2].Tenant = "t2"; return r }), true},
		"a member before its parent": {inheritProc(t), nil,
			edit(func(r []supervise.Run) []supervise.Run { r[1], r[2] = r[2], r[1]; return r }), true},
		"a member whose parent is outside": {inheritProc(t), nil,
			edit(func(r []supervise.Run) []supervise.Run { r[2].Parent = outsiderRun; return r }), true},
		"a member twice": {inheritProc(t), nil,
			edit(func(r []supervise.Run) []supervise.Run { return append(r, r[2]) }), true},
		"a member that is no opened run": {inheritProc(t), nil,
			edit(func(r []supervise.Run) []supervise.Run { r[2].ID = "run-1"; return r }), true},
		"a child as the root of an inherited tree": {inheritProc(t), nil, family()[1:2], true},
		"a tree that starts at another run": {separateProc(t), &supervise.Run{ID: childRun, Tenant: tenant, Parent: runID},
			family()[:2], true},
		"a grandchild under separate": {separateProc(t), nil, family(), true},
		"a separate run whose parent is no opened run": {separateProc(t), nil,
			[]supervise.Run{{ID: childRun, Tenant: tenant, Parent: "run-1"}}, true},
		"a child under separate": {separateProc(t), nil, family()[:2], false},
	} {
		t.Run(name, func(t *testing.T) {
			in := supervise.Input{Procedure: c.p, Tree: c.tree, Exports: x}
			in.Run = c.tree[0]
			if c.run != nil {
				in.Run = *c.run
			}
			_, err := supervise.Evaluate(in)
			refused := errors.Is(err, supervise.ErrInput) || errors.Is(err, supervise.ErrRunID)
			if refused != c.refuse || (!c.refuse && err != nil) {
				t.Fatalf("Evaluate = %v, refused %t; want refused %t", err, refused, c.refuse)
			}
		})
	}
}

// TestA01ProcedureJudgesOneRootRun: a 0.1 procedure takes neither a tree
// beyond the run nor a child as the run.
func TestA01ProcedureJudgesOneRootRun(t *testing.T) {
	x := []supervise.Export{export(conforming()...)}
	for name, in := range map[string]supervise.Input{
		"a tree":  {Run: family()[0], Tree: family()},
		"a child": {Run: family()[1]},
	} {
		in.Procedure, in.Exports = procWith(t), x
		if _, err := supervise.Evaluate(in); !errors.Is(err, supervise.ErrInput) {
			t.Errorf("%s: Evaluate = %v, want ErrInput", name, err)
		}
	}
	if _, err := supervise.Evaluate(supervise.Input{Procedure: procWith(t), Run: family()[0], Tree: family()[:1], Exports: x}); err != nil {
		t.Errorf("the run alone as its tree: %v", err)
	}
}

// TestATreeIsBoundedByMaxTreeRuns: a tree of MaxTreeRuns is judged and one
// more is refused.
func TestATreeIsBoundedByMaxTreeRuns(t *testing.T) {
	tree := []supervise.Run{{ID: runID, Tenant: tenant}}
	for i := 1; i < supervise.MaxTreeRuns; i++ {
		tree = append(tree, supervise.Run{ID: fmt.Sprintf("run-%032x", i), Tenant: tenant, Parent: runID})
	}
	x := []supervise.Export{export(conforming()...)}
	if _, err := supervise.Evaluate(supervise.Input{Procedure: inheritProc(t), Run: tree[0], Tree: tree, Exports: x}); err != nil {
		t.Fatalf("a tree of %d: %v", len(tree), err)
	}
	tree = append(tree, supervise.Run{ID: fmt.Sprintf("run-%032x", supervise.MaxTreeRuns), Tenant: tenant, Parent: runID})
	if _, err := supervise.Evaluate(supervise.Input{Procedure: inheritProc(t), Run: tree[0], Tree: tree, Exports: x}); !errors.Is(err, supervise.ErrInput) {
		t.Fatalf("a tree of %d: %v, want ErrInput", len(tree), err)
	}
}

// TestARequestThatNamesTwoRunsConfirmsNothing: a request of the root whose
// completion names the child is a broken chain, a plane stamping one run on a
// whole trail, so the request is in doubt: neither run gets a confirmed
// deadline finding from it, and every rule the doubt reaches is not checked
// and names it.
func TestARequestThatNamesTwoRunsConfirmsNothing(t *testing.T) {
	x := export(call{req: "r1", tool: "get_order", upstream: "shop"})
	last := x.Events[len(x.Events)-1]
	if last.GetKind() != controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED {
		t.Fatalf("fixture: the last event is %v", last.GetKind())
	}
	last.RunId = childRun
	last.OccurredAt = at(700 * time.Second)
	res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family(), Exports: []supervise.Export{x}})
	for _, v := range verdicts(res, supervise.RuleDeadlineExceeded) {
		if v == childC || v == rootC {
			t.Fatalf("DEADLINE_EXCEEDED %q from a request that names two runs, want no confirmed finding", v)
		}
	}
	got := rules(res)
	for _, id := range []string{"REPEATED_DENIAL", "STEP_OUTSIDE_PROCEDURE", "DEADLINE_EXCEEDED",
		"REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE", "RESOURCE_OUTSIDE_RUN",
		"DENIED_ACTION_RETRIED_ARGUMENTS", "DENIED_ACTION_RETRIED_RESOURCE", "DENIED_ACTION_RETRIED_AROUND"} {
		state, ok := got[id]
		switch {
		case !ok:
			t.Errorf("the report lists no %s", id)
		case !strings.HasPrefix(state, "RULE_STATE_NOT_CHECKED:") || !strings.HasSuffix(state, `request "r1" is in doubt`):
			t.Errorf("%s is %s, want it not checked because request \"r1\" is in doubt", id, state)
		}
	}
}

// TestARequestWithAnEventOutsideTheRunsReadIsInDoubt: the run's read leaves
// out an event of a run it does not judge, or of none, so the request's
// events it keeps would chain as a whole trail. The request is in doubt
// instead, whichever run its left-out event names.
func TestARequestWithAnEventOutsideTheRunsReadIsInDoubt(t *testing.T) {
	root := supervise.Run{ID: runID, Tenant: tenant}
	for name, tc := range map[string]struct {
		run string
		in  supervise.Input
	}{
		"a run outside the tree":     {outsiderRun, supervise.Input{Procedure: inheritProc(t), Run: family()[0], Tree: family()}},
		"the child, the root judged": {childRun, supervise.Input{Procedure: procWith(t), Run: root}},
		"no run":                     {"", supervise.Input{Procedure: procWith(t), Run: root}},
	} {
		t.Run(name, func(t *testing.T) {
			x := export(call{req: "r1", tool: "get_order", upstream: "shop"})
			last := x.Events[len(x.Events)-1]
			last.RunId = tc.run
			last.OccurredAt = at(700 * time.Second)
			tc.in.Exports = []supervise.Export{x}
			res, err := supervise.Evaluate(tc.in)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got := res.Report.GetRead().GetEventsLeftOut()["another run"]; got != 1 {
				t.Fatalf("events left out as another run: %d, want 1", got)
			}
			got := rules(res)
			for _, id := range []string{"REPEATED_DENIAL", "STEP_OUTSIDE_PROCEDURE", "DEADLINE_EXCEEDED",
				"REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE"} {
				if state := got[id]; !strings.HasPrefix(state, "RULE_STATE_NOT_CHECKED:") || !strings.HasSuffix(state, `request "r1" is in doubt`) {
					t.Errorf("%s is %q, want it not checked because request \"r1\" is in doubt", id, state)
				}
			}
		})
	}
}

// TestARequestWhollyInAnotherRunPutsNothingInDoubt: the control for the test
// above. A request none of whose events the run's read keeps is another
// run's, and so is a request of the same id in another project or another
// tenant; the run's own request stays checked.
func TestARequestWhollyInAnotherRunPutsNothingInDoubt(t *testing.T) {
	x := export(call{req: "r1", tool: "get_order", upstream: "shop"},
		call{req: "r9", tool: "get_order", upstream: "shop", at: 10 * time.Second, run: outsiderRun},
		call{req: "r1", tool: "get_order", upstream: "shop", at: 20 * time.Second, run: outsiderRun, proj: "p2"},
		call{req: "r1", tool: "get_order", upstream: "shop", at: 30 * time.Second, run: outsiderRun, tenant: "t2"})
	res, err := supervise.Evaluate(supervise.Input{Procedure: procWith(t), Run: supervise.Run{ID: runID, Tenant: tenant},
		Exports: []supervise.Export{x}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got := res.Report.GetRead().GetEventsLeftOut()["another run"]; got != 12 {
		t.Fatalf("events left out as another run: %d, want 12", got)
	}
	for id, state := range rules(res) {
		if strings.Contains(state, "in doubt") {
			t.Errorf("%s is %q, want no doubt", id, state)
		}
	}
	if got := rules(res)["REPEATED_DENIAL"]; got != "RULE_STATE_CHECKED:" {
		t.Errorf("REPEATED_DENIAL is %q, want it checked", got)
	}
}
