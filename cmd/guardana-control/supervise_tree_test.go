package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/supervise"
)

// supProcedure02 is the refund procedure in schema 0.2, children inherit,
// with no binding and no exception.
var supProcedure02 = strings.NewReplacer(
	`"schema_version":"0.1"`, `"schema_version":"0.2"`,
	`"version":"1",`, `"version":"2","bindings":{},`,
	`"required":true}`, `"required":true,"binds":[]}`,
	`"required":false}`, `"required":false,"binds":[]}`,
	`"observed_as":["search_docs"]}`, `"observed_as":["search_docs"],"binds":[]}`,
	`"max_denials":4`, `"exceptions":[],"children":"inherit","max_denials":4`,
	`"CONTINUED_AFTER_FAILURE":{"severity":"critical","escalation":"alert"}}`,
	`"CONTINUED_AFTER_FAILURE":{"severity":"critical","escalation":"alert"},`+
		`"RESOURCE_OUTSIDE_RUN":{"severity":"critical","escalation":"alert"},`+
		`"DENIED_ACTION_RETRIED_ARGUMENTS":{"severity":"medium","escalation":"inform"},`+
		`"DENIED_ACTION_RETRIED_RESOURCE":{"severity":"high","escalation":"alert"},`+
		`"DENIED_ACTION_RETRIED_AROUND":{"severity":"low","escalation":"inform"},`+
		`"EXCEPTION_TAKEN":{"severity":"info","escalation":"inform"}}`,
).Replace(supProcedure)

// supFamily is the fixture run as a root, a child under it, the child's own
// child, and another root of the tenant.
type supFamily struct{ root, child, grandchild, other string }

func (tr supTree) family(t *testing.T) supFamily {
	t.Helper()
	f := supFamily{root: tr.run}
	f.child = openRun(t, tr.runs, who, "30m", "--parent", f.root).runID
	f.grandchild = openRun(t, tr.runs, who, "20m", "--parent", f.child).runID
	f.other = openRun(t, tr.runs, who, "1h").runID
	return f
}

// plantRun writes a record into the runs directory as a writer of it could,
// without the operator's lock or its checks of a parent.
func plantRun(t *testing.T, dir, id, tenant, root, parent string) {
	t.Helper()
	body := fmt.Sprintf(`{"schema_version":"1.0","run_id":%q,"tenant_id":%q,"principal_type":"user",`+
		`"principal_id":"p","agent_id":"a","root":%q,"parent":%q,"opened_at":"2026-03-01T12:00:00Z",`+
		`"expires_at":"2026-03-01T13:00:00Z","closed_at":"","secret_sha256":%q}`,
		id, tenant, root, parent, strings.Repeat("0", 64))
	writeFixture(t, filepath.Join(dir, id+".run.json"), body)
}

func plantedRun(i int) string { return fmt.Sprintf("run-%032x", i+1) }

// treeOf is each run of a tree as "id<parent", in order.
func treeOf(tree []supervise.Run) []string {
	out := make([]string, 0, len(tree))
	for _, r := range tree {
		out = append(out, r.ID+"<"+r.Parent)
	}
	return out
}

// TestSuperviseInputReadsTheTreeTheProcedureAsksFor: under inherit the root
// and its whole tree, each run after its parent; under separate a child and
// its own children; under 0.1 the root alone. The other root is in none.
func TestSuperviseInputReadsTheTreeTheProcedureAsksFor(t *testing.T) {
	tr := newSupTree(t)
	f := tr.family(t)
	for name, c := range map[string]struct {
		mode supervise.Children
		run  string
		want []string
	}{
		"inherit":          {supervise.ChildrenInherit, f.root, []string{f.root + "<", f.child + "<" + f.root, f.grandchild + "<" + f.child}},
		"separate, a root": {supervise.ChildrenSeparate, f.root, []string{f.root + "<", f.child + "<" + f.root}},
		"separate, a child": {supervise.ChildrenSeparate, f.child,
			[]string{f.child + "<" + f.root, f.grandchild + "<" + f.child}},
		"separate, a leaf": {supervise.ChildrenSeparate, f.grandchild, []string{f.grandchild + "<" + f.child}},
		"0.1":              {supervise.ChildrenUnstated, f.root, nil},
	} {
		t.Run(name, func(t *testing.T) {
			run, tree, err := readRun(tr.runs, c.run, c.mode)
			if err != nil {
				t.Fatalf("readRun: %v", err)
			}
			if run.ID != c.run || run.Tenant != who.TenantID || run.Closed || !slices.Equal(treeOf(tree), c.want) {
				t.Fatalf("readRun = %+v, %v; want %s and tree %v", run, treeOf(tree), c.run, c.want)
			}
		})
	}
}

// TestSuperviseInputUnderInheritTakesARootOnly: a child is refused as the
// run of an inherited tree, as of a 0.1 procedure, and taken under separate.
func TestSuperviseInputUnderInheritTakesARootOnly(t *testing.T) {
	tr := newSupTree(t)
	f := tr.family(t)
	for _, mode := range []supervise.Children{supervise.ChildrenInherit, supervise.ChildrenUnstated} {
		if _, _, err := readRun(tr.runs, f.child, mode); err == nil || !strings.Contains(err.Error(), "a child run") ||
			!strings.Contains(err.Error(), "--run") {
			t.Errorf("mode %d: readRun(child) = %v, want a child run refused", mode, err)
		}
	}
	if _, _, err := readRun(tr.runs, f.child, supervise.ChildrenSeparate); err != nil {
		t.Errorf("separate: readRun(child) = %v", err)
	}
}

// TestSuperviseInputRefusesATreeItCannotVouchFor: a run of the tree of
// another tenant, one whose parents never reach the root, and a tree one past
// MaxTreeRuns are refused; a tree of MaxTreeRuns is read.
func TestSuperviseInputRefusesATreeItCannotVouchFor(t *testing.T) {
	for name, c := range map[string]struct {
		plant func(t *testing.T, tr supTree)
		want  error
	}{
		"another tenant": {func(t *testing.T, tr supTree) {
			plantRun(t, tr.runs, plantedRun(1), "other", tr.run, tr.run)
		}, runs.ErrTreeTenant},
		"a parent in no tree": {func(t *testing.T, tr supTree) {
			plantRun(t, tr.runs, plantedRun(1), who.TenantID, tr.run, plantedRun(2))
		}, runs.ErrTreeBroken},
		"one past the bound": {func(t *testing.T, tr supTree) {
			for i := range supervise.MaxTreeRuns {
				plantRun(t, tr.runs, plantedRun(i), who.TenantID, tr.run, tr.run)
			}
		}, runs.ErrTreeBound},
		"at the bound": {func(t *testing.T, tr supTree) {
			for i := range supervise.MaxTreeRuns - 1 {
				plantRun(t, tr.runs, plantedRun(i), who.TenantID, tr.run, tr.run)
			}
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newSupTree(t)
			c.plant(t, tr)
			_, tree, err := readRun(tr.runs, tr.run, supervise.ChildrenInherit)
			if !errors.Is(err, c.want) || (c.want == nil && len(tree) != supervise.MaxTreeRuns) {
				t.Fatalf("readRun = %d runs, %v; want %v", len(tree), err, c.want)
			}
			if c.want != nil && !strings.Contains(err.Error(), "--runs") {
				t.Errorf("the refusal %q names no --runs", err)
			}
		})
	}
}

// TestSuperviseRunsOfOtherTenantsBoundNoTree: 1001 runs of another tenant,
// more than a listing of the directory takes, neither refuse the run as a
// 0.1 procedure supervises it nor its tree as an inherited one reads it.
func TestSuperviseRunsOfOtherTenantsBoundNoTree(t *testing.T) {
	tr := newSupTree(t)
	f := tr.family(t)
	for i := range 1001 {
		plantRun(t, tr.runs, plantedRun(i), "other", plantedRun(i), "")
	}
	if code, stdout, stderr := invoke(t, "runs", "list", tr.runs); code == exitOK || !strings.Contains(stderr, "incomplete") {
		t.Fatalf("runs list: exit %d, %q, %q; want the listing refused as incomplete", code, stdout, stderr)
	}
	_, tree, err := readRun(tr.runs, f.root, supervise.ChildrenInherit)
	if err != nil || len(tree) != 3 {
		t.Fatalf("inherit: %v, %v", treeOf(tree), err)
	}
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	if code, stdout, stderr := invoke(t, tr.args("--evidence", x)...); code != exitOK {
		t.Fatalf("supervise: exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
	}
}

// TestSuperviseInputOfA02ProcedureHoldsTheTree: the input a 0.2 procedure
// reads holds its tree, which Evaluate judges and its report names.
func TestSuperviseInputOfA02ProcedureHoldsTheTree(t *testing.T) {
	tr := newSupTree(t)
	f := tr.family(t)
	writeFixture(t, tr.procedure, supProcedure02)
	in, err := readSuperviseInput(&superviseArgs{procedure: valueList{tr.procedure}, runs: valueList{tr.runs},
		run: valueList{tr.run}, findings: valueList{tr.findings}})
	if err != nil {
		t.Fatalf("readSuperviseInput: %v", err)
	}
	if in.Procedure.Children() != supervise.ChildrenInherit || in.Run.ID != f.root ||
		!slices.Equal(treeOf(in.Tree), []string{f.root + "<", f.child + "<" + f.root, f.grandchild + "<" + f.child}) {
		t.Fatalf("input run %+v, tree %v", in.Run, treeOf(in.Tree))
	}
	res, err := supervise.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var tree []string
	for _, m := range res.Report.GetRunTree() {
		tree = append(tree, m.GetRunId()+"<"+m.GetParentRunId())
	}
	if !slices.Equal(tree, []string{f.root + "<", f.child + "<" + f.root, f.grandchild + "<" + f.child}) {
		t.Fatalf("the report names the tree %v", tree)
	}
}

// TestSuperviseHearsASourceOnlyFromItsOwnTenantAndProject: an import report
// written under the descriptor's project is the source heard; the same log
// is not read under a descriptor of another project, which is refused.
func TestSuperviseHearsASourceOnlyFromItsOwnTenantAndProject(t *testing.T) {
	tr := newSupTree(t)
	descriptor, log := tr.source(t)
	tr.observe(t, descriptor, log, "search_docs", supBase.Add(5*time.Second))
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	if code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...); code != exitOK {
		t.Fatalf("its own project: exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
	}
	raw, err := os.ReadFile(descriptor) //nolint:gosec // G304: a path in this test's own directory
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.Replace(string(raw), fmt.Sprintf("%q", supProject), `"elsewhere"`, 1)
	if moved == string(raw) {
		t.Fatal("the descriptor names no project to move")
	}
	writeFixture(t, descriptor, moved)
	supRefused(t, tr.args("--evidence", x, "--source", descriptor, "--log", log), `source "agent-runtime" is of project "elsewhere"`)
}
