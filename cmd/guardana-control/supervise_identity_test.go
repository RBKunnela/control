package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSuperviseRefusesASourceOfAnotherProject: one log holds an import of
// the run's project that refused a span claimed for the run, and a healthy
// import under the same source id in another project. The run's reports and
// observations are read under one identity, so the other project's
// descriptor is refused, and the run's own still finds the run in doubt.
func TestSuperviseRefusesASourceOfAnotherProject(t *testing.T) {
	const why = `not checked: source "agent-runtime" is in doubt: an import refused a copy that may be a call of a run judged`
	tr := newSupTree(t)
	writeFixture(t, tr.procedure, supProcedure02)
	descriptor, log := tr.source(t)
	end := supBase.Add(5 * time.Second)
	tr.importSpans(t, descriptor, log, spansLine(toolSpan("00f067aa0ba90001", "search_docs", tr.run, 1, end),
		toolSpan("00f067aa0ba90002", "drop_table", tr.run, 7, end)), 0, 1)
	elsewhere := tr.descriptorAs(t, descriptor, "elsewhere.json", `"`+supProject+`"`, `"elsewhere"`)
	healthy := filepath.Join(tr.dir, "healthy.jsonl")
	writeFixture(t, healthy, spansLine(toolSpan("00f067aa0ba90009", "search_docs", tr.run, 1, end)))
	if code, out, stderr := invoke(t, "observe", "import", "--source", elsewhere, "--log", log, healthy); code != exitOK {
		t.Fatalf("import under the other project: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	supRefused(t, tr.args("--evidence", x, "--source", elsewhere, "--log", log),
		`source "agent-runtime" is of project "elsewhere", the run's events of project "orders"`)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
	if code != exitFail || stderr != "" {
		t.Fatalf("the run's own descriptor: exit %d, stderr %q, stdout\n%s\nwant 1", code, stderr, stdout)
	}
	for _, rule := range []string{"STEP_OUTSIDE_PROCEDURE", "DENIED_ACTION_RETRIED_AROUND"} {
		if want := "rule " + rule + " " + why + "\n"; !strings.Contains(stdout, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, stdout)
		}
	}
}

// TestSuperviseRefusesASourceOfAnotherTenant: a descriptor of another tenant
// is refused before its log is judged, though no event names that tenant.
func TestSuperviseRefusesASourceOfAnotherTenant(t *testing.T) {
	tr := newSupTree(t)
	descriptor, log := tr.source(t)
	other := tr.descriptorAs(t, descriptor, "other-tenant.json", fmt.Sprintf("%q", who.TenantID), `"tenant-b"`)
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	supRefused(t, tr.args("--evidence", x, "--source", other, "--log", log),
		`source "agent-runtime" is of tenant "tenant-b", the run of tenant "acme"`)
}

// descriptorAs writes descriptor with from replaced by to once, as name in
// the tree, and returns its path.
func (tr supTree) descriptorAs(t *testing.T, descriptor, name, from, to string) string {
	t.Helper()
	raw, err := os.ReadFile(descriptor) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), from) {
		t.Fatalf("descriptor holds no %s", from)
	}
	path := filepath.Join(tr.dir, name)
	writeFixture(t, path, strings.Replace(string(raw), from, to, 1))
	return path
}
