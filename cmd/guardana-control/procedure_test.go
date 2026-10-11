package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

const procedureDir = "../../testdata/procedure"

// TestProcedureLintPrintsWhatTheProcedureConfigures: the schema, id,
// version and digest, the children mode of a 0.2 document, and each rule of
// its schema with its version and whether it may stop a run. The digests
// are SHA-256 over each document's sorted, compact form, computed apart from
// this program.
func TestProcedureLintPrintsWhatTheProcedureConfigures(t *testing.T) {
	for _, c := range []struct{ file, want string }{
		{"refund-0.1.json", "schema_version: 0.1\nprocedure_id: refund\nversion: 1\n" +
			"digest: c5f8c68405a63f0be8c3eb4bed6115d9a233d1ed759be6f4c85702adcb3a770a\n" +
			"rule: REPEATED_DENIAL version 2, may stop\n" +
			"rule: STEP_OUTSIDE_PROCEDURE version 1, may stop\n" +
			"rule: DEADLINE_EXCEEDED version 1, may stop\n" +
			"rule: REQUIRED_STEP_SKIPPED version 1, never stops\n" +
			"rule: STEP_OUT_OF_ORDER version 2, never stops\n" +
			"rule: CONTINUED_AFTER_FAILURE version 2, never stops\n"},
		{"refund-0.2.json", "schema_version: 0.2\nprocedure_id: refund\nversion: 2\n" +
			"digest: 3bdccd18fb0503f6168a59a8bae712b9b37be7e4435f796b111be409f7d59dd6\n" +
			"children: inherit\n" +
			"rule: REPEATED_DENIAL version 2, may stop\n" +
			"rule: STEP_OUTSIDE_PROCEDURE version 1, may stop\n" +
			"rule: DEADLINE_EXCEEDED version 1, may stop\n" +
			"rule: REQUIRED_STEP_SKIPPED version 1, never stops\n" +
			"rule: STEP_OUT_OF_ORDER version 2, never stops\n" +
			"rule: CONTINUED_AFTER_FAILURE version 2, never stops\n" +
			"rule: RESOURCE_OUTSIDE_RUN version 1, may stop\n" +
			"rule: DENIED_ACTION_RETRIED_ARGUMENTS version 1, may stop\n" +
			"rule: DENIED_ACTION_RETRIED_RESOURCE version 1, may stop\n" +
			"rule: DENIED_ACTION_RETRIED_AROUND version 1, never stops\n" +
			"rule: EXCEPTION_TAKEN version 1, never stops\n"},
	} {
		code, stdout, stderr := invoke(t, "procedure", "lint", filepath.Join(procedureDir, c.file))
		if code != exitOK || stdout != c.want || stderr != "" {
			t.Errorf("%s: exit %d, stderr %q, stdout\n%s--- want\n%s", c.file, code, stderr, stdout, c.want)
		}
	}
}

// TestProcedureLintRefusesWithTheReadersReason: an exception taken on a
// failed step cannot waive STEP_OUTSIDE_PROCEDURE, a rule that may stop a
// run, since the agent can make a step fail; the refusal is exit 2, nothing
// on stdout and the reader's reason on one line. The same exception taken on
// an approval lints, so the condition is what is refused.
func TestProcedureLintRefusesWithTheReadersReason(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(procedureDir, "refund-0.2.json"))
	if err != nil {
		t.Fatal(err)
	}
	approval := `"condition": {"approval": "granted"}}`
	if strings.Count(string(doc), approval) != 2 {
		t.Fatalf("the fixture's exceptions changed: %s", doc)
	}
	dir := t.TempDir()
	stepFailed := filepath.Join(dir, "step-failed.json")
	writeFixture(t, stepFailed, strings.Replace(string(doc), approval, `"condition": {"step_failed": "lookup"}}`, 1))
	code, stdout, stderr := invoke(t, "procedure", "lint", stepFailed)
	line := oneStderrLine(t, stderr)
	if code != exitUsage || stdout != "" {
		t.Fatalf("exit %d, stdout %q; want 2 and nothing printed", code, stdout)
	}
	for _, want := range []string{brand.CLI + ": procedure lint: ", stepFailed,
		"an exception on a rule that may stop a run is taken only on an approval"} {
		if !strings.Contains(line, want) {
			t.Errorf("stderr %q does not hold %q", line, want)
		}
	}

	approved := filepath.Join(dir, "approved.json")
	writeFixture(t, approved, string(doc))
	if code, _, stderr := invoke(t, "procedure", "lint", approved); code != exitOK {
		t.Errorf("the same document on an approval: exit %d, %q", code, stderr)
	}
}

// TestProcedureTestPassesTheWorkedExamples: every case of both documents
// matches, one line each and a summary, exit 0.
func TestProcedureTestPassesTheWorkedExamples(t *testing.T) {
	for _, c := range []struct{ file, want string }{
		{"cases-0.1.json", "ok   the procedure kept: no finding\n" +
			"ok   a tool outside the procedure: STEP_OUTSIDE_PROCEDURE CONFIRMED\n" +
			"ok   a run still open: no finding\n" +
			"procedure refund version 1: 3 cases, 3 passed, 0 failed\n"},
		{"cases-0.2.json", "ok   a waiver taken: EXCEPTION_TAKEN CONFIRMED\n" +
			"ok   a resource outside the run: RESOURCE_OUTSIDE_RUN CONFIRMED\n" +
			"ok   a denied refund retried with other arguments: DENIED_ACTION_RETRIED_ARGUMENTS CONFIRMED\n" +
			"procedure refund version 2: 3 cases, 3 passed, 0 failed\n"},
	} {
		code, stdout, stderr := invoke(t, "procedure", "test", filepath.Join(procedureDir, c.file))
		if code != exitOK || stdout != c.want || stderr != "" {
			t.Errorf("%s: exit %d, stderr %q, stdout\n%s--- want\n%s", c.file, code, stderr, stdout, c.want)
		}
	}
}
