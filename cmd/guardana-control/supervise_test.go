package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/findinglog"
)

func everyRule(state string) string {
	var b strings.Builder
	for _, rule := range []string{"REPEATED_DENIAL", "STEP_OUTSIDE_PROCEDURE", "DEADLINE_EXCEEDED",
		"REQUIRED_STEP_SKIPPED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE"} {
		b.WriteString("rule " + rule + " " + state + "\n")
	}
	return b.String()
}

func readLog(t *testing.T, dir string) []*findingv1alpha1.Record {
	t.Helper()
	records, err := findinglog.ReadFile(filepath.Join(dir, findinglog.FileName))
	if err != nil {
		t.Fatalf("reading the findings log: %v", err)
	}
	if len(records) == 0 || records[0].GetLogHeader() == nil {
		t.Fatalf("a log supervise created starts with no header: %v", records)
	}
	return records[1:]
}

// TestSuperviseAConformingRunExitsZero: a closed run that keeps to its
// procedure, from one whole export, gives no finding, checks every rule,
// names each step's requests and closes the log with its report.
func TestSuperviseAConformingRunExitsZero(t *testing.T) {
	tr := newSupTree(t)
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	want := "run " + tr.run + " tenant acme project orders procedure refund version 1\n" +
		"events: 12 taken\nobservations: 0 taken\nexports: 1 whole, 0 not whole\n" +
		"step lookup: requests r1\nstep refund: requests r2\nstep notify: requests r3\n" +
		everyRule("checked") + "findings log: 0 written, 0 already held\n"
	if stdout != want {
		t.Errorf("stdout\n%s\nwant\n%s", stdout, want)
	}
	records := readLog(t, tr.findings)
	if len(records) != 1 || records[0].GetSuperviseReport().GetRunId() != tr.run ||
		records[0].GetSuperviseReport().GetRead().GetEventsTaken() != 12 {
		t.Errorf("the log holds %v, want one report of the run with 12 events taken", records)
	}
}

// TestSuperviseAWrongRunIsNotAPass: an opened run none of whose events were
// read checks no rule and exits 1, though it has no finding.
func TestSuperviseAWrongRunIsNotAPass(t *testing.T) {
	tr := newSupTree(t)
	other := openRun(t, tr.runs, who, "1h").runID
	x := tr.export(t, other, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	for _, want := range []string{"events: 0 taken, 12 another run\n", everyRule("not checked: no plane event of the run"),
		"findings log: nothing written, no event of the run was read\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, stdout)
		}
	}
}

// TestSuperviseATrailInDoubtIsNotAPass: the conforming run with the
// refund's last event linked to one never read finds nothing, checks no rule
// and exits 1.
func TestSuperviseATrailInDoubtIsNotAPass(t *testing.T) {
	tr := newSupTree(t)
	calls := conformingCalls()
	calls[1].broken = true
	x := tr.export(t, tr.run, supBase, calls...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	for _, want := range []string{everyRule(`not checked: request "r2" is in doubt`), "findings log: 0 written, 0 already held\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, stdout)
		}
	}
}

// TestSuperviseALongRequestIDInDoubtStillWritesItsReport: a request id
// past the contract's string bound puts its trail in doubt; the report names
// it cut, so the log line holding every rule's why fits, and the run exits 1.
func TestSuperviseALongRequestIDInDoubtStillWritesItsReport(t *testing.T) {
	tr := newSupTree(t)
	long := "z" + strings.Repeat("x", 12000)
	calls := append(conformingCalls(), supCall{req: long, tool: "send_mail", upstream: "mail", at: 30 * time.Second})
	x := tr.export(t, tr.run, supBase, calls...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %.400q", code, stderr, stdout)
	}
	want := everyRule(`not checked: request "z` + strings.Repeat("x", 63) + `" (truncated) is in doubt`)
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout does not hold %q:\n%.2000s", want, stdout)
	}
	records := readLog(t, tr.findings)
	if len(records) != 1 || records[0].GetSuperviseReport().GetRunId() != tr.run {
		t.Errorf("the log holds %d records, want the run's report", len(records))
	}
}

// TestSuperviseRefusesARunItCannotSupervise: a local run's id, an id no
// record holds and a child run are refused before the log is opened.
func TestSuperviseRefusesARunItCannotSupervise(t *testing.T) {
	tr := newSupTree(t)
	child := openRun(t, tr.runs, who, "30m", "--parent", tr.run).runID
	for name, c := range map[string]struct{ run, want string }{
		"a local run":   {"01J9Z3A6S5K8M2P4Q7R9T1V3W5", "not an opened run's id"},
		"no record":     {"run-" + strings.Repeat("ab", 16), "no record"},
		"a child run":   {child, "a child run"},
		"an upper case": {strings.ToUpper(tr.run), "not an opened run's id"},
	} {
		t.Run(name, func(t *testing.T) {
			args := tr.args()
			args[6] = c.run
			supRefused(t, args, "--run", c.want)
			if _, err := os.Stat(filepath.Join(tr.findings, findinglog.FileName)); err == nil {
				t.Error("a refused run created the findings log")
			}
		})
	}
}

// TestSuperviseRefusesAProcedureItCannotRead: a procedure another account
// could write, or one ReadProcedure refuses, prints nothing.
func TestSuperviseRefusesAProcedureItCannotRead(t *testing.T) {
	tr := newSupTree(t)
	if err := os.Chmod(tr.procedure, 0o620); err != nil { //nolint:gosec // G302: the mode the command must refuse
		t.Fatal(err)
	}
	supRefused(t, tr.args(), "--procedure", tr.procedure)
	if err := os.Chmod(tr.procedure, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, tr.procedure, strings.Replace(supProcedure, `"version":"1"`, `"version":"1","extra":1`, 1))
	supRefused(t, tr.args(), "--procedure", "procedure refused")
}

// TestSuperviseRefusesAnEditedProcedureUnderItsVersion: the same procedure
// supervised again is accepted; once edited under the same id and version
// it is refused before the log is opened, so a line a crashed write left
// after the last report is not cut and the file is byte for byte as it was.
func TestSuperviseRefusesAnEditedProcedureUnderItsVersion(t *testing.T) {
	tr := newSupTree(t)
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	for range 2 {
		if code, stdout, stderr := invoke(t, tr.args("--evidence", x)...); code != 0 {
			t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
		}
	}
	path := filepath.Join(tr.findings, findinglog.FileName)
	before, err := os.ReadFile(path) //nolint:gosec // G304: a path in this test's own directory
	if err != nil {
		t.Fatal(err)
	}
	before = append(before, `{"findingRecord":`...)
	writeFixture(t, path, string(before))
	writeFixture(t, tr.procedure, strings.Replace(supProcedure, `"deadline_seconds":600`, `"deadline_seconds":601`, 1))
	supRefused(t, tr.args("--evidence", x), "refund", "another digest")
	if n := len(readLog(t, tr.findings)); n != 2 {
		t.Errorf("the log holds %d records, want the 2 reports of the accepted runs", n)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(before) { //nolint:gosec // G304: a path in this test's own directory
		t.Errorf("the refusal changed the log: %v\n%q\nwant\n%q", err, after, before)
	}
}

// TestSuperviseRepeatedDenialsWriteTheirFinding: four DENYs of one tool at
// max_denials 4 is one confirmed alert, printed with its references and
// written to the log; a retry that then succeeds is no other finding.
func TestSuperviseRepeatedDenialsWriteTheirFinding(t *testing.T) {
	tr := newSupTree(t)
	calls := []supCall{{req: "r1", tool: "get_order", upstream: "shop"}}
	for i, req := range []string{"d1", "d2", "d3", "d4"} {
		calls = append(calls, supCall{req: req, tool: "issue_refund", upstream: "pay", at: time.Duration(10+10*i) * time.Second, deny: true})
	}
	calls = append(calls, supCall{req: "r2", tool: "issue_refund", upstream: "pay", at: 60 * time.Second},
		supCall{req: "r3", tool: "send_mail", upstream: "mail", at: 70 * time.Second})
	x := tr.export(t, tr.run, supBase, calls...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	line := regexp.MustCompile(`(?m)^finding REPEATED_DENIAL confirmed alert (fnd-[0-9a-f]{32}) ` +
		`event d1-e3 \(request d1\), event d2-e3 \(request d2\), event d3-e3 \(request d3\), event d4-e3 \(request d4\)$`).
		FindStringSubmatch(stdout)
	if line == nil || strings.Count(stdout, "finding ") != 1 {
		t.Fatalf("stdout holds no one REPEATED_DENIAL line with its four denials:\n%s", stdout)
	}
	for _, want := range []string{"step refund: requests d1, d2, d3, d4, r2\n", everyRule("checked"), "findings log: 1 written, 0 already held\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, stdout)
		}
	}
	loggedDenial(t, tr.findings, line[1])
}

// loggedDenial wants the log to hold the printed finding with its four
// references, then a report of one finding written.
func loggedDenial(t *testing.T, dir, id string) {
	t.Helper()
	records := readLog(t, dir)
	if len(records) != 2 {
		t.Fatalf("the log holds %d records, want the finding and its report", len(records))
	}
	f := records[0].GetFindingRecord()
	if f.GetFinding().GetFindingId() != id || f.GetFinding().GetRuleId() != "REPEATED_DENIAL" ||
		f.GetFinding().GetVerdict().String() != "FINDING_VERDICT_CONFIRMED" || len(f.GetRefs()) != 4 ||
		records[1].GetSuperviseReport().GetFindingsWritten() != 1 {
		t.Errorf("the log holds %v, want the printed finding then a report of one written", records)
	}
}

// TestSuperviseCannotWriteTheLogPrintsNothing: a findings directory the
// group may enter is refused after the evaluation, and nothing is printed.
func TestSuperviseCannotWriteTheLogPrintsNothing(t *testing.T) {
	tr := newSupTree(t)
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	if err := os.Chmod(tr.findings, 0o750); err != nil { //nolint:gosec // G302: the mode the log must refuse
		t.Fatal(err)
	}
	supRefused(t, tr.args("--evidence", x), "--findings", tr.findings)
}

// TestSuperviseRefusesAnExportAnotherAccountCouldWrite: an export the group
// or others could write is refused like the procedure, before the log is
// opened, so no event planted in it becomes a finding.
func TestSuperviseRefusesAnExportAnotherAccountCouldWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o666, 0o620, 0o602} {
		t.Run(mode.String(), func(t *testing.T) {
			tr := newSupTree(t)
			x := tr.export(t, tr.run, supBase, conformingCalls()...)
			tr.closeRun(t, tr.run)
			if err := os.Chmod(x, mode); err != nil {
				t.Fatal(err)
			}
			supRefused(t, tr.args("--evidence", x), "--evidence", x, "mode")
			if _, err := os.Stat(filepath.Join(tr.findings, findinglog.FileName)); err == nil {
				t.Error("a refused export created the findings log")
			}
		})
	}
}
