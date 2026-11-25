//go:build unix

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/findinglog"
)

const (
	ntAlertID  = "fnd-0123456789abcdef0123456789abcdef"
	ntInformID = "fnd-11111111111111111111111111111111"
	ntRunID    = "run-00112233445566778899aabbccddeeff"
	// ntAlertKey is the alert's delivery key, spelled out.
	ntAlertKey = ntAlertID + ":FINDING_VERDICT_CONFIRMED"
)

// notifyRig is a findings log holding one alert and one inform finding, a
// state directory, and a directory the helper program records into.
type notifyRig struct {
	findings, state, record string
}

func newNotifyRig(t *testing.T) notifyRig {
	t.Helper()
	r := notifyRig{findings: ntOwnerDir(t), state: ntOwnerDir(t), record: ntOwnerDir(t)}
	l, err := findinglog.Open(r.findings)
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Write([]*findingv1alpha1.FindingRecord{
		ntFinding(ntAlertID, findingv1alpha1.Escalation_ESCALATION_ALERT),
		ntFinding(ntInformID, findingv1alpha1.Escalation_ESCALATION_INFORM),
	}, ntReport())
	if err := errors.Join(err, l.Close()); err != nil {
		t.Fatal(err)
	}
	return r
}

func ntOwnerDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: an owner-only directory, which the owner must enter
		t.Fatal(err)
	}
	return dir
}

func ntFinding(id string, esc findingv1alpha1.Escalation) *findingv1alpha1.FindingRecord {
	return &findingv1alpha1.FindingRecord{
		SchemaVersion: "0.1", TenantId: "tenant-a", ProjectId: "project-a",
		Procedure:  &findingv1alpha1.ProcedureRef{ProcedureId: "refund", Version: "1", Digest: "aa"},
		Escalation: esc,
		Refs: []*findingv1alpha1.Reference{
			{Ref: &findingv1alpha1.Reference_Event{Event: &findingv1alpha1.EventRef{EventId: "evt-1", RequestId: "req-1"}}},
		},
		Finding: &controlv1.Finding{
			FindingId: id, RuleId: "repeated_denial", RuleVersion: "1",
			Severity: controlv1.FindingSeverity_FINDING_SEVERITY_HIGH, Verdict: controlv1.FindingVerdict_FINDING_VERDICT_CONFIRMED,
			RunId: ntRunID, Source: controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC,
		},
	}
}

func ntReport() *findingv1alpha1.SuperviseReport {
	return &findingv1alpha1.SuperviseReport{
		SchemaVersion: "0.1", TenantId: "tenant-a", ProjectId: "project-a", RunId: ntRunID,
		Procedure: &findingv1alpha1.ProcedureRef{ProcedureId: "refund", Version: "1", Digest: "aa"},
	}
}

// notify runs the command with flags, delivering to the helper in mode.
func (r notifyRig) notify(t *testing.T, mode string, flags ...string) (status int, stdout, stderr string) {
	t.Helper()
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"notify", "--findings", r.findings, "--state", r.state}, flags...)
	args = append(args, "--", self, notifyHelperArg, mode, r.record)
	var out, errOut bytes.Buffer
	status = run(args, &out, &errOut)
	return status, out.String(), errOut.String()
}

// received is every standard input the helper was given, concatenated.
func (r notifyRig) received(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.record, "received"))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// alertLine is the log's line that carries the alert, read from the file.
func (r notifyRig) alertLine(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.findings, findinglog.FileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if strings.Contains(l, `"findingId":"`+ntAlertID+`"`) {
			return l
		}
	}
	t.Fatal("no line of the log carries the alert")
	return ""
}

func wantNotify(t *testing.T, what string, status int, stdout, stderr string, wantStatus int, wantStdout string) {
	t.Helper()
	if status != wantStatus || stdout != wantStdout {
		t.Errorf("%s: status %d, stdout %q (stderr %q); want %d and %q", what, status, stdout, stderr, wantStatus, wantStdout)
	}
}

// TestNotifyDeliversAnAlertOnce: init delivers the alert, the log's own line
// on the program's standard input, and leaves the inform finding; the next
// run delivers nothing. The program's outputs are the command's own.
func TestNotifyDeliversAnAlertOnce(t *testing.T) {
	r := newNotifyRig(t)
	status, stdout, stderr := r.notify(t, "ok", "--init")
	wantNotify(t, "the first run", status, stdout, stderr, exitOK,
		"helper-stdout\n1 delivered, 0 already delivered, 0 failed, 1 inform left\n")
	if stderr != "helper-stderr\n" {
		t.Errorf("the first run's standard error = %q, want the program's alone", stderr)
	}
	if got, want := r.received(t), r.alertLine(t); got != want {
		t.Errorf("the program received\n%q\nwant\n%q", got, want)
	}
	status, stdout, stderr = r.notify(t, "ok")
	wantNotify(t, "the second run", status, stdout, stderr, exitOK, "0 delivered, 1 already delivered, 0 failed, 1 inform left\n")
	if got, want := r.received(t), r.alertLine(t); got != want {
		t.Errorf("the second run delivered again: %q", got)
	}
}

// TestNotifyExitsOneOnAFailedDeliveryAndTheNextRunRetriesIt: a program that
// exits 1 is a failure named by its key and why, exit 1, and nothing marked.
func TestNotifyExitsOneOnAFailedDeliveryAndTheNextRunRetriesIt(t *testing.T) {
	r := newNotifyRig(t)
	status, stdout, stderr := r.notify(t, "fail", "--init")
	wantNotify(t, "the failing run", status, stdout, stderr, exitFail,
		"helper-stdout\nfailed "+ntAlertKey+": exit status 1\n0 delivered, 0 already delivered, 1 failed, 1 inform left\n")
	status, stdout, stderr = r.notify(t, "ok")
	wantNotify(t, "the retry", status, stdout, stderr, exitOK,
		"helper-stdout\n1 delivered, 0 already delivered, 0 failed, 1 inform left\n")
	if got, want := r.received(t), strings.Repeat(r.alertLine(t), 2); got != want {
		t.Errorf("the program received\n%q\nwant the alert twice", got)
	}
}

// TestNotifyPassesItsTimeoutOn: a timeout too short for any program fails
// the delivery, which the default never does.
func TestNotifyPassesItsTimeoutOn(t *testing.T) {
	r := newNotifyRig(t)
	status, stdout, stderr := r.notify(t, "ok", "--init", "--timeout", "1ns")
	if status != exitFail || !strings.Contains(stdout, "failed "+ntAlertKey+": notify: the program did not exit within the timeout") {
		t.Errorf("a 1ns timeout: status %d, stdout %q (stderr %q); want %d and a timed-out failure", status, stdout, stderr, exitFail)
	}
}

// TestNotifyRefusesAStateNotInitialised: a state never started is refused
// before any delivery, with nothing on standard output and exit 2.
func TestNotifyRefusesAStateNotInitialised(t *testing.T) {
	r := newNotifyRig(t)
	status, stdout, stderr := r.notify(t, "ok")
	wantNotify(t, "a run without init", status, stdout, stderr, exitUsage, "")
	if want := brand.CLI + ": notify: notify: the state directory is not initialised"; !strings.HasPrefix(stderr, want) {
		t.Errorf("stderr = %q, want a line starting %q", stderr, want)
	}
	if got := r.received(t); got != "" {
		t.Errorf("a refused run delivered %q", got)
	}
}

// TestNotifyExitsOneOnAWriteNoWriterWillClose: a finding line after the
// last report, with no writer holding the log, is never delivered, and the
// run says how many bytes it is and exits 1.
func TestNotifyExitsOneOnAWriteNoWriterWillClose(t *testing.T) {
	r := newNotifyRig(t)
	rec := &findingv1alpha1.Record{Record: &findingv1alpha1.Record_FindingRecord{
		FindingRecord: ntFinding("fnd-22222222222222222222222222222222", findingv1alpha1.Escalation_ESCALATION_ALERT)}}
	line, err := findinglog.Line(rec)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(r.findings, findinglog.FileName), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(append(line, '\n'))
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr := r.notify(t, "ok", "--init")
	wantNotify(t, "a log ending in an unclosed write", status, stdout, stderr, exitFail,
		"helper-stdout\nunclosed: "+strconv.Itoa(len(line)+1)+" bytes after the last write a report closed, and no writer holds the log\n"+
			"1 delivered, 0 already delivered, 0 failed, 1 inform left\n")
}

// TestNotifyPassesTheVariablesEnvNames: --env hands the program a variable
// of the command's environment, and a name the command does not set is
// refused before any program runs, printing nothing on standard output.
func TestNotifyPassesTheVariablesEnvNames(t *testing.T) {
	t.Setenv("NOTIFY_CLI_TOKEN", "for-the-program")
	r := newNotifyRig(t)
	status, stdout, stderr := r.notify(t, "env", "--init", "--env", "NOTIFY_CLI_UNSET")
	if status != exitUsage || stdout != "" || !strings.Contains(stderr, "NOTIFY_CLI_UNSET") || r.received(t) != "" {
		t.Errorf("an unset --env: status %d, stdout %q, stderr %q, delivered %q; want 2 naming it and nothing run",
			status, stdout, stderr, r.received(t))
	}
	status, _, stderr = r.notify(t, "env", "--init", "--env", "NOTIFY_CLI_TOKEN")
	if status != exitOK {
		t.Fatalf("notify --env: status %d, stderr %q", status, stderr)
	}
	env, err := os.ReadFile(filepath.Join(r.record, "env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+string(env), "\nNOTIFY_CLI_TOKEN=for-the-program\n") {
		t.Errorf("the program's environment lacks the variable --env named:\n%s", env)
	}
}
