package notify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/findinglog"
)

// helperArg makes the test binary the program a run delivers to.
const helperArg = "-notify-test-helper"

const (
	idA   = "fnd-0123456789abcdef0123456789abcdef"
	idB   = "fnd-11111111111111111111111111111111"
	idC   = "fnd-22222222222222222222222222222222"
	runID = "run-00112233445566778899aabbccddeeff"
)

// keyA is idA confirmed as the delivered list holds it.
const keyA = `"` + idA + `:FINDING_VERDICT_CONFIRMED"` + "\n"

const (
	alert     = findingv1alpha1.Escalation_ESCALATION_ALERT
	inform    = findingv1alpha1.Escalation_ESCALATION_INFORM
	confirmed = controlv1.FindingVerdict_FINDING_VERDICT_CONFIRMED
	suspected = controlv1.FindingVerdict_FINDING_VERDICT_SUSPECTED
)

func TestMain(m *testing.M) {
	if len(os.Args) > 3 && os.Args[1] == helperArg {
		os.Exit(helper(os.Args[2], os.Args[3], os.Args[4:]))
	}
	os.Exit(m.Run())
}

// helper is the program under delivery. In mode "deliver" it appends its
// standard input to dir/received and its arguments to dir/argv, writes a word
// to its standard error, and then obeys the first rule whose finding id its
// input carries: fail=<id> exits 3; hang=<id> starts a sleeping child,
// records its pid in dir/grandchild and sleeps; linger=<id> does the same
// but exits 0 at once, the child holding its standard error; detach=<id>
// exits 0 at once, the child holding no output of its.
func helper(mode, dir string, rules []string) int {
	if mode == "sleep" {
		time.Sleep(time.Hour)
		return 0
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 9
	}
	if appendFile(filepath.Join(dir, "received"), in) != nil ||
		appendFile(filepath.Join(dir, "argv"), []byte(strings.Join(rules, "\x00")+"\n")) != nil {
		return 9
	}
	_, _ = os.Stderr.WriteString("helper-stderr\n")
	for _, rule := range rules {
		verb, id, _ := strings.Cut(rule, "=")
		if !bytes.Contains(in, []byte(id)) {
			continue
		}
		switch verb {
		case "fail":
			return 3
		case "hang":
			return hang(dir, false, false)
		case "linger":
			return hang(dir, true, true)
		case "detach":
			return hang(dir, false, true)
		}
	}
	return 0
}

// hang starts a sleeping child, holding its standard error when holdStderr,
// and records its pid; then it sleeps too, or exits 0.
func hang(dir string, holdStderr, exit bool) int {
	child := exec.Command(os.Args[0], helperArg, "sleep", dir) //nolint:gosec // G204: the test binary's own path and its own flags
	if holdStderr {
		child.Stderr = os.Stderr
	}
	if child.Start() != nil {
		return 9
	}
	if os.WriteFile(filepath.Join(dir, "grandchild"), []byte(strconv.Itoa(child.Process.Pid)), 0o600) != nil {
		return 9
	}
	if !exit {
		time.Sleep(time.Hour)
	}
	return 0
}

func appendFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G304: the test's own file
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return errors.Join(err, f.Close())
}

// rig is one findings log, one state and one helper program's record.
type rig struct {
	findings, state, record string
}

func newRig(t *testing.T) rig {
	t.Helper()
	r := rig{findings: ownerDir(t), state: ownerDir(t), record: t.TempDir()}
	l, err := findinglog.Open(r.findings)
	mustDo(t, err)
	mustDo(t, l.Close())
	return r
}

// ownerDir is a fresh directory only this account may enter.
func ownerDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "d")
	mustDo(t, os.Mkdir(dir, 0o700))
	mustDo(t, os.Chmod(dir, 0o700)) //nolint:gosec // G302: a directory, owner-only, as the state requires
	return dir
}

// write appends one supervision's findings to the rig's log.
func (r rig) write(t *testing.T, findings ...*findingv1alpha1.FindingRecord) {
	t.Helper()
	l, err := findinglog.Open(r.findings)
	mustDo(t, err)
	_, err = l.Write(findings, report())
	mustDo(t, errors.Join(err, l.Close()))
}

// options run the helper on r with rules, under a timeout long enough for
// the test binary to start.
func (r rig) options(init bool, rules ...string) Options {
	self, _ := filepath.Abs(os.Args[0])
	return Options{
		FindingsDir: r.findings, StateDir: r.state, Init: init,
		Program: self, Args: append([]string{helperArg, "deliver", r.record}, rules...),
		Timeout: 30 * time.Second,
	}
}

func (r rig) run(t *testing.T, o Options) Summary {
	t.Helper()
	s, err := Run(t.Context(), o)
	if err != nil {
		t.Fatalf("Run = %+v, %v", s, err)
	}
	return s
}

// received is every standard input the helper was given, concatenated.
func (r rig) received(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.record, "received"))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	mustDo(t, err)
	return string(b)
}

// logLine is the line of the rig's log that carries id with verdict, read
// from the file itself.
func (r rig) logLine(t *testing.T, id string, verdict controlv1.FindingVerdict) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.findings, findinglog.FileName))
	mustDo(t, err)
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if strings.Contains(l, `"findingId":"`+id+`"`) && strings.Contains(l, `"verdict":"`+verdict.String()+`"`) {
			return l
		}
	}
	t.Fatalf("no line of the log carries %s %s", id, verdict)
	return ""
}

func (r rig) delivered(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.state, "delivered.jsonl"))
	mustDo(t, err)
	return string(b)
}

func finding(id string, verdict controlv1.FindingVerdict, esc findingv1alpha1.Escalation) *findingv1alpha1.FindingRecord {
	return &findingv1alpha1.FindingRecord{
		SchemaVersion: "0.1", TenantId: "tenant-a", ProjectId: "project-a",
		Procedure:  &findingv1alpha1.ProcedureRef{ProcedureId: "refund", Version: "1", Digest: "aa"},
		Escalation: esc,
		Refs: []*findingv1alpha1.Reference{
			{Ref: &findingv1alpha1.Reference_Event{Event: &findingv1alpha1.EventRef{EventId: "evt-1", RequestId: "req-1"}}},
		},
		Finding: &controlv1.Finding{
			FindingId: id, RuleId: "repeated_denial", RuleVersion: "1",
			Severity: controlv1.FindingSeverity_FINDING_SEVERITY_HIGH, Verdict: verdict,
			RunId: runID, Source: controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC,
		},
	}
}

func report() *findingv1alpha1.SuperviseReport {
	return &findingv1alpha1.SuperviseReport{
		SchemaVersion: "0.1", TenantId: "tenant-a", ProjectId: "project-a", RunId: runID,
		Procedure: &findingv1alpha1.ProcedureRef{ProcedureId: "refund", Version: "1", Digest: "aa"},
	}
}

func mustDo(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantSummary(t *testing.T, got Summary, delivered, already, failed, inform int) {
	t.Helper()
	if got.Delivered != delivered || got.AlreadyDelivered != already || got.Failed != failed || got.Inform != inform {
		t.Errorf("summary = %+v, want delivered %d, already %d, failed %d, inform %d", got, delivered, already, failed, inform)
	}
	if len(got.Failures) != got.Failed {
		t.Errorf("summary names %d failures and counts %d", len(got.Failures), got.Failed)
	}
}

func wantIs(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}

func describe(s Summary) string { return fmt.Sprintf("%+v", s) }
