//go:build unix

package notify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
)

// TestAProgramThatLeavesItsOutputHeldIsNotMarked: a program that exits 0
// while a child it started still holds its standard error is a failure
// once waitDelay passes, not a delivery and not a run that waits on the
// child.
func TestAProgramThatLeavesItsOutputHeldIsNotMarked(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert), finding(idB, confirmed, alert))
	o := r.options(true, "linger="+idA)
	var stderr bytes.Buffer
	o.Stderr = &stderr
	t.Cleanup(func() { killRecorded(r) })
	s := r.run(t, o)
	wantSummary(t, s, 1, 0, 1, 0)
	if len(s.Failures) == 1 && !errors.Is(s.Failures[0].Err, exec.ErrWaitDelay) {
		t.Errorf("the failure = %v, want exec.ErrWaitDelay", s.Failures[0].Err)
	}
	if got, want := r.delivered(t), `"`+idB+`:FINDING_VERDICT_CONFIRMED"`+"\n"; got != want {
		t.Errorf("delivered list = %q, want %q", got, want)
	}
	wantChildGone(t, r)
}

// TestAProgramsChildDoesNotOutliveItsDelivery: a program that starts a child
// holding none of its output and exits 0 is a delivery, and the child is
// killed with the program's group once the program has exited.
func TestAProgramsChildDoesNotOutliveItsDelivery(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	t.Cleanup(func() { killRecorded(r) })
	wantSummary(t, r.run(t, r.options(true, "detach="+idA)), 1, 0, 0, 0)
	if got := r.delivered(t); got != keyA {
		t.Errorf("delivered list = %q, want %q", got, keyA)
	}
	wantChildGone(t, r)
}

// wantChildGone waits a bounded time for the child the program recorded to
// be gone, and fails the test if it is still there.
func wantChildGone(t *testing.T, r rig) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.record, "grandchild"))
	mustDo(t, err)
	pid, err := strconv.Atoi(string(raw))
	mustDo(t, err)
	for deadline := time.Now().Add(10 * time.Second); ; {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the program's child %d outlived its delivery", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func killRecorded(r rig) {
	raw, err := os.ReadFile(filepath.Join(r.record, "grandchild"))
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(string(raw)); err == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// TestADoneContextStopsTheRun: nothing is delivered or marked and the
// context's error is returned.
func TestADoneContextStopsTheRun(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Run(ctx, r.options(true))
	wantIs(t, "a cancelled run", err, context.Canceled)
	if r.received(t) != "" || r.delivered(t) != "" {
		t.Errorf("a cancelled run delivered %q and marked %q", r.received(t), r.delivered(t))
	}
}

// TestALineThatIsNotItsRecordIsNeverHanded: the bytes handed to the program
// must decode to the record findinglog judged.
func TestALineThatIsNotItsRecordIsNeverHanded(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert), finding(idB, confirmed, alert))
	rec := &findingv1alpha1.Record{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: finding(idA, confirmed, alert)}}
	if err := sameRecord([]byte(r.logLine(t, idA, confirmed)), rec); err != nil {
		t.Fatalf("the record's own line: %v", err)
	}
	for name, line := range map[string]string{
		"another record's line": r.logLine(t, idB, confirmed),
		"a torn line":           r.logLine(t, idA, confirmed)[:40],
		"no line":               "",
	} {
		if err := sameRecord([]byte(line), rec); !errors.Is(err, ErrChanged) {
			t.Errorf("%s: sameRecord = %v, want ErrChanged", name, err)
		}
	}
}

// TestALogChangedAfterItWasReadStopsTheRun: the log holds A and B and its
// report, and is changed after the run judged it, before it reads the lines.
// Every line is held to its record, delivered or not, finding or report, and
// a changed one stops the run before anything is handed on for it.
func TestALogChangedAfterItWasReadStopsTheRun(t *testing.T) {
	for name, c := range map[string]struct {
		delivered bool
		line      int
		old, new  string
		want      error
	}{
		"nothing changed":      {true, 2, "", "", nil},
		"the header":           {true, 0, `"logId":"log-`, `"logId":"log-0`, ErrChanged},
		"an undelivered alert": {false, 1, `"ruleId":"repeated_denial"`, `"ruleId":"repeated_denials"`, ErrChanged},
		"an alert re-spelled":  {false, 1, `"tenantId":"tenant-a",`, `"tenantId":"tenant-a", `, ErrChanged},
		"a delivered alert":    {true, 2, `"ruleId":"repeated_denial"`, `"ruleId":"repeated_denials"`, ErrChanged},
		"the report":           {true, 3, `"tenantId":"tenant-a"`, `"tenantId":"tenant-b"`, ErrChanged},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.write(t, finding(idA, confirmed, alert), finding(idB, confirmed, alert))
			if c.delivered {
				wantSummary(t, r.run(t, r.options(true)), 2, 0, 0, 0)
			}
			before := r.received(t)
			ops := osOps
			ops.openLog = func(path string) (*os.File, error) {
				raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
				mustDo(t, err)
				lines := strings.SplitAfter(string(raw), "\n")
				edited := strings.Replace(lines[c.line], c.old, c.new, 1)
				if c.old != "" && edited == lines[c.line] {
					t.Fatalf("line %d holds no %s", c.line, c.old)
				}
				lines[c.line] = edited
				mustDo(t, os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600))
				return osOps.openLog(path)
			}
			o := r.options(!c.delivered)
			if _, err := run(t.Context(), o, ops); !errors.Is(err, c.want) {
				t.Errorf("run = %v, want %v", err, c.want)
			}
			if got := r.received(t); got != before {
				t.Errorf("the changed run handed the program %q", strings.TrimPrefix(got, before))
			}
		})
	}
}

// TestAnEscalationNeitherInformNorAlertStopsTheRun: findinglog refuses one,
// so meeting it here means the record did not come from the log as judged.
func TestAnEscalationNeitherInformNorAlertStopsTheRun(t *testing.T) {
	r := newRig(t)
	s, err := openState(r.state, true, osOps)
	mustDo(t, err)
	t.Cleanup(func() { _ = s.close() })
	d := &deliveries{o: r.options(true), s: s}
	f := finding(idA, confirmed, findingv1alpha1.Escalation_ESCALATION_UNSPECIFIED)
	rec := &findingv1alpha1.Record{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: f}}
	err = d.one(t.Context(), rec, nil)
	wantIs(t, "an unspecified escalation", err, ErrChanged)
	wantSummary(t, d.sum, 0, 0, 0, 0)
}
