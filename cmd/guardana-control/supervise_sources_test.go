package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSuperviseSaysWhatOfASourceItRead: a descriptor that does not exist is
// left out and one whose log directory holds no log yet was never heard;
// neither is a refused input, and neither is a pass.
func TestSuperviseSaysWhatOfASourceItRead(t *testing.T) {
	tr := newSupTree(t)
	descriptor, log := tr.source(t)
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
	if want := "source agent-runtime: never heard\n"; code != 1 || stderr != "" || !strings.Contains(stdout, want) ||
		!strings.HasSuffix(stdout, "not checked: source agent-runtime never heard\nfindings log: 0 written, 0 already held\n") {
		t.Errorf("exit %d, stderr %q, stdout\n%s\nwant 1, %q and the source not checked", code, stderr, stdout, want)
	}
	if err := os.Remove(descriptor); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
	if want := "source " + descriptor + ": left out, no descriptor at that path\n"; code != 1 || stderr != "" ||
		!strings.Contains(stdout, want) || !strings.Contains(stdout, "not checked: source "+descriptor+" absent\n") {
		t.Errorf("exit %d, stderr %q, stdout\n%s\nwant 1, %q and the source not checked", code, stderr, stdout, want)
	}
}

// TestSuperviseASilentSourceIsNotAPass: a conforming run whose source was
// heard within its heartbeat of the run's last plane event exits 0; the same
// run dated past the source's import finds it silent and exits 1, naming it.
func TestSuperviseASilentSourceIsNotAPass(t *testing.T) {
	for name, c := range map[string]struct {
		base time.Time
		code int
	}{
		"heard":                 {supBase, 0},
		"dated past its import": {time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second), 1},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newSupTree(t)
			descriptor, log := tr.source(t)
			tr.observe(t, descriptor, log, "search_docs", c.base.Add(5*time.Second))
			x := tr.export(t, tr.run, c.base, conformingCalls()...)
			tr.closeRun(t, tr.run)
			code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
			if code != c.code || stderr != "" || strings.Contains(stdout, "finding ") {
				t.Fatalf("exit %d, stderr %q, stdout\n%s\nwant %d and no finding", code, stderr, stdout, c.code)
			}
			if silent := strings.Contains(stdout, "not checked: source agent-runtime silent\n"); silent != (c.code == 1) {
				t.Errorf("stdout names the source silent: %v, want %v:\n%s", silent, c.code == 1, stdout)
			}
		})
	}
}

// TestSuperviseJudgesASourceHeardAsOfTheRunsLastEvent: a call the source
// claims for the run and no step lists is suspected while the source was
// heard within its heartbeat of the run's last plane event. A source is heard
// no later than its import report was received, so events dated after that
// by more than the heartbeat find it silent, and the finding indeterminate.
func TestSuperviseJudgesASourceHeardAsOfTheRunsLastEvent(t *testing.T) {
	for name, c := range map[string]struct {
		base          time.Time
		verdict, last string
	}{
		"heard":                 {supBase, "suspected", "last heard 2026-01-05T09:00:05Z"},
		"dated past its import": {time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second), "indeterminate", "last heard "},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newSupTree(t)
			descriptor, log := tr.source(t)
			tr.observe(t, descriptor, log, "search_web", c.base.Add(5*time.Second))
			x := tr.export(t, tr.run, c.base, conformingCalls()...)
			tr.closeRun(t, tr.run)
			code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
			if code != 1 || stderr != "" {
				t.Fatalf("exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
			}
			finding := regexp.MustCompile(`(?m)^finding STEP_OUTSIDE_PROCEDURE ` + c.verdict +
				` alert fnd-[0-9a-f]{32} observation obs-[0-9a-f]{32} \(source agent-runtime\)$`)
			if !finding.MatchString(stdout) || strings.Count(stdout, "finding ") != 1 {
				t.Errorf("stdout holds no one %s STEP_OUTSIDE_PROCEDURE line citing the observation:\n%s", c.verdict, stdout)
			}
			if want := "source agent-runtime: 1 observation, " + c.last; !strings.Contains(stdout, want) {
				t.Errorf("stdout does not hold %q:\n%s", want, stdout)
			}
		})
	}
}

// TestSuperviseReadsNoEventOfALineCutShort: an export whose last line has no
// newline was cut short; the line is not read, the export is not whole, and
// the rules that rest on what was not seen are not checked.
func TestSuperviseReadsNoEventOfALineCutShort(t *testing.T) {
	tr := newSupTree(t)
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	raw, err := os.ReadFile(x) //nolint:gosec // G304: a path in this test's own directory
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	writeFixture(t, x, strings.Join(lines[:len(lines)-1], "\n"))
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
	}
	for _, want := range []string{"events: 11 taken\n", "exports: 0 whole, 1 not whole\n",
		"rule REQUIRED_STEP_SKIPPED not checked: an export is not whole: it has no trailer: it was cut short\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, stdout)
		}
	}
}

// TestSuperviseAnAbsentDescriptorPutsAbsenceInDoubt: a required step the run
// skipped is a suspected finding with no source named, and an indeterminate
// one when a named source's descriptor is absent, since what that source did
// not report was not read.
func TestSuperviseAnAbsentDescriptorPutsAbsenceInDoubt(t *testing.T) {
	for name, c := range map[string]struct {
		absent  bool
		verdict string
	}{
		"no source named":      {false, "suspected"},
		"an absent descriptor": {true, "indeterminate"},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newSupTree(t)
			x := tr.export(t, tr.run, supBase, supCall{req: "r1", tool: "get_order", upstream: "shop"})
			tr.closeRun(t, tr.run)
			args := tr.args("--evidence", x)
			if c.absent {
				args = append(args, "--source", filepath.Join(tr.dir, "gone.json"), "--log", tr.dir)
			}
			code, stdout, stderr := invoke(t, args...)
			if code != 1 || stderr != "" {
				t.Fatalf("exit %d, stderr %q, stdout\n%s", code, stderr, stdout)
			}
			want := regexp.MustCompile(`(?m)^finding REQUIRED_STEP_SKIPPED ` + c.verdict + ` alert fnd-[0-9a-f]{32}`)
			if !want.MatchString(stdout) {
				t.Errorf("stdout holds no %s REQUIRED_STEP_SKIPPED finding:\n%s", c.verdict, stdout)
			}
		})
	}
}

// TestSuperviseAnUnjoinedObservationIsNoInstanceOfItsStep: a call of a step's
// tool that only the runtime reported is printed as reported by the runtime
// only, never as an instance of the step.
func TestSuperviseAnUnjoinedObservationIsNoInstanceOfItsStep(t *testing.T) {
	tr := newSupTree(t)
	descriptor, log := tr.source(t)
	tr.observe(t, descriptor, log, "issue_refund", supBase.Add(5*time.Second))
	x := tr.export(t, tr.run, supBase, supCall{req: "r1", tool: "get_order", upstream: "shop"})
	tr.closeRun(t, tr.run)
	_, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
	want := regexp.MustCompile(`(?m)^step refund: no instance; reported by the runtime only: obs-[0-9a-f]{32}$`)
	if !want.MatchString(stdout) || strings.Contains(stdout, "; observations ") {
		t.Errorf("stderr %q, stdout\n%s\nwant the refund step's observation reported by the runtime only", stderr, stdout)
	}
}

// spansLine is one OTLP/JSON line of supSpan's resource holding spans.
func spansLine(spans ...string) string {
	line := fmt.Sprintf(supSpan, 0, 0, "", "")
	open, closing := `"spans":[`, `]}],"schemaUrl"`
	return line[:strings.Index(line, open)+len(open)] + strings.Join(spans, ",") + line[strings.Index(line, closing):]
}

// toolSpan is supSpan's span with spanID, a call of tool claimed for run
// with status code status, ending at end.
func toolSpan(spanID, tool, run string, status int, end time.Time) string {
	line := fmt.Sprintf(supSpan, end.Add(-time.Second).UnixNano(), end.UnixNano(), tool, run)
	open, closing := `"spans":[`, `]}],"schemaUrl"`
	span := line[strings.Index(line, open)+len(open) : strings.Index(line, closing)]
	return strings.NewReplacer(`"00f067aa0ba90001"`, strconv.Quote(spanID),
		`"status":{"code":1}`, fmt.Sprintf(`"status":{"code":%d}`, status)).Replace(span)
}

// importSpans imports line and wants the conflicts and refusals counted, and
// exit 1 for any.
func (tr supTree) importSpans(t *testing.T, descriptor, log, line string, conflicts, refused int) {
	t.Helper()
	input := filepath.Join(tr.dir, "spans.jsonl")
	writeFixture(t, input, line)
	code, out, stderr := invoke(t, "observe", "import", "--source", descriptor, "--log", log, input)
	want := exitOK
	if conflicts+refused > 0 {
		want = exitFail
	}
	if counted(t, out, "conflict") != conflicts || counted(t, out, "refused") != refused || code != want {
		t.Fatalf("import: exit %d, stdout %q, stderr %q; want %d conflict(s), %d refused", code, out, stderr, conflicts, refused)
	}
}

// TestSuperviseACopyTheImportRefusedIsNotAPass: an agent that sends an
// allowed call and then a call no step lists, under the same trace and span
// id or in a span the import refuses, has its log keep the allowed call
// alone. The run is not judged as if the log held all it was sent: while a
// refused span, either copy of a conflict, or a refused copy of no run
// claimed it, the rules that read the source's reports are not checked and
// supervise exits 1. Copies that all claimed another run leave it judged.
func TestSuperviseACopyTheImportRefusedIsNotAPass(t *testing.T) {
	const why = `not checked: source "agent-runtime" is in doubt: an import refused a copy that may be a call of a run judged`
	const other = "run-ffffffffffffffffffffffffffffffff"
	end := supBase.Add(5 * time.Second)
	call := func(tool, run string) string { return toolSpan("00f067aa0ba90001", tool, run, 1, end) }
	refused := func(run string) string { return toolSpan("00f067aa0ba90002", "drop_table", run, 7, end) }
	for name, c := range map[string]struct {
		spans                    func(run string) []string
		conflicts, refused, code int
	}{
		"the allowed call alone": {func(run string) []string { return []string{call("search_docs", run)} }, 0, 0, exitOK},
		"a forbidden call, the same ids": {func(run string) []string {
			return []string{call("search_docs", run), call("drop_table", run)}
		}, 1, 0, exitFail},
		"a forbidden call refused": {func(run string) []string { return []string{call("search_docs", run), refused(run)} }, 0, 1, exitFail},
		"a forbidden call of no run": {func(run string) []string {
			return []string{call("search_docs", run), call("drop_table", "")}
		}, 1, 0, exitFail},
		"a forbidden call of another run, the same ids as this run's": {func(run string) []string {
			return []string{call("search_docs", run), call("drop_table", other)}
		}, 1, 0, exitFail},
		"two calls of another run, the same ids": {func(run string) []string {
			return []string{call("search_docs", run), toolSpan("00f067aa0ba90003", "search_docs", other, 1, end),
				toolSpan("00f067aa0ba90003", "drop_table", other, 1, end)}
		}, 1, 0, exitOK},
		"a refused call of another run": {func(run string) []string { return []string{call("search_docs", run), refused(other)} }, 0, 1, exitOK},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newSupTree(t)
			writeFixture(t, tr.procedure, supProcedure02)
			descriptor, log := tr.source(t)
			spans := c.spans(tr.run)
			tr.importSpans(t, descriptor, log, spansLine(spans...), c.conflicts, c.refused)
			x := tr.export(t, tr.run, supBase, conformingCalls()...)
			tr.closeRun(t, tr.run)
			code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
			if code != c.code || stderr != "" || strings.Contains(stdout, "finding ") {
				t.Fatalf("exit %d, stderr %q, stdout\n%s\nwant %d and no finding", code, stderr, stdout, c.code)
			}
			for _, rule := range []string{"STEP_OUTSIDE_PROCEDURE", "DENIED_ACTION_RETRIED_AROUND"} {
				want := "rule " + rule + " checked\n"
				if c.code != exitOK {
					want = "rule " + rule + " " + why + "\n"
				}
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout does not hold %q:\n%s", want, stdout)
				}
			}
		})
	}
}

// TestSuperviseAnotherSourcesDoubtIsNotThisSources: a line another source's
// import refused whole, in the same log directory, puts that source's runs in
// doubt and not the supervised source's, whose rules are still checked.
func TestSuperviseAnotherSourcesDoubtIsNotThisSources(t *testing.T) {
	tr := newSupTree(t)
	writeFixture(t, tr.procedure, supProcedure02)
	descriptor, log := tr.source(t)
	end := supBase.Add(5 * time.Second)
	tr.importSpans(t, descriptor, log, spansLine(toolSpan("00f067aa0ba90001", "search_docs", tr.run, 1, end)), 0, 0)
	raw, err := os.ReadFile(descriptor) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(tr.dir, "other.json")
	writeFixture(t, other, strings.Replace(string(raw), `"agent-runtime"`, `"other-runtime"`, 1))
	malformed := filepath.Join(tr.dir, "malformed.jsonl")
	writeFixture(t, malformed, "{not a line of spans\n")
	if code, out, stderr := invoke(t, "observe", "import", "--source", other, "--log", log, malformed); code != exitFail || counted(t, out, "refused") != 1 {
		t.Fatalf("import of the other source: exit %d, stdout %q, stderr %q; want 1 and one refusal", code, out, stderr)
	}
	x := tr.export(t, tr.run, supBase, conformingCalls()...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout\n%s\nwant 0", code, stderr, stdout)
	}
	for _, rule := range []string{"STEP_OUTSIDE_PROCEDURE", "DENIED_ACTION_RETRIED_AROUND"} {
		if want := "rule " + rule + " checked\n"; !strings.Contains(stdout, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, stdout)
		}
	}
	code, stdout, _ = invoke(t, tr.args("--evidence", x, "--source", other, "--log", log)...)
	if want := `source "other-runtime" is in doubt`; code != exitFail || !strings.Contains(stdout, want) {
		t.Errorf("supervised against the other source: exit %d, stdout\n%s\nwant 1 and %q", code, stdout, want)
	}
}
