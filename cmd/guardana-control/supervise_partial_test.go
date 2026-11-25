package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/observelog"
)

// TestSuperviseASourceThatMayHaveMissedACallIsNotAPass: a source whose
// descriptor says it samples, or whose log holds a write no import report
// closes, may not have reported a call around the plane, so the rules that
// read its reports are not checked and supervise exits 1; the same source
// complete, with every write closed, exits 0.
func TestSuperviseASourceThatMayHaveMissedACallIsNotAPass(t *testing.T) {
	end := supBase.Add(5 * time.Second)
	for name, c := range map[string]struct {
		sampling string
		tail     string
		code     int
		why      string
	}{
		"complete, every write closed": {"SAMPLING_COMPLETE", "", exitOK, ""},
		"sampled":                      {"SAMPLING_PARTIAL", "", exitFail, `source "agent-runtime" is in doubt: its descriptor does not say it reports every call`},
		"a write not closed":           {"SAMPLING_COMPLETE", `{"observation":{"sche`, exitFail, `source "agent-runtime" is in doubt: its log holds a write no import report closes`},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newSupTree(t)
			writeFixture(t, tr.procedure, supProcedure02)
			descriptor, log := tr.source(t)
			raw, err := os.ReadFile(descriptor) //nolint:gosec // G304: the test's own temporary directory
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, descriptor, strings.Replace(string(raw), `"SAMPLING_COMPLETE"`, `"`+c.sampling+`"`, 1))
			tr.importSpans(t, descriptor, log, spansLine(toolSpan("00f067aa0ba90001", "search_docs", tr.run, 1, end)), 0, 0)
			if c.tail != "" {
				f, err := os.OpenFile(filepath.Join(log, observelog.FileName), os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own temporary directory
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteString(c.tail); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			x := tr.export(t, tr.run, supBase, conformingCalls()...)
			tr.closeRun(t, tr.run)
			code, stdout, stderr := invoke(t, tr.args("--evidence", x, "--source", descriptor, "--log", log)...)
			if code != c.code || stderr != "" {
				t.Fatalf("exit %d, stderr %q, stdout\n%s\nwant %d", code, stderr, stdout, c.code)
			}
			for _, rule := range []string{"STEP_OUTSIDE_PROCEDURE", "DENIED_ACTION_RETRIED_AROUND"} {
				want := "rule " + rule + " checked\n"
				if c.why != "" {
					want = "rule " + rule + " not checked: " + c.why
				}
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout does not hold %q:\n%s", want, stdout)
				}
			}
		})
	}
}
