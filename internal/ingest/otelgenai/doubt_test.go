package otelgenai_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/ingest/otelgenai"
)

const runB = "run-11111111111111111111111111111111"

func runAttr(run string) string {
	return `,{"key":"app.run_id","value":{"stringValue":"` + run + `"}}`
}

const badStatus = `,"status":{"code":7}`

// TestARefusedSpanPutsTheRunItClaimsInDoubt: the report names the runs its
// refused spans claim, sorted and once each; a refused span that claims no
// run, or a line refused before any span of it is read, puts every run in
// doubt. A span observed puts nothing in doubt.
func TestARefusedSpanPutsTheRunItClaimsInDoubt(t *testing.T) {
	second := func(line, spanExtra, run string) string {
		return strings.Replace(line, `"spans":[`, `"spans":[{"traceId":"`+traceA+`","spanId":"00f067aa0ba90002"`+spanExtra+
			`,"attributes":[{"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}}`+runAttr(run)+`]},`, 1)
	}
	for name, c := range map[string]struct {
		lines []string
		every bool
		runs  []string
	}{
		"a span observed":           {[]string{oneSpan("", runAttr(runA))}, false, nil},
		"a status outside 0 to 2":   {[]string{oneSpan(badStatus, runAttr(runA))}, false, []string{runA}},
		"a zero span id":            {[]string{strings.Replace(oneSpan("", runAttr(runA)), "00f067aa0ba90001", "0000000000000000", 1)}, false, []string{runA}},
		"two runs, one twice":       {[]string{second(oneSpan(badStatus, runAttr(runB)), badStatus, runA), oneSpan(badStatus, runAttr(runB))}, false, []string{runA, runB}},
		"a refused span and a kept": {[]string{second(oneSpan("", runAttr(runB)), badStatus, runA)}, false, []string{runA}},
		"no run claimed":            {[]string{oneSpan(badStatus, "")}, true, nil},
		"a malformed run claimed":   {[]string{oneSpan(badStatus, runAttr("run-1"))}, true, nil},
		"a line that does not read": {[]string{oneSpan("", runAttr(runA)) + "}"}, true, nil},
		"a line over the bound":     {[]string{strings.Repeat(" ", otelgenai.MaxLineBytes+1)}, true, nil},
	} {
		t.Run(name, func(t *testing.T) {
			b := importBytes(t, []byte(strings.Join(c.lines, "\n")+"\n"), descriptor(t))
			if r := b.Report; r.GetEveryRunDoubted() != c.every || !slices.Equal(r.GetDoubtedRunIds(), c.runs) {
				t.Fatalf("every %v, runs %v; want %v, %v", r.GetEveryRunDoubted(), r.GetDoubtedRunIds(), c.every, c.runs)
			}
			version := "0.1"
			if c.every || len(c.runs) > 0 {
				version = "0.2"
			}
			if got := b.Report.GetSchemaVersion(); got != version {
				t.Errorf("schema_version %q, want %q", got, version)
			}
		})
	}
}

// TestRefusedSpansNameAtMost64Runs: 64 runs are named; a 65th puts every
// run in doubt.
func TestRefusedSpansNameAtMost64Runs(t *testing.T) {
	for _, c := range []struct {
		runs, named int
		every       bool
	}{{64, 64, false}, {65, 0, true}} {
		var lines []string
		for i := range c.runs {
			lines = append(lines, oneSpan(badStatus, runAttr(fmt.Sprintf("run-%032x", i))))
		}
		r := importBytes(t, []byte(strings.Join(lines, "\n")+"\n"), descriptor(t)).Report
		if r.GetEveryRunDoubted() != c.every || len(r.GetDoubtedRunIds()) != c.named {
			t.Errorf("%d runs: every %v, %d named; want %v, %d", c.runs, r.GetEveryRunDoubted(), len(r.GetDoubtedRunIds()), c.every, c.named)
		}
	}
}
