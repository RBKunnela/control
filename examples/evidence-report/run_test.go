package main

import (
	"strings"
	"testing"
)

// inRun moves the event of r1 numbered n to run.
func inRun(events []string, n int, run string) []string {
	out := append([]string(nil), events...)
	out[n] = strings.Replace(out[n], `"runId":"run-r1"`, `"runId":"`+run+`"`, 1)
	return out
}

// outsideRuns is r1 with no event naming a run, an action taken outside one.
func outsideRuns(events []string) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = strings.Replace(e, `"runId":"run-r1",`, "", 1)
	}
	return out
}

// laterRun is r1 with only its third event naming a run.
func laterRun(events []string) []string {
	out := outsideRuns(events)
	out[2] = events[2]
	return out
}

// followedInSplits feeds trail to a fresh state as the exports splits cuts
// it into, and returns the worst exit and every line written to stderr.
func followedInSplits(t *testing.T, trail []string, splits []int) outcome {
	t.Helper()
	dir := newState(t)
	var all outcome
	for i := 0; i+1 < len(splits); i++ {
		got := consume(t, dir, framed("a.trail", trail, splits[i], splits[i+1], 1000))
		all.code, all.stderr = max(all.code, got.code), all.stderr+got.stderr
	}
	return all
}

// TestARequestWhoseRunChangesIsUnknown: a plane stamps one run on a whole
// request, so one whose event names another run, or none where the first
// names one, cannot say which run did what. The walk and the follower, in
// the export that changes the run, which may follow a checkpoint, report it
// unknown at that event.
func TestARequestWhoseRunChangesIsUnknown(t *testing.T) {
	r1 := chain("r1", allowed...)
	for name, tc := range map[string]struct {
		trail []string
		note  string
	}{
		"the last event names another run": {inRun(r1, 3, "run-x"), "event r1-4 names run run-x, and the request's first event run-r1"},
		"a middle event names no run":      {inRun(r1, 1, ""), "event r1-2 names run -, and the request's first event run-r1"},
		"only a later event names a run":   {laterRun(r1), "event r1-3 names run run-r1, and the request's first event -"},
	} {
		t.Run(name, func(t *testing.T) {
			walked := report(t, newExport("1.0").event(tc.trail...).whole())
			rows, _ := table(t, walked.stdout)
			if walked.code != 1 || len(rows) != 1 || !strings.HasSuffix(rows[0], "\tunknown\t"+tc.note) {
				t.Errorf("the walk: exit %d, rows %q; want 1 and r1 unknown: %s", walked.code, rows, tc.note)
			}
			for exports, splits := range map[string][]int{"one export": {0, 4}, "two exports": {0, 2, 4}} {
				all := followedInSplits(t, tc.trail, splits)
				if all.code != 1 || !strings.Contains(alertLines(all.stderr), `"alert":"lifecycle_unknown"`) ||
					!strings.Contains(all.stderr, `"note":"`+tc.note+`"`) {
					t.Errorf("followed in %s: exit %d, stderr:\n%s\nwant 1 and r1 unknown: %s", exports, all.code, all.stderr, tc.note)
				}
			}
		})
	}
}

// TestARequestOutsideAnyRunIsCompleted: no event naming a run is one run,
// none, for the walk and the follower alike.
func TestARequestOutsideAnyRunIsCompleted(t *testing.T) {
	trail := outsideRuns(chain("r1", allowed...))
	walked := report(t, newExport("1.0").event(trail...).whole())
	rows, _ := table(t, walked.stdout)
	if want := "t\tp\tr1\t-\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"; walked.code != 0 || len(rows) != 1 || rows[0] != want {
		t.Errorf("the walk: exit %d, rows %q; want 0 and %q", walked.code, rows, want)
	}
	if followed := followedInSplits(t, trail, []int{0, 2, 4}); followed.code != 0 || followed.stderr != "" {
		t.Errorf("followed: exit %d, stderr %q; want 0 and nothing", followed.code, followed.stderr)
	}
}

// findingOf is a FINDING_RAISED linked after r1's last event, naming run, or
// no run when run is empty.
func findingOf(run string) string {
	e := evt("r1", "r1-5", "r1-4", "FINDING_RAISED", "")
	if run == "" {
		return strings.Replace(e, `"runId":"run-r1",`, "", 1)
	}
	return strings.Replace(e, `"runId":"run-r1"`, `"runId":"`+run+`"`, 1)
}

// TestTheFollowerHoldsAnAnnotationAfterTheEndToTheRun: a finding linked
// after a request's end is held to the request's run by the follower as by
// the walk, in the export that ends the request and in one after the state
// was saved, a request outside any run included.
func TestTheFollowerHoldsAnAnnotationAfterTheEndToTheRun(t *testing.T) {
	r1 := chain("r1", allowed...)
	for name, tc := range map[string]struct {
		trail []string
		note  string
	}{
		"of the request's run":     {append(append([]string(nil), r1...), findingOf("run-r1")), ""},
		"of another run":           {append(append([]string(nil), r1...), findingOf("run-x")), "event r1-5 names run run-x, and the request's first event run-r1"},
		"of no run, the request's": {append(outsideRuns(r1), findingOf("")), ""},
		"of no run, after a run":   {append(append([]string(nil), r1...), findingOf("")), "event r1-5 names run -, and the request's first event run-r1"},
		"of a run, after none":     {append(outsideRuns(r1), findingOf("run-r1")), "event r1-5 names run run-r1, and the request's first event -"},
	} {
		t.Run(name, func(t *testing.T) {
			walked := report(t, framed("a.trail", tc.trail, 0, 5, 1000))
			for exports, splits := range map[string][]int{"one export": {0, 5}, "two exports": {0, 4, 5}} {
				followed := followedInSplits(t, tc.trail, splits)
				if tc.note == "" {
					if walked.code != 0 || followed.code != 0 || followed.stderr != "" {
						t.Errorf("%s: walk exit %d, follow exit %d, stderr %q; want both 0", exports, walked.code, followed.code, followed.stderr)
					}
					continue
				}
				if walked.code != 1 || !strings.Contains(walked.stdout, "\tunknown\t"+tc.note) {
					t.Errorf("the walk: exit %d, stdout %q; want 1 and r1 unknown: %s", walked.code, walked.stdout, tc.note)
				}
				if followed.code != 1 || !strings.Contains(alertLines(followed.stderr), `"alert":"lifecycle_unknown"`) ||
					!strings.Contains(followed.stderr, `"note":"`+tc.note+`"`) {
					t.Errorf("followed in %s: exit %d, stderr:\n%s\nwant 1 and r1 unknown: %s", exports, followed.code, followed.stderr, tc.note)
				}
			}
		})
	}
}

// TestA11StateHoldsNoClosedRun: a 1.1 state, whose closed requests hold no
// run, is read; a finding after the end of such a request, even of its own
// run, cannot be held to it and is unknown, and the state is written back
// as 1.2.
func TestA11StateHoldsNoClosedRun(t *testing.T) {
	trail := append(chain("r1", allowed...), findingOf("run-r1"))
	dir := newState(t)
	if got := consume(t, dir, framed("a.trail", trail, 0, 4, 1000)); got.code != 0 {
		t.Fatalf("the first export: exit %d, stderr %q", got.code, got.stderr)
	}
	inTurn(editState(`"schema_version":"1.2"`, `"schema_version":"1.1"`), editState(`,"run":"run-r1"`, ``))(t, dir)
	got := consume(t, dir, framed("a.trail", trail, 4, 5, 1000))
	note := "event r1-5 follows the end of a request whose run the state does not hold"
	if got.code != 1 || !strings.Contains(got.stderr, `"note":"`+note+`"`) {
		t.Fatalf("after a 1.1 state: exit %d, stderr %q; want 1 and %s", got.code, got.stderr, note)
	}
	if s := stateOf(t, dir); !strings.HasPrefix(s, `{"schema_version":"1.2",`) {
		t.Errorf("the state written back:\n%s\nwant 1.2", s)
	}
}
