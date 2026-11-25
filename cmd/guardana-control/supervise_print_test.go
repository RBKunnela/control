package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

var findingIDs = regexp.MustCompile(`fnd-[0-9a-f]{32}`)

// masked is out with the run ids given as the names beside them and every
// finding id as FND, the parts a fixture's run makes anew each time.
func masked(out string, runs ...string) string {
	for i := 0; i+1 < len(runs); i += 2 {
		out = strings.ReplaceAll(out, runs[i], runs[i+1])
	}
	return findingIDs.ReplaceAllString(out, "FND")
}

// TestSuperviseOutputOf01IsUnchanged pins, byte for byte, what a 0.1
// procedure's run prints: steps, findings with what they rest on, the six
// rules and the log.
func TestSuperviseOutputOf01IsUnchanged(t *testing.T) {
	tr := newSupTree(t)
	calls := []supCall{{req: "r1", tool: "get_order", upstream: "shop"}}
	for i, req := range []string{"d1", "d2", "d3", "d4"} {
		calls = append(calls, supCall{req: req, tool: "issue_refund", upstream: "pay", at: time.Duration(10+10*i) * time.Second, deny: true})
	}
	calls = append(calls, supCall{req: "w1", tool: "wipe_disk", upstream: "ops", at: 60 * time.Second},
		supCall{req: "r3", tool: "send_mail", upstream: "mail", at: 70 * time.Second})
	x := tr.export(t, tr.run, supBase, calls...)
	tr.closeRun(t, tr.run)
	code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	if code != exitFail || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	want := "run RUN tenant acme project orders procedure refund version 1\n" +
		"events: 24 taken\nobservations: 0 taken\nexports: 1 whole, 0 not whole\n" +
		"step lookup: requests r1\nstep refund: requests d1, d2, d3, d4\nstep notify: requests r3\n" +
		"finding REPEATED_DENIAL confirmed alert FND event d1-e3 (request d1), event d2-e3 (request d2), " +
		"event d3-e3 (request d3), event d4-e3 (request d4)\n" +
		"finding STEP_OUTSIDE_PROCEDURE confirmed alert FND event w1-e1 (request w1)\n" +
		"finding CONTINUED_AFTER_FAILURE suspected alert FND event d4-e3 (request d4), event r3-e1 (request r3)\n" +
		everyRule("checked") + "findings log: 3 written, 0 already held\n"
	if got := masked(stdout, tr.run, "RUN"); got != want {
		t.Errorf("stdout\n%s\nwant\n%s", got, want)
	}
}

// supervise02 writes the 0.2 procedure at version with children as given,
// an export of a lookup in the root, a call of wipe_disk in its child and a
// refund in the root, and supervises run.
func (tr supTree) supervise02(t *testing.T, f supFamily, version, children, run string) (int, string) {
	t.Helper()
	writeFixture(t, tr.procedure, strings.NewReplacer(`"children":"inherit"`, `"children":"`+children+`"`,
		`"version":"2"`, `"version":"`+version+`"`).Replace(supProcedure02))
	x := tr.exportRuns(t, supBase,
		runCalls{run: f.root, calls: []supCall{{req: "r1", tool: "get_order", upstream: "shop"}}},
		runCalls{run: f.child, calls: []supCall{{req: "w1", tool: "wipe_disk", upstream: "ops", at: 10 * time.Second}}},
		runCalls{run: f.root, calls: []supCall{{req: "r2", tool: "issue_refund", upstream: "pay", at: 20 * time.Second}}})
	args := tr.args("--evidence", x)
	args[6] = run
	code, stdout, stderr := invoke(t, args...)
	if stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	return code, masked(stdout, f.root, "ROOT", f.child, "CHILD", f.grandchild, "GRANDCHILD")
}

// rules02 is the eleven rules of an open tree under the 0.2 fixture.
const rules02 = "rule REPEATED_DENIAL checked\nrule STEP_OUTSIDE_PROCEDURE checked\nrule DEADLINE_EXCEEDED checked\n" +
	"rule REQUIRED_STEP_SKIPPED not checked: the run is open\nrule STEP_OUT_OF_ORDER not checked: the run is open\n" +
	"rule CONTINUED_AFTER_FAILURE not checked: the run is open\n" +
	"rule RESOURCE_OUTSIDE_RUN off: no step or allowed tool binds a resource\n" +
	"rule DENIED_ACTION_RETRIED_ARGUMENTS checked\nrule DENIED_ACTION_RETRIED_RESOURCE checked\n" +
	"rule DENIED_ACTION_RETRIED_AROUND not checked: no observation source was read\n" +
	"rule EXCEPTION_TAKEN off: the procedure states no exception\n"

// TestSuperviseOutputOf02NamesTheTree: under inherit the output names the
// mode and every run of the tree after its parent, each finding the run it
// names and each event's run, and every rule of the report; under separate
// the run's children are listed as not judged and the child's call is not
// read.
func TestSuperviseOutputOf02NamesTheTree(t *testing.T) {
	tr := newSupTree(t)
	f := tr.family(t)
	code, got := tr.supervise02(t, f, "2", "inherit", f.root)
	want := "run ROOT tenant acme project orders procedure refund version 2\n" +
		"children: inherit, every run of the tree judged\n" +
		"tree: ROOT\ntree: CHILD under ROOT\ntree: GRANDCHILD under CHILD\n" +
		"events: 12 taken\nobservations: 0 taken\nexports: 1 whole, 0 not whole\n" +
		"step lookup: requests r1\nstep refund: requests r2\nstep notify: no instance\n" +
		"finding STEP_OUTSIDE_PROCEDURE confirmed alert FND run CHILD event w1-e1 (request w1, run CHILD)\n" +
		rules02 + "findings log: 1 written, 0 already held\n"
	if code != exitFail || got != want {
		t.Errorf("inherit: exit %d, stdout\n%s\nwant\n%s", code, got, want)
	}

	code, got = tr.supervise02(t, f, "3", "separate", f.root)
	want = "run ROOT tenant acme project orders procedure refund version 3\n" +
		"children: separate, the run's own calls judged\n" +
		"tree: ROOT\ntree: CHILD under ROOT, not judged\n" +
		"events: 8 taken, 4 another run\nobservations: 0 taken\nexports: 1 whole, 0 not whole\n" +
		"step lookup: requests r1\nstep refund: requests r2\nstep notify: no instance\n" +
		rules02 + "findings log: 0 written, 0 already held\n"
	if code != exitFail || got != want {
		t.Errorf("separate: exit %d, stdout\n%s\nwant\n%s", code, got, want)
	}
}

// TestSuperviseSaysWhatAFindingLeftOut: twelve denials of one tool are one
// finding citing ten of them, and its line says the two it left out.
func TestSuperviseSaysWhatAFindingLeftOut(t *testing.T) {
	tr := newSupTree(t)
	var calls []supCall
	for i := range 12 {
		calls = append(calls, supCall{req: fmt.Sprintf("d%02d", i), tool: "issue_refund", upstream: "pay",
			at: time.Duration(i) * time.Second, deny: true})
	}
	x := tr.export(t, tr.run, supBase, calls...)
	_, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
	line := ""
	for _, l := range strings.Split(masked(stdout, tr.run, "RUN"), "\n") {
		if strings.HasPrefix(l, "finding REPEATED_DENIAL ") {
			line = l
		}
	}
	if stderr != "" || !strings.HasPrefix(line, "finding REPEATED_DENIAL confirmed alert FND event d00-e3 (request d00, run RUN), ") ||
		!strings.HasSuffix(line, "event d09-e3 (request d09, run RUN), 2 more left out") {
		t.Fatalf("stderr %q, the finding's line %q in\n%s", stderr, line, stdout)
	}
}

// TestAClosedRunWhoseCallsEndIsUnreadIsNoPass: a run closed after a call was
// allowed, or asked for its approval, but before its end was read may hide a
// failure the next call continued past, so the rule that reads ends is not
// checked and supervise exits 1; the same run with every end read exits 0.
// On the run still open, the call waiting on its approval puts nothing in
// doubt: REPEATED_DENIAL is checked, and the exit is 1 only for the rules an
// open run leaves unchecked.
func TestAClosedRunWhoseCallsEndIsUnreadIsNoPass(t *testing.T) {
	for name, c := range map[string]struct {
		cut        int
		held, open bool
		code       int
		line       string
	}{
		"every end read":        {0, false, false, exitOK, "rule CONTINUED_AFTER_FAILURE checked\n"},
		"a lookup's end unread": {2, false, false, exitFail, `rule CONTINUED_AFTER_FAILURE not checked: request "r1" is in doubt: its end was not read` + "\n"},
		"a lookup left at its approval request": {0, true, false, exitFail,
			`rule CONTINUED_AFTER_FAILURE not checked: request "r1" is in doubt: its end was not read` + "\n"},
		"an open run's lookup waiting on its approval": {0, true, true, exitFail,
			"rule REPEATED_DENIAL checked\n" + "rule STEP_OUTSIDE_PROCEDURE checked\n" + "rule DEADLINE_EXCEEDED checked\n" +
				"rule REQUIRED_STEP_SKIPPED not checked: the run is open\n" + "rule STEP_OUT_OF_ORDER not checked: the run is open\n" +
				"rule CONTINUED_AFTER_FAILURE not checked: the run is open\n"},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newSupTree(t)
			calls := conformingCalls()
			calls[0].cut, calls[0].held = c.cut, c.held
			x := tr.export(t, tr.run, supBase, calls...)
			if !c.open {
				tr.closeRun(t, tr.run)
			}
			code, stdout, stderr := invoke(t, tr.args("--evidence", x)...)
			if code != c.code || stderr != "" || !strings.Contains(stdout, c.line) {
				t.Errorf("exit %d, stderr %q, stdout\n%s\nwant %d and %q", code, stderr, stdout, c.code, c.line)
			}
		})
	}
}
