package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const tooLong = "an event holds a value longer than 64 bytes as JSON writes it, or more than 16 reason codes, which this reader does not keep"

// reasonList is n reason codes, each of length bytes.
func reasonList(n, length int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("C%0*d", length-1, i)
	}
	return out
}

// TestValueBound: a value of 64 bytes and 16 reason codes are followed; one
// byte or one code more and the event is not kept: it raises
// lifecycle_unknown without the value, and its request ends unknown.
func TestValueBound(t *testing.T) {
	at64, at65 := strings.Repeat("e", 64), strings.Repeat("e", 65)
	head := evt("x", "x-1", "", "ACTION_PROPOSED", proposed("read_order"))
	decidedWith := func(cs []string) string {
		return evt("x", "x-2", "x-1", "POLICY_DECIDED", decided("ALLOW", cs...))
	}
	unknownAt := func(offset int, event string) string {
		return `{"v":1,"alert":"lifecycle_unknown","tenant":"t","project":"p","request":"x","run":"run-x",` + event +
			fmt.Sprintf(`"offset":%d,"note":"%s"}`, offset, tooLong) + "\n"
	}
	second := len(head) + 1
	for _, tc := range []struct {
		name   string
		lines  []string
		alerts string
	}{
		{name: "an event id JSON writes in 65 bytes", lines: []string{evt("x", strings.Repeat("e", 59)+`\u003c`, "", "ACTION_PROPOSED", proposed("read_order"))},
			alerts: unknownAt(0, "")},
		{name: "an event id of 64 bytes", lines: []string{evt("x", at64, "", "ACTION_PROPOSED", proposed("read_order"))}},
		{name: "an event id of 65 bytes", lines: []string{evt("x", at65, "", "ACTION_PROPOSED", proposed("read_order"))},
			alerts: unknownAt(0, "")},
		{name: "a tenant of 65 bytes", lines: []string{strings.Replace(head, `"tenantId":"t"`, `"tenantId":"`+at65+`"`, 1)},
			alerts: strings.Replace(unknownAt(0, `"event":"x-1",`), `"tenant":"t",`, "", 1)},
		{name: "an action name of 64 bytes", lines: []string{evt("x", "x-1", "", "ACTION_PROPOSED", proposed(at64))}},
		{name: "an action name of 65 bytes", lines: []string{evt("x", "x-1", "", "ACTION_PROPOSED", proposed(at65))},
			alerts: unknownAt(0, `"event":"x-1",`)},
		{name: "16 reason codes of 64 bytes", lines: []string{head, decidedWith(reasonList(16, 64))}},
		{name: "17 reason codes", lines: []string{head, decidedWith(reasonList(17, 8))}, alerts: unknownAt(second, `"event":"x-2",`)},
		{name: "a reason code of 65 bytes", lines: []string{head, decidedWith(reasonList(1, 65))}, alerts: unknownAt(second, `"event":"x-2",`)},
		{name: "a decision id of 65 bytes", lines: []string{head, evt("x", "x-2", "x-1", "POLICY_DECIDED", decidedAs(at65, "ALLOW", "R"))},
			alerts: unknownAt(second, `"event":"x-2",`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := consume(t, newState(t), framed("x.trail", tc.lines, 0, len(tc.lines), 1000))
			want := 0
			if tc.alerts != "" {
				want = 1
			}
			if got.code != want || withoutCursors(alertLines(got.stderr)) != tc.alerts {
				t.Errorf("exit %d, alerts\n%s\nwant %d,\n%s", got.code, alertLines(got.stderr), want, tc.alerts)
			}
			if strings.Contains(got.stdout+got.stderr, at65) {
				t.Errorf("a value over the bound was printed:\n%s%s", got.stdout, got.stderr)
			}
		})
	}
}

// TestStateSizeBound: a state of exactly the bound is saved; one byte over,
// the run exits 2 before it appends an alert, and nothing changes.
func TestStateSizeBound(t *testing.T) {
	ref := newState(t)
	consume(t, ref, fixture(t, "gaps.jsonl"))
	size := len(stateOf(t, ref))
	t.Cleanup(func() { maxStateBytes = 64 << 20 })
	for _, tc := range []struct {
		bound, code int
	}{{size, 1}, {size - 1, 2}} {
		maxStateBytes = 64 << 20
		dir := newState(t)
		maxStateBytes = tc.bound
		before := snapshot(t, dir)
		got := consume(t, dir, fixture(t, "gaps.jsonl"))
		if got.code != tc.code {
			t.Errorf("a state of %d bytes under a bound of %d: exit %d, want %d; stderr %s", size, tc.bound, got.code, tc.code, got.stderr)
		}
		if tc.code == 2 && (snapshot(t, dir) != before || !strings.Contains(got.stderr, "bytes")) {
			t.Errorf("a state over the bound: stderr %q, and the directory changed: %v", got.stderr, snapshot(t, dir) != before)
		}
	}
}

// TestTailGapOnce: the bytes after the last newline are alerted once, though
// every export after the cursor, which cannot pass them, reports them again.
func TestTailGapOnce(t *testing.T) {
	again := followStep{export: "gaps-2.jsonl", totals: totalsLine(0, 0, 0, 0, 0, 1, 0, 0, "trailer 15 bytes cut, no writer holds them")}
	runSteps(t, []followStep{{export: "gaps.jsonl", code: 1, rows: []string{rowG},
		totals: totalsLine(1, 1, 0, 0, 0, 3, 0, 0, "trailer 15 bytes cut, no writer holds them"),
		alerts: []expectedAlert{gapAlert(305, "malformed"), gapAlert(646, "unsupported_version"),
			{`{"v":1,"alert":"evidence_gap","offset":1540,"note":"partial_tail","source":"` + gapsSource + `"}`, 1540}}}, again, again})
}

// TestEventAlertsAfterABreak: a request whose chain broke, or that ended,
// still raises what its later events call for.
func TestEventAlertsAfterABreak(t *testing.T) {
	broken := []string{evt("b", "b-1", "", "ACTION_PROPOSED", proposed("read_order")),
		evt("b", "b-3", "b-2", "POLICY_DECIDED", decidedAs("k1", "INDETERMINATE", "PDP_TIMEOUT")),
		evt("b", "b-4", "b-3", "ACTION_BLOCKED", decidedAs("p1", "DENY", "PAUSED"))}
	ended := append(chain("c", allowed...), evt("c", "c-5", "c-4", "ACTION_BLOCKED", decidedAs("p1", "DENY", "PAUSED")))
	ids := `"tenant":"t","project":"p","request":"%s","run":"run-%[1]s","event":"%s","offset":%d`
	for _, tc := range []struct {
		name   string
		lines  []string
		alerts func(at []int) string
	}{
		{name: "a broken chain", lines: broken, alerts: func(at []int) string {
			return `{"v":1,"alert":"indeterminate",` + fmt.Sprintf(ids, "b", "b-3", at[1]) + `,"verdict":"INDETERMINATE","reasons":["PDP_TIMEOUT"]}` + "\n" +
				`{"v":1,"alert":"lifecycle_unknown",` + fmt.Sprintf(ids, "b", "b-3", at[1]) + `,"note":"event b-3 follows b-2, which this export does not hold"}` + "\n" +
				`{"v":1,"alert":"plane_block",` + fmt.Sprintf(ids, "b", "b-4", at[2]) + `,"block":"DENY PAUSED"}` + "\n"
		}},
		{name: "an ended request", lines: ended, alerts: func(at []int) string {
			return `{"v":1,"alert":"plane_block",` + fmt.Sprintf(ids, "c", "c-5", at[4]) + `,"block":"DENY PAUSED"}` + "\n" +
				`{"v":1,"alert":"lifecycle_unknown",` + fmt.Sprintf(ids, "c", "c-5", at[4]) + `,"note":"event c-5 follows c-4 after request c ended at c-4"}` + "\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := make([]int, len(tc.lines))
			for i := 1; i < len(at); i++ {
				at[i] = at[i-1] + len(tc.lines[i-1]) + 1
			}
			got := consume(t, newState(t), framed("b.trail", tc.lines, 0, len(tc.lines), 1000))
			if want := tc.alerts(at); got.code != 1 || withoutCursors(alertLines(got.stderr)) != want {
				t.Errorf("exit %d, alerts\n%s\nwant 1,\n%s", got.code, alertLines(got.stderr), want)
			}
		})
	}
}

// TestFollowForkAfterTheEnd: a finding that follows the last event of an
// ended request leaves it as it ended; one that forks from the middle of its
// chain raises lifecycle_unknown.
func TestFollowForkAfterTheEnd(t *testing.T) {
	runSteps(t, []followStep{{export: "fork.jsonl", code: 1, rows: []string{"acme\tdemo\tH\trun-H\tread_order\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"},
		totals: totalsLine(1, 1, 0, 0, 0, 0, 0, 0, reached),
		alerts: []expectedAlert{{`{"v":1,"alert":"lifecycle_unknown","tenant":"acme","project":"demo","request":"H","run":"run-H","event":"H6",` +
			`"offset":1495,"cursor":"%s","occurred_at":"2026-10-02T10:01:46Z","note":"event H6 follows H2 after request H ended at H5"}`, 1495}}}})
}

// TestLock: while another run holds the state directory's lock, a run exits 2
// and changes nothing; once it is let go, the run goes on.
func TestLock(t *testing.T) {
	dir := newState(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	held, err := root.OpenFile("lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := lockExclusive(held); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	got := consume(t, dir, fixture(t, "gaps.jsonl"))
	if got.code != 2 || !strings.Contains(got.stderr, "another run") || snapshot(t, dir) != before {
		t.Errorf("a held lock: exit %d, stderr %q, changed %v; want 2, another run, nothing changed", got.code, got.stderr, snapshot(t, dir) != before)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if got := consume(t, dir, fixture(t, "gaps.jsonl")); got.code != 1 {
		t.Errorf("after the lock was let go: exit %d, want 1; stderr %s", got.code, got.stderr)
	}
}

// TestCrashThenShorterRerun: a run that crashed after logging the one-shot
// export's alerts is followed by shorter exports; each alert stays in the
// log once, though the run after the crash never reached most of them.
func TestCrashThenShorterRerun(t *testing.T) {
	for _, point := range []string{"alerts", "state"} {
		t.Run(point, func(t *testing.T) {
			dir := newState(t)
			crashOnce(t, point)
			consume(t, dir, fixture(t, "outage.jsonl"))
			for _, e := range []string{"outage-1.jsonl", "outage-2.jsonl", "outage-3.jsonl", "outage-4.jsonl", "outage-5.jsonl"} {
				if got := consume(t, dir, fixture(t, e)); got.code != 0 || alertLines(got.stderr) != "" {
					t.Errorf("%s: exit %d, alerts\n%s\nwant 0 and none raised again", e, got.code, alertLines(got.stderr))
				}
			}
			var want strings.Builder
			for _, a := range []expectedAlert{alertC2, alertGap, alertD3, alertE4, alertE5} {
				want.WriteString(a.in(t, "outage.jsonl") + "\n")
			}
			if got := alertLog(t, dir); got != want.String() {
				t.Errorf("alerts.jsonl:\n%s\nwant each alert once:\n%s", got, want.String())
			}
			if strings.Contains(stateOf(t, dir), `"pending":[{`) {
				t.Errorf("the state still carries alerts the cursor passed:\n%s", stateOf(t, dir))
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("the reader went away") }

// TestStdoutFailure: rows that cannot be written come after the alerts are
// logged and shown, and stop the run before the state is replaced: exit 2,
// state.json as it was, and the alerts kept in the log, which the next run
// does not raise again.
func TestStdoutFailure(t *testing.T) {
	dir := newState(t)
	saved := stateOf(t, dir)
	var stderr bytes.Buffer
	code := run([]string{"-state", dir}, strings.NewReader(fixture(t, "gaps.jsonl")), failingWriter{}, &stderr)
	want := gapAlert(305, "malformed").in(t, "gaps.jsonl") + "\n" + gapAlert(646, "unsupported_version").in(t, "gaps.jsonl") + "\n" +
		`{"v":1,"alert":"evidence_gap","offset":1540,"note":"partial_tail","source":"` + gapsSource + `"}` + "\n"
	if code != 2 || !strings.Contains(stderr.String(), "could not be written") || stateOf(t, dir) != saved {
		t.Errorf("exit %d, stderr %q, state changed %v; want 2, could not be written, state.json as it was", code, stderr.String(), stateOf(t, dir) != saved)
	}
	if alertLines(stderr.String()) != want || alertLog(t, dir) != want {
		t.Errorf("stderr alerts\n%s\nalerts.jsonl\n%s\nwant both:\n%s", alertLines(stderr.String()), alertLog(t, dir), want)
	}
	got := consume(t, dir, fixture(t, "gaps.jsonl"))
	if got.code != 0 || alertLines(got.stderr) != "" || alertLog(t, dir) != want || !strings.Contains(got.stdout, rowG) {
		t.Errorf("the run after: exit %d, alerts %q, stdout %q; want 0, none raised again, the row", got.code, got.stderr, got.stdout)
	}
}

// TestFormatCharacters: a format or separator character in a value is
// quoted in a row and escaped in an alert, so neither reorders nor breaks
// what a terminal shows.
func TestFormatCharacters(t *testing.T) {
	for _, c := range []struct{ raw, escaped string }{{"\u202e", `\u202e`}, {"\u2028", `\u2028`}, {"\u2029", `\u2029`}, {"\u200b", `\u200b`}} {
		got := report(t, newExport("1.0").event(chain("r1", then(allowed[:0], step{"ACTION_PROPOSED", proposed("read" + c.raw + "order")},
			allowed[1], allowed[2], allowed[3])...)...).whole())
		rows, _ := table(t, got.stdout)
		if want := "t\tp\tr1\trun-r1\t\"read" + c.escaped + "order\"\tALLOW\tRULE_ALLOW\t-\tno\t-\tcompleted\t-"; len(rows) != 1 || rows[0] != want {
			t.Errorf("report mode, %q: rows %q, want %q", c.escaped, rows, want)
		}
		lines := chain("r"+c.raw, undetermined...)
		got = consume(t, newState(t), framed("u.trail", lines, 0, len(lines), 1000))
		if strings.Contains(got.stdout+got.stderr, c.raw) || !strings.Contains(alertLines(got.stderr), `"request":"r`+c.escaped+`"`) {
			t.Errorf("state mode, %q: stdout %q, stderr %q", c.escaped, got.stdout, got.stderr)
		}
	}
}

// TestStateSymlink: a -state that is a link to a state directory is refused.
func TestStateSymlink(t *testing.T) {
	dir := newState(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if got := consume(t, link, fixture(t, "outage-1.jsonl")); got.code != 2 || !strings.Contains(got.stderr, "not a directory") {
		t.Errorf("exit %d, stderr %q; want 2, not a directory", got.code, got.stderr)
	}
}

// TestTheBoundsFitTheState builds the largest state the bounds allow:
// maxOpen requests, each with every value it keeps at maxValueBytes and its
// decisions at maxReasons codes, a full window, and a request ended at each
// of its events. It has to fit under maxStateBytes, or a run could save a
// state the next run refuses to read. Alerts carried past a crash are not
// bounded by count; a state they would push over is refused when saved.
func TestTheBoundsFitTheState(t *testing.T) {
	value := func(prefix string, i int) string { return fmt.Sprintf("%s%0*d", prefix, maxValueBytes-len(prefix), i) }
	full := &decisionFacts{id: value("d", 0), verdict: "ALLOW_WITH_OBLIGATIONS", codes: reasonList(maxReasons, maxValueBytes)}
	s := emptyState()
	s.cursor, s.source = someCursor, strings.Repeat("a", 64)
	s.tailGap = &gapRecord{offset: 1 << 62, reason: "conflicting_event_id"}
	for i := range maxOpen {
		k := requestKey{value("t", i), value("p", i), value("r", i)}
		s.open[k] = &openRequest{key: k, firstOffset: 1 << 62, tailOffset: 1 << 62, head: value("h", i), tail: value("e", i),
			desc: description{run: value("u", i), action: value("a", i), kernel: full, blocked: true, block: full, held: true, approval: "expired"},
			walk: walker{at: atApprovalExpired, prevKind: "APPROVAL_REQUESTED", mode: 6, verdict: 4, answer: "rejected", running: value("x", i),
				note: "ran under OBSERVE, which enforces nothing, after verdict ALLOW_WITH_OBLIGATIONS, which no approval lifts"}}
	}
	for i := range windowSize {
		e := seenEvent{key: eventKey{value("t", i), value("p", i), value("w", i)}, request: value("q", i), hash: strings.Repeat("f", 64)}
		s.window = append(s.window, e)
		s.closed[requestKey{e.key.tenant, e.key.project, e.request}] = &closedRequest{tail: e.key.id, kernel: value("k", i), unknown: true}
	}
	b, err := json.Marshal(s.file(1 << 62))
	if err != nil {
		t.Fatal(err)
	}
	if len(b)+1 > maxStateBytes {
		t.Fatalf("the largest state the bounds allow is %d bytes, over maxStateBytes, %d", len(b)+1, maxStateBytes)
	}
	if !strings.Contains(string(b), value("k", windowSize-1)) || !strings.Contains(string(b), value("x", maxOpen-1)) {
		t.Fatal("the state built holds less than the bounds allow")
	}
}

// TestCrashThenTheTailEnds: a run crashed after alerting the bytes after the
// last newline, and a writer then ended that line as a line the export reads
// as another gap. The run after it raises that gap, which is another alert at
// the same offset, and stops carrying the first once its cursor passed it.
func TestCrashThenTheTailEnds(t *testing.T) {
	dir := newState(t)
	crashOnce(t, "alerts")
	consume(t, dir, fixture(t, "gaps.jsonl"))
	got := consume(t, dir, fixture(t, "gaps-grown.jsonl"))
	want := gapAlert(1540, "unsupported_version").in(t, "gaps-grown.jsonl") + "\n"
	if got.code != 1 || alertLines(got.stderr) != want {
		t.Errorf("exit %d, alerts\n%s\nwant 1,\n%s", got.code, alertLines(got.stderr), want)
	}
	if !strings.Contains(stateOf(t, dir), `"pending":[]`) {
		t.Errorf("the state carries an alert its cursor passed:\n%s", stateOf(t, dir))
	}
	if n := strings.Count(alertLog(t, dir), "\n"); n != 4 {
		t.Errorf("alerts.jsonl holds %d alerts, want the three the crash logged and the new gap:\n%s", n, alertLog(t, dir))
	}
}

// TestClosedStdout runs the program with a stdout whose reader is gone: it is
// an error the run reports, exit 2, not a signal that kills it before the
// alerts are logged.
func TestClosedStdout(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "evidence-report")
	//nolint:gosec // G204: the program is "go" and its arguments are this test's own.
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	dir := newState(t)
	saved := stateOf(t, dir)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(t.Context(), bin, "-state", dir) //nolint:gosec // G204: the binary this test built
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(fixture(t, "gaps.jsonl")), w, &stderr
	err = cmd.Run()
	_ = w.Close()
	code := cmd.ProcessState.ExitCode()
	if code != 2 || !strings.Contains(stderr.String(), "could not be written") {
		t.Errorf("exit %d (%v), stderr %q; want 2 and the write refused", code, err, stderr.String())
	}
	if n := strings.Count(alertLog(t, dir), "\n"); n != 3 || stateOf(t, dir) != saved {
		t.Errorf("alerts.jsonl holds %d alerts and state.json changed %v; want the three logged and the state as it was", n, stateOf(t, dir) != saved)
	}
}

// TestPendingBound: the alerts one run appends fit the length the log may
// hold past its checkpoint, or the run refuses the export and appends
// nothing, so a crash cannot leave a log the next run refuses.
func TestPendingBound(t *testing.T) {
	ref := newState(t)
	consume(t, ref, fixture(t, "gaps.jsonl"))
	size := len(alertLog(t, ref))
	t.Cleanup(func() { maxPendingBytes = 64 << 20 })
	for _, tc := range []struct{ bound, code int }{{size, 1}, {size - 1, 2}} {
		maxPendingBytes = int64(tc.bound)
		dir := newState(t)
		before := snapshot(t, dir)
		got := consume(t, dir, fixture(t, "gaps.jsonl"))
		if got.code != tc.code {
			t.Errorf("%d bytes of alerts under a bound of %d: exit %d, want %d; stderr %s", size, tc.bound, got.code, tc.code, got.stderr)
		}
		if tc.code == 2 && (snapshot(t, dir) != before || !strings.Contains(got.stderr, "--limit")) {
			t.Errorf("alerts over the bound: stderr %q, and the directory changed: %v", got.stderr, snapshot(t, dir) != before)
		}
	}
}

// TestStateLoadBound: a state.json of exactly the bound is read; one byte
// over it is refused.
func TestStateLoadBound(t *testing.T) {
	dir := newState(t)
	consume(t, dir, fixture(t, "outage-1.jsonl"))
	size := len(stateOf(t, dir))
	t.Cleanup(func() { maxStateBytes = 64 << 20 })
	for _, tc := range []struct{ bound, code int }{{size, 0}, {size - 1, 2}} {
		maxStateBytes = tc.bound
		if got := report(t, "", "-state", dir, "-cursor"); got.code != tc.code {
			t.Errorf("a state of %d bytes under a bound of %d: exit %d, want %d; stderr %s", size, tc.bound, got.code, tc.code, got.stderr)
		}
	}
}

const leftOut = "a value longer than 64 bytes as JSON writes it, or past 16 reason codes, is left out of this alert"

// TestOversizeEventStillAlerts: an event holding a value over the bounds
// still raises the alert it calls for, with that value left out, and no
// alert holds a value over the bounds.
func TestOversizeEventStillAlerts(t *testing.T) {
	at65 := strings.Repeat("e", 65)
	head := evt("x", "x-1", "", "ACTION_PROPOSED", proposed("read_order"))
	decidedX := evt("x", "x-2", "x-1", "POLICY_DECIDED", decidedAs("k1", "ALLOW", "R"))
	undecided := func(codes ...string) string {
		return evt("x", "x-2", "x-1", "POLICY_DECIDED", decidedAs("k1", "INDETERMINATE", codes...))
	}
	for _, tc := range []struct {
		name, code string
		lines      []string
		reasons    string
	}{
		{name: "17 reason codes", code: "indeterminate", lines: []string{head, undecided(reasonList(17, 8)...)},
			reasons: `["` + strings.Join(reasonList(16, 8), `","`) + `"]`},
		{name: "a reason code of 65 bytes", code: "indeterminate", lines: []string{head, undecided(at65, "PDP_TIMEOUT")}, reasons: `["PDP_TIMEOUT"]`},
		{name: "a decision id of 65 bytes", code: "plane_block",
			lines: []string{head, decidedX, evt("x", "x-3", "x-2", "ACTION_BLOCKED", decidedAs(at65, "DENY", "PAUSED"))}},
		{name: "a run id of 65 bytes", code: "indeterminate",
			lines: []string{head, strings.Replace(undecided("PDP_TIMEOUT"), `"runId":"run-x"`, `"runId":"`+at65+`"`, 1)}},
		{name: "a request id of 65 bytes", code: "indeterminate", lines: []string{strings.ReplaceAll(undecided("PDP_TIMEOUT"), `"x`, `"`+at65)}},
		{name: "a tenant of 65 bytes", code: "indeterminate",
			lines: []string{head, strings.Replace(undecided("PDP_TIMEOUT"), `"tenantId":"t"`, `"tenantId":"`+at65+`"`, 1)}},
		{name: "an event id of 65 bytes", code: "approval_expired", lines: concat(chain("x", approved[:3]...),
			[]string{evt("x", at65, "x-3", "APPROVAL_EXPIRED", approval("EXPIRED"))})},
		{name: "a previous event id of 65 bytes", code: "indeterminate", lines: []string{evt("x", "x-2", at65, "POLICY_DECIDED",
			decidedAs("k1", "INDETERMINATE", "PDP_TIMEOUT"))}},
		{name: "an execution id of 65 bytes", code: "plane_block",
			lines: []string{head, decidedX, evt("x", "x-3", "x-2", "ACTION_BLOCKED", execution(at65)+decidedAs("p1", "DENY", "PAUSED"))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := consume(t, newState(t), framed("x.trail", tc.lines, 0, len(tc.lines), 1000))
			found := false
			for _, line := range strings.Split(strings.TrimSuffix(alertLines(got.stderr), "\n"), "\n") {
				a := boundedAlert(t, line)
				if a.Alert != tc.code {
					continue
				}
				found = true
				if a.Note != leftOut || (tc.reasons != "" && !strings.Contains(line, `"reasons":`+tc.reasons)) {
					t.Errorf("the %s alert: %s; want the note %q and reasons %s", tc.code, line, leftOut, tc.reasons)
				}
			}
			if !found {
				t.Errorf("no %s alert:\n%s", tc.code, alertLines(got.stderr))
			}
			if strings.Contains(got.stdout+got.stderr, at65) {
				t.Errorf("a value over the bound was printed:\n%s%s", got.stdout, got.stderr)
			}
		})
	}
}

// boundedAlert reads an alert line and fails when it holds an id or a reason
// code over the bounds, or more reason codes than they allow.
func boundedAlert(t *testing.T, line string) alert {
	t.Helper()
	a, err := readAlert([]byte(line))
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	for _, v := range append([]string{a.Tenant, a.Project, a.Request, a.Run, a.Event}, a.Reasons...) {
		if !fits(v) {
			t.Errorf("an alert holds a value over the bound: %s", line)
		}
	}
	if len(a.Reasons) > maxReasons {
		t.Errorf("an alert holds %d reason codes: %s", len(a.Reasons), line)
	}
	return a
}
