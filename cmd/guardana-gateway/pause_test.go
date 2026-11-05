package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/pause"
)

// Pause documents as the file spells them, written byte for byte so a case
// never takes its input from the writer it is testing against.
const (
	pauseClear       = `{"schema_version":"2","entries":[]}`
	pauseEntryFormat = `{"id":%q,"scope":%s,"created_at":"2026-09-24T10:00:00Z","reason":"the reason is never printed"}`
	scopeGlobal      = `{"kind":"global"}`
	scopeOrders      = `{"kind":"provider","provider":"orders"}`
	scopeElsewhere   = `{"kind":"provider","provider":"billing"}`
	scopeReadOrder   = `{"kind":"action","action":"tool","provider":"orders","name":"read_order"}`
	scopeRun         = `{"kind":"run","id":"run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	scopeOurAgent    = `{"kind":"agent","id":"orders-assistant"}`
	scopeOtherAgent  = `{"kind":"agent","id":"billing-assistant"}`
	scopeOurUser     = `{"kind":"principal","id":"agent-runner"}`
	scopeOtherUser   = `{"kind":"principal","id":"someone-else"}`
)

func pauseDocument(entries ...string) string {
	return `{"schema_version":"2","entries":[` + strings.Join(entries, ",") + `]}`
}

func pauseEntry(id, scope string) string { return fmt.Sprintf(pauseEntryFormat, id, scope) }

// withPauseFile gives the tree a pause file of its own directory, holding
// document, and points the configuration at it with interval.
func (tr tree) withPauseFile(t *testing.T, document string, interval time.Duration) string {
	t.Helper()
	dir := filepath.Join(tr.dir, "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("making the pause directory: %v", err)
	}
	path := filepath.Join(dir, "pause.json")
	writePauseFile(t, path, document)
	setEnv(t, "pause.file", "pause/pause.json")
	setEnv(t, "pause.poll_interval", interval.String())
	return path
}

func writePauseFile(t *testing.T, path, document string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the pause file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("setting the pause file's mode: %v", err)
	}
}

// TestAConfiguredPauseFileReachesThePipeline: the plane decides every call
// under the pause file its configuration names. A read the fixture policy
// allows runs while the file pauses nothing and is blocked with PAUSED once a
// read of the file finds an entry covering it; an entry naming another
// upstream leaves it running.
func TestAConfiguredPauseFileReachesThePipeline(t *testing.T) {
	tr := newTree(t)
	path := tr.withPauseFile(t, pauseClear, time.Second)
	p := tr.plane(t)
	if d := admitRead(p, "req-clear"); d.Action != core.Execute {
		t.Fatalf("a read under a clear pause file is %v: %v", d.Action, d.Decision)
	}

	writePauseFile(t, path, pauseDocument(pauseEntry("elsewhere", scopeElsewhere)))
	p.poller.Poll()
	if d := admitRead(p, "req-elsewhere"); d.Action != core.Execute {
		t.Errorf("a read under a pause of another upstream is %v: %v", d.Action, d.Decision)
	}

	writePauseFile(t, path, pauseDocument(pauseEntry("orders", scopeOrders)))
	p.poller.Poll()
	d := admitRead(p, "req-paused")
	if d.Action != core.Block || !slices.Equal(d.Decision.GetReasonCodes(), []string{"PAUSED"}) {
		t.Errorf("a read of a paused upstream is %v with %v, want a block with PAUSED alone", d.Action, d.Decision.GetReasonCodes())
	}
}

// TestWithoutAPauseFileThePlaneIsDisabled: no pause.file, no poller, and a
// call is decided by the policy alone.
func TestWithoutAPauseFileThePlaneIsDisabled(t *testing.T) {
	p := newTree(t).plane(t)
	if p.poller != nil {
		t.Fatal("a plane with no pause.file opened a poller")
	}
	if d := admitRead(p, "req-disabled"); d.Action != core.Execute {
		t.Errorf("a read with no pause file is %v: %v", d.Action, d.Decision)
	}
	status, body := ask(t, p, "/healthz")
	if status != http.StatusOK {
		t.Fatalf("a plane with no pause file answered %d: %v", status, body)
	}
	if got := pauseMember(t, body)["state"]; got != "disabled" {
		t.Errorf("pause.state = %v, want disabled", got)
	}
}

// unknownCause is one way a pause file becomes unreadable, the words a report
// names it by, and the change that makes it so.
type unknownCause struct {
	name  string
	cause string
	apply func(t *testing.T, path string)
}

// unknownCauses is every cause a first read can meet. Stale and dated ahead
// are causes of a snapshot's age, which a first read never has.
func unknownCauses() []unknownCause {
	over := pauseClear + strings.Repeat(" ", pause.MaxFileBytes+1-len(pauseClear))
	write := func(document string) func(*testing.T, string) {
		return func(t *testing.T, path string) { writePauseFile(t, path, document) }
	}
	chmod := func(mode os.FileMode, dir bool) func(*testing.T, string) {
		return func(t *testing.T, path string) {
			target := path
			if dir {
				target = filepath.Dir(path)
			}
			if err := os.Chmod(target, mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	return []unknownCause{
		{"missing", "missing", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{"group may write the file", "file writable by others", chmod(0o620, false)},
		{"others may write the file", "file writable by others", chmod(0o602, false)},
		{"group may write the directory", "directory writable by others", chmod(0o770, true)},
		{"a link", "a link", func(t *testing.T, path string) {
			target := path + ".target"
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"a directory", "unreadable", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"one byte over the bound", "too large", write(over)},
		{"not JSON", "malformed", write(`{"schema_version":"2","entries":[`)},
		{"an unknown version", "unknown version", write(`{"schema_version":"3","entries":[]}`)},
		{"an unknown member", "malformed", write(`{"schema_version":"2","entries":[],"paused":true}`)},
		{"an unknown scope", "malformed", write(pauseDocument(pauseEntry("p1", `{"kind":"principal","provider":"orders"}`)))},
		{"a resource scope with a name", "malformed", write(pauseDocument(pauseEntry("p1", `{"kind":"action","action":"resource","provider":"orders","name":"file:///a"}`)))},
	}
}

// TestAStartIsRefusedOnEveryUnknownCause: a plane never starts on a pause
// state it cannot read. Each refusal names the key and the cause, and nothing
// is written to standard output, where a started plane says it serves.
func TestAStartIsRefusedOnEveryUnknownCause(t *testing.T) {
	for _, c := range unknownCauses() {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			path := tr.withPauseFile(t, pauseClear, time.Second)
			c.apply(t, path)
			var stdout, stderr bytes.Buffer
			if status := serve(context.Background(), tr.config, "", &stdout, &stderr); status != exitFail {
				t.Fatalf("run answered %d on a pause file that is %s", status, c.name)
			}
			if stdout.Len() != 0 {
				t.Errorf("run wrote to standard output before refusing: %q", stdout.String())
			}
			if got := stderr.String(); !strings.Contains(got, "pause.file: ") || !strings.Contains(got, ": "+c.cause+": ") {
				t.Errorf("the refusal %q does not name pause.file and the cause %q", got, c.cause)
			}
		})
	}
}

// TestAPauseFileAtItsByteBoundStarts is the other side of the bound the
// table refuses one byte past.
func TestAPauseFileAtItsByteBoundStarts(t *testing.T) {
	tr := newTree(t)
	at := pauseClear + strings.Repeat(" ", pause.MaxFileBytes-len(pauseClear))
	tr.withPauseFile(t, at, time.Second)
	if p := tr.plane(t); p.poller.Current().State() != pause.Clear {
		t.Errorf("a pause file of exactly the bound reads %v", p.poller.Current().State())
	}
}

// TestDoctorNamesEveryUnknownCause: doctor runs the start's checks and fails
// on the pause line, naming the cause, before it builds anything.
func TestDoctorNamesEveryUnknownCause(t *testing.T) {
	for _, c := range unknownCauses() {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			path := tr.withPauseFile(t, pauseClear, time.Second)
			c.apply(t, path)
			var stdout, stderr bytes.Buffer
			if status := doctor(context.Background(), tr.config, &stdout, &stderr); status != exitFail {
				t.Fatalf("doctor answered %d on a pause file that is %s", status, c.name)
			}
			line := reportLine(stdout.String(), "pause")
			if !strings.HasPrefix(line, "fail    pause ") || !strings.Contains(line, ": "+c.cause+": ") {
				t.Errorf("the pause line %q does not fail naming %q:\n%s", line, c.cause, stdout.String())
			}
			if strings.Contains(stdout.String(), "seams") {
				t.Errorf("doctor went on past the failing pause line:\n%s", stdout.String())
			}
		})
	}
}

// TestDoctorReportsThePauseFile: the path, the state, the number of entries,
// how many cover all, some or none of the plane's calls, every entry naming
// an upstream this configuration does not have and every agent or principal
// entry naming another than the listener's. A reason is never printed.
func TestDoctorReportsThePauseFile(t *testing.T) {
	const billing = "       pause entry billing names upstream \"billing\", which this configuration does not have: " +
		"it pauses only calls that carry no provider, which are calls to names no upstream lists"
	for _, c := range []struct {
		name     string
		document string
		want     string
		lines    []string
	}{
		{"clear", pauseClear, "is clear: 0 entry(ies), 0 naming an upstream this configuration does not have; " +
			"0 covering all of this plane's calls, 0 some, 0 none", nil},
		{"paused", pauseDocument(pauseEntry("all", scopeGlobal), pauseEntry("orders", scopeOrders), pauseEntry("billing", scopeElsewhere)),
			"is paused: 3 entry(ies), 1 naming an upstream this configuration does not have; " +
				"1 covering all of this plane's calls, 1 some, 1 none", []string{billing}},
		{"identities", pauseDocument(pauseEntry("run", scopeRun), pauseEntry("ours", scopeOurAgent), pauseEntry("theirs", scopeOtherAgent),
			pauseEntry("me", scopeOurUser), pauseEntry("them", scopeOtherUser)),
			"is paused: 5 entry(ies), 0 naming an upstream this configuration does not have; " +
				"3 covering all of this plane's calls, 0 some, 2 none", []string{
				`       pause entry theirs names agent "billing-assistant", which is not this listener's: it pauses no call this plane runs`,
				`       pause entry them names principal "someone-else", which is not this listener's: it pauses no call this plane runs`,
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			tr.withPauseFile(t, c.document, 250*time.Millisecond)
			var stdout, stderr bytes.Buffer
			doctor(context.Background(), tr.config, &stdout, &stderr)
			out := tr.output(stdout.String())
			line := reportLine(out, "pause")
			if want := "ok      pause         <tree>/pause/pause.json " + c.want + ", before the upstreams check judges the tools; read every 250ms"; line != want {
				t.Errorf("the pause line is\n%q, want\n%q", line, want)
			}
			if !strings.Contains(out, "ok      seams") {
				t.Errorf("doctor did not build the plane over a readable pause file:\n%s", out)
			}
			for _, want := range c.lines {
				if !strings.Contains(out, want+"\n") {
					t.Errorf("doctor does not say\n%s\nin:\n%s", want, out)
				}
			}
			if n := strings.Count(out, "       pause entry "); n != len(c.lines) {
				t.Errorf("doctor named %d entries, want %d:\n%s", n, len(c.lines), out)
			}
			if strings.Contains(out, "never printed") {
				t.Errorf("doctor printed a reason:\n%s", out)
			}
		})
	}
}

// reportLine is the line of one check in doctor's output, or empty.
func reportLine(out, check string) string {
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) > 1 && fields[1] == check && len(line) > 8 && line[0] != ' ' {
			return line
		}
	}
	return ""
}

// pauseMember is the pause member of a health answer.
func pauseMember(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	member, ok := body["pause"].(map[string]any)
	if !ok {
		t.Fatalf("no pause member in the answer: %v", body)
	}
	return member
}

// TestHealthAnswersThePauseState: an operator's pause is not a problem and
// answers 200, with the entries, whether one is global, the entries that
// pause only calls to names no upstream lists, the share of the plane's calls
// each entry covers, and the snapshot's age. On a plane with no runs.dir no
// call is under an opened run, so a run entry covers all of them.
func TestHealthAnswersThePauseState(t *testing.T) {
	for _, c := range []struct {
		name     string
		document string
		state    string
		entries  float64
		global   bool
		unlisted []any
		coverage map[string]any
	}{
		{"clear", pauseClear, "clear", 0, false, []any{}, map[string]any{}},
		{"an upstream paused", pauseDocument(pauseEntry("orders", scopeOrders), pauseEntry("billing", scopeElsewhere)), "paused", 2, false,
			[]any{"billing"}, map[string]any{"orders": "some", "billing": "none"}},
		{"everything paused", pauseDocument(pauseEntry("tool", scopeReadOrder), pauseEntry("all", scopeGlobal)), "paused", 2, true,
			[]any{}, map[string]any{"tool": "some", "all": "all"}},
		{"identities", pauseDocument(pauseEntry("run", scopeRun), pauseEntry("ours", scopeOurAgent), pauseEntry("theirs", scopeOtherAgent),
			pauseEntry("me", scopeOurUser), pauseEntry("them", scopeOtherUser)), "paused", 5, false,
			[]any{}, map[string]any{"run": "all", "ours": "all", "theirs": "none", "me": "all", "them": "none"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			tr.withPauseFile(t, c.document, time.Second)
			p := tr.plane(t)
			readAt := p.poller.Current().ReadAt()
			status, body := p.healthAt(readAt.Add(1500 * time.Millisecond))
			if status != http.StatusOK {
				t.Fatalf("a %s pause state answered %d: %v", c.state, status, body)
			}
			member := pauseMember(t, body)
			for key, want := range map[string]any{
				"state": c.state, "entries": c.entries, "global": c.global, "age_ms": float64(1500),
			} {
				if member[key] != want {
					t.Errorf("pause.%s = %v, want %v", key, member[key], want)
				}
			}
			if unlisted, _ := member["unlisted_only"].([]any); !slices.Equal(unlisted, c.unlisted) {
				t.Errorf("pause.unlisted_only = %v, want %v", member["unlisted_only"], c.unlisted)
			}
			if covers, ok := member["coverage"].(map[string]any); !ok || !maps.Equal(covers, c.coverage) {
				t.Errorf("pause.coverage = %v, want %v", member["coverage"], c.coverage)
			}
			if _, set := member["cause"]; set {
				t.Errorf("a readable state carries a cause: %v", member)
			}
		})
	}
}

// TestHealthAnswers503OnEveryUnknownState: a pause state the plane cannot
// read blocks every call, which is a problem an operator has to see. Each
// cause a read can meet after the start is named, and so are the two a
// snapshot's age raises: older than three intervals, and dated ahead.
func TestHealthAnswers503OnEveryUnknownState(t *testing.T) {
	for _, c := range unknownCauses() {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			path := tr.withPauseFile(t, pauseClear, time.Second)
			p := tr.plane(t)
			c.apply(t, path)
			p.poller.Poll()
			expectUnknown(t, p, time.Now(), c.cause)
		})
	}
	for _, c := range []struct {
		name  string
		after time.Duration
		cause string
		ok    bool
	}{
		{"three intervals old", 3 * time.Second, "", true},
		{"one tick past three intervals", 3*time.Second + time.Nanosecond, "stale", false},
		{"dated one tick ahead", -time.Nanosecond, "dated ahead", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			tr.withPauseFile(t, pauseClear, time.Second)
			p := tr.plane(t)
			at := p.poller.Current().ReadAt().Add(c.after)
			if c.ok {
				if status, body := p.healthAt(at); status != http.StatusOK {
					t.Errorf("a snapshot %s answered %d: %v", c.name, status, body)
				}
				return
			}
			expectUnknown(t, p, at, c.cause)
		})
	}
}

func expectUnknown(t *testing.T, p *plane, at time.Time, cause string) {
	t.Helper()
	status, body := p.healthAt(at)
	if status != http.StatusServiceUnavailable {
		t.Errorf("an unknown pause state answered %d, want %d", status, http.StatusServiceUnavailable)
	}
	member := pauseMember(t, body)
	if member["state"] != "unknown" || member["cause"] != cause {
		t.Errorf("pause = %v, want state unknown with cause %q", member, cause)
	}
	problems, _ := body["problems"].([]any)
	if !slices.ContainsFunc(problems, func(p any) bool { s, _ := p.(string); return strings.Contains(s, cause) }) {
		t.Errorf("the problems %v do not name the cause %q", problems, cause)
	}
}

// healthAt is the health answer at now, as the handler would serve it.
func (p *plane) healthAt(now time.Time) (int, map[string]any) {
	answer, ok := p.health(p.pauseSource(), func() time.Time { return now })
	var body map[string]any
	raw, err := json.Marshal(answer)
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	if !ok {
		return http.StatusServiceUnavailable, body
	}
	return http.StatusOK, body
}
