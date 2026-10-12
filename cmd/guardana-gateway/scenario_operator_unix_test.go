//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/scenario"
)

// loggingControl is an approver's binary of this version that appends every
// command line it gets to log, and does body for every run with arguments.
func loggingControl(t *testing.T, log, body string) sibling {
	t.Helper()
	path := script(t, `echo "$@" >> `+log+`
if [ $# -eq 0 ]; then echo "`+brand.Name+` `+version+`"; exit 0; fi
`+body)
	s, err := findSibling(context.Background(), brand.CLI, path, childWait)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const heldThenApproved = `{"kind":"agent-scenario/v1alpha1","about":"held and approved","plane":{"mode":"APPROVE","bundle":{"id":"scenario-fixture"}},
"steps":[
 {"call":{"tool":"update_order","args":{"id":"ord-10"},"answer":{"kind":"pending","codes":["APPROVAL_PENDING"]},
   "decided":{"verdict":"ALLOW","codes":["RULE_ALLOW"],"obligations":[]},
   "trail":{"request":"new","kinds":["ACTION_PROPOSED","POLICY_DECIDED","APPROVAL_REQUESTED"]}}},
 {"approve":{"step":0,"approver":"alice"}}]}`

// TestAnOperatorStepAnswersTheApprovalTheTrailRequested: a pending answer
// naming an approval other than the one its trail requested differs on
// answer.approval_id, and the approve step never runs; the answer naming the
// requested one is approved by that id.
func TestAnOperatorStepAnswersTheApprovalTheTrailRequested(t *testing.T) {
	for _, c := range []struct {
		name, answered string
		exit           int
		want           []string
		ran            string
	}{
		{"another approval", "someone-elses", exitDiffered, []string{
			"held.json identity: principal p1, agent a1",
			"held.json step[0].answer.approval_id: want mine, got someone-elses",
			"held.json failed",
		}, "\n"},
		{"the requested approval", "mine", exitOK, []string{
			"held.json identity: principal p1, agent a1", "held.json step[0] call: ok", "held.json step[1] approve: ok", "held.json passed",
		}, "\napprovals approve --approver-id alice -- HOLDS mine\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			log, holds := filepath.Join(dir, "log"), filepath.Join(dir, "holds")
			exit, got := runFake(t, "held.json", heldThenApproved, func(int) fakeCall {
				return fakeCall{request: "req-0", pending: c.answered,
					events: fakeTrail("req-0", controlv1.Verdict_VERDICT_ALLOW, hashOrd10, "mine", proposed, decided, approvalAsked)}
			}, func(r *runner) { r.plane.approvals, r.control = holds, loggingControl(t, log, "true") })
			ran, err := os.ReadFile(log) //nolint:gosec // G304: a file under the test's own directory
			if err != nil {
				t.Fatal(err)
			}
			if want := strings.ReplaceAll(c.ran, "HOLDS", holds); exit != c.exit || !slices.Equal(got, c.want) || string(ran) != want {
				t.Fatalf("exit %d, output:\n%s\ncontrol ran %q\nwant exit %d, control ran %q, and:\n%s",
					exit, strings.Join(got, "\n"), ran, c.exit, want, strings.Join(c.want, "\n"))
			}
		})
	}
}

const pauseThenRead = `{"kind":"agent-scenario/v1alpha1","about":"a pause, then a read","plane":{"mode":"APPROVE","bundle":{"id":"scenario-fixture"}},
"steps":[
 {"pause":{"global":true}},
 {"call":{"tool":"read_order","args":{"id":"ord-1"},"answer":{"kind":"blocked","codes":["PAUSED"]},
   "decided":"none","trail":{"request":"new","kinds":["ACTION_PROPOSED"]}}}]}`

// pauseControl is an approver's binary that keeps the pause file as the
// lines pause list prints, one per entry, in state, and does add for pause
// add, with $reason set to the reason the add was given.
func pauseControl(t *testing.T, log, state, add string) sibling {
	t.Helper()
	return loggingControl(t, log, `state=`+state+`
reason=; prev=; for a in "$@"; do [ "$prev" = --reason ] && reason=$a; prev=$a; done
case "$1 $2" in
"pause list") if [ -s "$state" ]; then cat "$state"; else echo "no entries"; fi ;;
"pause add") `+add+` ;;
"pause remove") grep -v "^$5 " "$state" > "$state.next"; mv "$state.next" "$state"; echo "removed $5" ;;
*) exit 9 ;;
esac`)
}

// oldEntry is an entry the pause file holds before any step.
const oldEntry = "OLD global created 2026-01-01T00:00:00Z reason \"\"\n"

// TestAPauseAddThatFailsLeavesNoEntry: an add that writes its entry and then
// fails, or prints something other than one id, has the entry it wrote
// removed; an entry the file held before the add stays.
func TestAPauseAddThatFailsLeavesNoEntry(t *testing.T) {
	const own = `echo "NEW global created 2026-01-01T00:00:01Z reason \"$reason\"" >> "$state"; `
	for _, c := range []struct{ name, add, says string }{
		{"exits non-zero", own + `echo "the lock broke" >&2; exit 3`, "control exited 3: the lock broke"},
		{"prints two lines", own + `echo NEW; echo NEW`, `pause add printed "NEW\nNEW\n", not one entry id`},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			log, state := filepath.Join(dir, "log"), filepath.Join(dir, "entries")
			if err := os.WriteFile(state, []byte(oldEntry), 0o600); err != nil {
				t.Fatal(err)
			}
			control := pauseControl(t, log, state, c.add)
			exit, got := runFake(t, "paused.json", pauseThenRead, nil, func(r *runner) { r.plane.pauseFile, r.control = "/pause.json", control })
			left, err := os.ReadFile(state) //nolint:gosec // G304: a file under the test's own directory
			if err != nil {
				t.Fatal(err)
			}
			ran, _ := os.ReadFile(log) //nolint:gosec // G304: a file under the test's own directory
			switch {
			case exit != exitCouldNotRun || len(got) != 2 || !strings.HasPrefix(got[0], "paused.json step[0] pause: could not run: ") ||
				!strings.Contains(got[0], c.says):
				t.Fatalf("exit %d, want 2 saying %q:\n%s", exit, c.says, strings.Join(got, "\n"))
			case string(left) != oldEntry:
				t.Fatalf("the pause file holds %q, want only the entry it held before; control ran:\n%s", left, ran)
			case !strings.Contains(string(ran), "pause remove -- /pause.json NEW\n"):
				t.Fatalf("control never removed NEW:\n%s", ran)
			}
		})
	}
}

// failedAdd runs one pause step whose add does add and fails, under ctx, and
// returns the step's error, the pause file's lines after it, and every
// command line control was given.
func failedAdd(ctx context.Context, t *testing.T, dir string, ps *scenario.Pause, add string) (left, ran string, err error) {
	t.Helper()
	log, state := filepath.Join(dir, "log"), filepath.Join(dir, "entries")
	if err := os.WriteFile(state, []byte(oldEntry), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &runner{control: pauseControl(t, log, state, add), plane: planeTarget{pauseFile: "/pause.json"}, timeout: childWait}
	p := &play{r: r, added: map[int]string{}}
	err = p.pause(ctx, 0, ps)
	file, readErr := os.ReadFile(state) //nolint:gosec // G304: a file under the test's own directory
	if readErr != nil {
		t.Fatal(readErr)
	}
	lines, _ := os.ReadFile(log) //nolint:gosec // G304: a file under the test's own directory
	if err == nil {
		t.Fatalf("the add failed and the step did not; control ran:\n%s", lines)
	}
	if len(p.added) != 0 {
		t.Errorf("a failed add was recorded as added: %v", p.added)
	}
	return string(file), string(lines), err
}

// keptLines is the pause file's lines with each entry the add wrote cut to
// its id, since its reason carries a marker the test does not know.
func keptLines(file string) string {
	var b strings.Builder
	for line := range strings.Lines(file) {
		if id, _, _ := strings.Cut(line, " "); strings.Contains(line, "[scenario ") {
			line = id + "\n"
		}
		b.WriteString(line)
	}
	return b.String()
}

// TestAFailedPauseAddRemovesOnlyItsOwnEntry: of the entries new since a
// failed add, only the one with the step's scope and the reason the runner
// gave the add is removed. An entry an operator added meanwhile stays, and
// when no new entry or more than one is the add's, none is removed and the
// step names every new one.
func TestAFailedPauseAddRemovesOnlyItsOwnEntry(t *testing.T) {
	const (
		fail     = `echo "disk full" >&2; exit 1`
		own      = `echo "OWN global created 2026-01-01T00:00:01Z reason \"$reason\"" >> "$state"; `
		twice    = `echo "TWIN global created 2026-01-01T00:00:01Z reason \"$reason\"" >> "$state"; `
		operator = `echo "STOP global created 2026-01-01T00:00:02Z reason \"incident\"" >> "$state"; `
		other    = `echo "ELSE provider p created 2026-01-01T00:00:01Z reason \"$reason\"" >> "$state"; `
		stopLine = "STOP global created 2026-01-01T00:00:02Z reason \"incident\"\n"
	)
	global := &scenario.Pause{Scope: pause.Scope{Kind: pause.ScopeGlobal}, Reason: "maintenance"}
	for _, c := range []struct {
		name, add, left string
		removed         []string
		says            string
	}{
		{"its own and an operator's", own + operator + fail, oldEntry + stopLine, []string{"OWN"}, "disk full"},
		{"an operator's alone", operator + fail, oldEntry + stopLine, nil, "any of STOP may be"},
		{"two of its own", own + twice + fail, oldEntry + "OWN\nTWIN\n", nil, "any of OWN, TWIN may be"},
		{"its reason on another scope", other + fail, oldEntry + "ELSE\n", nil, "any of ELSE may be"},
	} {
		t.Run(c.name, func(t *testing.T) {
			left, ran, err := failedAdd(context.Background(), t, t.TempDir(), global, c.add)
			if kept := keptLines(left); kept != c.left {
				t.Errorf("the pause file holds %q, want %q", kept, c.left)
			}
			var removed []string
			for line := range strings.Lines(ran) {
				if id, ok := strings.CutPrefix(line, "pause remove -- /pause.json "); ok {
					removed = append(removed, strings.TrimSuffix(id, "\n"))
				}
			}
			if !slices.Equal(removed, c.removed) || !strings.Contains(err.Error(), "disk full") || !strings.Contains(err.Error(), c.says) {
				t.Errorf("removed %q, want %q; the step says %q, want it to say %q", removed, c.removed, err, c.says)
			}
			if !strings.Contains(ran, "--reason maintenance [scenario ") {
				t.Errorf("the add was not given the step's reason and a marker:\n%s", ran)
			}
		})
	}
}

// TestAFailedPauseAddIsCleanedUpAfterAnInterrupt: an interrupt that ends the
// run while the add is under way still has the entry the add wrote removed.
// The interrupt comes once the add has written its entry, however long the
// steps before it take.
func TestAFailedPauseAddIsCleanedUpAfterAnInterrupt(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			if _, err := os.Stat(started); err == nil {
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	add := `echo "OWN global created 2026-01-01T00:00:01Z reason \"$reason\"" >> "$state"; : > ` + started + `; exec sleep 5`
	left, ran, err := failedAdd(ctx, t, dir, &scenario.Pause{Scope: pause.Scope{Kind: pause.ScopeGlobal}}, add)
	if !errors.Is(err, context.Canceled) || left != oldEntry || !strings.Contains(ran, "pause remove -- /pause.json OWN\n") {
		t.Errorf("the step says %v; the pause file holds %q, want %q; control ran:\n%s", err, left, oldEntry, ran)
	}
}

// TestAPauseReasonLeavesRoomForTheMarker: a reason with no room left for the
// marker the runner adds under the pause file's bound never reaches an add.
func TestAPauseReasonLeavesRoomForTheMarker(t *testing.T) {
	const overhead = len(" [scenario ") + 26 + len("]")
	for _, c := range []struct {
		size int
		adds bool
	}{{pause.MaxReasonBytes - overhead, true}, {pause.MaxReasonBytes - overhead + 1, false}} {
		dir := t.TempDir()
		log, state := filepath.Join(dir, "log"), filepath.Join(dir, "entries")
		r := &runner{control: pauseControl(t, log, state, `exit 1`), plane: planeTarget{pauseFile: "/pause.json"}, timeout: childWait}
		p := &play{r: r, added: map[int]string{}}
		err := p.pause(context.Background(), 0, &scenario.Pause{Scope: pause.Scope{Kind: pause.ScopeGlobal}, Reason: strings.Repeat("r", c.size)})
		ran, _ := os.ReadFile(log) //nolint:gosec // G304: a file under the test's own directory
		added := strings.Contains(string(ran), "pause add ")
		if added != c.adds || (!c.adds && (err == nil || !strings.Contains(err.Error(), "no room"))) {
			t.Errorf("a reason of %d bytes: the step says %v, and control ran:\n%s", c.size, err, ran)
		}
	}
}

// TestFinishRemovesEntriesAfterAnInterrupt: an interrupt that ended the
// run's context still has every entry the scenario added removed and the
// plane's read of the file without it waited for.
func TestFinishRemovesEntriesAfterAnInterrupt(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	r := scriptedPlane(t, healthDoc{polls: 5, pauseState: "paused", entries: 1}, healthDoc{polls: 6, pauseState: "clear"},
		healthDoc{polls: 7, pauseState: "clear"})
	r.control, r.plane.pauseFile = loggingControl(t, log, "true"), "/pause.json"
	p := &play{r: r, added: map[int]string{0: "ENTRY"}, entries: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := p.finish(ctx)
	ran, _ := os.ReadFile(log) //nolint:gosec // G304: a file under the test's own directory
	if err != nil || len(p.added) != 0 || !strings.Contains(string(ran), "pause remove -- /pause.json ENTRY\n") {
		t.Fatalf("finish = %v, entries left %v; control ran:\n%s", err, p.added, ran)
	}
}
