package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/trailfile"
)

const shapeLine = "the check proves each chain's shape and not its integrity: a record altered to keep that shape passes it\n"

// trailOf is one request's events of the kinds given, linked in order.
func trailOf(request string, kinds ...controlv1.EventKind) []*controlv1.Event {
	out := make([]*controlv1.Event, 0, len(kinds))
	prev := ""
	for i, kind := range kinds {
		ev := &controlv1.Event{EventId: request + "-" + strconv.Itoa(i), Kind: kind, RequestId: request,
			ProjectId: "p1", TenantId: "t1", SchemaVersion: evidence.SchemaVersion, PrevEventId: prev,
			EnforcementMode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE}
		if kind == controlv1.EventKind_EVENT_KIND_ACTION_STARTED || kind == controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED {
			ev.ExecutionId = "x"
		}
		prev = ev.EventId
		out = append(out, ev)
	}
	return out
}

func trailFile(t *testing.T, tail string, events ...*controlv1.Event) string {
	t.Helper()
	var b bytes.Buffer
	if err := evidence.EncodeJSONL(&b, events); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trail.jsonl")
	if err := os.WriteFile(path, append(b.Bytes(), tail...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func trailCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), append([]string{"trail"}, args...), &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

const (
	kProposed  = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	kDecided   = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	kRequested = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
	kStarted   = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	kCompleted = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	kBlocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
)

// tornTrail is a file of whole and open trails with a line sent twice, and
// the start of a line after them, and what trail prints of it.
func tornTrail(t *testing.T) (path, report string) {
	t.Helper()
	done := trailOf("a", kProposed, kDecided, kStarted, kCompleted)
	held := trailOf("b", kProposed, kDecided, kRequested)
	path = trailFile(t, `{"eventId":"c-0",`, done[0], held[0], done[1], done[1], held[1], done[2], held[2], done[3])
	return path, "request=a project=p1 tenant=t1 last=EVENT_KIND_ACTION_COMPLETED ok\n" +
		"request=b project=p1 tenant=t1 last=EVENT_KIND_APPROVAL_REQUESTED open\n" +
		"trails 2: ok 1, open 1, failed 0, indeterminate 0; lines 8, repeated lines collapsed 1, bytes after the last newline 17\n" +
		shapeLine
}

// TestTrailPrintsOneLinePerTrail: a file a collector holds, with a line it
// has not finished, exits 0 and prints each trail, the counts and what the
// check does not prove.
func TestTrailPrintsOneLinePerTrail(t *testing.T) {
	path, want := tornTrail(t)
	whole, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	// Opening a writer cuts the unfinished line, so it is written again under
	// the writer, as a collector in the middle of an append leaves it.
	w, err := trailfile.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := os.WriteFile(path, whole, 0o600); err != nil { //nolint:gosec // G703: the test's own temp file
		t.Fatal(err)
	}
	status, stdout, stderr := trailCommand(t, path)
	if status != exitOK || stdout != want || stderr != "" {
		t.Errorf("trail answered %d with\n%s\nand %q; want %d with\n%s", status, stdout, stderr, exitOK, want)
	}
}

// TestTrailCallsATailNoCollectorHoldsDamage: the same file with no collector
// holding it ends in a line nobody is writing, which is damage: trail prints
// what it read and exits 1 with a line saying so.
func TestTrailCallsATailNoCollectorHoldsDamage(t *testing.T) {
	path, want := tornTrail(t)
	status, stdout, stderr := trailCommand(t, path)
	if status != exitFail || stdout != want || !strings.Contains(stderr, "17 byte(s) after its last newline and no collector holds it") ||
		strings.Count(stderr, "\n") != 1 {
		t.Errorf("trail answered %d with\n%s\nand %q; want %d, the report and one line naming the tail", status, stdout, stderr, exitFail)
	}
}

// TestTrailExitsOneWhenAnyTrailIsNotWhole: a broken chain and one this build
// cannot place each exit 1, and their lines carry the check's reason.
func TestTrailExitsOneWhenAnyTrailIsNotWhole(t *testing.T) {
	good := trailOf("a", kProposed, kDecided, kBlocked)
	broken := trailOf("b", kProposed, kStarted)
	later := trailOf("c", kProposed, kDecided, controlv1.EventKind(99))
	for name, c := range map[string]struct {
		events []*controlv1.Event
		line   string
	}{
		"a broken chain":  {append(append([]*controlv1.Event{}, good...), broken...), "request=b project=p1 tenant=t1 last=EVENT_KIND_ACTION_STARTED failed: evidence: chain broken: "},
		"an unknown kind": {append(append([]*controlv1.Event{}, good...), later...), "request=c project=p1 tenant=t1 last=99 indeterminate: evidence: chain indeterminate: "},
	} {
		status, stdout, _ := trailCommand(t, trailFile(t, "", c.events...))
		if status != exitFail || !strings.Contains(stdout, "request=a project=p1 tenant=t1 last=EVENT_KIND_ACTION_BLOCKED ok\n") ||
			!strings.Contains(stdout, "\n"+c.line) || !strings.HasSuffix(stdout, shapeLine) {
			t.Errorf("%s: trail answered %d with\n%s", name, status, stdout)
		}
	}
}

// TestTrailFailsATrailWhoseRunChanges: a plane stamps one run on a whole
// request, so a trail whose last event names another run fails at that event,
// and one that names no run at all is whole.
func TestTrailFailsATrailWhoseRunChanges(t *testing.T) {
	outside := trailOf("a", kProposed, kDecided, kStarted, kCompleted)
	moved := trailOf("b", kProposed, kDecided, kStarted, kCompleted)
	for _, ev := range moved {
		ev.RunId = "run-1"
	}
	moved[3].RunId = "run-2"
	status, stdout, _ := trailCommand(t, trailFile(t, "", append(outside, moved...)...))
	want := "request=a project=p1 tenant=t1 last=EVENT_KIND_ACTION_COMPLETED ok\n" +
		`request=b project=p1 tenant=t1 last=EVENT_KIND_ACTION_COMPLETED failed: evidence: chain broken: event 3 belongs to run "run-2", not "run-1"` + "\n" +
		"trails 2: ok 1, open 0, failed 1, indeterminate 0; lines 8, repeated lines collapsed 0, bytes after the last newline 0\n" +
		shapeLine
	if status != exitFail || stdout != want {
		t.Errorf("trail answered %d with\n%s\nwant %d with\n%s", status, stdout, exitFail, want)
	}
}

// TestTrailRefusesWhatItCannotRead: a file with no trail, a damaged one, one
// that is not there and a second argument are each refused, never an empty
// pass.
func TestTrailRefusesWhatItCannotRead(t *testing.T) {
	c := trailOf("a", kProposed, kDecided, kBlocked)
	changed := trailOf("a", kProposed, kDecided, kBlocked)
	changed[1].RunId = "changed"
	for name, path := range map[string]string{
		"an empty file":           trailFile(t, ""),
		"only an unfinished line": trailFile(t, `{"eventId":`),
		"one id with two lines":   trailFile(t, "", c[0], c[1], changed[1]),
		"a line that is no event": trailFile(t, "{}x\n"),
		"no file":                 filepath.Join(t.TempDir(), "none.jsonl"),
	} {
		status, stdout, stderr := trailCommand(t, path)
		if status != exitFail || stdout != "" || !strings.HasPrefix(stderr, brand.Gateway+": trail: ") || strings.Count(stderr, "\n") != 1 {
			t.Errorf("%s: trail answered %d with %q and %q", name, status, stdout, stderr)
		}
	}
	if status, _, _ := trailCommand(t, "a", "b"); status != exitUsage {
		t.Errorf("two files answered %d, want %d", status, exitUsage)
	}
}

// TestTrailPrintsAnIdentifierOnOneLine: an identifier the file carries is
// printed quoted when it holds anything a terminal could act on, and cut.
func TestTrailPrintsAnIdentifierOnOneLine(t *testing.T) {
	c := trailOf("r\n\x1b[2Jx", kProposed, kDecided, kBlocked)
	long := trailOf(strings.Repeat("y", 100), kProposed, kDecided, kBlocked)
	status, stdout, _ := trailCommand(t, trailFile(t, "", append(c, long...)...))
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if status != exitOK || len(lines) != 4 {
		t.Fatalf("trail answered %d with\n%s", status, stdout)
	}
	if want := `request="r\n\x1b[2Jx" project=p1`; !strings.HasPrefix(lines[0], want) {
		t.Errorf("the first line is %q, want it to start %q", lines[0], want)
	}
	if want := `request="` + strings.Repeat("y", 64) + `" (cut) project=p1`; !strings.HasPrefix(lines[1], want) {
		t.Errorf("the second line is %q, want it to start %q", lines[1], want)
	}
}

// TestTrailsLineBoundIsTheDocumentedOne: the pages promise that trail refuses
// a file of more than 100,000 lines; Read's own tests hold what a bound does.
func TestTrailsLineBoundIsTheDocumentedOne(t *testing.T) {
	if trailfile.DefaultMaxLines != 100_000 {
		t.Errorf("trail reads at most %d lines, and the pages say 100,000", trailfile.DefaultMaxLines)
	}
}

// TestTrailRepeatsNoKeyTextItReads: a file holding a key's body line, as a
// line, as a value, as a member's name or after a blank line, is refused
// without the body line in the refusal, and an identifier that is a body line
// is printed withheld.
func TestTrailRepeatsNoKeyTextItReads(t *testing.T) {
	_, body := fixtureKeyText(t)
	for name, content := range map[string]string{
		"a body line alone":            body + "\n",
		"a body line as a field value": `{"schemaVersion":"` + body + `"}` + "\n",
		"a body line as a member name": `{"` + body + `":1}` + "\n",
		"a blank line, then a body":    "\n" + body + "\n",
	} {
		f := filepath.Join(t.TempDir(), "t.jsonl")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		status, stdout, stderr := trailCommand(t, f)
		if status != exitFail || strings.Contains(stdout+stderr, body[:21]) {
			t.Errorf("%s: trail answered %d with %q%q, want %d and no body line", name, status, stdout, stderr, exitFail)
		}
	}
	status, stdout, stderr := trailCommand(t, trailFile(t, "", trailOf(body, kProposed, kDecided, kBlocked)...))
	want := "request=[key text withheld] project=p1"
	if status != exitOK || !strings.HasPrefix(stdout, want) || strings.Contains(stdout+stderr, body[:21]) {
		t.Errorf("a body line as the request id: trail answered %d with %q%q, want it to start %q", status, stdout, stderr, want)
	}
}
