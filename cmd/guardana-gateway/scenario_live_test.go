package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
)

// TestTheDemoScenariosPassOnOnePlane runs the directory of demo scenarios in
// name order against one live plane: an allowed read whose text feeds the
// next call, a denied transfer, a hold approved and resumed, a hold rejected,
// and a pause lifted around a call. Every line the runner prints is held to
// the literal below.
func TestTheDemoScenariosPassOnOnePlane(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	exit, out := r.runScenarios(nil, filepath.Join("testdata", "scenario"))
	identity := " identity: principal agent-runner, agent orders-assistant"
	want := []string{
		"allowed-read.json" + identity,
		"allowed-read.json step[0] call: ok",
		"allowed-read.json step[1] call: ok",
		"allowed-read.json passed",
		"blocked-transfer.json" + identity,
		"blocked-transfer.json step[0] call: ok",
		"blocked-transfer.json step[1] call: ok",
		"blocked-transfer.json passed",
		"hold-approved.json" + identity,
		"hold-approved.json step[0] call: ok",
		"hold-approved.json step[1] approve: ok",
		"hold-approved.json step[2] call: ok",
		"hold-approved.json step[3] call: ok",
		"hold-approved.json passed",
		"hold-rejected.json" + identity,
		"hold-rejected.json step[0] call: ok",
		"hold-rejected.json step[1] reject: ok",
		"hold-rejected.json step[2] call: ok",
		"hold-rejected.json step[3] call: ok",
		"hold-rejected.json passed",
		"pause-around-call.json step[0] pause: ok",
		"pause-around-call.json" + identity,
		"pause-around-call.json step[1] call: ok",
		"pause-around-call.json step[2] unpause: ok",
		"pause-around-call.json step[3] call: ok",
		"pause-around-call.json passed",
	}
	if exit != exitOK || !slices.Equal(lines(out), want) {
		t.Fatalf("exit %d, output:\n%s\nwant exit 0 and:\n%s", exit, out, strings.Join(want, "\n"))
	}
}

// mutant is one change to a demo scenario that its plane does not meet: the
// nth occurrence of old replaced by new, which must make exactly member of
// step differ.
type mutant struct {
	file     string
	old, new string
	nth      int
	step     int
	member   string
}

var mutants = []mutant{
	{"allowed-read.json", `"verdict": "ALLOW"`, `"verdict": "DENY"`, 2, 1, "decided.verdict"},
	{"allowed-read.json", `"codes": ["RULE_ALLOW"]`, `"codes": ["RULE_ALLOW", "PAUSED"]`, 2, 1, "decided.codes"},
	{"allowed-read.json", `, "ACTION_COMPLETED"]`, `]`, 2, 1, "trail.kinds"},
	{"allowed-read.json", `"kind": "result"`, `"kind": "error"`, 2, 1, "answer.kind"},
	{"allowed-read.json", `"obligations": []`, `"obligations": [{"type": "emit_alert", "params": {}, "advisory": true}]`, 1, 0, "decided.obligations"},
	{"allowed-read.json", `"decided": {"verdict": "ALLOW", "codes": ["RULE_ALLOW"], "obligations": []}`, `"decided": "none"`, 1, 0, "decided"},

	{"blocked-transfer.json", `"verdict": "DENY"`, `"verdict": "ALLOW"`, 1, 0, "decided.verdict"},
	{"blocked-transfer.json", `"blocked", "codes": ["RULE_DENY"]`, `"blocked", "codes": ["RULE_DENY", "PAUSED"]`, 1, 0, "answer.codes"},
	{"blocked-transfer.json", `, "ACTION_BLOCKED"]`, `]`, 1, 0, "trail.kinds"},
	{"blocked-transfer.json", `"kind": "result"`, `"kind": "error"`, 1, 1, "answer.kind"},

	{"hold-approved.json", `"verdict": "ALLOW"`, `"verdict": "REQUIRE_APPROVAL"`, 2, 2, "decided.verdict"},
	{"hold-approved.json", `"codes": ["RULE_ALLOW"]`, `"codes": ["RULE_ALLOW", "APPROVAL_REQUIRED"]`, 2, 2, "decided.codes"},
	{"hold-approved.json", `, "ACTION_COMPLETED"]`, `]`, 1, 2, "trail.kinds"},
	{"hold-approved.json", `"kind": "result"`, `"kind": "error"`, 1, 2, "answer.kind"},
	{"hold-approved.json", `"request": "step[0]"`, `"request": "new"`, 1, 2, "trail.request"},
	{"hold-approved.json", `"request": "new"`, `"request": "step[0]"`, 2, 3, "trail.request"},

	{"hold-rejected.json", `"verdict": "ALLOW"`, `"verdict": "DENY"`, 2, 2, "decided.verdict"},
	{"hold-rejected.json", `"codes": ["APPROVAL_REJECTED"]`, `"codes": ["APPROVAL_REJECTED", "RULE_DENY"]`, 1, 2, "answer.codes"},
	{"hold-rejected.json", `, "ACTION_BLOCKED"]`, `]`, 1, 2, "trail.kinds"},
	{"hold-rejected.json", `"kind": "result"`, `"kind": "error"`, 1, 3, "answer.kind"},
	{"hold-rejected.json", `"request": "step[0]"`, `"request": "new"`, 1, 2, "trail.request"},

	{"pause-around-call.json", `"verdict": "ALLOW"`, `"verdict": "DENY"`, 1, 1, "decided.verdict"},
	{"pause-around-call.json", `"blocked", "codes": ["PAUSED"]`, `"blocked", "codes": ["PAUSED", "RULE_DENY"]`, 1, 1, "answer.codes"},
	{"pause-around-call.json", `, "ACTION_BLOCKED"]`, `]`, 1, 1, "trail.kinds"},
	{"pause-around-call.json", `"kind": "result"`, `"kind": "error"`, 1, 3, "answer.kind"},
}

// TestEveryMutantOfADemoScenarioIsCaught runs each mutant against a plane of
// its own. A mutant is caught only by exit 1 with the scenario failed on
// exactly the member it changed: a timeout, a precondition or a refusal to
// load is exit 2 and does not count. A request cannot be swapped on a
// scenario with no pending call, since the reader refuses one naming a step
// that is not pending.
func TestEveryMutantOfADemoScenarioIsCaught(t *testing.T) {
	t.Parallel()
	for _, m := range mutants {
		t.Run(fmt.Sprintf("%s/step[%d].%s/%s", m.file, m.step, m.member, m.new), func(t *testing.T) {
			t.Parallel()
			file := m.write(t)
			r := newRig(t)
			exit, out := r.runScenarios(nil, file)
			got := lines(out)
			prefix := fmt.Sprintf("%s step[%d].%s: want ", m.file, m.step, m.member)
			var diffs []string
			for _, line := range got {
				if strings.HasPrefix(line, m.file+" step[") && strings.Contains(line, ": want ") {
					diffs = append(diffs, line)
				}
			}
			switch {
			case exit != exitDiffered || strings.Contains(out, "could not run"):
				t.Fatalf("exit %d, want 1 for a difference:\n%s", exit, out)
			case len(diffs) != 1 || !strings.HasPrefix(diffs[0], prefix):
				t.Fatalf("the differences are %q, want one starting %q:\n%s", diffs, prefix, out)
			case got[len(got)-1] != m.file+" failed":
				t.Fatalf("the last line is %q, want the scenario failed:\n%s", got[len(got)-1], out)
			}
		})
	}
}

// write writes the mutated scenario under its own name in a directory of the
// test's, and refuses a mutant whose text is not there to change.
func (m mutant) write(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "scenario", m.file))
	if err != nil {
		t.Fatalf("reading %s: %v", m.file, err)
	}
	text := string(raw)
	parts := strings.SplitN(text, m.old, m.nth+1)
	if len(parts) < m.nth+1 {
		t.Fatalf("%s holds %q %d time(s), fewer than %d", m.file, m.old, strings.Count(text, m.old), m.nth)
	}
	mutated := strings.Join(parts[:m.nth], m.old) + m.new + parts[m.nth]
	if mutated == text {
		t.Fatalf("the mutant of %s changes nothing", m.file)
	}
	path := filepath.Join(t.TempDir(), m.file)
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatalf("writing the mutant: %v", err)
	}
	return path
}

// TestAFailedScenarioLeavesThePlaneUnpaused: pause-around-call fails at
// step[1] with its pause in force, and the next scenario on the same plane
// starts, which it can only from a clear pause state the plane has read. The
// plane reads its pause file every second, so a runner that removes the entry
// without waiting for that read leaves the next scenario a paused plane.
func TestAFailedScenarioLeavesThePlaneUnpaused(t *testing.T) {
	t.Parallel()
	r := newRigPolling(t, "1s")
	failing := mutant{"pause-around-call.json", `"verdict": "ALLOW"`, `"verdict": "DENY"`, 1, 1, "decided.verdict"}
	exit, out := r.runScenarios(nil, failing.write(t), filepath.Join("testdata", "scenario", "allowed-read.json"))
	identity := " identity: principal agent-runner, agent orders-assistant"
	want := []string{
		"pause-around-call.json step[0] pause: ok",
		"pause-around-call.json" + identity,
		"pause-around-call.json step[1].decided.verdict: want DENY, got ALLOW",
		"pause-around-call.json failed",
		"allowed-read.json" + identity,
		"allowed-read.json step[0] call: ok",
		"allowed-read.json step[1] call: ok",
		"allowed-read.json passed",
	}
	if exit != exitDiffered || !slices.Equal(lines(out), want) {
		t.Fatalf("exit %d, output:\n%s\nwant exit 1 and:\n%s", exit, out, strings.Join(want, "\n"))
	}
}

// TestADifferenceOutranksAScenarioThatCouldNotRun: one scenario that cannot
// run for its precondition, then one that differs, on the same plane: the
// run exits 1, not 2.
func TestADifferenceOutranksAScenarioThatCouldNotRun(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	raw, err := os.ReadFile(filepath.Join("testdata", "scenario", "allowed-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := strings.Replace(string(raw), `"id": "scenario-fixture"`, `"id": "other-fixture"`, 1)
	if elsewhere == string(raw) {
		t.Fatal("allowed-read.json names no bundle to change")
	}
	stopped := filepath.Join(t.TempDir(), "other-bundle.json")
	if err := os.WriteFile(stopped, []byte(elsewhere), 0o600); err != nil {
		t.Fatal(err)
	}
	differs := mutant{"blocked-transfer.json", `"verdict": "DENY"`, `"verdict": "ALLOW"`, 1, 0, "decided.verdict"}
	exit, out := r.runScenarios(nil, stopped, differs.write(t))
	want := []string{
		"other-bundle.json could not run: the plane serves bundle scenario-fixture, and the scenario is for other-fixture",
		"blocked-transfer.json identity: principal agent-runner, agent orders-assistant",
		"blocked-transfer.json step[0].decided.verdict: want ALLOW, got DENY",
		"blocked-transfer.json failed",
	}
	if exit != exitDiffered || !slices.Equal(lines(out), want) {
		t.Fatalf("exit %d, output:\n%s\nwant exit 1 and:\n%s", exit, out, strings.Join(want, "\n"))
	}
}

// TestArgumentsCanonRefusesAreComparedWithNone: an integer canon cannot hash
// reaches the plane, which blocks the call and records no hash, and the step
// holds that to the none the runner could compute, so the scenario passes
// with every member compared. A number past float64 never reaches a trail:
// the plane answers with no request, and the step could not run.
func TestArgumentsCanonRefusesAreComparedWithNone(t *testing.T) {
	t.Parallel()
	const blocked = `{"kind":"agent-scenario/v1alpha1","about":"arguments canon cannot hash","run":"continues",
"plane":{"mode":"APPROVE","bundle":{"id":"scenario-fixture"}},
"steps":[{"call":{"tool":"read_order","args":{"id":"ord-1","n":NUMBER},"answer":{"kind":"blocked","codes":["INVALID_FIELD_VALUE"]},
  "decided":{"verdict":"INDETERMINATE","codes":["INVALID_FIELD_VALUE"],"obligations":[]},
  "trail":{"request":"new","kinds":["ACTION_PROPOSED","POLICY_DECIDED","ACTION_BLOCKED"]}}}]}`
	for _, c := range []struct {
		number string
		exit   int
		want   []string
	}{
		{"12345678901234567890", exitOK, []string{
			"huge.json identity: principal agent-runner, agent orders-assistant",
			"huge.json step[0] call: ok",
			"huge.json passed",
		}},
		{"1e400", exitCouldNotRun, []string{
			"huge.json step[0] call: could not run: the answer carries no " + brand.OTelNamespace + "/request_id, so it names no trail",
			"huge.json could not run: step[0]: the answer carries no " + brand.OTelNamespace + "/request_id, so it names no trail",
		}},
	} {
		t.Run(c.number, func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			file := filepath.Join(t.TempDir(), "huge.json")
			if err := os.WriteFile(file, []byte(strings.Replace(blocked, "NUMBER", c.number, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			exit, out := r.runScenarios(nil, file)
			if exit != c.exit || !slices.Equal(lines(out), c.want) {
				t.Fatalf("exit %d, output:\n%s\nwant exit %d and:\n%s", exit, out, c.exit, strings.Join(c.want, "\n"))
			}
		})
	}
}

// TestAScenarioAfterATaintedRunIsNotFresh: on one plane, a read of untrusted
// content taints the run, and a scenario that expects a fresh run fails on
// its first call although every other member of it holds.
func TestAScenarioAfterATaintedRunIsNotFresh(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	exit, out := r.runScenarios(nil, filepath.Join("testdata", "scenario-more", "taint-web.json"),
		filepath.Join("testdata", "scenario", "allowed-read.json"))
	want := []string{
		"taint-web.json identity: principal agent-runner, agent orders-assistant",
		"taint-web.json step[0] call: ok",
		"taint-web.json passed",
		"allowed-read.json identity: principal agent-runner, agent orders-assistant",
		"allowed-read.json step[0].run: want fresh (flow.v1.untrusted=false, flow.v1.max_read=PUBLIC), got flow.v1.untrusted=true, flow.v1.max_read=PUBLIC",
		"allowed-read.json failed",
	}
	if exit != exitDiffered || !slices.Equal(lines(out), want) {
		t.Fatalf("exit %d, output:\n%s\nwant exit 1 and:\n%s", exit, out, strings.Join(want, "\n"))
	}
}

// TestAnotherClientStopsTheScenario: the upstream calls the plane back while
// the scenario's call is under way, the plane admits two calls for one, and
// the step cannot be compared.
func TestAnotherClientStopsTheScenario(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	exit, out := r.runScenarios(nil, filepath.Join("testdata", "scenario-more", "second-client.json"))
	if exit != exitCouldNotRun || !strings.Contains(out, "second-client.json step[0] call: could not run: the plane admitted 2 call(s) since the scenario began and this runner made 1: another client is calling") {
		t.Fatalf("exit %d, want 2 naming the other client:\n%s", exit, out)
	}
}

// TestATrailFileThatIsNotThePlanesCannotPass: the trail file a second
// collector writes, which this plane never sends to, holds nothing of what
// the plane shipped, and the scenario could not run.
func TestATrailFileThatIsNotThePlanesCannotPass(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	other := filepath.Join(t.TempDir(), "other")
	r.startProcess("collect", "--listen", "unix://"+exportSocket(t), "--dir", other, "--tenant", "acme", "--project", "orders",
		"--credential-file", credentialFile(t, collectToken)).waitFor(t, "collect: listening on ")
	r.trail = other
	exit, out := r.runScenarios(nil, filepath.Join("testdata", "scenario", "allowed-read.json"))
	if exit != exitCouldNotRun || !strings.Contains(out, "holds none of them: it is not this plane's") ||
		strings.Contains(out, ": ok") {
		t.Fatalf("exit %d, want 2 naming the trail file and no step passed:\n%s", exit, out)
	}
}

// TestNoScenarioIsNotAPass: an empty directory runs nothing, and nothing is
// not a pass; a file the reader refuses stops every scenario before the
// plane's configuration is read.
func TestNoScenarioIsNotAPass(t *testing.T) {
	t.Parallel()
	gatewayBin, _ := builtBinaries(t)
	empty := t.TempDir()
	absent := filepath.Join(empty, "plane.yaml")
	out, err := runBinary(gatewayBin, "scenario", "run", "--config", absent, "--trail", filepath.Join(empty, "trail.jsonl"), empty)
	if code := exitOf(t, err); code != exitCouldNotRun || !strings.Contains(out, "no scenario") {
		t.Fatalf("exit %d, want 2 for no scenario:\n%s", code, out)
	}
	bad := filepath.Join(t.TempDir(), "Allowed.json")
	raw, err := os.ReadFile(filepath.Join("testdata", "scenario", "allowed-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runBinary(gatewayBin, "scenario", "run", "--config", absent, "--trail", filepath.Join(empty, "trail.jsonl"),
		filepath.Join("testdata", "scenario", "allowed-read.json"), bad)
	want := bad + ` could not run: scenario: the file name is not a scenario id: want [a-z0-9][a-z0-9-]{0,63}.json "Allowed.json"` + "\n"
	if code := exitOf(t, err); code != exitCouldNotRun || out != want {
		t.Fatalf("exit %d, output:\n%s\nwant 2 and:\n%s", code, out, want)
	}
}

// TestAControlOfAnotherVersionIsRefused: an approver's binary that answers
// with another version is refused before the plane is touched, and so is one
// that is not there.
func TestAControlOfAnotherVersionIsRefused(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	other := filepath.Join(t.TempDir(), "other-control")
	if err := goBuild(other, brand.CLI, "-X main.version=9.9.9-other"); err != nil {
		t.Fatal(err)
	}
	hold := filepath.Join("testdata", "scenario", "hold-approved.json")
	for _, c := range []struct{ control, says string }{
		{other, "answers \"" + brand.Name + " 9.9.9-other\""},
		{filepath.Join(t.TempDir(), "absent"), "go install ./cmd/..."},
	} {
		exit, out := r.runScenarios([]string{"--control", c.control}, hold)
		if exit != exitCouldNotRun || !strings.Contains(out, c.says) || strings.Contains(out, "step[") {
			t.Errorf("--control %s: exit %d, want 2 naming %q before any step:\n%s", c.control, exit, c.says, out)
		}
	}
	if exit, out := r.runScenarios([]string{"--control", r.control}, hold); exit != exitOK {
		t.Errorf("the control built beside the gateway: exit %d:\n%s", exit, out)
	}
}

// TestTheRunnerReadsItsEntryAsPauseListPrintsIt: the line the approver's
// binary built from this tree prints for an entry is the one the runner takes
// for that entry's scope and reason, for every kind of scope, and not for
// another reason or another scope.
func TestTheRunnerReadsItsEntryAsPauseListPrintsIt(t *testing.T) {
	t.Parallel()
	_, control := builtBinaries(t)
	file := filepath.Join(t.TempDir(), "pause.json")
	if out, err := runBinary(control, "pause", "init", file); err != nil {
		t.Fatalf("pause init: %v\n%s", err, out)
	}
	cases := []struct {
		flags  []string
		scope  pause.Scope
		reason string
	}{
		{[]string{"--global"}, pause.Scope{Kind: pause.ScopeGlobal}, `a "quoted" stop [scenario A]`},
		{[]string{"--provider", "orders"}, pause.Scope{Kind: pause.ScopeProvider, Provider: "orders"}, "[scenario B]"},
		{[]string{"--provider", "orders", "--action", "tool", "--name", "refund"},
			pause.Scope{Kind: pause.ScopeAction, Provider: "orders", Action: pause.ActionTool, Name: "refund"}, "[scenario C]"},
		{[]string{"--provider", "orders", "--action", "prompt"},
			pause.Scope{Kind: pause.ScopeAction, Provider: "orders", Action: pause.ActionPrompt}, "[scenario D]"},
	}
	ids := make([]string, len(cases))
	for i, c := range cases {
		out, err := runBinary(control, append(append([]string{"pause", "add"}, c.flags...), "--reason", c.reason, "--", file)...)
		if err != nil {
			t.Fatalf("pause add %v: %v\n%s", c.flags, err, out)
		}
		ids[i] = strings.TrimSuffix(out, "\n")
	}
	out, err := runBinary(control, "pause", "list", file)
	if err != nil {
		t.Fatalf("pause list: %v\n%s", err, out)
	}
	listed := map[string]string{}
	for line := range strings.Lines(out) {
		id, _, _ := strings.Cut(line, " ")
		listed[id] = strings.TrimSuffix(line, "\n")
	}
	for i, c := range cases {
		line, other := listed[ids[i]], cases[(i+1)%len(cases)]
		if !listsAs(line, ids[i], c.scope, c.reason) || listsAs(line, ids[i], c.scope, other.reason) || listsAs(line, ids[i], other.scope, c.reason) {
			t.Errorf("pause list printed %q for %v with reason %q", line, c.scope, c.reason)
		}
	}
}
