//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// runDevToEnd runs dev with args to its end, bounded, and returns its exit
// status and what it wrote to each stream.
func runDevToEnd(t *testing.T, limit time.Duration, args ...string) (int, string, string) {
	t.Helper()
	p := startDev(t, args...)
	code := p.exit(t, limit)
	return code, p.stdout.String(), p.stderr.String()
}

// scenarioFlags is --scenario once per file.
func scenarioFlags(files ...string) []string {
	var out []string
	for _, f := range files {
		out = append(out, "--scenario", f)
	}
	return out
}

// TestDevRunsEachScenarioOnItsOwnPlane: every demo scenario, and one of them
// a second time, passes on a plane laid out for it alone; on one plane the
// second run of it would not start fresh. The scenarios run are the files
// given, each in a state directory of its own.
func TestDevRunsEachScenarioOnItsOwnPlane(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(filepath.Join("testdata", "scenario"))
	if err != nil {
		t.Fatal(err)
	}
	var files, names []string
	for _, e := range entries {
		files, names = append(files, filepath.Join("testdata", "scenario", e.Name())), append(names, e.Name())
	}
	demoNames := []string{"allowed-read.json", "blocked-transfer.json", "hold-approved.json", "hold-rejected.json", "pause-around-call.json"}
	if !slices.Equal(names, demoNames) {
		t.Fatalf("the demo scenarios are %q, want %q", names, demoNames)
	}
	files = append(files, filepath.Join("testdata", "scenario", "hold-approved.json"))
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "")
	state := filepath.Join(t.TempDir(), "state")
	code, stdout, stderr := runDevToEnd(t, 3*time.Minute, append([]string{"--config", d.config, "--policy", d.policy, "--state", state}, scenarioFlags(files...)...)...)
	var passed, planes []string
	for _, line := range lines(stdout) {
		if id, ok := strings.CutSuffix(line, " passed"); ok {
			passed = append(passed, id)
		}
		if _, dir, ok := strings.Cut(line, " plane: state in "); ok {
			planes = append(planes, dir)
		}
	}
	want := append(slices.Clone(demoNames), "hold-approved.json")
	if code != exitOK || !slices.Equal(passed, want) || len(slices.Compact(slices.Clone(planes))) != len(want) {
		t.Fatalf("exit %d, passed %q, planes %q; want 0, %q, one plane each:\n%s\n%s", code, passed, planes, want, stdout, stderr)
	}
	if subdirs, err := os.ReadDir(state); err != nil || len(subdirs) != len(want) {
		t.Errorf("--state holds %d directories, %v; want %d", len(subdirs), err, len(want))
	}
}

// TestDevExitsOneWhenAScenarioDiffers: a scenario with one expected member
// flipped fails on its own plane, the scenario after it still runs and
// passes, and dev exits 1, which is not the 2 of a scenario that could not
// run.
func TestDevExitsOneWhenAScenarioDiffers(t *testing.T) {
	t.Parallel()
	flipped := mutant{"allowed-read.json", `"verdict": "ALLOW"`, `"verdict": "DENY"`, 2, 1, "decided.verdict"}
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "")
	code, stdout, stderr := runDevToEnd(t, time.Minute, append([]string{"--config", d.config, "--policy", d.policy},
		scenarioFlags(flipped.write(t), filepath.Join("testdata", "scenario", "blocked-transfer.json"))...)...)
	for _, line := range lines(stdout) {
		if _, dir, ok := strings.Cut(line, " plane: state in "); ok {
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
		}
	}
	if code != exitDiffered || strings.Contains(stdout, "could not run") ||
		!strings.Contains(stdout, "\nallowed-read.json step[1].decided.verdict: want DENY, got ALLOW\nallowed-read.json failed\n") ||
		!strings.Contains(stdout, "\nblocked-transfer.json passed\n") {
		t.Fatalf("exit %d, want 1 with the flipped member named and the next scenario passed:\n%s\n%s", code, stdout, stderr)
	}
}

// TestDevExitsOneWhenOneDiffersAndAnotherCannotRun: a scenario for another
// bundle cannot run and the one after it differs; the difference decides the
// exit, 1 and not 2.
func TestDevExitsOneWhenOneDiffersAndAnotherCannotRun(t *testing.T) {
	t.Parallel()
	elsewhere := mutant{"blocked-transfer.json", `"id": "scenario-fixture"`, `"id": "another-bundle"`, 1, 0, "plane.bundle.id"}
	flipped := mutant{"allowed-read.json", `"verdict": "ALLOW"`, `"verdict": "DENY"`, 2, 1, "decided.verdict"}
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "")
	code, stdout, stderr := runDevToEnd(t, time.Minute, append([]string{"--config", d.config, "--policy", d.policy, "--state", filepath.Join(t.TempDir(), "state")},
		scenarioFlags(elsewhere.write(t), flipped.write(t))...)...)
	if code != exitDiffered ||
		!strings.Contains(stdout, "\nblocked-transfer.json could not run: the plane serves bundle scenario-fixture, and the scenario is for another-bundle\n") ||
		!strings.Contains(stdout, "\nallowed-read.json failed\n") {
		t.Fatalf("exit %d, want 1 with one scenario that could not run and one that failed:\n%s\n%s", code, stdout, stderr)
	}
}

// TestDevExitsTwoWhenAPlaneDoesNotStopCleanly: a scenario that passed on a
// plane whose upstream cannot be let go has not run cleanly, and dev exits 2.
func TestDevExitsTwoWhenAPlaneDoesNotStopCleanly(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, startLiveUpstream(t, true).url, "5ms", "")
	code, stdout, stderr := runDevToEnd(t, time.Minute, append([]string{"--config", d.config, "--policy", d.policy, "--state", filepath.Join(t.TempDir(), "state")},
		scenarioFlags(filepath.Join("testdata", "scenario", "allowed-read.json"))...)...)
	if code != exitCouldNotRun || !strings.Contains(stdout, "\nallowed-read.json passed\n") ||
		!strings.Contains(stdout, "\nallowed-read.json could not run: its plane did not stop cleanly\n") {
		t.Fatalf("exit %d, want 2 with the scenario passed and its plane's stop named:\n%s\n%s", code, stdout, stderr)
	}
}

// TestDevRefusesAScenarioItCannotRead: a file the reader refuses stops every
// scenario before any plane is laid out.
func TestDevRefusesAScenarioItCannotRead(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "")
	bad := filepath.Join(t.TempDir(), "Bad.json")
	if err := os.WriteFile(bad, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	code, stdout, _ := runDevToEnd(t, time.Minute, append([]string{"--config", d.config, "--policy", d.policy, "--state", state},
		scenarioFlags(filepath.Join("testdata", "scenario", "allowed-read.json"), bad)...)...)
	if code != exitCouldNotRun || strings.Contains(stdout, "plane: state in") {
		t.Fatalf("exit %d, want 2 before any plane:\n%s", code, stdout)
	}
	untouched(t, state)
}

// pauseThenCall is a scenario of n rounds, each a pause of one tool, a call
// to it made as soon as the plane has read the pause, and the lift.
func pauseThenCall(t *testing.T, n int) string {
	t.Helper()
	var steps []string
	for i := range n {
		steps = append(steps,
			`{"pause": {"provider": "orders", "action": "tool", "name": "read_order", "reason": "round `+fmt.Sprint(i)+`"}}`,
			`{"call": {"tool": "read_order", "args": {"id": "ord-`+fmt.Sprint(i)+`"},
			  "answer": {"kind": "blocked", "codes": ["PAUSED"]},
			  "decided": {"verdict": "ALLOW", "codes": ["RULE_ALLOW"], "obligations": []},
			  "trail": {"request": "new", "kinds": ["ACTION_PROPOSED", "POLICY_DECIDED", "ACTION_BLOCKED"]}}}`,
			fmt.Sprintf(`{"unpause": {"step": %d}}`, 3*i))
	}
	doc := `{"kind": "agent-scenario/v1alpha1", "about": "A pause bites the call made right after it, every time.",
	  "plane": {"mode": "APPROVE", "bundle": {"id": "scenario-fixture"}},
	  "steps": [` + strings.Join(steps, ",\n") + `]}`
	path := filepath.Join(t.TempDir(), "pause-then-call.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAPauseBitesTheCallRightAfterIt: fifty times on one plane that reads
// its pause file as often as it may, a call made once the plane has read a
// pause is blocked by it.
func TestAPauseBitesTheCallRightAfterIt(t *testing.T) {
	t.Parallel()
	const rounds = 50
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "")
	started := time.Now()
	code, stdout, stderr := runDevToEnd(t, 5*time.Minute, "--config", d.config, "--policy", d.policy,
		"--state", filepath.Join(t.TempDir(), "state"), "--scenario", pauseThenCall(t, rounds))
	blocked := strings.Count(stdout, " call: ok\n")
	if code != exitOK || blocked != rounds || !strings.HasSuffix(stdout, "pause-then-call.json passed\n") {
		t.Fatalf("exit %d, %d calls blocked, want 0 and %d:\n%s\n%s", code, blocked, rounds, stdout, stderr)
	}
	t.Logf("%d rounds of pause, call and lift took %v", rounds, time.Since(started).Round(time.Millisecond))
}

// TestADevScenarioPastTheBudgetStaysFresh: under a document whose budget is
// twelve seconds, a scenario that runs more than twice that long keeps every
// verdict and never decides a call stale, since dev renews the statement
// every third of the budget; every decision names the one bundle digest, and
// the confirmations they carry moved forward without a new bundle.
func TestADevScenarioPastTheBudgetStaysFresh(t *testing.T) {
	t.Parallel()
	// Dev renews every third of the budget, so twelve seconds leaves room for a
	// renewal held up eight seconds by a loaded machine before a call goes stale.
	const budget = 12 * time.Second
	// The pauses are here to make the scenario long. A plane answers for a
	// pause read three intervals old, so it reads once a second: a machine
	// that holds a read up for a moment does not turn a PAUSED into a pause
	// state the plane cannot vouch for.
	const rounds = 16
	d := writeDemo(t, newLiveUpstream(t).url, "5ms", "")
	rewrite(t, d.config, "poll_interval: 100ms", "poll_interval: 1s")
	rewrite(t, d.policy, `"maxStaleSeconds":600`, `"maxStaleSeconds":12`)
	state := filepath.Join(t.TempDir(), "state")
	started := time.Now()
	code, stdout, stderr := runDevToEnd(t, 5*time.Minute, "--config", d.config, "--policy", d.policy,
		"--state", state, "--scenario", pauseThenCall(t, rounds))
	took := time.Since(started)
	if code != exitOK || !strings.HasSuffix(stdout, "pause-then-call.json passed\n") {
		t.Fatalf("exit %d after %v, want 0 and passed:\n%s\n%s", code, took, stdout, stderr)
	}
	if took < 2*budget {
		t.Fatalf("the scenario took %v, not past twice the %v budget, so it examined no renewal", took, budget)
	}
	decisions, digests, confirmed := decisionsOn(t, filepath.Join(state, "1-pause-then-call.json", "trail.jsonl"))
	if decisions < rounds || len(digests) != 1 {
		t.Errorf("%d decisions name %d bundle digest(s), want at least %d naming one", decisions, len(digests), rounds)
	}
	if len(confirmed) < 3 {
		t.Errorf("the decisions carry %d confirmation time(s) over %v; the statement was not renewed", len(confirmed), took)
	}
}

// decisionsOn counts the decisions on the trail file at path, and gathers the
// bundle digests they name and the confirmation times they carry.
func decisionsOn(t *testing.T, path string) (n int, digests map[string]bool, confirmed map[int64]bool) {
	t.Helper()
	trail, err := readTrail(path, false)
	if err != nil {
		t.Fatal(err)
	}
	digests, confirmed = map[string]bool{}, map[int64]bool{}
	for _, events := range trail.trails {
		for _, e := range events {
			if dec := e.GetDecision(); dec != nil && e.GetKind() == decided {
				n++
				digests[dec.GetPolicyBundleDigest()] = true
				confirmed[dec.GetPolicyLoadedAt().GetSeconds()] = true
			}
		}
	}
	return n, digests, confirmed
}
