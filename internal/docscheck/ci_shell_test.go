package docscheck

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	nightlyWorkflowPath = ".github/workflows/nightly.yml"
	nightlyFuzzJob      = "fuzz"
	nightlyFuzzCommand  = "/usr/bin/env -u MAKEFLAGS -u GNUMAKEFLAGS -u MFLAGS -u MAKEFILES make fuzz-smoke"
	// nightlyReportIf is the report job's condition: a red scheduled night.
	nightlyReportIf = "${{ failure() && github.event_name == 'schedule' }}"
	// gateCommitFuzzLine is the line of scripts/gate-commit.sh that fuzzes
	// the release commit's archive.
	gateCommitFuzzLine = `(cd "${tree}" && "${clean[@]}" make GO=go fuzz-smoke) >>"${log}" 2>&1 || rc=$?`
)

// unquotedKey is a key as YAML reads it, quoted or not.
func unquotedKey(key string) string {
	if len(key) >= 2 && (key[0] == '"' || key[0] == '\'') && key[len(key)-1] == key[0] {
		return key[1 : len(key)-1]
	}
	return key
}

// shellWalk gathers what one file says about the shell its run steps start
// in.
type shellWalk struct {
	action, runs, defaulted bool
	problems                []string
}

// shellProblems holds one workflow or composite action to ciShell. A
// workflow with a run step sets it as its default and nothing sets another
// shell, at the workflow, a job or a step; every run step of a composite
// action carries it, since an action has no default. A step written as a flow
// mapping is refused: this check cannot read one.
func shellProblems(lines []string, action bool) []string {
	root, err := parseBlockYAML(lines)
	if err != nil {
		return []string{err.Error()}
	}
	w := &shellWalk{action: action}
	w.walk(root, nil)
	if w.runs && !w.defaulted && !action {
		w.problems = append(w.problems, "the workflow has run steps and no default run.shell: "+ciShell)
	}
	return w.problems
}

func (w *shellWalk) walk(n *yamlNode, path []string) {
	for _, kid := range n.kids {
		key := unquotedKey(kid.key)
		at := append(slices.Clone(path), key)
		w.visit(n, kid, key, at)
		w.walk(kid, at)
	}
}

func (w *shellWalk) visit(parent, kid *yamlNode, key string, at []string) {
	switch {
	case strings.HasPrefix(key, "{") || strings.HasPrefix(kid.value, "{"):
		w.problems = append(w.problems, fmt.Sprintf("line %d: a flow mapping, which this check cannot read", kid.line))
	case key == "run" && slices.Contains(at, "steps"):
		w.runs = true
		if w.action && !slices.ContainsFunc(parent.kids, func(k *yamlNode) bool { return unquotedKey(k.key) == "shell" }) {
			w.problems = append(w.problems, fmt.Sprintf("line %d: a run step of an action carries no shell: %s", kid.line, ciShell))
		}
	case key == "shell" && kid.value == ciShell && (w.action || slices.Equal(at, []string{"defaults", "run", "shell"})):
		w.defaulted = true
	case key == "shell":
		w.problems = append(w.problems, fmt.Sprintf("line %d: %s is %q; every run step starts in %s", kid.line, strings.Join(at, "."), kid.value, ciShell))
	}
}

func TestEveryWorkflowStartsItsShellClean(t *testing.T) {
	glob := func(patterns ...string) []string {
		var found []string
		for _, pattern := range patterns {
			paths, err := fs.Glob(repoFS(t), pattern)
			if err != nil {
				t.Fatal(err)
			}
			found = append(found, paths...)
		}
		return found
	}
	workflows := glob(".github/workflows/*.yml", ".github/workflows/*.yaml")
	actions := glob(".github/actions/*/action.yml", ".github/actions/*/action.yaml")
	if len(workflows) == 0 {
		t.Fatal("no workflow found; refusing to report a pass")
	}
	for _, path := range slices.Concat(workflows, actions) {
		for _, problem := range shellProblems(readLines(t, repoFS(t), path), slices.Contains(actions, path)) {
			t.Errorf("%s: %s", path, problem)
		}
	}
}

func TestShellProblems(t *testing.T) {
	good := "on: push\ndefaults:\n  run:\n    shell: " + ciShell + "\njobs:\n  a:\n    steps:\n      - run: true\n"
	if problems := shellProblems(strings.Split(good, "\n"), false); len(problems) != 0 {
		t.Fatalf("the correct fixture reported %q", problems)
	}
	for name, c := range map[string]struct{ old, replacement, want string }{
		"GitHub's own bash":  {"    shell: " + ciShell + "\n", "    shell: bash\n", "no default run.shell"},
		"no defaults":        {"defaults:\n  run:\n    shell: " + ciShell + "\n", "", "no default run.shell"},
		"a step's own shell": {"      - run: true\n", "      - run: true\n        shell: bash\n", "jobs.a.steps.-.shell is \"bash\""},
		"a quoted shell key": {"      - run: true\n", "      - run: true\n        \"shell\": bash\n", "jobs.a.steps.-.shell is \"bash\""},
		"a job default":      {"    steps:\n", "    defaults:\n      run:\n        shell: sh\n    steps:\n", "jobs.a.defaults.run.shell"},
		"a flow step":        {"      - run: true\n", "      - {run: true, shell: sh}\n", "a flow mapping"},
	} {
		problems := shellProblems(strings.Split(replaceOnce(t, good, c.old, c.replacement), "\n"), false)
		if !slices.ContainsFunc(problems, func(s string) bool { return strings.Contains(s, c.want) }) {
			t.Errorf("%s: want a problem containing %q, got %q", name, c.want, problems)
		}
	}
	if problems := shellProblems(strings.Split("on: push\njobs:\n  a:\n    steps:\n      - uses: x/y@0123 # v1\n", "\n"), false); len(problems) != 0 {
		t.Errorf("a workflow with no run step reported %q", problems)
	}
	action := "runs:\n  using: composite\n  steps:\n    - run: true\n      shell: " + ciShell + "\n"
	if problems := shellProblems(strings.Split(action, "\n"), true); len(problems) != 0 {
		t.Errorf("a correct action reported %q", problems)
	}
	if problems := shellProblems(strings.Split(replaceOnce(t, action, "      shell: "+ciShell+"\n", "      shell: bash\n"), "\n"), true); len(problems) == 0 {
		t.Error("an action step in GitHub's own bash reported nothing")
	}
}

// runShell runs args with env added to a clean environment and returns what
// it printed and its exit status.
func runShell(t *testing.T, env string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec // G204: a shell over a script this test wrote
	cmd.Env = append(cleanMakeEnv(), env)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	}
	t.Fatalf("%v: %v", args, err)
	return "", 0
}

// TestTheShellIgnoresTheStartupStateOfTheEnvironment runs the shell line
// every workflow names over a script that prints and exits 7, under what an
// earlier step could write through $GITHUB_ENV to change what bash runs; on
// CI it runs against the runner's own bash. Each case first shows that
// GitHub's plain bash line is changed by the same input, so a case cannot pass
// because the input never reached the shell. The variables stay in the
// environment, so a bash the step starts in turn still reads them: make
// quality refuses them itself, and other scripts do not (ADR-0062).
func TestTheShellIgnoresTheStartupStateOfTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "step.sh")
	startup := filepath.Join(dir, "startup.sh")
	for name, body := range map[string]string{script: "echo ran\nexit 7\n", startup: "echo startup ran\n"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	line := strings.Fields(strings.Replace(ciShell, "{0}", script, 1))
	plain := []string{"bash", "--noprofile", "--norc", "-e", "-o", "pipefail", script}
	for _, env := range []string{
		"SHELLOPTS=noexec",
		"BASH_ENV=" + startup,
		"BASH_FUNC_echo%%=() { builtin printf 'a function ran\\n'; }",
	} {
		if out, code := runShell(t, env, plain...); out == "ran\n" && code == 7 {
			t.Errorf("plain bash under %s ran the step unchanged; this case cannot tell the shell line from an input that never arrived", env)
		}
		if out, code := runShell(t, env, line...); out != "ran\n" || code != 7 {
			t.Errorf("%s under %s = %d, %q; want 7 and the step's own line", ciShell, env, code, out)
		}
	}
}

// nightlyProblems names every way the nightly workflow stops fuzzing each
// night, or reporting a red one: no schedule, no fuzz job, a fuzz job that can
// be skipped, masked or handed another FUZZTIME, no unconditional step running
// exactly the fuzz command, or a report job that is gone, does not wait for
// the fuzz job, or runs under another condition.
func nightlyProblems(lines []string) []string {
	root, err := parseBlockYAML(lines)
	if err != nil {
		return []string{err.Error()}
	}
	var problems []string
	if !slices.ContainsFunc(root.children("on"), func(on *yamlNode) bool { return len(on.children("schedule")) == 1 }) {
		problems = append(problems, "the workflow runs on no schedule")
	}
	for _, env := range root.children("env") {
		problems = append(problems, fmt.Sprintf("line %d: the workflow sets env, which reaches the fuzz step", env.line))
	}
	var jobs, reports []*yamlNode
	for _, all := range root.children("jobs") {
		jobs = append(jobs, all.children(nightlyFuzzJob)...)
		reports = append(reports, all.children("report")...)
	}
	problems = append(problems, reportProblems(reports)...)
	if len(jobs) != 1 {
		return append(problems, fmt.Sprintf("found %d %s job(s), want 1", len(jobs), nightlyFuzzJob))
	}
	for _, key := range []string{"if", "continue-on-error", "env", "strategy", "needs", "defaults", "container"} {
		for _, kid := range jobs[0].children(key) {
			problems = append(problems, fmt.Sprintf("line %d: the %s job carries %s", kid.line, nightlyFuzzJob, key))
		}
	}
	if found := plainSteps(jobs[0], nightlyFuzzCommand); found != 1 {
		problems = append(problems, fmt.Sprintf("%d step(s) of the %s job run exactly %q with no if, continue-on-error or env, want 1", found, nightlyFuzzJob, nightlyFuzzCommand))
	}
	return problems
}

// reportProblems holds the report job to waiting for the fuzz job and to
// running on a red scheduled night.
func reportProblems(reports []*yamlNode) []string {
	if len(reports) != 1 {
		return []string{fmt.Sprintf("found %d report job(s), want 1", len(reports))}
	}
	var problems []string
	needs := reports[0].children("needs")
	if len(needs) != 1 || !slices.Contains(flowList(needs[0].value), nightlyFuzzJob) {
		problems = append(problems, fmt.Sprintf("line %d: the report job does not wait for the %s job", reports[0].line, nightlyFuzzJob))
	}
	ifs := reports[0].children("if")
	if len(ifs) != 1 || ifs[0].value != nightlyReportIf {
		problems = append(problems, fmt.Sprintf("line %d: the report job runs on another condition than %s", reports[0].line, nightlyReportIf))
	}
	return problems
}

// plainSteps counts the steps of job that run exactly command with no if,
// continue-on-error or env of their own.
func plainSteps(job *yamlNode, command string) int {
	found := 0
	for _, steps := range job.children("steps") {
		for _, step := range steps.kids {
			runs := slices.ContainsFunc(step.kids, func(k *yamlNode) bool { return k.key == "run" && k.value == command })
			if runs && len(step.children("if")) == 0 && len(step.children("continue-on-error")) == 0 && len(step.children("env")) == 0 {
				found++
			}
		}
	}
	return found
}

// TestFuzzingRunsOutsideTheGate holds the two places ADR-0062 moved the fuzz
// run to: the nightly workflow, and the cold gate of a release commit.
func TestFuzzingRunsOutsideTheGate(t *testing.T) {
	for _, problem := range nightlyProblems(readLines(t, repoFS(t), nightlyWorkflowPath)) {
		t.Errorf("%s: %s", nightlyWorkflowPath, problem)
	}
	if !slices.ContainsFunc(readLines(t, repoFS(t), "scripts/gate-commit.sh"), func(l string) bool { return strings.TrimSpace(l) == gateCommitFuzzLine }) {
		t.Errorf("scripts/gate-commit.sh holds no line %q, which fuzzes the release commit's archive", gateCommitFuzzLine)
	}
}

func TestNightlyProblems(t *testing.T) {
	good := "on:\n  schedule:\n    - cron: \"1 2 * * *\"\njobs:\n  fuzz:\n    runs-on: x\n    steps:\n      - run: " + nightlyFuzzCommand +
		"\n  report:\n    needs: [race, fuzz]\n    if: " + nightlyReportIf + "\n"
	if problems := nightlyProblems(strings.Split(good, "\n")); len(problems) != 0 {
		t.Fatalf("the correct fixture reported %q", problems)
	}
	step := "      - run: " + nightlyFuzzCommand + "\n"
	for name, c := range map[string]struct{ old, replacement, want string }{
		"no schedule":             {"  schedule:\n    - cron: \"1 2 * * *\"\n", "  workflow_dispatch:\n", "no schedule"},
		"a fuzz time on the step": {step, step + "        env:\n          FUZZTIME: 1ns\n", "want 1"},
		"a fuzz time on the job":  {"    runs-on: x\n", "    runs-on: x\n    env:\n      FUZZTIME: 1ns\n", "carries env"},
		"masked on the job":       {"    runs-on: x\n", "    runs-on: x\n    continue-on-error: true\n", "carries continue-on-error"},
		"another command":         {step, "      - run: make fuzz-smoke FUZZTIME=1ns\n", "want 1"},
		"a report that waits not": {"needs: [race, fuzz]", "needs: race", "does not wait"},
		"a report with no needs":  {"    needs: [race, fuzz]\n", "", "does not wait"},
		"a report never run":      {"    if: " + nightlyReportIf + "\n", "    if: false\n", "another condition"},
		"no report":               {"  report:\n", "  later:\n", "found 0 report job(s)"},
	} {
		problems := nightlyProblems(strings.Split(replaceOnce(t, good, c.old, c.replacement), "\n"))
		if !slices.ContainsFunc(problems, func(s string) bool { return strings.Contains(s, c.want) }) {
			t.Errorf("%s: want a problem containing %q, got %q", name, c.want, problems)
		}
	}
}
