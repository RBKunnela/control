package docscheck

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// requiredCheckIf is the one condition a required check's job may carry: it
// holds on every pull request, where the check is required.
const requiredCheckIf = "github.event_name == 'pull_request'"

// requiredJobKeys are the keys a required check's job may carry. Any other
// can skip the job, mask its result or change the context it reports:
// needs, continue-on-error, strategy, uses, or a quoted spelling of if.
var requiredJobKeys = []string{"name", "runs-on", "timeout-minutes", "permissions", "steps", "if"}

// maskingStepKeys are the step keys that let a required job report success
// without the step's work: a condition that skips it, or a failure ignored.
var maskingStepKeys = []string{"if", "continue-on-error"}

// workflowJob is one job of a workflow, keyed elsewhere by the check-run
// context it reports: its name, or its id when it has none.
type workflowJob struct {
	file    string
	node    *yamlNode
	everyPR bool
}

// jobsOf reads one workflow's jobs by the context each reports, and refuses
// a job whose name is an expression, since its context is known only when it
// runs.
func jobsOf(file string, lines []string, into map[string][]workflowJob) error {
	doc, err := parseBlockYAML(lines)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	everyPR := runsOnEveryPullRequest(doc)
	for _, jobs := range doc.children("jobs") {
		for _, job := range jobs.kids {
			context := job.key
			if names := job.children("name"); len(names) == 1 {
				context = unquote(names[0].value)
			}
			if strings.Contains(context, "${{") {
				return fmt.Errorf("%s:%d: the job's name is an expression", file, job.line)
			}
			into[context] = append(into[context], workflowJob{file: file, node: job, everyPR: everyPR})
		}
	}
	return nil
}

// runsOnEveryPullRequest reports whether doc's on: starts it for every pull
// request and every push to one: a pull_request trigger with no filter but
// activity types that include opened, reopened and synchronize.
func runsOnEveryPullRequest(doc *yamlNode) bool {
	ons := doc.children("on")
	if len(ons) != 1 {
		return false
	}
	if ons[0].value != "" {
		return slices.Contains(flowList(ons[0].value), "pull_request")
	}
	triggers := ons[0].children("pull_request")
	if len(triggers) != 1 || triggers[0].value != "" {
		return false
	}
	for _, filter := range triggers[0].kids {
		types := sequence(filter)
		if filter.key != "types" || !slices.Contains(types, "opened") ||
			!slices.Contains(types, "reopened") || !slices.Contains(types, "synchronize") {
			return false
		}
	}
	return true
}

// hasAlias reports whether an alias or a merge key sits anywhere under n:
// either can bring in a key the allowlists never see.
func hasAlias(n *yamlNode) bool {
	return slices.ContainsFunc(n.kids, func(kid *yamlNode) bool {
		return kid.key == "<<" || strings.HasPrefix(kid.key, "*") || strings.HasPrefix(kid.value, "*") || hasAlias(kid)
	})
}

// requiredCheckProblems names a check listed twice, and each required check
// no job reports, or more than one does, or whose job a pull request can
// leave unreported, skip or turn green without its work.
func requiredCheckProblems(checks []string, jobs map[string][]workflowJob) []string {
	var problems []string
	if len(slices.Compact(slices.Sorted(slices.Values(checks)))) != len(checks) {
		problems = append(problems, fmt.Sprintf("a required check is listed twice: %q", checks))
	}
	for _, check := range checks {
		found := jobs[check]
		if len(found) != 1 {
			problems = append(problems, fmt.Sprintf("%d jobs report the required check %q, want 1", len(found), check))
			continue
		}
		problems = append(problems, requiredJobProblems(check, found[0])...)
	}
	return problems
}

func requiredJobProblems(check string, job workflowJob) []string {
	where := fmt.Sprintf("%s: the job of %q", job.file, check)
	problems := keyProblems(job.node, requiredJobKeys, where)
	if !job.everyPR {
		problems = append(problems, where+" is in a workflow that does not run on every pull request")
	}
	if hasAlias(job.node) {
		problems = append(problems, where+" holds an alias or a merge key")
	}
	for _, cond := range job.node.children("if") {
		if expr := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cond.value, "${{"), "}}")); expr != requiredCheckIf {
			problems = append(problems, fmt.Sprintf("%s runs only if %s", where, cond.value))
		}
	}
	for _, steps := range job.node.children("steps") {
		for _, step := range steps.kids {
			for _, kid := range step.kids {
				if slices.Contains(maskingStepKeys, unquote(kid.key)) {
					problems = append(problems, fmt.Sprintf("line %d: %s has a step with %s", kid.line, where, kid.key))
				}
			}
		}
	}
	return problems
}

// TestEveryRequiredCheckIsAJobEveryPullRequestRuns: a required check no job
// reports blocks every merge until an admin edits the ruleset, and one whose
// job is skipped reads as passed. The bootstrap refuses the first before it
// applies anything; this holds the list to the workflows on every change. It
// guards against a careless change, not a hostile one: a pull request runs
// the workflows and this test from its own branch, so review of .github/**
// is the control there.
func TestEveryRequiredCheckIsAJobEveryPullRequestRuns(t *testing.T) {
	root := repoRoot(t)
	var paths []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		found, err := filepath.Glob(filepath.Join(root, ".github", "workflows", pattern))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		t.Fatal("no workflow")
	}
	jobs := map[string][]workflowJob{}
	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a workflow this repository keeps
		if err != nil {
			t.Fatal(err)
		}
		if err := jobsOf(filepath.Base(path), strings.Split(string(raw), "\n"), jobs); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range requiredCheckProblems(settingsValues(t, `printf '%s\n' "${REQUIRED_CHECKS[@]}"`), jobs) {
		t.Error(p)
	}
}

const plantedWorkflow = "on:\n  pull_request:\njobs:\n  gate:\n    name: Gate\n    runs-on: ubuntu-latest\n" +
	"    steps:\n      - run: make check\n"

func plantedJobs(t *testing.T, doc string) map[string][]workflowJob {
	t.Helper()
	jobs := map[string][]workflowJob{}
	if err := jobsOf("planted.yml", strings.Split(doc, "\n"), jobs); err != nil {
		t.Fatal(err)
	}
	return jobs
}

// Each planted workflow breaks the rule one way, and only that way.
func TestARequiredCheckAPullRequestCanMissIsCaught(t *testing.T) {
	good := plantedWorkflow
	step := "      - run: make check\n"
	for name, doc := range map[string]string{
		"a renamed job":             strings.Replace(good, "name: Gate", "name: Gates", 1),
		"no name, another id":       strings.Replace(good, "    name: Gate\n", "", 1),
		"a path filter":             strings.Replace(good, "  pull_request:\n", "  pull_request:\n    paths: [docs/**]\n", 1),
		"no synchronize":            strings.Replace(good, "  pull_request:\n", "  pull_request:\n    types: [opened, reopened]\n", 1),
		"no pull request trigger":   strings.Replace(good, "  pull_request:\n", "  push:\n", 1),
		"a condition":               good + "    if: github.event_name == 'push'\n",
		"a quoted condition":        good + "    \"if\": false\n",
		"a job it waits on":         good + "    needs: build\n",
		"a quoted job it waits on":  good + "    'needs': build\n",
		"an ignored failure":        good + "    continue-on-error: true\n",
		"a matrix":                  good + "    strategy:\n      matrix:\n        os: [a, b]\n",
		"a called workflow":         good + "    uses: ./.github/workflows/other.yml\n",
		"an alias":                  strings.Replace(good, "runs-on: ubuntu-latest", "runs-on: *runner", 1),
		"a skipped step":            strings.Replace(good, step, step+"        if: false\n", 1),
		"a step whose failure goes": strings.Replace(good, step, step+"        \"continue-on-error\": true\n", 1),
		"two jobs of the name":      good + "  again:\n    name: Gate\n",
	} {
		if got := requiredCheckProblems([]string{"Gate"}, plantedJobs(t, doc)); len(got) != 1 {
			t.Errorf("%s: %q, want one problem", name, got)
		}
	}
	if got := requiredCheckProblems([]string{"Gate", "Gate"}, plantedJobs(t, good)); len(got) != 1 {
		t.Errorf("a check listed twice: %q, want one problem", got)
	}
	if err := jobsOf("planted.yml", strings.Split(good+"  other:\n    name: ${{ 'Gate' }}\n", "\n"), map[string][]workflowJob{}); err == nil {
		t.Error("a job named by an expression was read")
	}
	for name, doc := range map[string]string{
		"a bare trigger":             good,
		"a flow list":                strings.Replace(good, "on:\n  pull_request:\n", "on: [push, pull_request]\n", 1),
		"every activity it needs":    strings.Replace(good, "  pull_request:\n", "  pull_request:\n    types: [opened, edited, reopened, synchronize]\n", 1),
		"the pull request condition": good + "    if: ${{ " + requiredCheckIf + " }}\n",
	} {
		if got := requiredCheckProblems([]string{"Gate"}, plantedJobs(t, doc)); len(got) != 0 {
			t.Errorf("%s: %q, want none", name, got)
		}
	}
}
