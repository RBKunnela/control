package docscheck

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The step of the gate job that asks GitHub whether each pinned action SHA is
// the commit its version comment names in that action's repository. The
// offline checks see only a SHA's shape.
const (
	ciPinCommand  = "scripts/pin-actions.sh --check"
	ciPinEnvName  = "GH_TOKEN"
	ciPinEnvValue = "${{ github.token }}"
)

// ciPinStepKeys are the keys the pin step may carry; an if or a
// continue-on-error would let the job pass without it.
var ciPinStepKeys = []string{"name", "env", "run"}

// ciPinProblems names every way the gate job stops checking the pins online:
// no step or two run exactly the check, or the step carries a key that can
// skip it or mask its result, or an environment other than the job's own
// token.
func ciPinProblems(lines []string) []string {
	root, err := parseBlockYAML(lines)
	if err != nil {
		return []string{err.Error()}
	}
	steps := gateJobSteps(root, ciPinCommand)
	if len(steps) != 1 {
		return []string{fmt.Sprintf("%d steps of the %s job run exactly %q, want 1", len(steps), ciGateJob, ciPinCommand)}
	}
	step := steps[0]
	where := fmt.Sprintf("the pin step at line %d", step.line)
	problems := keyProblems(step, ciPinStepKeys, where)
	envs := step.children("env")
	if len(envs) != 1 {
		return append(problems, fmt.Sprintf("%s has no env handing it %s", where, ciPinEnvName))
	}
	if kids := envs[0].kids; len(kids) != 1 || kids[0].key != ciPinEnvName || kids[0].value != ciPinEnvValue {
		problems = append(problems, fmt.Sprintf("%s: env must be exactly %s: %s", where, ciPinEnvName, ciPinEnvValue))
	}
	return problems
}

// gateJobSteps returns the steps of the gate job whose run is exactly command.
func gateJobSteps(root *yamlNode, command string) []*yamlNode {
	var steps []*yamlNode
	for _, jobs := range root.children("jobs") {
		for _, job := range jobs.children(ciGateJob) {
			for _, list := range job.children("steps") {
				for _, step := range list.kids {
					if slices.ContainsFunc(step.kids, func(k *yamlNode) bool { return k.key == "run" && k.value == command }) {
						steps = append(steps, step)
					}
				}
			}
		}
	}
	return steps
}

func TestCIChecksEveryPinOnline(t *testing.T) {
	for _, problem := range ciPinProblems(readLines(t, repoFS(t), ciWorkflowPath)) {
		t.Errorf("%s: %s", ciWorkflowPath, problem)
	}
}

func TestCIPinProblems(t *testing.T) {
	checkout := "          persist-credentials: false\n"
	pinStep := "      - name: Check every action pin\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: " + ciPinCommand + "\n"
	good := replaceOnce(t, ciFixture, checkout, checkout+"\n"+pinStep)
	if problems := ciPinProblems(strings.Split(good, "\n")); len(problems) != 0 {
		t.Fatalf("the correct fixture reported %q", problems)
	}
	if problems := ciGateProblems(strings.Split(good, "\n")); len(problems) != 0 {
		t.Fatalf("the gate check refuses the fixture with the pin step: %q", problems)
	}
	tokenLine := "          GH_TOKEN: ${{ github.token }}\n"
	runLine := "        run: " + ciPinCommand + "\n"
	for name, c := range map[string]struct{ old, replacement, want string }{
		"no pin step":             {pinStep, "", "0 steps of the quality job run exactly"},
		"two pin steps":           {pinStep, pinStep + pinStep, "2 steps of the quality job run exactly"},
		"a fallback":              {runLine, "        run: " + ciPinCommand + " || true\n", "0 steps"},
		"the check without flag":  {runLine, "        run: scripts/pin-actions.sh\n", "0 steps"},
		"an if on the step":       {runLine, runLine + "        if: false\n", "carries if"},
		"continue-on-error":       {runLine, runLine + "        continue-on-error: true\n", "carries continue-on-error"},
		"no token":                {"        env:\n" + tokenLine, "", "has no env handing it GH_TOKEN"},
		"another token":           {tokenLine, "          GH_TOKEN: ${{ secrets.PAT }}\n", "env must be exactly GH_TOKEN"},
		"a host beside the token": {tokenLine, tokenLine + "          GH_HOST: example.com\n", "env must be exactly GH_TOKEN"},
		"in another job":          {pinStep, "", "0 steps"},
	} {
		text := replaceOnce(t, good, c.old, c.replacement)
		if name == "in another job" {
			text += "  other-pins:\n    steps:\n" + pinStep
		}
		problems := ciPinProblems(strings.Split(text, "\n"))
		if !slices.ContainsFunc(problems, func(s string) bool { return strings.Contains(s, c.want) }) {
			t.Errorf("%s: want a problem containing %q, got %q", name, c.want, problems)
		}
	}
}
