package docscheck

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

const (
	ciWorkflowPath = ".github/workflows/ci.yml"
	ciGateJob      = "quality"
	ciGateCommand  = "env -u MAKEFLAGS -u GNUMAKEFLAGS -u MFLAGS -u MAKEFILES make quality GO=go"
)

// The keys the gate job and its gate step may carry. Anything else can skip
// the job, mask its result or change what the command runs: if, needs,
// continue-on-error, strategy, env, defaults, container, shell,
// working-directory and keys no one has thought of yet.
var (
	ciJobKeys  = []string{"name", "runs-on", "timeout-minutes", "steps"}
	ciStepKeys = []string{"name", "run"}
)

// The variables make, go and the recipes' bash take flags, makefiles and
// startup files from. An earlier step that writes one to $GITHUB_ENV changes
// what the gate step runs without touching it.
var ciLooseningNames = []string{"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES", "GOFLAGS", "GOENV", "BASH_ENV"}

// ciEnvWrites are the only lines of the quality job that may name the files
// a step hands variables and the path to later steps through: the pins of
// scripts/tool-versions.env and the directory of the tools the job installs.
// The check reads text, so a write a step spells some other way is the
// Makefile's guard to refuse; this keeps every plain one visible.
var ciEnvWrites = []string{
	`printf '%s\n' "${pins}" >>"$GITHUB_ENV"`,
	`scripts/tool-versions.env | grep . >>"$GITHUB_ENV"`,
	`echo "${bin}" >>"$GITHUB_PATH"`,
}

// yamlNode is one mapping key or sequence item ("-") of a block-style YAML
// document, with the scalar written after its colon and the lines of a block
// scalar.
type yamlNode struct {
	line  int
	key   string
	value string
	block []string
	kids  []*yamlNode
}

// parseBlockYAML reads the block layout a workflow uses: mappings, sequences
// of mappings and scalars, with a block scalar (| or >) kept as its raw lines.
// A line it cannot read is an error, never a key it drops.
func parseBlockYAML(lines []string) (*yamlNode, error) {
	root := &yamlNode{}
	p := &yamlParser{stack: []yamlFrame{{-1, root}}}
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimLeft(lines[i], " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "\t") {
			return nil, fmt.Errorf("line %d: indented with a tab", i+1)
		}
		node, indent, err := p.entry(i+1, len(lines[i])-len(trimmed), trimmed)
		if err != nil {
			return nil, err
		}
		if node != nil && (strings.HasPrefix(node.value, "|") || strings.HasPrefix(node.value, ">")) {
			for i+1 < len(lines) && (strings.TrimSpace(lines[i+1]) == "" || len(lines[i+1])-len(strings.TrimLeft(lines[i+1], " ")) > indent) {
				i++
				node.block = append(node.block, lines[i])
			}
		}
	}
	return root, nil
}

type yamlFrame struct {
	indent int
	node   *yamlNode
}

type yamlParser struct {
	stack []yamlFrame
}

// parent closes every open node at indent or deeper and returns the one a
// node at indent belongs to.
func (p *yamlParser) parent(indent int) *yamlNode {
	for p.stack[len(p.stack)-1].indent >= indent {
		p.stack = p.stack[:len(p.stack)-1]
	}
	return p.stack[len(p.stack)-1].node
}

func (p *yamlParser) open(indent int, node *yamlNode) {
	parent := p.parent(indent)
	parent.kids = append(parent.kids, node)
	p.stack = append(p.stack, yamlFrame{indent, node})
}

// entry places one line's sequence items and key, and returns the key node
// with the column its key starts at, or nil for a scalar item.
func (p *yamlParser) entry(line, indent int, text string) (*yamlNode, int, error) {
	for text == "-" || strings.HasPrefix(text, "- ") {
		item := &yamlNode{line: line, key: "-"}
		p.open(indent, item)
		rest := strings.TrimPrefix(text[1:], " ")
		text = strings.TrimLeft(rest, " ")
		indent += 2 + len(rest) - len(text)
		if !isYAMLKey(text) {
			item.value = stripYAMLComment(text)
			return nil, indent, nil
		}
	}
	if !isYAMLKey(text) {
		return nil, 0, fmt.Errorf("line %d: %q is not a key", line, text)
	}
	key, value, _ := strings.Cut(text, ":")
	node := &yamlNode{line: line, key: strings.TrimSpace(key), value: stripYAMLComment(value)}
	p.open(indent, node)
	return node, indent, nil
}

// isYAMLKey reports a "key:" or "key: value" line. A quoted scalar is
// never read as a key, though a quoted key is.
func isYAMLKey(text string) bool {
	key, value, ok := strings.Cut(text, ":")
	if !ok || key == "" || value != "" && !strings.HasPrefix(value, " ") {
		return false
	}
	if q := key[0]; q == '"' || q == '\'' {
		return len(key) > 1 && key[len(key)-1] == q
	}
	return true
}

func stripYAMLComment(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "#") {
		return ""
	}
	if i := strings.Index(value, " #"); i >= 0 && !strings.ContainsAny(value[:i], `'"`) {
		value = strings.TrimSpace(value[:i])
	}
	return value
}

func (n *yamlNode) children(key string) []*yamlNode {
	var found []*yamlNode
	for _, kid := range n.kids {
		if kid.key == key {
			found = append(found, kid)
		}
	}
	return found
}

// ciGateProblems names every way ci.yml stops proving that `make quality`
// ran and passed: the gate job is missing or doubled, carries a key that can
// skip it or mask its result, or has no step that runs exactly the gate and
// nothing else, unconditionally; or the workflow sets an environment or a
// default shell that changes what the step runs.
func ciGateProblems(lines []string) []string {
	root, err := parseBlockYAML(lines)
	if err != nil {
		return []string{err.Error()}
	}
	problems := slices.Concat(workflowLevelProblems(root), triggerProblems(root))
	var jobs []*yamlNode
	for _, j := range root.children("jobs") {
		jobs = append(jobs, j.children(ciGateJob)...)
	}
	if len(jobs) != 1 {
		return append(problems, fmt.Sprintf("found %d %s job(s) under jobs, want 1", len(jobs), ciGateJob))
	}
	job := jobs[0]
	problems = append(problems, aliasProblems(job)...)
	problems = append(problems, keyProblems(job, ciJobKeys, "the "+ciGateJob+" job")...)
	var gate []*yamlNode
	for _, steps := range job.children("steps") {
		for _, step := range steps.kids {
			isGate := slices.ContainsFunc(step.kids, func(k *yamlNode) bool { return k.key == "run" && k.value == ciGateCommand })
			if isGate {
				gate = append(gate, step)
			}
			problems = append(problems, looseningProblems(step, isGate)...)
		}
	}
	switch len(gate) {
	case 0:
		problems = append(problems, fmt.Sprintf("no step of the %s job runs exactly %q", ciGateJob, ciGateCommand))
	case 1:
	default:
		problems = append(problems, fmt.Sprintf("%d steps of the %s job run %q, want 1", len(gate), ciGateJob, ciGateCommand))
	}
	for _, step := range gate {
		problems = append(problems, keyProblems(step, ciStepKeys, fmt.Sprintf("the step at line %d", step.line))...)
	}
	return problems
}

func workflowLevelProblems(root *yamlNode) []string {
	var problems []string
	for _, env := range root.children("env") {
		problems = append(problems, fmt.Sprintf("line %d: the workflow sets env, which reaches the gate step", env.line))
	}
	for _, defaults := range root.children("defaults") {
		for _, run := range defaults.kids {
			for _, kid := range run.kids {
				if run.key != "run" || kid.key != "shell" || kid.value != "bash" {
					problems = append(problems, fmt.Sprintf("line %d: the workflow default %s.%s is %q, want only run.shell: bash", kid.line, run.key, kid.key, kid.value))
				}
			}
			if run.key != "run" || len(run.kids) == 0 {
				problems = append(problems, fmt.Sprintf("line %d: the workflow default %s is not run.shell: bash", run.line, run.key))
			}
		}
	}
	return problems
}

// looseningProblems refuses a step of the gate job whose text names a
// variable make or go reads its flags from. Any mention is refused, not only
// a write to $GITHUB_ENV: a step can save the file's path for a later one, or
// hand the name to a write through its env. The gate command itself names the
// variables it clears, and only that one line of the gate step is exempt.
func looseningProblems(step *yamlNode, isGate bool) []string {
	var problems []string
	text := step.text()
	if isGate {
		text = strings.Replace(text, "run: "+ciGateCommand+"\n", "", 1)
	}
	for _, name := range ciLooseningNames {
		if strings.Contains(text, name) {
			problems = append(problems, fmt.Sprintf("line %d: a step of the %s job names %s, which a write to $GITHUB_ENV hands to the gate step", step.line, ciGateJob, name))
		}
	}
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		if (strings.Contains(line, "GITHUB_ENV") || strings.Contains(line, "GITHUB_PATH")) && !slices.Contains(ciEnvWrites, line) {
			problems = append(problems, fmt.Sprintf("line %d: a step of the %s job writes the environment or the path of later steps other than as the pins and the tools do: %s", step.line, ciGateJob, line))
		}
	}
	return problems
}

// text is everything written under n: its keys, scalars and block lines.
func (n *yamlNode) text() string {
	var b strings.Builder
	b.WriteString(n.key + ": " + n.value + "\n")
	for _, line := range n.block {
		b.WriteString(line + "\n")
	}
	for _, kid := range n.kids {
		b.WriteString(kid.text())
	}
	return b.String()
}

// triggerProblems refuses an on: that no longer runs the workflow on every
// pull request and on every push to main: a missing event, a filter on the
// pull request, or a push filter other than branches naming main.
func triggerProblems(root *yamlNode) []string {
	ons := root.children("on")
	if len(ons) != 1 {
		return []string{fmt.Sprintf("found %d on key(s), want 1", len(ons))}
	}
	on := ons[0]
	if on.value != "" {
		var problems []string
		for _, event := range []string{"push", "pull_request"} {
			if !slices.Contains(flowList(on.value), event) {
				problems = append(problems, fmt.Sprintf("line %d: the workflow does not run on %s", on.line, event))
			}
		}
		return problems
	}
	var problems []string
	for _, event := range []string{"push", "pull_request"} {
		triggers := on.children(event)
		if len(triggers) != 1 {
			problems = append(problems, fmt.Sprintf("line %d: the workflow does not run on %s exactly once", on.line, event))
			continue
		}
		trigger := triggers[0]
		where := fmt.Sprintf("line %d: the %s trigger", trigger.line, event)
		if trigger.value != "" {
			problems = append(problems, where+" is not bare")
		}
		for _, kid := range trigger.kids {
			if problem := triggerFilterProblem(where, event, kid); problem != "" {
				problems = append(problems, problem)
			}
		}
	}
	return problems
}

// triggerFilterProblem judges one filter of a trigger: only a push may be
// filtered, and only by branches that name main and exclude none.
func triggerFilterProblem(where, event string, kid *yamlNode) string {
	switch branches := sequence(kid); {
	case event == "pull_request" || kid.key != "branches":
		return fmt.Sprintf("%s carries %s", where, kid.key)
	case !slices.Contains(branches, "main"):
		return where + " runs on no main branch"
	case slices.ContainsFunc(branches, func(b string) bool { return strings.HasPrefix(b, "!") }):
		return where + " excludes a branch, which can take main back out"
	}
	return ""
}

// sequence is the scalars of n's value as a flow list, or of its block items.
func sequence(n *yamlNode) []string {
	if n.value != "" {
		return flowList(n.value)
	}
	var items []string
	for _, kid := range n.kids {
		if kid.key == "-" && len(kid.kids) == 0 {
			items = append(items, unquote(kid.value))
		}
	}
	return items
}

// flowList reads "[a, 'b']" or a single scalar into its unquoted items.
func flowList(value string) []string {
	inner, ok := strings.CutPrefix(value, "[")
	if ok {
		inner, ok = strings.CutSuffix(inner, "]")
	}
	if !ok {
		return []string{unquote(value)}
	}
	var items []string
	for _, item := range strings.Split(inner, ",") {
		items = append(items, unquote(item))
	}
	return items
}

// keyProblems refuses any key of n outside allowed, and any allowed key
// written twice.
func keyProblems(n *yamlNode, allowed []string, where string) []string {
	var problems []string
	var seen []string
	for _, kid := range n.kids {
		switch {
		case !slices.Contains(allowed, kid.key):
			problems = append(problems, fmt.Sprintf("line %d: %s carries %s", kid.line, where, kid.key))
		case slices.Contains(seen, kid.key):
			problems = append(problems, fmt.Sprintf("line %d: %s carries %s twice", kid.line, where, kid.key))
		}
		seen = append(seen, kid.key)
	}
	return problems
}

// aliasProblems refuses an alias or a merge key anywhere under n: either
// can bring in a key the allowlists above never see.
func aliasProblems(n *yamlNode) []string {
	var problems []string
	for _, kid := range n.kids {
		if kid.key == "<<" || strings.HasPrefix(kid.value, "*") || strings.HasPrefix(kid.key, "*") {
			problems = append(problems, fmt.Sprintf("line %d: an alias or merge key in the %s job", kid.line, ciGateJob))
		}
		problems = append(problems, aliasProblems(kid)...)
	}
	return problems
}

// TestCIRunsTheWholeGate pins what CI runs: TestQualityRunsTheWholeGate holds
// make quality to its targets, and this holds ci.yml to make quality.
func TestCIRunsTheWholeGate(t *testing.T) {
	for _, problem := range ciGateProblems(readLines(t, repoFS(t), ciWorkflowPath)) {
		t.Errorf("%s: %s", ciWorkflowPath, problem)
	}
}

const ciFixture = `name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

defaults:
  run:
    # a comment
    shell: bash

jobs:
  quality:
    name: Quality gate
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - name: Check out the repository
        uses: actions/checkout@0123 # v1
        with:
          persist-credentials: false

      - name: Load pins
        # a comment
        run: |
          printf '%s\n' "${pins}" >>"$GITHUB_ENV"
          if: this is script text, not a key
      - name: Run the quality gate
        run: env -u MAKEFLAGS -u GNUMAKEFLAGS -u MFLAGS -u MAKEFILES make quality GO=go

  other:
    if: false
    continue-on-error: true
    steps:
      - run: make quality-quick
`

func TestCIGateProblems(t *testing.T) {
	if problems := ciGateProblems(strings.Split(ciFixture, "\n")); len(problems) != 0 {
		t.Fatalf("the correct fixture reported %q", problems)
	}
	gateRun := "run: " + ciGateCommand + "\n"
	gateStep := "      - name: Run the quality gate\n        " + gateRun
	jobHead := "    name: Quality gate\n"
	pinsWrite := "          printf '%s\\n' \"${pins}\" >>\"$GITHUB_ENV\"\n"
	cases := map[string]struct{ old, replacement, want string }{
		"the quick gate":                {gateRun + "\n", "run: make quality-quick\n\n", "no step of the quality job runs exactly \"" + ciGateCommand + "\""},
		"the gate in the caller's env":  {gateRun + "\n", "run: make quality GO=go\n\n", "runs exactly"},
		"the gate with MAKEFLAGS kept":  {gateRun + "\n", "run: env -u GNUMAKEFLAGS -u MFLAGS -u MAKEFILES make quality GO=go\n\n", "runs exactly"},
		"the gate with MAKEFILES kept":  {gateRun + "\n", "run: env -u MAKEFLAGS -u GNUMAKEFLAGS -u MFLAGS make quality GO=go\n\n", "runs exactly"},
		"the gate with GO from the env": {gateRun + "\n", "run: env -u MAKEFLAGS -u GNUMAKEFLAGS -u MFLAGS -u MAKEFILES make quality\n\n", "runs exactly"},
		"the gate with a fallback":      {gateRun + "\n", "run: " + ciGateCommand + " || true\n\n", "runs exactly"},
		"the gate in a block":           {gateRun + "\n", "run: |\n          " + ciGateCommand + "\n\n", "runs exactly"},
		"the gate quoted":               {gateRun + "\n", "run: \"" + ciGateCommand + "\"\n\n", "runs exactly"},
		"an if on the step":             {gateStep, gateStep + "        if: false\n", "carries if"},
		"an if before the run":          {gateStep, "      - name: Run the quality gate\n        if: false\n        " + gateRun, "carries if"},
		"continue-on-error on a step":   {gateStep, gateStep + "        continue-on-error: true\n", "carries continue-on-error"},
		"a shell on the step":           {gateStep, gateStep + "        shell: true {0}\n", "carries shell"},
		"env on the step":               {gateStep, gateStep + "        env:\n          MAKEFLAGS: -n\n", "carries env"},
		"a working directory":           {gateStep, gateStep + "        working-directory: docs\n", "carries working-directory"},
		"the run written twice":         {gateStep, gateStep + "        " + gateRun, "carries run twice"},
		"two gate steps":                {gateStep, gateStep + gateStep, "2 steps of the quality job run \"" + ciGateCommand + "\""},
		"the gate step names a flag":    {gateStep, "      - name: Run the quality gate with GOFLAGS\n        " + gateRun, "names GOFLAGS"},
		"an if on the job":              {jobHead, jobHead + "    if: false\n", "the quality job carries if"},
		"continue-on-error on a job":    {jobHead, jobHead + "    continue-on-error: true\n", "the quality job carries continue-on-error"},
		"needs on the job":              {jobHead, jobHead + "    needs: other\n", "the quality job carries needs"},
		"a quoted if on the job":        {jobHead, jobHead + "    'if': false\n", "the quality job carries 'if'"},
		"a merge key on the job":        {jobHead, jobHead + "    <<: *skip\n", "an alias or merge key"},
		"a job default shell":           {jobHead, jobHead + "    defaults:\n      run:\n        shell: true {0}\n", "the quality job carries defaults"},
		"a workflow default shell":      {"    shell: bash\n", "    shell: true {0}\n", `the workflow default run.shell is "true {0}"`},
		"a workflow env":                {"permissions:\n", "env:\n  MAKEFLAGS: -i\npermissions:\n", "the workflow sets env"},
		"no gate job":                   {"  quality:\n", "  quality-renamed:\n", "found 0 quality job(s)"},
		"two gate jobs":                 {"  other:\n", "  quality:\n", "found 2 quality job(s)"},
		"a tab":                         {"    runs-on: ubuntu-24.04\n", "\truns-on: ubuntu-24.04\n", "indented with a tab"},
		"a plain scalar over two lines": {"    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n      more text\n", `"more text" is not a key`},
		"MAKEFLAGS through GITHUB_ENV":  {pinsWrite, pinsWrite + "          echo 'MAKEFLAGS=-k' >>\"$GITHUB_ENV\"\n", "names MAKEFLAGS"},
		"MFLAGS through GITHUB_ENV":     {pinsWrite, pinsWrite + "          echo MFLAGS=-i >>\"$GITHUB_ENV\"\n", "names MFLAGS"},
		"GNUMAKEFLAGS in a printf":      {pinsWrite, pinsWrite + "          printf '%s\\n' GNUMAKEFLAGS=-n >>$GITHUB_ENV\n", "names GNUMAKEFLAGS"},
		"GOFLAGS in an inline step":     {gateStep, "      - run: echo GOFLAGS=-tags=skip >> $GITHUB_ENV\n" + gateStep, "names GOFLAGS"},
		"GOENV in a step's env":         {gateStep, "      - name: x\n        env:\n          NAME: GOENV\n        run: echo \"$NAME=/tmp/env\" >>\"$GITHUB_ENV\"\n" + gateStep, "names GOENV"},
		"a name split in quotes":        {pinsWrite, pinsWrite + "          echo 'MAKE'FLAGS=-n >>\"$GITHUB_ENV\"\n", "other than as the pins and the tools do"},
		"BASH_ENV through GITHUB_ENV":   {pinsWrite, pinsWrite + "          echo \"BASH_ENV=$PWD/x.sh\" >>\"$GITHUB_ENV\"\n", "names BASH_ENV"},
		"MAKEFILES through GITHUB_ENV":  {pinsWrite, pinsWrite + "          echo MAKEFILES=loose.mk >>\"$GITHUB_ENV\"\n", "names MAKEFILES"},
		"a directory on GITHUB_PATH":    {pinsWrite, pinsWrite + "          echo \"$PWD/fakebin\" >>\"$GITHUB_PATH\"\n", "other than as the pins and the tools do"},
		"a branch excluded":             {"branches: [main]", "branches: [main, '!main']", "excludes a branch"},
		"no pull_request trigger":       {"  pull_request:\n", "", "does not run on pull_request"},
		"a pull_request filter":         {"  pull_request:\n", "  pull_request:\n    paths: [docs/**]\n", "the pull_request trigger carries paths"},
		"pull_request types":            {"  pull_request:\n", "  pull_request: {types: [closed]}\n", "the pull_request trigger is not bare"},
		"no push trigger":               {"  push:\n    branches: [main]\n", "", "does not run on push"},
		"push to another branch":        {"branches: [main]", "branches: [release]", "push trigger runs on no main branch"},
		"a push paths filter":           {"    branches: [main]\n", "    branches: [main]\n    paths-ignore: ['**.md']\n", "the push trigger carries paths-ignore"},
		"a single trigger":              {"on:\n  push:\n    branches: [main]\n  pull_request:\n", "on: push\n", "does not run on pull_request"},
		"no on":                         {"on:\n  push:\n    branches: [main]\n  pull_request:\n", "", "found 0 on key(s)"},
	}
	for name, c := range cases {
		text := replaceOnce(t, ciFixture, c.old, c.replacement)
		problems := ciGateProblems(strings.Split(text, "\n"))
		if !slices.ContainsFunc(problems, func(s string) bool { return strings.Contains(s, c.want) }) {
			t.Errorf("%s: want a problem containing %q, got %q", name, c.want, problems)
		}
	}
	trigger := "on:\n  push:\n    branches: [main]\n  pull_request:\n"
	for name, replacement := range map[string]string{
		"every push and pull request": "on: [push, pull_request]\n",
		"branches as a block list":    "on:\n  push:\n    branches:\n      - release\n      - 'main'\n  pull_request:\n  workflow_dispatch:\n",
	} {
		if problems := ciGateProblems(strings.Split(replaceOnce(t, ciFixture, trigger, replacement), "\n")); len(problems) != 0 {
			t.Errorf("%s: reported %q", name, problems)
		}
	}
}
