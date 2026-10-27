package docscheck

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The targets `make quality` has to run. Adding a target to quality needs no
// change here; dropping one fails this test, so weakening the gate takes an
// edit to the Makefile and one to this list, in the same review. This holds
// the target list and the shape of quality's recipe only: a check's recipe
// edited to ignore its command's exit, or to print its pass line
// unconditionally, passes here, which is what folding each pass line into its
// command (`cmd && echo ...`) in the Makefile is for.
var gateTargets = []string{
	"fmt-check", "vet", "lint", "test", "test-race", "fuzz-list", "security",
	"scan-repo-files-probe", "proto-check", "tidy-check", "check-imports",
	"check-imports-probe", "check-modules-probe", "check-brand", "check-sizes",
	"check-actions", "check-shell", "scan-binaries-probe", "pre-push-probe",
	"check-python", "check-python-probe",
}

func TestQualityRunsTheWholeGate(t *testing.T) {
	targets, err := qualityTargets(readLines(t, repoFS(t), "Makefile"))
	if err != nil {
		t.Fatalf("Makefile: %v", err)
	}
	for _, target := range gateTargets {
		if !slices.Contains(targets, target) {
			t.Errorf("make quality no longer runs %s", target)
		}
	}
}

// The command quality's recipe counts the makefiles make read with, and the
// one it starts the checks with, before their names.
const (
	qualityCount   = `@[ $(words $(MAKEFILE_LIST)) = 1 ] || { echo "make quality reads one makefile, this one; $(words $(MAKEFILE_LIST)) were read" >&2; exit 1; }`
	qualitySubMake = `@MAKEFLAGS= GNUMAKEFLAGS= MFLAGS= $(MAKE) --no-print-directory -f "$$REPO_ROOT/$(notdir $(firstword $(MAKEFILE_LIST)))"`
)

// qualityTargets returns the checks the quality rule runs. The rule has no
// prerequisite, since make can be told to skip one; its recipe is exactly the
// count of makefiles read, a second make with no flags of the first naming
// each check as a plain word, then the pass line. Anything else is an error: a
// flag or a variable among the names could change which checks run or whether
// their failure counts.
func qualityTargets(lines []string) ([]string, error) {
	recipe, err := qualityRecipe(lines)
	if err != nil {
		return nil, err
	}
	if len(recipe) != 3 || recipe[0] != qualityCount || recipe[2] != `@echo "quality: green"` {
		return nil, fmt.Errorf("quality's recipe is %q, want the makefile count, a second make and then the pass line", recipe)
	}
	names, ok := strings.CutPrefix(recipe[1], qualitySubMake+" ")
	if !ok {
		return nil, fmt.Errorf("quality's recipe starts %q, want %q", recipe[0], qualitySubMake)
	}
	targets := strings.Fields(names)
	for _, target := range targets {
		if strings.Trim(target, "abcdefghijklmnopqrstuvwxyz-") != "" || strings.HasPrefix(target, "-") {
			return nil, fmt.Errorf("quality's second make is handed %q, which is not a check's name", target)
		}
	}
	return targets, nil
}

// qualityRecipe returns the commands of the one quality rule, each with its
// backslash continuations joined, and refuses a prerequisite.
func qualityRecipe(lines []string) ([]string, error) {
	rules := 0
	var recipe []string
	for i := 0; i < len(lines); i++ {
		rest, ok := strings.CutPrefix(lines[i], "quality:")
		if !ok {
			continue
		}
		rules++
		if strings.TrimSpace(rest) != "" {
			return nil, fmt.Errorf("line %d: quality has prerequisites %q, which make can be told to skip", i+1, strings.TrimSpace(rest))
		}
		for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "\t") {
			i++
			command := strings.TrimPrefix(lines[i], "\t")
			for strings.HasSuffix(command, `\`) && i+1 < len(lines) {
				i++
				command = strings.TrimSuffix(command, `\`) + " " + strings.TrimSpace(lines[i])
			}
			recipe = append(recipe, command)
		}
	}
	if rules != 1 {
		return nil, fmt.Errorf("found %d rule(s) for quality, want 1", rules)
	}
	return recipe, nil
}

func TestQualityTargets(t *testing.T) {
	good := "quality-quick: a\nquality:\n\t" + qualityCount + "\n\t" + qualitySubMake + " \\\n\t  a b \\\n\t  c-d\n\t@echo \"quality: green\"\nother: e\n"
	got, err := qualityTargets(strings.Split(good, "\n"))
	if err != nil || !slices.Equal(got, []string{"a", "b", "c-d"}) {
		t.Fatalf("qualityTargets = %q, %v; want [a b c-d]", got, err)
	}
	for name, c := range map[string]struct{ old, replacement, want string }{
		"no rule":                {"quality:\n", "qualities:\n", "found 0 rule(s)"},
		"two rules":              {"other: e\n", "quality:\n", "found 2 rule(s)"},
		"a prerequisite":         {"quality:\n", "quality: a\n", "quality has prerequisites"},
		"no pass line":           {"\t@echo \"quality: green\"\n", "", "want the makefile count, a second make and then the pass line"},
		"a step after the pass":  {"\nother", "\n\t@true\nother", "want the makefile count, a second make and then the pass line"},
		"no makefile count":      {"\t" + qualityCount + "\n", "", "want the makefile count, a second make and then the pass line"},
		"checks run in place":    {qualitySubMake, "@true", "quality's recipe starts"},
		"the first make's flags": {qualitySubMake, strings.Replace(qualitySubMake, "MAKEFLAGS= ", "", 1), "quality's recipe starts"},
		"a flag to the make":     {"a b", "-i a b", "is handed \"-i\""},
		"a variable as a name":   {"a b", "$(CHECKS) b", "is handed \"$(CHECKS)\""},
		"a failure ignored":      {"c-d\n", "c-d || true\n", "is handed \"||\""},
	} {
		lines := strings.Split(replaceOnce(t, good, c.old, c.replacement), "\n")
		if _, err := qualityTargets(lines); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: qualityTargets error = %v, want one containing %q", name, err, c.want)
		}
	}
}
