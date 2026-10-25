package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// cleanMakeEnv is this process's environment without the variables make, go
// and the recipes' shell take flags, tools, makefiles or startup files from.
func cleanMakeEnv() []string {
	var base []string
	for _, kv := range os.Environ() {
		switch name, _, _ := strings.Cut(kv, "="); {
		case slices.Contains([]string{"MAKEFLAGS", "MFLAGS", "MAKELEVEL", "GNUMAKEFLAGS", "MAKEFILES", "MAKECMDGOALS", ".DEFAULT_GOAL",
			"MAKE", "GO", "GOFLAGS", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE"}, name), strings.HasPrefix(name, "BASH_FUNC_"):
		default:
			base = append(base, kv)
		}
	}
	return base
}

// TestTheGateRefusesALoosenedMake: make quality asked for a dry run or a
// question, on the command line or through the environment as an earlier CI
// step could set it, and make quality under GOFLAGS, another makefile, a shell
// startup file, a stand-in for make or go, a variable set on the command line,
// or a fuzz time or range from the environment, each refuse before any recipe,
// naming why. Every form here runs no
// recipe even without the guard, so the test cannot start the gate.
func TestTheGateRefusesALoosenedMake(t *testing.T) {
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Fatalf("the gate needs make: %v", err)
	}
	root := repoRoot(t)
	empty := t.TempDir() + "/empty.mk"
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	base := cleanMakeEnv()
	for _, c := range []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{"a dry run on the command line", []string{"-n", "quality"}, nil, "MAKEFLAGS asks for a dry run"},
		{"a question on the command line", []string{"-q", "quality"}, nil, "MAKEFLAGS asks for a dry run"},
		{"a dry run through the environment", []string{"quality"}, []string{"MAKEFLAGS=n"}, "MAKEFLAGS asks for a dry run"},
		{"GOFLAGS through the environment", []string{"-n", "quality"}, []string{"GOFLAGS=-tags=gate_off"}, "GOFLAGS is set"},
		{"a shell startup file", []string{"-n", "quality"}, []string{"BASH_ENV=" + empty}, shellRefused},
		{"shell options", []string{"-n", "quality"}, []string{"SHELLOPTS=noexec"}, shellRefused},
		{"bash options", []string{"-n", "quality"}, []string{"BASHOPTS=expand_aliases"}, shellRefused},
		{"an exported function", []string{"-n", "quality"}, []string{"BASH_FUNC_go%%=() {  :; }"}, shellRefused},
		{"shell options make expands to nothing", []string{"-n", "quality"}, []string{"SHELLOPTS=$(if ,:noexec:)"}, shellRefused},
		{"a startup file make expands to nothing", []string{"-n", "quality"}, []string{"BASH_ENV=${X:-" + empty + "}"}, shellRefused},
		{"a cd path", []string{"-n", "quality"}, []string{"CDPATH=" + filepath.Dir(empty)}, shellRefused},
		{"a glob filter", []string{"-n", "quality"}, []string{"GLOBIGNORE=*.go"}, shellRefused},
		{"GOFLAGS make expands to nothing", []string{"-n", "quality"}, []string{"GOFLAGS=$(if ,-tags=gate_off)"}, "GOFLAGS is set"},
		{"another makefile make expands to nothing", []string{"-n", "quality"}, []string{"MAKEFILES=$(if ," + empty + ")"}, makefilesRefused},
		{"another makefile", []string{"-n", "quality"}, []string{"MAKEFILES=" + empty}, makefilesRefused},
		{"another makefile for another goal", []string{"-n", "quality-quick"}, []string{"MAKEFILES=" + empty}, makefilesRefused},
		{"another go through the environment", []string{"-n", "quality"}, []string{"GO=true"}, "make quality runs go itself; GO is true"},
		{"another go on the command line", []string{"-n", "quality", "GO=true"}, nil, "make quality runs go itself; GO is true"},
		{"another make through the environment", []string{"-n", "quality"}, []string{"MAKE=true"}, "MAKE comes from the environment"},
		{"a variable on the command line", []string{"-n", "quality", "PKGS=./cmd/..."}, nil, "sets no variable but GO=go: PKGS=./cmd/..."},
		{"a fuzz time through the environment", []string{"-n", "quality"}, []string{"FUZZTIME=1ns"}, "FUZZTIME comes from the environment"},
		{"a range through the environment", []string{"-n", "quality"}, []string{"RANGE=HEAD..HEAD"}, "RANGE from the environment"},
		{"go named on the command line passes to the next check", []string{"-n", "quality", "GO=go"}, nil, "MAKEFLAGS asks for a dry run"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(makeBin, append([]string{"-C", root}, c.args...)...) //nolint:gosec // G204: make, at the repository root, with fixed arguments
			cmd.Env = append(append([]string(nil), base...), c.env...)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), c.want) {
				t.Errorf("make %s with %v = %v, want a refusal saying %q:\n%.600s", strings.Join(c.args, " "), c.env, err, c.want, out)
			}
		})
	}
	cmd := exec.Command(makeBin, "-C", root, "-n", "quality-quick") //nolint:gosec // G204: make, at the repository root, with fixed arguments
	cmd.Env = base
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("make -n quality-quick, which the guard leaves alone, = %v:\n%.600s", err, out)
	}
}

// shellRefused is the refusal of what the recipes' bash reads at startup.
const shellRefused = "BASH_ENV, ENV, SHELLOPTS, BASHOPTS, CDPATH, GLOBIGNORE or an exported function is set"

// defaultGoalRefused is the refusal of a .DEFAULT_GOAL this Makefile did not set.
const defaultGoalRefused = ".DEFAULT_GOAL is this Makefile's"

// makefilesRefused is the refusal of a makefile named in MAKEFILES.
const makefilesRefused = "this Makefile is read alone; MAKEFILES names"

// goalsRefused is the refusal of a MAKECMDGOALS make did not set itself.
const goalsRefused = "MAKECMDGOALS is make's own"

// The line the stand-in file lists print before they fail, so a run that
// shows it reached a check.
const standInRefusal = "stand-in refuses to list"

// standInTree is a directory holding a copy of the repository's Makefile and
// file lists that fail at once, so every check make quality starts there fails
// in a moment and none runs the real gate.
func standInTree(t *testing.T) string {
	t.Helper()
	makefile, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "scripts", "lib"), 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"Makefile":                  string(makefile),
		"scripts/lib/repo-files.sh": "repo_files() { echo \"repo_files: " + standInRefusal + "\" >&2; return 1; }\n",
		"scripts/lib/go-modules.sh": "go_modules() { echo \"go_modules: " + standInRefusal + "\" >&2; return 1; }\n",
		"empty.mk":                  "",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// shellOffBelowTheTop is an eval that leaves the first make's shell alone and
// gives every make it starts one that runs nothing and succeeds.
const shellOffBelowTheTop = `override SHELL := $(if $(filter 0,$(MAKELEVEL)),/usr/bin/env bash,/bin/true)`

// makeTakes reports whether make accepts args as options; make 3.81 has no
// --eval and no -E, and before 4.4 no -E.
func makeTakes(t *testing.T, makeBin string, args ...string) bool {
	t.Helper()
	cmd := exec.Command(makeBin, append(args, "--version")...) //nolint:gosec // G204: make with fixed arguments
	// Probe make itself, away from this Makefile's refusal of eval and the
	// flags inherited from the gate that started this test.
	cmd.Dir = t.TempDir()
	cmd.Env = cleanMakeEnv()
	return cmd.Run() == nil
}

// refusedIf is refusal when this make reaches the guard that says it, and the
// stand-in's own refusal when it runs the goal instead.
func refusedIf(reached bool, refusal string) string {
	if reached {
		return refusal
	}
	return standInRefusal
}

// makeReadsAssignment reports whether make takes a variable assignment from
// flags: make 3.81 does not read GNUMAKEFLAGS at all, while 4.3 takes an
// assignment there though it ignores -f.
func makeReadsAssignment(t *testing.T, makeBin, flags string) bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("probe:\n\t@printf '%s\\n' '$(PROBE)'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(makeBin, "-C", dir, "--no-print-directory", "probe") //nolint:gosec // G204: make with fixed arguments in a probe directory
	cmd.Env = append(cleanMakeEnv(), flags+"=PROBE=read")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe an assignment through %s: %v:\n%s", flags, err, out)
	}
	switch strings.TrimSpace(string(out)) {
	case "":
		return false
	case "read":
		return true
	default:
		t.Fatalf("probe an assignment through %s printed %q", flags, out)
		return false
	}
}

// makeReadsExtraFile measures the makefile option separately from eval:
// make 4.3 ignores -f in these environment variables, while 4.4 reads it.
func makeReadsExtraFile(t *testing.T, makeBin, flags string) bool {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Makefile": "probe:\n\t@printf '%s\\n' '$(words $(MAKEFILE_LIST))'\n",
		"extra.mk": "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(makeBin, "-C", dir, "--no-print-directory", "probe") //nolint:gosec // G204: make with fixed arguments in a probe directory
	cmd.Env = append(cleanMakeEnv(), flags+"=-f Makefile -f extra.mk")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe makefiles through %s: %v:\n%s", flags, err, out)
	}
	switch strings.TrimSpace(string(out)) {
	case "1":
		return false
	case "2":
		return true
	default:
		t.Fatalf("probe makefiles through %s returned an unknown count: %q", flags, out)
		return false
	}
}

// TestTheGateRunsTheChecksMakeWasToldToSkip: make told that every check of
// quality is already up to date, on the command line or through the
// environment, still runs them, so a tree where every check fails at once
// never prints the gate's pass line. Environment overrides, an eval, and a
// makefile read before or after this one are refused, and so are a
// MAKECMDGOALS make did not set itself and a .DEFAULT_GOAL the Makefile did
// not, for any goal. It runs in a stand-in
// tree, so a broken gate cannot start the real checks. A make with no eval
// option refuses the eval itself, and the case asserts only that.
func TestTheGateRunsTheChecksMakeWasToldToSkip(t *testing.T) {
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Fatalf("the gate needs make: %v", err)
	}
	dir := standInTree(t)
	var old, oldLong []string
	for _, target := range gateTargets {
		old = append(old, "-o", target)
		oldLong = append(oldLong, "--old-file="+target)
	}
	evalRefused, shortRefused := "", ""
	if makeTakes(t, makeBin, "--eval=X:=1") {
		evalRefused = "this Makefile takes no --eval or -E"
	}
	if makeTakes(t, makeBin, "-E", "X:=1") {
		shortRefused = "this Makefile takes no --eval or -E"
	}
	if evalRefused == "" {
		t.Logf("%s takes no --eval; the eval cases assert only that make refuses them", makeBin)
	}
	const oneMakefile = "make quality reads one makefile, this one"
	laterThroughFlags := refusedIf(makeReadsExtraFile(t, makeBin, "MAKEFLAGS"), oneMakefile)
	laterThroughGNUFlags := refusedIf(makeReadsExtraFile(t, makeBin, "GNUMAKEFLAGS"), oneMakefile)
	goalThroughGNUFlags := refusedIf(makeReadsAssignment(t, makeBin, "GNUMAKEFLAGS"), defaultGoalRefused)
	escaped := strings.ReplaceAll(shellOffBelowTheTop, " ", `\ `)
	base := cleanMakeEnv()
	for _, c := range []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{"nothing skipped", []string{"quality"}, nil, standInRefusal},
		{"every check skipped with -o", append(append([]string(nil), old...), "quality"), nil, standInRefusal},
		{"every check skipped with --old-file", append(append([]string(nil), oldLong...), "quality"), nil, standInRefusal},
		{"every check skipped through MAKEFLAGS", []string{"quality"}, []string{"MAKEFLAGS=" + strings.Join(old, " ")}, standInRefusal},
		{"every check skipped through GNUMAKEFLAGS", []string{"quality"}, []string{"GNUMAKEFLAGS=" + strings.Join(old, " ")}, standInRefusal},
		{"the environment over the Makefile", []string{"-e", "quality"}, []string{"PKGS=./cmd/..."}, "MAKEFLAGS asks for a dry run, a touch, a question, ignored errors or the environment"},
		{"an eval on the command line", []string{"--eval=" + shellOffBelowTheTop, "quality"}, nil, evalRefused},
		{"an eval in short form", []string{"-E", shellOffBelowTheTop, "quality"}, nil, shortRefused},
		{"an eval through MAKEFLAGS", []string{"quality"}, []string{"MAKEFLAGS=--eval=" + escaped}, evalRefused},
		{"an eval through GNUMAKEFLAGS", []string{"quality"}, []string{"GNUMAKEFLAGS=--eval=" + escaped}, evalRefused},
		{"an eval that renames the goal", []string{"--eval=" + shellOffBelowTheTop, "--eval=override MAKECMDGOALS :=", "quality"}, nil, evalRefused},
		{"an eval that names the default goal", []string{"--eval=" + shellOffBelowTheTop, "--eval=.DEFAULT_GOAL := quality"}, nil, evalRefused},
		{"a makefile read before this one", []string{"-f", "empty.mk", "-f", "Makefile", "quality"}, nil, "make quality reads one makefile, this one"},
		{"a makefile read after this one", []string{"-f", "Makefile", "-f", "empty.mk", "quality"}, nil, "make quality reads one makefile, this one"},
		{"an additional makefile through MAKEFLAGS", []string{"quality"}, []string{"MAKEFLAGS=-f Makefile -f empty.mk"}, laterThroughFlags},
		{"an additional makefile through GNUMAKEFLAGS", []string{"quality"}, []string{"GNUMAKEFLAGS=-f Makefile -f empty.mk"}, laterThroughGNUFlags},
		{"the goals cleared and make replaced", []string{"quality", "MAKECMDGOALS=", "MAKE=/usr/bin/true"}, nil, goalsRefused},
		{"the goals cleared", []string{"quality", "MAKECMDGOALS="}, nil, goalsRefused},
		{"the goals restated", []string{"quality", "MAKECMDGOALS=quality"}, nil, goalsRefused},
		{"the goals through the environment", []string{"quality"}, []string{"MAKECMDGOALS=lint"}, goalsRefused},
		{"the goals cleared for another goal", []string{"-n", "quality-quick", "MAKECMDGOALS="}, nil, goalsRefused},
		{"the default goal named and make replaced", []string{".DEFAULT_GOAL=quality", "MAKE=/usr/bin/true"}, nil, defaultGoalRefused},
		{"the default goal through MAKEFLAGS", nil, []string{"MAKEFLAGS= -- .DEFAULT_GOAL=quality MAKE=/usr/bin/true"}, defaultGoalRefused},
		{"the default goal through GNUMAKEFLAGS", nil, []string{"GNUMAKEFLAGS=.DEFAULT_GOAL=quality MAKE=/usr/bin/true"}, goalThroughGNUFlags},
		{"the default goal from the environment", []string{"-e"}, []string{".DEFAULT_GOAL=quality", "MAKE=/usr/bin/true"}, defaultGoalRefused},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(makeBin, append([]string{"-C", dir}, c.args...)...) //nolint:gosec // G204: make, in a stand-in tree, with fixed arguments
			cmd.Env = append(append([]string(nil), base...), c.env...)
			out, err := cmd.CombinedOutput()
			if err == nil || strings.Contains(string(out), "quality: green") || !strings.Contains(string(out), c.want) {
				t.Errorf("make %s with %v = %v, want a failure saying %q and no pass line:\n%.800s", strings.Join(c.args, " "), c.env, err, c.want, out)
			}
		})
	}
}
