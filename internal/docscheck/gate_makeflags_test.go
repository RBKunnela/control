package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cleanMakeEnv is this process's environment without the variables make, go
// and the recipes' shell take flags, tools, makefiles or startup files from.
func cleanMakeEnv() []string {
	var base []string
	for _, kv := range os.Environ() {
		switch name, _, _ := strings.Cut(kv, "="); name {
		case "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "GNUMAKEFLAGS", "MAKEFILES", "MAKE", "GO", "GOFLAGS", "BASH_ENV", "ENV":
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
		{"a shell startup file", []string{"-n", "quality"}, []string{"BASH_ENV=" + empty}, "BASH_ENV or ENV is set"},
		{"another makefile", []string{"-n", "quality"}, []string{"MAKEFILES=" + empty}, "BASH_ENV or ENV is set"},
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
func makeTakes(makeBin string, args ...string) bool {
	return exec.Command(makeBin, append(args, "--version")...).Run() == nil //nolint:gosec // G204: make with fixed arguments
}

// TestTheGateRunsTheChecksMakeWasToldToSkip: make told that every check of
// quality is already up to date, on the command line or through the
// environment, still runs them, so a tree where every check fails at once
// never prints the gate's pass line. Environment overrides, an eval, and a
// makefile read before or after this one are refused. It runs in a stand-in
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
	if makeTakes(makeBin, "--eval=X:=1") {
		evalRefused = "this Makefile takes no --eval or -E"
	}
	if makeTakes(makeBin, "-E", "X:=1") {
		shortRefused = "this Makefile takes no --eval or -E"
	}
	// make 3.81 takes no makefile from MAKEFLAGS, so this one runs the checks.
	laterThroughFlags := standInRefusal
	if evalRefused == "" {
		t.Logf("%s takes no --eval; the eval cases assert only that make refuses them", makeBin)
	} else {
		laterThroughFlags = "make quality reads one makefile, this one"
	}
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
		{"a makefile read after this one through MAKEFLAGS", []string{"quality"}, []string{"MAKEFLAGS=-f Makefile -f empty.mk"}, laterThroughFlags},
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
