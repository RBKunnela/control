package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/supervise"
)

// judgedLayout is a signed layout holding alice's run of t1/p1, a run signed
// by a key the roster does not name, and alice's run of another layout
// copied into it, with the flags that judge it for a plane of t1/p1.
type judgedLayout struct {
	s                    signedRuns
	taken, alien, copied string
	read                 runsReadFlags
}

func newJudgedLayout(t *testing.T) judgedLayout {
	t.Helper()
	l := judgedLayout{s: newSignedRuns(t)}
	l.taken = openRunOK(t, l.s, tenantP1)
	l.alien = openSignedBy(t, l.s.dir, seeded(0x6d))
	other := newSignedRuns(t)
	l.copied = openRunOK(t, other, tenantP1)
	copyFile(t, filepath.Join(other.dir, runs.RecordsDir, l.copied+".run.json"),
		filepath.Join(l.s.dir, runs.RecordsDir, l.copied+".run.json"))
	l.read = runsReadFlags{roster: valueList{l.s.roster}, rootKey: valueList{l.s.root},
		tenant: valueList{"t1"}, project: valueList{"p1"}}
	return l
}

// unjudged are flag sets a signed layout is refused under, each lacking or
// repeating one of the four.
func (l judgedLayout) unjudged() map[string]runsReadFlags {
	noProject, twoRosters := l.read, l.read
	noProject.project = nil
	twoRosters.roster = valueList{l.s.roster, l.s.roster}
	return map[string]runsReadFlags{"none": {}, "no --project": noProject, "--roster twice": twoRosters}
}

// TestSuperviseTakesOnlyTheRunsTheRosterVouchesFor: supervise reads alice's
// run of a signed layout under the four flags, refuses a run signed by a key
// the roster does not name and one copied from another layout, naming the
// record, and refuses the layout under fewer flags, naming them.
func TestSuperviseTakesOnlyTheRunsTheRosterVouchesFor(t *testing.T) {
	l := newJudgedLayout(t)
	if run, _, err := readRun(l.s.dir, l.taken, supervise.ChildrenUnstated, l.read); err != nil || run.ID != l.taken {
		t.Fatalf("readRun of alice's run = %+v, %v", run, err)
	}
	for id, want := range map[string]error{l.alien: runs.ErrUnauthenticated, l.copied: runs.ErrOtherDirectory} {
		if _, _, err := readRun(l.s.dir, id, supervise.ChildrenUnstated, l.read); !refusedWith(err, want, id) {
			t.Errorf("readRun of %s = %v, want %v naming it", id, err, want)
		}
	}
	for name, f := range l.unjudged() {
		if _, _, err := readRun(l.s.dir, l.taken, supervise.ChildrenUnstated, f); !refusedWith(err, runs.ErrUnjudged, runsReadHint) {
			t.Errorf("%s: readRun = %v, want the four flags named", name, err)
		}
	}
	tr := newSupTree(t)
	if _, _, err := readRun(tr.runs, tr.run, supervise.ChildrenUnstated, l.read); !errors.Is(err, errUnsignedJudged) {
		t.Errorf("readRun of an unsigned directory under the flags = %v, want them refused", err)
	}
	code, stdout, stderr := invoke(t, "supervise", "--procedure", tr.procedure, "--runs", l.s.dir, "--run", l.taken,
		"--findings", tr.findings)
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, runsReadHint) {
		t.Errorf("supervise of a signed layout with no judge answered %d: %q %q", code, stdout, stderr)
	}
}

// TestReactLooksUpOnlyTheRunsTheRosterVouchesFor: react opens a signed
// layout under the four flags and stops at a finding of a run the roster
// does not vouch for, naming it, and refuses the layout under fewer flags,
// naming them.
func TestReactLooksUpOnlyTheRunsTheRosterVouchesFor(t *testing.T) {
	l := newJudgedLayout(t)
	tr := newStopTree(t)
	logs := 0
	pass := func(read runsReadFlags, run string) (int, string, string) {
		logs++
		a := tr.reactArgs(tr.findingsDir(t, fmt.Sprintf("log-%d", logs), finding(1, run, denial, confirmed)))
		a.runs, a.read = l.s.dir, read
		var out, errOut strings.Builder
		code := react(t.Context(), a, clockAt(time.Now()), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, stdout, stderr := pass(l.read, l.taken); code != exitOK || stderr != "" ||
		!strings.Contains(stdout, "not stopping 1, not written 0") {
		t.Fatalf("react over alice's run answered %d: %q %q", code, stdout, stderr)
	}
	for id, want := range map[string]string{l.alien: runs.ErrUnauthenticated.Error(), l.copied: runs.ErrOtherDirectory.Error()} {
		if code, _, stderr := pass(l.read, id); !failedWith(code, stderr, "run "+id, want) {
			t.Errorf("react over %s answered %d: %q; want it refused with %q", id, code, stderr, want)
		}
	}
	for name, f := range l.unjudged() {
		if code, _, stderr := pass(f, l.taken); !failedWith(code, stderr, runsReadHint) {
			t.Errorf("%s: react answered %d: %q; want the four flags named", name, code, stderr)
		}
	}
	a := tr.reactArgs(tr.findingsDir(t, "log-unsigned", finding(1, tr.open, denial, confirmed)))
	a.read = l.read
	var out, errOut strings.Builder
	if code := react(t.Context(), a, clockAt(time.Now()), &out, &errOut); !failedWith(code, errOut.String(), errUnsignedJudged.Error()) {
		t.Errorf("react over an unsigned directory under the flags answered %d: %q", code, errOut.String())
	}
}

// refusedWith reports whether err is want and names text.
func refusedWith(err, want error, text string) bool {
	return errors.Is(err, want) && strings.Contains(err.Error(), text)
}

// failedWith reports whether a command exited 1 with every one of texts on
// stderr.
func failedWith(code int, stderr string, texts ...string) bool {
	for _, text := range texts {
		if !strings.Contains(stderr, text) {
			return false
		}
	}
	return code == exitFail
}
