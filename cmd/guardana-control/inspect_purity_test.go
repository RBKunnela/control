//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/observelog"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// inspection is one way the purity test reaches a command the table
// classifies inspects: its arguments over the damaged state, and its status
// and what its output has to hold with and without the writers at work, so a
// run that refused before it read anything never counts as one that changed
// nothing.
type inspection struct {
	args               []string
	says, free, held   []string
	freeExit, heldExit int
}

// damagedState is what the operator commands read, as a crash and the
// passing of time leave it: an approvals directory holding a record in every
// state, one of them past its expiry; a pause file with an entry; a runs
// directory with open, closed, child and foreign runs; a stop list and a
// findings log and two observation logs, each ending in half a line; and the
// policy and procedure files the lint and test commands read.
type damagedState struct {
	roots                         []string
	approvals, pause, runs, stops string
	findings, observe, coverage   string
	route, routePub               string
	policy, procedure             string
	coverageArgs                  []string
	stoppedRun                    string
}

func newDamagedState(t *testing.T) damagedState {
	t.Helper()
	approvalsDir := everyStateClosed(t)
	stopTr := newStopTree(t)
	appendLog(t, stopTr.findings, finding(1, stopTr.open, denial, confirmed))
	obs := newObserveTree(t)
	if code, out, stderr := invoke(t, obs.importArgs()...); code != exitOK {
		t.Fatalf("observe import: exit %d, %q %q", code, out, stderr)
	}
	cov := newCoverageTree(t, "")
	cov.importFresh(t)
	st := damagedState{
		approvals: approvalsDir, pause: initialized(t), runs: stopTr.runs,
		stops:    stopTr.listUnder(t, "list", stopTr.parsed, stopTr.open),
		findings: stopTr.findings, observe: obs.log, coverage: cov.log,
		route: stopTr.route, routePub: stopTr.routePub, stoppedRun: stopTr.open,
		coverageArgs: cov.args(),
	}
	if code, _, stderr := invoke(t, "pause", "add", "--provider", "orders", "--reason", "orders misbehave", st.pause); code != exitOK {
		t.Fatalf("pause add: exit %d, %q", code, stderr)
	}
	copies := t.TempDir()
	st.policy, st.procedure = filepath.Join(copies, "policy"), filepath.Join(copies, "procedure")
	copyTree(t, filepath.Join("..", "..", "testdata", "policy"), st.policy)
	copyTree(t, filepath.Join("..", "..", "testdata", "procedure"), st.procedure)
	copyTree(t, casesDir, filepath.Join(copies, "cases"))
	tearHalfALine(t, filepath.Join(st.stops, stoplist.FileName))
	tearHalfALine(t, filepath.Join(st.findings, findinglog.FileName))
	tearHalfALine(t, filepath.Join(st.observe, observelog.FileName))
	tearHalfALine(t, filepath.Join(st.coverage, observelog.FileName))
	st.roots = []string{filepath.Dir(approvalsDir), filepath.Dir(filepath.Dir(st.pause)), stopTr.dir,
		filepath.Dir(obs.log), cov.dir, copies}
	return st
}

// everyStateClosed is everyState's directory with the plane that made it
// closed, so the lock is free until a test takes it.
func everyStateClosed(t *testing.T) string {
	t.Helper()
	dir, plane := everyState(t)
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// tearHalfALine appends the first half of the file's last line to it, which
// is what a writer stopped part way through an append leaves.
func tearHalfALine(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(strings.TrimSuffix(string(raw), "\n"), "\n")
	last := lines[len(lines)-1]
	appendBytes(t, path, last[:len(last)/2])
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a fixture under testdata
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600) //nolint:gosec // G703: a path under the test's temp dir
	})
	if err != nil {
		t.Fatal(err)
	}
}

// holdAsWriters opens what holds a lock on this state while it works: the
// approvals plane on its directory, and the writers of the findings log and
// of both observation logs, each repairing what its open repairs, and then
// leaves half a line in each log again, as a writer between two records.
func (st damagedState) holdAsWriters(t *testing.T) {
	t.Helper()
	plane, err := approvals.OpenPlane(st.approvals)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plane.Close() })
	findings, err := findinglog.Open(st.findings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = findings.Close() })
	tearHalfALine(t, filepath.Join(st.findings, findinglog.FileName))
	for _, dir := range []string{st.observe, st.coverage} {
		log, err := observelog.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = log.Close() })
		tearHalfALine(t, filepath.Join(dir, observelog.FileName))
	}
}

// inspections is every inspecting command's run over the damaged state.
func (st damagedState) inspections() map[string][]inspection {
	policyDir := filepath.Dir(st.policy)
	observed := []string{`"type":"observation"`}
	return map[string][]inspection{
		"policy lint": {{args: []string{"policy", "lint", filepath.Join(st.policy, "documents", "example.json")}}},
		"policy test": {{args: []string{"policy", "test", filepath.Join(st.policy, "fixtures")},
			says: []string{"ok   allow.json: ALLOW Execute"}}},
		"policy explain": {{args: []string{"policy", "explain", filepath.Join(policyDir, "cases", "approve-refund.json")},
			says: []string{"verdict: REQUIRE_APPROVAL"}}},
		"approvals list": {{args: []string{"approvals", "list", st.approvals},
			says: []string{"approval " + waitingID + "\n", "approval " + staleID + "\n"}}},
		"pause list": {{args: []string{"pause", "list", st.pause}, says: []string{` provider orders `, `"orders misbehave"`}}},
		"runs list":  {{args: []string{"runs", "list", st.runs}, says: []string{st.stoppedRun + " open root "}}},
		"observe export": {{args: []string{"observe", "export", filepath.Join(st.observe, observelog.FileName)},
			says: observed, free: []string{`"reason":"partial_tail"`}, held: []string{`"writer_held":true`},
			freeExit: exitFail}},
		"coverage": {{args: st.coverageArgs, says: []string{"orders.read-file observed"}}},
		"procedure lint": {{args: []string{"procedure", "lint", filepath.Join(st.procedure, "refund-0.2.json")},
			says: []string{"procedure_id: refund\n"}}},
		"procedure test": {{args: []string{"procedure", "test", filepath.Join(st.procedure, "cases-0.2.json")},
			says: []string{"3 cases, 3 passed, 0 failed"}}},
		"findings export": {{args: []string{"findings", "export", "--findings", st.findings},
			says: []string{`"type":"finding_record"`}, free: []string{`"reason":"partial_tail"`}, held: []string{`"writer_held":true`},
			freeExit: exitFail}},
		"stops list": {{args: []string{"stops", "list", "--route", st.route, "--public-key", st.routePub, st.stops},
			says: []string{"run " + st.stoppedRun + " finding "}}},
	}
}

// TestEveryCommandIsClassified: a command left at the zero effect is
// neither held to changing nothing nor known to write, so it is refused, and
// every command classified inspects has its run in the purity test.
func TestEveryCommandIsClassified(t *testing.T) {
	cases := damagedState{}.inspections()
	for _, c := range commands {
		switch c.effect {
		case inspects:
			if len(cases[c.words()]) == 0 {
				t.Errorf("%s inspects and the purity test does not run it", c.words())
			}
			delete(cases, c.words())
		case writes:
		default:
			t.Errorf("%s is classified neither inspects nor writes", c.words())
		}
	}
	for name := range cases {
		t.Errorf("the purity test runs %s, which the table does not classify inspects", name)
	}
}

// TestInspectionChangesNothing runs every command classified inspects over
// the damaged state, once with no writer at work and once beside the writers
// that hold a lock on it, each part way through an append, and requires every
// name under it to keep its bytes, mode, modification time and link count.
// What moved is printed.
func TestInspectionChangesNothing(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(map[bool]string{false: "free", true: "held"}[held], func(t *testing.T) {
			st := newDamagedState(t)
			if held {
				st.holdAsWriters(t)
			}
			for name, ways := range st.inspections() {
				for _, c := range ways {
					t.Run(name, func(t *testing.T) {
						pinTrees(t, st.roots)
						before := treesState(t, st.roots)
						status, out := runWithin(t, c.args)
						if moved := treeChanges(before, treesState(t, st.roots)); len(moved) > 0 {
							t.Errorf("%s changed what it inspected:\n  %s\noutput:\n%s", name, strings.Join(moved, "\n  "), out)
						}
						want, exit := append(slices.Clone(c.says), c.free...), c.freeExit
						if held {
							want, exit = append(slices.Clone(c.says), c.held...), c.heldExit
						}
						if status != exit {
							t.Errorf("%s exited %d, want %d:\n%s", name, status, exit, out)
						}
						for _, w := range want {
							if !strings.Contains(out, w) {
								t.Errorf("%s did not say %q, so it did not read what it was pointed at:\n%s", name, w, out)
							}
						}
					})
				}
			}
		})
	}
}

// runWithin runs the entry point and fails the test if it does not return in
// time, which is what an inspection waiting on a writer's lock looks like.
func runWithin(t *testing.T, args []string) (int, string) {
	t.Helper()
	type result struct {
		status int
		out    string
	}
	done := make(chan result, 1)
	go func() {
		var out bytes.Buffer
		status := run(slices.Clone(args), &out, &out)
		done <- result{status, out.String()}
	}()
	select {
	case r := <-done:
		return r.status, r.out
	case <-time.After(time.Minute):
		t.Fatalf("%v did not return within a minute", args)
		return 0, ""
	}
}

// pinnedTime is what every name under the state is dated before a run, so a
// write in the same clock tick as the fixture still moves a time.
var pinnedTime = time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)

// pinTrees dates every name under the roots but a link at pinnedTime,
// deepest first, so dating a name does not move its directory's time after.
func pinTrees(t *testing.T, roots []string) {
	t.Helper()
	var paths []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink == 0 {
				paths = append(paths, path)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Reverse(paths)
	for _, path := range paths {
		if err := os.Chtimes(path, pinnedTime, pinnedTime); err != nil {
			t.Fatal(err)
		}
	}
}

// treesState describes every name under the roots as the kernel does: type
// and permissions, owner, size, modification time, link count, and a file's
// contents or a link's target.
func treesState(t *testing.T, roots []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			line, err := describe(path)
			out[path] = line
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func describe(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: the platform gives no link count", path)
	}
	line := fmt.Sprintf("%v uid %d gid %d size %d mtime %d links %d",
		info.Mode(), st.Uid, st.Gid, info.Size(), info.ModTime().UnixNano(), st.Nlink)
	switch {
	case info.Mode().IsRegular():
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's temp dir
		if err != nil {
			return "", err
		}
		line += fmt.Sprintf(" sha256 %x", sha256.Sum256(raw))
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		line += " -> " + target
	}
	return line, nil
}

// treeChanges lists every name whose description differs between two states.
func treeChanges(before, after map[string]string) []string {
	var out []string
	for name, was := range before {
		if now, ok := after[name]; !ok {
			out = append(out, fmt.Sprintf("%s: removed (was %s)", name, was))
		} else if now != was {
			out = append(out, fmt.Sprintf("%s: %s -> %s", name, was, now))
		}
	}
	for name, now := range after {
		if _, ok := before[name]; !ok {
			out = append(out, fmt.Sprintf("%s: created (%s)", name, now))
		}
	}
	slices.Sort(out)
	return out
}
