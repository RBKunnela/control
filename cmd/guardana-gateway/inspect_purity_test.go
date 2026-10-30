//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/trailfile"
)

// inspection is one way the purity test reaches a command the table
// classifies inspects: its arguments over the damaged tree, and its status
// and what its output has to hold with no writer at work, beside every
// writer, and beside every writer but the spool's, so a run that refused
// before it read anything never counts as one that changed nothing.
type inspection struct {
	args                              []string
	free, whileHeld, whileSpoolFree   []string
	freeExit, heldExit, spoolFreeExit int
}

// damagedTree is a plane's tree as a crash leaves it: a spool segment that
// ends in five bytes no record holds, a lost hold in the file provider's
// directories that a start would close, an expired pause entry, an open run,
// and a trail file that ends in a partial line. Every writer of it would
// change something at its next open.
func damagedTree(t *testing.T) (tree, string) {
	t.Helper()
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))

	sp, err := openSpool(tr.load(t))
	if err != nil {
		t.Fatal(err)
	}
	err = sp.Append(context.Background(), &controlv1.Event{
		EventId: "evt-1", Kind: controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED, RequestId: "req-1",
		RunId: "run-1", ProjectId: "orders", TenantId: "acme", SchemaVersion: evidence.SchemaVersion,
	})
	if err = errors.Join(err, sp.Close()); err != nil {
		t.Fatalf("writing the one record: %v", err)
	}
	segments, err := filepath.Glob(filepath.Join(tr.dir, "spool", "*.seg"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("the spool holds segments %v (%v), want one", segments, err)
	}
	appendTail(t, segments[0], "torn!")

	records, holds := tr.fileProvider(t)
	lostHold(t, records, holds, time.Now().Add(-time.Minute))

	tr.withPauseFile(t, pauseDocument(pauseEntry("p-1", scopeElsewhere)), time.Second)

	runsDir := filepath.Join(tr.dir, "runs")
	if err := os.Mkdir(runsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	admin, err := runs.InitAdmin(context.Background(), runsDir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = admin.Open(context.Background(), runs.OpenRequest{
		Who: runs.Identity{ProjectID: "orders", TenantID: "acme", PrincipalType: "service", PrincipalID: "agent-runner", AgentID: "orders-assistant"},
		TTL: time.Hour, Now: time.Now(),
	})
	if err = errors.Join(err, admin.Close()); err != nil {
		t.Fatalf("opening a run: %v", err)
	}
	setEnv(t, "runs.dir", runsDir)

	whole, torn := trailLines(t)
	trailPath := filepath.Join(tr.dir, "trail.jsonl")
	if err := os.WriteFile(trailPath, []byte(whole+torn), 0o600); err != nil {
		t.Fatal(err)
	}
	return tr, trailPath
}

// trailLines is one request's first two evidence lines whole, and the first
// half of its third, which is what a collector cut short leaves.
func trailLines(t *testing.T) (whole, torn string) {
	t.Helper()
	var b bytes.Buffer
	if err := evidence.EncodeJSONL(&b, trailOf("req-1", kProposed, kDecided, kRequested)); err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(b.String(), "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("three events encode as %d line(s)", len(lines)-1)
	}
	return lines[0] + lines[1], lines[2][:len(lines[2])/2]
}

func appendTail(t *testing.T, path, tail string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: a file under the test's temp dir
	if err == nil {
		_, err = f.WriteString(tail)
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		t.Fatal(err)
	}
}

// inspections is every inspecting command's run over the damaged tree.
func inspections(tr tree, trailPath string) map[string][]inspection {
	everyCheck := []string{
		"\nok      evidence      ", "a start would cut a torn tail of 5 byte(s)",
		"\nok      approvals     ", "a restart would close 1 lost hold(s)",
		"\nok      pause         ", "\nok      runs          ", "\nok      seams         ", "\nok      upstreams     ",
	}
	return map[string][]inspection{
		"doctor": {{
			args:           []string{"doctor", "--config", tr.config},
			free:           everyCheck,
			whileHeld:      []string{"\nfail    evidence      ", "held by another spool"},
			whileSpoolFree: everyCheck,
			freeExit:       exitOK, heldExit: exitFail, spoolFreeExit: exitOK,
		}},
		"trail": {
			{
				args:           []string{"trail", trailPath},
				free:           []string{"request=req-1 ", "no collector holds it"},
				whileHeld:      []string{"request=req-1 "},
				whileSpoolFree: []string{"request=req-1 "},
				freeExit:       exitFail, heldExit: exitOK, spoolFreeExit: exitOK,
			},
			{
				args:           []string{"trail", "export", trailPath},
				free:           []string{`"eventId":"req-1-1"`, `"reason":"partial_tail"`},
				whileHeld:      []string{`"eventId":"req-1-1"`, `"writer_held":true`},
				whileSpoolFree: []string{`"eventId":"req-1-1"`, `"writer_held":true`},
				freeExit:       exitFail, heldExit: exitOK, spoolFreeExit: exitOK,
			},
		},
	}
}

// TestEveryCommandIsClassified: a command left at the zero effect is
// neither held to changing nothing nor known to write, so it is refused, and
// every command classified inspects has its run in the purity test.
func TestEveryCommandIsClassified(t *testing.T) {
	cases := inspections(tree{}, "")
	for _, c := range commands {
		switch c.effect {
		case inspects:
			if len(cases[c.name]) == 0 {
				t.Errorf("%s inspects and the purity test does not run it", c.name)
			}
			delete(cases, c.name)
		case writes:
		default:
			t.Errorf("%s is classified neither inspects nor writes", c.name)
		}
	}
	for name := range cases {
		t.Errorf("the purity test runs %s, which the table does not classify inspects", name)
	}
}

// The writers an inspection runs beside.
const (
	noWriter = iota
	everyWriter
	everyWriterButTheSpool
)

// TestInspectionChangesNothing runs every command classified inspects over
// the damaged tree three times: with no writer at work; beside a plane built
// to serve it and a collector writing its trail, each holding its locks and
// part way through an append; and beside the plane's approval directories and
// the collector with the spool free, so that every check doctor makes after
// the spool's runs beside a lock. It requires every name under the tree to
// keep its bytes, mode, owner, modification time and link count, and prints
// what moved.
func TestInspectionChangesNothing(t *testing.T) {
	for _, beside := range []int{noWriter, everyWriter, everyWriterButTheSpool} {
		t.Run([]string{"free", "held", "held but the spool"}[beside], func(t *testing.T) {
			tr, trailPath := damagedTree(t)
			switch beside {
			case everyWriter:
				holdAsWriters(t, tr, trailPath)
			case everyWriterButTheSpool:
				holdButTheSpool(t, tr, trailPath)
			}
			for name, ways := range inspections(tr, trailPath) {
				for _, c := range ways {
					t.Run(strings.Join(c.args[:2], " "), func(t *testing.T) {
						pinTree(t, tr.dir)
						before := treeState(t, tr.dir)
						status, out := runWithin(t, c.args)
						if moved := treeChanges(before, treeState(t, tr.dir)); len(moved) > 0 {
							t.Errorf("%s changed what it inspected:\n  %s\noutput:\n%s", name, strings.Join(moved, "\n  "), out)
						}
						want, exit := c.free, c.freeExit
						switch beside {
						case everyWriter:
							want, exit = c.whileHeld, c.heldExit
						case everyWriterButTheSpool:
							want, exit = c.whileSpoolFree, c.spoolFreeExit
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

// holdAsWriters builds the plane `run` would serve over the tree and opens
// the trail file as the collector does, each taking its locks and repairing
// what its open repairs, then leaves an append part way written in the
// spool and in the trail, as each writer does between two records.
func holdAsWriters(t *testing.T, tr tree, trailPath string) {
	t.Helper()
	tr.plane(t)
	segments, err := filepath.Glob(filepath.Join(tr.dir, "spool", "*.seg"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("the spool holds segments %v (%v), want one", segments, err)
	}
	appendTail(t, segments[0], "in flight")
	collectInto(t, trailPath)
}

// holdButTheSpool opens the approval records and the hold journal as a
// serving plane holds them, and the trail as the collector does, and leaves
// the spool to no one.
func holdButTheSpool(t *testing.T, tr tree, trailPath string) {
	t.Helper()
	records, err := approvals.OpenPlane(filepath.Join(tr.dir, recordsDir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = records.Close() })
	journal, err := holdjournal.Open(filepath.Join(tr.dir, holdsDir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	collectInto(t, trailPath)
}

// collectInto opens the trail as the collector does, which cuts its torn
// line, and leaves half a line in it again, as the collector between two
// appends.
func collectInto(t *testing.T, trailPath string) {
	t.Helper()
	w, err := trailfile.Open(trailPath)
	if err != nil {
		t.Fatalf("opening the trail as the collector does: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	_, torn := trailLines(t)
	appendTail(t, trailPath, torn)
}

// TestDoctorRefusesATornTailRunCannotCut: a torn last segment of mode 0400 is
// one `run` cannot open to cut, so doctor fails the evidence check and says
// why, and nothing in the tree moves.
func TestDoctorRefusesATornTailRunCannotCut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a file whatever its mode, so run would cut it")
	}
	tr, _ := damagedTree(t)
	segments, err := filepath.Glob(filepath.Join(tr.dir, "spool", "*.seg"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("the spool holds segments %v (%v), want one", segments, err)
	}
	if err := os.Chmod(segments[0], 0o400); err != nil {
		t.Fatal(err)
	}
	if sp, err := openSpool(tr.load(t)); err == nil {
		_ = sp.Close()
		t.Fatal("run's open cut a torn segment of mode 0400, so the case is not one run refuses")
	}
	pinTree(t, tr.dir)
	before := treeState(t, tr.dir)
	status, out := runWithin(t, []string{"doctor", "--config", tr.config})
	if moved := treeChanges(before, treeState(t, tr.dir)); len(moved) > 0 {
		t.Errorf("doctor changed what it inspected:\n  %s", strings.Join(moved, "\n  "))
	}
	if status != exitFail {
		t.Errorf("doctor exited %d, want %d:\n%s", status, exitFail, out)
	}
	for _, want := range []string{"\nfail    evidence      ", "segment 1: permission denied", "mode 0400"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor did not say %q:\n%s", want, out)
		}
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
		status := run(context.Background(), slices.Clone(args), &out, &out)
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

// pinnedTime is what every name under the tree is dated before a run, so a
// write in the same clock tick as the fixture still moves a time.
var pinnedTime = time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)

// pinTree dates every name under root but a link at pinnedTime, deepest
// first, so dating a name does not move its directory's time afterwards.
func pinTree(t *testing.T, root string) {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink == 0 {
			paths = append(paths, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(paths)
	for _, path := range paths {
		if err := os.Chtimes(path, pinnedTime, pinnedTime); err != nil {
			t.Fatal(err)
		}
	}
}

// treeState describes every name under root as the kernel does: type and
// permissions, owner, size, modification time, link count, and a file's
// contents or a link's target.
func treeState(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: the platform gives no link count", path)
		}
		line := fmt.Sprintf("%v uid %d gid %d size %d mtime %d links %d",
			info.Mode(), st.Uid, st.Gid, info.Size(), info.ModTime().UnixNano(), st.Nlink)
		switch {
		case info.Mode().IsRegular():
			raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's temp dir
			if err != nil {
				return err
			}
			line += fmt.Sprintf(" sha256 %x", sha256.Sum256(raw))
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			line += " -> " + target
		}
		rel, err := filepath.Rel(root, path)
		out[rel] = line
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
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
