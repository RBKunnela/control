package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// expiredRun opens a run in dir that expired an hour ago.
func expiredRun(t *testing.T, dir string) runs.Record {
	t.Helper()
	a, err := runs.InitAdmin(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	rec, _, err := a.Open(context.Background(), runs.OpenRequest{Who: who, TTL: time.Hour, Now: time.Now().Add(-2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestRunsPruneArchivesAndRemovesAnExpiredTree: the expired run is named,
// copied into the archive and gone from the directory; the open one stays.
func TestRunsPruneArchivesAndRemovesAnExpiredTree(t *testing.T) {
	dir := runsDir(t)
	gone := expiredRun(t, dir)
	live := openRun(t, dir, who, "2h")
	archive := filepath.Join(t.TempDir(), "archive")
	cutoff := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
	code, stdout, stderr := invoke(t, "runs", "prune", "--expired-before", cutoff, "--archive", archive, dir)
	if code != exitOK || stderr != "" || !strings.HasPrefix(stdout, "pruned "+gone.ID+"\n1 tree(s), 1 run(s), archived in ") {
		t.Errorf("prune answered %d, %q, %q", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(archive, gone.ID+".run.json")); err != nil {
		t.Errorf("the archive lacks the pruned record: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, gone.ID+".run.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the pruned record is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, live.runID+".run.json")); err != nil {
		t.Errorf("the open run went too: %v", err)
	}
}

// TestRunsPruneLeavesALiveTreeAndSucceeds: a live root with an expired
// child is neither removed nor named, and the command exits 0.
func TestRunsPruneLeavesALiveTreeAndSucceeds(t *testing.T) {
	dir := runsDir(t)
	root := openRun(t, dir, who, "3h")
	openRun(t, dir, who, "1m", "--parent", root.runID)
	a, err := runs.OpenAdmin(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := a.List(context.Background(), 10)
	if closeErr := a.Close(); err == nil {
		err = closeErr
	}
	if err != nil || len(l.Records) != 2 {
		t.Fatalf("the directory lists %+v, %v", l, err)
	}
	cutoff := time.Now().Add(2 * time.Minute).UTC()
	child := l.Records[0]
	if child.ID == root.runID {
		child = l.Records[1]
	}
	req := runs.PruneRequest{ExpiredBefore: cutoff, Archive: filepath.Join(t.TempDir(), "archive"), Now: cutoff}
	if !child.ExpiresAt.Before(cutoff) {
		t.Fatalf("the child expires at %s, after the cutoff %s, so the case examines nothing", child.ExpiresAt, cutoff)
	}
	admin, err := runs.OpenAdmin(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	code := pruneAndPrint(admin, req, &stdout, &stderr)
	if err := admin.Close(); err != nil {
		t.Fatal(err)
	}
	if code != exitOK || stderr.String() != "" || !strings.HasPrefix(stdout.String(), "0 tree(s), 0 run(s)") {
		t.Errorf("prune of a live tree answered %d, %q, %q", code, stdout.String(), stderr.String())
	}
}

// TestRunsPruneRefusals: a cutoff in the future fails and writes nothing;
// what the command cannot parse is a usage error.
func TestRunsPruneRefusals(t *testing.T) {
	dir := runsDir(t)
	gone := expiredRun(t, dir)
	archive := filepath.Join(t.TempDir(), "archive")
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if code, _, stderr := invoke(t, "runs", "prune", "--expired-before", future, "--archive", archive, dir); code != exitFail ||
		!strings.Contains(stderr, "no later than now") {
		t.Errorf("a future cutoff answered %d, %q", code, stderr)
	}
	if _, err := os.Lstat(archive); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused prune made its archive: %v", err)
	}
	for _, args := range [][]string{
		{"runs", "prune", "--archive", archive, dir},
		{"runs", "prune", "--expired-before", "yesterday", "--archive", archive, dir},
		{"runs", "prune", "--expired-before", future, dir},
		{"runs", "prune", "--expired-before", future, "--archive", archive},
	} {
		if code, _, _ := invoke(t, args...); code != exitUsage {
			t.Errorf("%q answered %d, want %d", args, code, exitUsage)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, gone.ID+".run.json")); err != nil {
		t.Errorf("a refused prune removed the run: %v", err)
	}
}

// TestRunsPruneNamesATreeItKeeps: a child written to outlive the cutoff keeps
// its expired root's tree; the command names the root on stderr and exits 1.
func TestRunsPruneNamesATreeItKeeps(t *testing.T) {
	dir := runsDir(t)
	root := expiredRun(t, dir)
	child := childID(7)
	copyRecord(t, dir, root.ID, child, map[string]string{
		"parent": root.ID, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	})
	cutoff := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
	code, stdout, stderr := invoke(t, "runs", "prune", "--expired-before", cutoff, "--archive", filepath.Join(t.TempDir(), "archive"), dir)
	if code != exitFail || !strings.Contains(stderr, root.ID+" is kept") || !strings.HasPrefix(stdout, "0 tree(s), 0 run(s)") {
		t.Errorf("prune of a tree with a live child answered %d, %q, %q", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, root.ID+".run.json")); err != nil {
		t.Errorf("the kept tree's root went: %v", err)
	}
}
