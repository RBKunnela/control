package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/spool"
)

// TestSpoolDrainRefusesASpoolAPlaneHolds: while a spool is open on the
// directory the command exits 1, names the lock and creates nothing; once it
// closes, the same command drains and says what moved.
func TestSpoolDrainRefusesASpoolAPlaneHolds(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(t.TempDir(), "drained.jsonl")
	s, err := spool.Open(spool.Options{Dir: dir, MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"spool", "drain", dir, out}, &stdout, &stderr); status != exitFail ||
		!strings.Contains(stderr.String(), "held by another spool") {
		t.Errorf("a drain of a held spool exits %d with %q, want 1 naming the lock", status, stderr.String())
	}
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused drain left %s: %v", out, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	status, said := command(t, "spool", "drain", dir, out)
	if status != exitOK || !strings.HasPrefix(said, "spool drain: 0 record(s), 0 byte(s), moved from the quarantine into ") {
		t.Errorf("the control, a drain once the spool closed: %d, %q", status, said)
	}
}

// TestSpoolTakesOnlyDrainWithTwoPaths: anything else is a usage error.
func TestSpoolTakesOnlyDrainWithTwoPaths(t *testing.T) {
	for _, args := range [][]string{{"spool"}, {"spool", "drain", "dir"}, {"spool", "drain", "a", "b", "c"}, {"spool", "empty", "a", "b"}} {
		if status, _ := command(t, args...); status != exitUsage {
			t.Errorf("%q exits %d, want %d", args, status, exitUsage)
		}
	}
}
