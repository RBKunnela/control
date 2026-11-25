//go:build unix

package spool_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/spool"
)

// TestADrainWritesWhereItJudged: a link in the drained file's path retargeted
// at the spool once the directory was judged does not move the file into the
// spool, where the next start would refuse it, and the records land where the
// drain judged they would.
func TestADrainWritesWhereItJudged(t *testing.T) {
	dir, events, _ := quarantined(t)
	elsewhere := t.TempDir()
	judged := filepath.Join(elsewhere, "judged")
	if err := os.Mkdir(judged, 0o700); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(elsewhere, "via")
	if err := os.Symlink(judged, via); err != nil {
		t.Fatal(err)
	}
	retarget := func() error {
		return errors.Join(os.Remove(via), os.Symlink(dir, via))
	}
	d, err := spool.DrainAfterCheck(dir, filepath.Join(via, "drained.jsonl"), retarget)
	if _, lerr := os.Lstat(filepath.Join(dir, "drained.jsonl")); !errors.Is(lerr, fs.ErrNotExist) {
		t.Fatalf("the drain created its file in the spool: %v (drain %+v, %v)", lerr, d, err)
	}
	if err != nil || d.Records != 2 {
		t.Fatalf("Drain = %+v, %v; want the two records drained", d, err)
	}
	if got := drainedEvents(t, filepath.Join(judged, "drained.jsonl")); !sameEvents(got, events) {
		t.Errorf("the judged directory's file holds %v", got)
	}
	expectEmptyQuarantine(t, dir)
}
