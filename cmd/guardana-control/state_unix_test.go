//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStateRestoreSaysWhatItWroteBeforeAFailure: a restore that fails after
// its first write names on stdout what it wrote, so the operator knows the
// tree is no longer as it was.
func TestStateRestoreSaysWhatItWroteBeforeAFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes into a directory its mode closes")
	}
	root, config := stoppedPlane(t)
	backup := filepath.Join(t.TempDir(), "backup")
	if code, _, stderr := invoke(t, "state", "backup", config, backup); code != exitOK {
		t.Fatalf("backup: exit %d, %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(root, "pause", "pause.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "pause"), 0o500); err != nil { //nolint:gosec // G302: a directory the restore cannot write into
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "pause"), 0o700) }) //nolint:gosec // G302: the directory's own mode back
	code, stdout, stderr := invoke(t, "state", "restore", config, backup)
	if code != exitFail || !strings.Contains(stderr, "pause.file") {
		t.Fatalf("restore into a closed pause directory: exit %d, stderr %q", code, stderr)
	}
	if stdout != "done before the failure: policy.state_dir: 0 floors stamped at the restore\n" {
		t.Fatalf("stdout = %q, want the floor named as written", stdout)
	}
}
