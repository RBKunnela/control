package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/recovery"
)

// signedStateBlock is planeConfig's approvals and pause made those of a
// signed plane named plane-a.
const signedStateBlock = `plane_id: plane-a
approvals:
  authority: signed
  dir: approvals
  hold_journal_dir: holds
  inbox_dir: inbox
trust:
  root_public_key: trust/root.pub
  roster: trust/roster.json
  roster_id: roster-a
  floor_dir: trust/floors
operators:
  authenticator:
    kind: roster
  authorizer:
    kind: roster
pause:
  file: pause/pause.json
  floor_dir: pausefloor
`

// signedStatePlane is stoppedPlane's directories under a signed
// configuration.
func signedStatePlane(t *testing.T) (root, config string) {
	t.Helper()
	root, config = stoppedPlane(t)
	unsigned := "approvals:\n  authority: directory\n  dir: approvals\n  hold_journal_dir: holds\npause:\n  file: pause/pause.json\n"
	if !strings.Contains(planeConfig, unsigned) {
		t.Fatal("planeConfig no longer holds the block signedStatePlane replaces")
	}
	if err := os.WriteFile(config, []byte(strings.Replace(planeConfig, unsigned, signedStateBlock, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, config
}

// TestStateCommandsUnderSignedTakeNoKeyFromTheEnvironment: a plane_id the
// environment sets is refused by backup and by restore, which write
// nothing; the control, the same commands with the environment clear, back
// up a manifest naming the file's plane_id.
func TestStateCommandsUnderSignedTakeNoKeyFromTheEnvironment(t *testing.T) {
	_, config := signedStatePlane(t)
	backup := filepath.Join(t.TempDir(), "backup")
	t.Setenv(brand.Env("PLANE_ID"), "plane-b")
	for _, command := range []string{"backup", "restore"} {
		code, stdout, stderr := invoke(t, "state", command, config, backup)
		want := brand.CLI + ": state " + command + ": approvals.authority: signed, and the environment sets plane_id;"
		if code != exitFail || stdout != "" || !strings.HasPrefix(stderr, want) || strings.Count(stderr, "\n") != 1 {
			t.Errorf("state %s with plane_id from the environment: exit %d, stdout %q, stderr %q; want one line %q", command, code, stdout, stderr, want)
		}
		if _, err := os.Lstat(backup); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refused state %s made %s: %v", command, backup, err)
		}
	}
	if err := os.Unsetenv(brand.Env("PLANE_ID")); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invoke(t, "state", "backup", config, backup); code != exitOK {
		t.Fatalf("the control, a backup with the environment clear: exit %d, %q", code, stderr)
	}
	m, err := recovery.ParseManifest(fileBytesOf(t, filepath.Join(backup, recovery.ManifestName)))
	if err != nil || m.PlaneID != "plane-a" {
		t.Errorf("the manifest names plane %q, %v; want the file's plane-a", m.PlaneID, err)
	}
}

// TestStateCommandsUnderDirectoryTakeTheEnvironment: outside signed a key
// the environment sets still counts, as it does for the plane: the manifest
// names the environment's tenant.
func TestStateCommandsUnderDirectoryTakeTheEnvironment(t *testing.T) {
	_, config := stoppedPlane(t)
	backup := filepath.Join(t.TempDir(), "backup")
	t.Setenv(brand.Env("TENANT_ID"), "acme-env")
	if code, _, stderr := invoke(t, "state", "backup", config, backup); code != exitOK {
		t.Fatalf("a directory backup with tenant_id from the environment: exit %d, %q", code, stderr)
	}
	m, err := recovery.ParseManifest(fileBytesOf(t, filepath.Join(backup, recovery.ManifestName)))
	if err != nil || m.Tenant != "acme-env" || m.PlaneID != "" {
		t.Errorf("the manifest names tenant %q and plane %q, %v; want the environment's acme-env and no plane", m.Tenant, m.PlaneID, err)
	}
}

func fileBytesOf(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestASignedRestoreOfA01ManifestSaysThePlaneWasNotChecked: on standard
// error, once; a restore of a 0.2 manifest says nothing of it.
func TestASignedRestoreOfA01ManifestSaysThePlaneWasNotChecked(t *testing.T) {
	_, config := signedStatePlane(t)
	backup := filepath.Join(t.TempDir(), "backup")
	if code, _, stderr := invoke(t, "state", "backup", config, backup); code != exitOK {
		t.Fatalf("backup: exit %d, %q", code, stderr)
	}
	if code, _, stderr := invoke(t, "state", "restore", config, backup); code != exitOK || stderr != "" {
		t.Fatalf("the control, a restore of the 0.2 manifest: exit %d, stderr %q", code, stderr)
	}
	manifest := filepath.Join(backup, recovery.ManifestName)
	old := strings.Replace(strings.Replace(string(fileBytesOf(t, manifest)), "  \"plane_id\": \"plane-a\",\n", "", 1),
		`"schema_version": "0.2"`, `"schema_version": "0.1"`, 1)
	if err := os.WriteFile(manifest, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := invoke(t, "state", "restore", config, backup)
	want := brand.CLI + ": state restore: plane not checked: the backup's manifest is of version 0.1"
	if code != exitOK || !strings.HasPrefix(stderr, want) || strings.Count(stderr, "\n") != 1 || strings.Contains(stdout, "plane not checked") {
		t.Errorf("a restore of a 0.1 manifest: exit %d, stdout %q, stderr %q; want one stderr line %q", code, stdout, stderr, want)
	}
}
