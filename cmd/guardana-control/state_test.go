package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/recovery"
)

// planeConfig is a directory plane whose paths are relative to the file.
const planeConfig = `mode: OBSERVE
project_id: orders
tenant_id: acme
listener:
  kind: stateless_http
  principal:
    id: agent-runner
  agent:
    id: orders-assistant
policy:
  bundle_id: orders-policy
  bundle_file: policy.bundle
  key_id: k1
  public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  statement_file: policy.statement
  state_dir: floors
  freshness_key_id: f1
  freshness_public_key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
  poll_interval: 5s
approvals:
  authority: directory
  dir: approvals
  hold_journal_dir: holds
pause:
  file: pause/pause.json
evidence:
  dir: spool
export:
  endpoint: http://127.0.0.1:4318/v1/logs
  allow_plaintext: true
upstreams:
  - name: orders
    endpoint: http://127.0.0.1:1/mcp
`

// stoppedPlane is a configuration and the directories a stopped plane
// leaves: a floor of no serial, a pause file with one entry, an empty spool
// and a hold journal.
func stoppedPlane(t *testing.T) (root, config string) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"spool", "holds", "pause"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	j, err := holdjournal.Open(filepath.Join(root, "holds"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := policystate.Init(t.Context(), filepath.Join(root, "floors"), policystate.KindPlane, "orders-policy"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "pause", "pause.json")
	if err := pause.Init(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	if err := pause.Add(t.Context(), path, pause.Entry{ID: "p1", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Reason: "maintenance"}); err != nil {
		t.Fatal(err)
	}
	config = filepath.Join(root, "plane.yaml")
	if err := os.WriteFile(config, []byte(planeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, config
}

// TestStateBackupThenRestore runs the guide's two commands in order: a
// backup, the pause file lost, a restore that writes it again.
func TestStateBackupThenRestore(t *testing.T) {
	root, config := stoppedPlane(t)
	backup := filepath.Join(t.TempDir(), "backup")
	code, stdout, stderr := invoke(t, "state", "backup", config, backup)
	if code != exitOK || stderr != "" || stdout != "backed up 3 files into "+backup+"\n" {
		t.Fatalf("backup: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if err := os.Remove(filepath.Join(root, "pause", "pause.json")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = invoke(t, "state", "restore", config, backup)
	if code != exitOK || stderr != "" {
		t.Fatalf("restore: exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"pause.file: 1 entries added\n", "still confirms, within policy.max_stale\n", " doctor --config <config> "} {
		if !strings.Contains(stdout, want) {
			t.Errorf("restore printed %q, without %q", stdout, want)
		}
	}
	l, err := pause.List(filepath.Join(root, "pause", "pause.json"))
	if err != nil || len(l.Entries) != 1 || l.Entries[0].ID != "p1" {
		t.Fatalf("the restored pause file: %+v, %v", l, err)
	}
}

// backupRefused runs a state command and holds it to the exit status, one
// stderr line under its two words holding want, and nothing on stdout.
func backupRefused(t *testing.T, name string, status int, want string, args ...string) {
	t.Helper()
	code, stdout, stderr := invoke(t, args...)
	prefix := brand.CLI + ": " + strings.Join(args[:2], " ") + ": "
	line := oneStderrLine(t, stderr)
	if code != status || stdout != "" || !strings.HasPrefix(line, prefix) || !strings.Contains(line, want) {
		t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d and a line holding %q", name, code, stdout, line, status, want)
	}
}

func TestStateCommandsRefuse(t *testing.T) {
	_, config := stoppedPlane(t)
	backup := filepath.Join(t.TempDir(), "backup")
	if code, _, _ := invoke(t, "state", "backup", config); code != exitUsage {
		t.Errorf("backup with one argument: exit %d, want %d", code, exitUsage)
	}
	backupRefused(t, "a restore with no backup", exitFail, "backup.json", "state", "restore", config, backup)
	backupRefused(t, "a missing configuration", exitFail, "reading the configuration", "state", "backup", filepath.Join(t.TempDir(), "none.yaml"), backup)
	if code, _, _ := invoke(t, "state", "backup", config, backup); code != exitOK {
		t.Fatalf("backup: exit %d", code)
	}
	backupRefused(t, "a backup into an existing directory", exitFail, "exists", "state", "backup", config, backup)
}

// TestRestoreLinesNameTheNewestFileToPutBack: a signed restore tells the
// operator to put back the newest signed copy and what an older one brings
// back, and for the stop list the way to a list the backup's floor refuses;
// a directory restore names neither.
func TestRestoreLinesNameTheNewestFileToPutBack(t *testing.T) {
	signed := strings.Join(restoreLines(true, recovery.Report{PutBack: []string{"pause.file"}}), "\n")
	for _, want := range []string{"pause.file: an operator's signed file", "put back the newest signed copy you hold", "a grant revoked, a route changed or a pause signed after the backup"} {
		if !strings.Contains(signed, want) {
			t.Errorf("a signed restore printed %q, without %q", signed, want)
		}
	}
	if strings.Contains(signed, "stops_floor_dir") {
		t.Errorf("a restore that put back no stop list printed the stop list's way back: %q", signed)
	}
	stops := strings.Join(restoreLines(true, recovery.Report{PutBack: []string{"reaction.stops"}}), "\n")
	for _, want := range []string{"refuses one two or more serials above", "each list of the chain in serial order", "move reaction.stops_floor_dir aside", "stops floor init"} {
		if !strings.Contains(stops, want) {
			t.Errorf("a restore that put back the stop list printed %q, without %q", stops, want)
		}
	}
	if directory := strings.Join(restoreLines(false, recovery.Report{}), "\n"); strings.Contains(directory, "grant revoked") {
		t.Errorf("a directory restore printed the signed residual: %q", directory)
	}
}
