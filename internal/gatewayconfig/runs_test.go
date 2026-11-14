package gatewayconfig

import (
	"os"
	"strings"
	"testing"
)

func TestARunsDirectoryIsOptional(t *testing.T) {
	if cfg := load(t, write(t, "")); cfg.Runs.Dir != "" {
		t.Errorf("a silent configuration names runs.dir %q", cfg.Runs.Dir)
	}
	cfg := load(t, write(t, "\nruns:\n  dir: runs\n"+fileProvider))
	if cfg.Runs.Dir != "runs" {
		t.Errorf("runs.dir = %q, want runs", cfg.Runs.Dir)
	}
	path := write(t, "")
	setEnv(t, "runs.dir", "from-env")
	if cfg := load(t, path); cfg.Runs.Dir != "from-env" {
		t.Errorf("runs.dir from the environment = %q, want from-env", cfg.Runs.Dir)
	}
}

// TestTheRunsDirectoryStandsApart: the spool, the approvals store, the hold
// journal and the pause file's directory each have another writer, so a runs
// directory that is one of them, holds one or sits inside one is refused.
func TestTheRunsDirectoryStandsApart(t *testing.T) {
	cases := map[string]struct{ add, names string }{
		"the spool":               {"\nruns:\n  dir: spool\n", "evidence.dir"},
		"inside the spool":        {"\nruns:\n  dir: spool/runs\n", "evidence.dir"},
		"holding the spool":       {"\nruns:\n  dir: .\n", "evidence.dir"},
		"the approvals directory": {"\nruns:\n  dir: approvals\n" + fileProvider, "approvals.dir"},
		"the hold journal":        {"\nruns:\n  dir: holds/runs\n" + fileProvider, "approvals.hold_journal_dir"},
		"the pause file's":        {"\nruns:\n  dir: control\npause:\n  file: control/pause.json\n", "pause.file"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, c.add), os.Environ())
			if err == nil {
				t.Fatalf("runs.dir sharing %s was accepted", name)
			}
			if !strings.Contains(err.Error(), "runs.dir") || !strings.Contains(err.Error(), c.names) {
				t.Errorf("the refusal names neither runs.dir nor %s: %v", c.names, err)
			}
		})
	}
	if _, err := Load(write(t, "\nruns:\n  dir: runs\npause:\n  file: control/pause.json\n"+fileProvider), os.Environ()); err != nil {
		t.Errorf("a runs directory of its own was refused: %v", err)
	}
}

// TestThePauseFilesDirectoryIsTakenAsTheFileResolves: the pause file's
// directory is the one its resolved path sits in, so a path that climbs out
// of its last element is held to the directory it reaches.
func TestThePauseFilesDirectoryIsTakenAsTheFileResolves(t *testing.T) {
	_, err := Load(write(t, "\nruns:\n  dir: ../runs\npause:\n  file: control/..\n"), os.Environ())
	if err == nil || !strings.Contains(err.Error(), "runs.dir") || !strings.Contains(err.Error(), "pause.file") {
		t.Errorf("a runs directory inside the directory the pause file resolves into: %v", err)
	}
	if _, err := Load(write(t, "\nruns:\n  dir: ../runs\npause:\n  file: control/pause.json\n"), os.Environ()); err != nil {
		t.Errorf("the same runs directory beside a pause file one level down was refused: %v", err)
	}
}

// TestTheBoundOnLocalRunsIsRefusedBesideARunsDirectory: flow.max_runs bounds
// the runs a plane keeps in memory, and a plane with a runs directory keeps
// none, so the setting would apply to nothing.
func TestTheBoundOnLocalRunsIsRefusedBesideARunsDirectory(t *testing.T) {
	_, err := Load(write(t, "\nruns:\n  dir: runs\nflow:\n  max_runs: 8\n"), os.Environ())
	if err == nil || !strings.Contains(err.Error(), "flow.max_runs") {
		t.Errorf("flow.max_runs beside runs.dir: %v, want a refusal naming flow.max_runs", err)
	}
	if cfg := load(t, write(t, "\nflow:\n  max_runs: 8\n")); cfg.Flow.MaxRuns != 8 {
		t.Errorf("flow.max_runs without runs.dir = %d, want 8", cfg.Flow.MaxRuns)
	}
}

func TestARunsDirectoryNeedsAPrincipalType(t *testing.T) {
	path := write(t, "\nruns:\n  dir: runs\n"+fileProvider)
	setEnv(t, "listener.principal.type", "")
	_, err := Load(path, os.Environ())
	if err == nil || !strings.Contains(err.Error(), "listener.principal.type") || !strings.Contains(err.Error(), "no run would ever match") {
		t.Errorf("an empty principal type beside runs.dir: %v, want this check's refusal", err)
	}
}
