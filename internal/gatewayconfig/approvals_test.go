package gatewayconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileProvider is the block a configuration adds to keep its held requests in
// a directory: the provider, the records and the plane's own journal, each in
// a directory of its own.
const fileProvider = `
approvals:
  provider: file
  dir: approvals
  hold_journal_dir: holds
`

// TestApprovalDefaultsStandWhereTheFileIsSilent pins what a configuration that
// says nothing about approvals runs with, as literals.
func TestApprovalDefaultsStandWhereTheFileIsSilent(t *testing.T) {
	cfg := load(t, write(t, ""))
	switch {
	case cfg.Approvals.Provider != ProviderMemory:
		t.Errorf("approvals.provider is %q, want %q", cfg.Approvals.Provider, ProviderMemory)
	case cfg.Approvals.Dir != "" || cfg.Approvals.HoldJournalDir != "":
		t.Errorf("a silent configuration names directories %q and %q", cfg.Approvals.Dir, cfg.Approvals.HoldJournalDir)
	case cfg.Approvals.MaxRecords != 1024:
		t.Errorf("approvals.max_records is %d, want 1024", cfg.Approvals.MaxRecords)
	case cfg.Approvals.MaxRecordBytes != 16384:
		t.Errorf("approvals.max_record_bytes is %d, want 16384", cfg.Approvals.MaxRecordBytes)
	case cfg.Approvals.ReconcileMax != 256:
		t.Errorf("approvals.reconcile_max is %d, want 256", cfg.Approvals.ReconcileMax)
	}
}

// TestApproveNeedsAProviderThatCanBeAnswered: APPROVE holds every allowed
// material call, so a store nothing outside the process can answer would hold
// each of them until it expired. The same mode with the file provider is
// accepted, which is what makes this a refusal of the pair and not of the mode.
func TestApproveNeedsAProviderThatCanBeAnswered(t *testing.T) {
	path := write(t, "")
	setEnv(t, "mode", "APPROVE")
	_, err := Load(path, os.Environ())
	if err == nil {
		t.Fatal("APPROVE was accepted with the memory provider, so every held call would expire")
	}
	if !strings.Contains(err.Error(), "approvals.provider") {
		t.Errorf("the refusal does not name the key: %v", err)
	}

	with := write(t, fileProvider)
	setEnv(t, "mode", "APPROVE")
	cfg := load(t, with)
	if cfg.ModeName != "APPROVE" || cfg.Approvals.Provider != ProviderFile {
		t.Errorf("the accepted configuration is %s with %s", cfg.ModeName, cfg.Approvals.Provider)
	}
}

// TestTheFileProviderNeedsBothDirectories: the records and the plane's own
// journal of its own holds are two durable artefacts, and a plane that keeps
// the first without the second closes no hold it loses (ADR-0016).
func TestTheFileProviderNeedsBothDirectories(t *testing.T) {
	for _, c := range []struct {
		name  string
		add   string
		names string
	}{
		{"no directory at all", "\napprovals:\n  provider: file\n", "approvals.dir"},
		{"records but no journal", "\napprovals:\n  provider: file\n  dir: approvals\n", "approvals.hold_journal_dir"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load(write(t, c.add), os.Environ()); err == nil {
				t.Fatalf("the file provider was accepted %s", c.name)
			} else if !strings.Contains(err.Error(), c.names) {
				t.Errorf("the refusal does not name %s: %v", c.names, err)
			}
		})
	}
}

// TestTheJournalIsNotInADirectoryAnotherWriterOwns: the spool owns and locks
// its own directory, and an approver may write the approvals directory. The
// journal is as trusted as the evidence, so nothing but the plane writes it.
func TestTheJournalIsNotInADirectoryAnotherWriterOwns(t *testing.T) {
	for _, c := range []struct {
		name    string
		journal string
	}{
		{"the spool's own directory", "spool"},
		{"a directory inside the spool's", "spool/holds"},
		{"a directory the spool sits in", "."},
		{"the approvals directory", "approvals"},
		{"a directory inside the approvals directory", "approvals/holds"},
	} {
		t.Run(c.name, func(t *testing.T) {
			add := "\napprovals:\n  provider: file\n  dir: approvals\n  hold_journal_dir: " + c.journal + "\n"
			_, err := Load(write(t, add), os.Environ())
			if err == nil {
				t.Fatalf("the journal was accepted in %s", c.name)
			}
			if !strings.Contains(err.Error(), "approvals.hold_journal_dir") {
				t.Errorf("the refusal does not name the key: %v", err)
			}
		})
	}
}

// TestADirectoryUnderTheMemoryProviderIsRefused: a directory the provider
// never reads would sit in the file looking like a store nobody wrote to.
func TestADirectoryUnderTheMemoryProviderIsRefused(t *testing.T) {
	for _, key := range []string{"approvals.dir", "approvals.hold_journal_dir"} {
		t.Run(key, func(t *testing.T) {
			path := write(t, "")
			setEnv(t, key, filepath.Join(t.TempDir(), "elsewhere"))
			if _, err := Load(path, os.Environ()); err == nil {
				t.Fatalf("%s was accepted under the memory provider", key)
			} else if !strings.Contains(err.Error(), key) {
				t.Errorf("the refusal does not name the key: %v", err)
			}
		})
	}
}

// TestAnApprovalBoundHasToBePositive: a store that takes no record, or a
// reconciliation that reads nothing, would otherwise be configured by a zero
// and could still report itself done.
func TestAnApprovalBoundHasToBePositive(t *testing.T) {
	for _, key := range []string{"approvals.max_records", "approvals.max_record_bytes", "approvals.reconcile_max"} {
		for _, value := range []string{"0", "-1"} {
			t.Run(key+"="+value, func(t *testing.T) {
				path := write(t, "")
				setEnv(t, key, value)
				if _, err := Load(path, os.Environ()); err == nil {
					t.Fatalf("%s was accepted as %s", key, value)
				} else if !strings.Contains(err.Error(), key) {
					t.Errorf("the refusal does not name the key: %v", err)
				}
			})
		}
	}
}

// TestTheBoundOnOneRunsHoldsStaysBelowThePlanes: under opened runs one run
// holds fewer requests than the plane, or it alone fills every hold of every
// other run; the bound is positive, defaults to 16, and is read only where a
// runs directory serves opened runs, an MCP listener's or an enforce_api one's.
func TestTheBoundOnOneRunsHoldsStaysBelowThePlanes(t *testing.T) {
	if cfg := load(t, writeDocument(t, enforceDocument)); cfg.Approvals.MaxHeldPerRun != 16 {
		t.Errorf("approvals.max_held_per_run defaults to %d, want 16", cfg.Approvals.MaxHeldPerRun)
	}
	mcpRuns := document + "\nruns:\n  dir: runs\n" + fileProvider
	for _, doc := range []string{enforceDocument, mcpRuns} {
		for _, env := range []map[string]string{
			{"approvals.max_held": "17"},
			{"approvals.max_held_per_run": "3", "approvals.max_held": "4"},
			{"approvals.max_held_per_run": "1", "approvals.max_held": "2"},
		} {
			path := writeDocument(t, doc)
			for k, v := range env {
				setEnv(t, k, v)
			}
			if _, err := Load(path, os.Environ()); err != nil {
				t.Errorf("%v was refused: %v", env, err)
			}
		}
		refusedSaying(t, doc, map[string]string{"approvals.max_held": "16"}, "approvals.max_held_per_run: 16 is at or above approvals.max_held")
		refusedSaying(t, doc, map[string]string{"approvals.max_held_per_run": "4", "approvals.max_held": "4"}, "approvals.max_held_per_run: ")
		refusedSaying(t, doc, map[string]string{"approvals.max_held_per_run": "0"}, "approvals.max_held_per_run: ")
		refusedSaying(t, doc, map[string]string{"approvals.max_held_per_run": "-1"}, "approvals.max_held_per_run: ")
	}
	if cfg := load(t, write(t, "")); cfg.Approvals.MaxHeld != 128 {
		t.Fatalf("approvals.max_held = %d", cfg.Approvals.MaxHeld)
	}
	path := write(t, "")
	setEnv(t, "approvals.max_held", "8")
	if _, err := Load(path, os.Environ()); err != nil {
		t.Errorf("approvals.max_held 8 without a runs directory was refused: %v", err)
	}
	refusedSaying(t, document, map[string]string{"approvals.max_held_per_run": "4"}, "approvals.max_held_per_run: set, and no runs.dir")
}
