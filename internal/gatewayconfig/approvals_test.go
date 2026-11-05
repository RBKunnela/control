package gatewayconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileProvider is the block a configuration adds to keep its held requests in
// a directory an approver answers: the authority, the records and the plane's
// own journal, each in a directory of its own.
const fileProvider = `
approvals:
  authority: directory
  dir: approvals
  hold_journal_dir: holds
`

// signedBlock is the signed authority with every key it reads.
const signedBlock = `
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
`

// TestApprovalDefaultsStandWhereTheFileIsSilent pins what a configuration that
// names only its authority runs with, as literals.
func TestApprovalDefaultsStandWhereTheFileIsSilent(t *testing.T) {
	cfg := load(t, write(t, ""))
	switch {
	case cfg.Approvals.Authority != "memory":
		t.Errorf("approvals.authority is %q, want memory", cfg.Approvals.Authority)
	case cfg.Approvals.Dir != "" || cfg.Approvals.HoldJournalDir != "" || cfg.Approvals.InboxDir != "":
		t.Errorf("a silent configuration names directories %q, %q and %q", cfg.Approvals.Dir, cfg.Approvals.HoldJournalDir, cfg.Approvals.InboxDir)
	case cfg.Approvals.MaxRecords != 1024:
		t.Errorf("approvals.max_records is %d, want 1024", cfg.Approvals.MaxRecords)
	case cfg.Approvals.MaxRecordBytes != 16384:
		t.Errorf("approvals.max_record_bytes is %d, want 16384", cfg.Approvals.MaxRecordBytes)
	case cfg.Approvals.ReconcileMax != 256:
		t.Errorf("approvals.reconcile_max is %d, want 256", cfg.Approvals.ReconcileMax)
	}
}

// TestTheAuthorityHasNoDefault: a configuration that names no authority is
// refused, naming the key and the one it replaces; the same document naming
// one loads.
func TestTheAuthorityHasNoDefault(t *testing.T) {
	_, err := Load(writeDocument(t, strings.Replace(document, memoryAuthority, "", 1)), os.Environ())
	if err == nil {
		t.Fatal("a configuration naming no approval authority was accepted")
	}
	for _, want := range []string{"approvals.authority", "approvals.provider", "no default"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	load(t, write(t, ""))
}

// TestTheOldProviderKeyIsRefusedNamingItsReplacement: approvals.provider, in
// the file or the environment, is refused saying what to write instead; a key
// that never existed gets the plain refusal, so the message is the retired
// key's own.
func TestTheOldProviderKeyIsRefusedNamingItsReplacement(t *testing.T) {
	for name, path := range map[string]func(t *testing.T) string{
		"in the file": func(t *testing.T) string { return write(t, "\napprovals:\n  provider: file\n") },
		"in the environment": func(t *testing.T) string {
			path := write(t, "")
			setEnv(t, "approvals.provider", "file")
			return path
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(path(t), os.Environ())
			if err == nil {
				t.Fatal("approvals.provider was accepted")
			}
			for _, want := range []string{"approvals.provider", "approvals.authority", "file becomes directory"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not say %q: %v", want, err)
				}
			}
		})
	}
	_, err := Load(write(t, "\napprovals:\n  providers: file\n"), os.Environ())
	if err == nil || !strings.Contains(err.Error(), "is not a configuration key") || strings.Contains(err.Error(), "approvals.authority") {
		t.Errorf("a key that never existed: %v", err)
	}
}

// TestApproveNeedsAnAuthorityThatCanBeAnswered: APPROVE holds every allowed
// material call, so a store nothing outside the process can answer would hold
// each of them until it expired. The same mode with the directory authority
// is accepted, which is what makes this a refusal of the pair and not of the
// mode.
func TestApproveNeedsAnAuthorityThatCanBeAnswered(t *testing.T) {
	path := write(t, "")
	setEnv(t, "mode", "APPROVE")
	_, err := Load(path, os.Environ())
	if err == nil {
		t.Fatal("APPROVE was accepted with the memory authority, so every held call would expire")
	}
	if !strings.Contains(err.Error(), "approvals.authority") {
		t.Errorf("the refusal does not name the key: %v", err)
	}

	with := write(t, fileProvider)
	setEnv(t, "mode", "APPROVE")
	cfg := load(t, with)
	if cfg.ModeName != "APPROVE" || cfg.Approvals.Authority != AuthorityDirectory {
		t.Errorf("the accepted configuration is %s with %s", cfg.ModeName, cfg.Approvals.Authority)
	}
}

// TestADurableAuthorityNeedsBothDirectories: under directory and signed the
// records and the plane's own journal, with its ledger of spent approvals,
// are two durable artefacts, and a plane without the second could spend an
// approval twice across a restart.
func TestADurableAuthorityNeedsBothDirectories(t *testing.T) {
	for _, block := range []string{fileProvider, signedBlock} {
		for _, c := range []struct {
			drop  string
			names string
		}{
			{"  dir: approvals\n", "approvals.dir"},
			{"  hold_journal_dir: holds\n", "approvals.hold_journal_dir"},
		} {
			add := strings.Replace(block, c.drop, "", 1)
			if add == block {
				t.Fatalf("the block holds no %q", c.drop)
			}
			if _, err := Load(write(t, add), os.Environ()); err == nil || !strings.Contains(err.Error(), c.names) {
				t.Errorf("without %s: %v", c.names, err)
			}
		}
	}
	if _, err := Load(write(t, signedBlock), os.Environ()); err != nil {
		t.Errorf("the whole signed block was refused: %v", err)
	}
}

// TestTheSignedAuthorityNeedsEveryKeyItReads: each key the signed authority
// reads is required under it, and refused under any other, since a key that
// applies to nothing is a setting the operator believes is in force.
func TestTheSignedAuthorityNeedsEveryKeyItReads(t *testing.T) {
	for key, line := range map[string]string{
		"approvals.inbox_dir":          "  inbox_dir: inbox\n",
		"trust.root_public_key":        "  root_public_key: trust/root.pub\n",
		"trust.roster":                 "  roster: trust/roster.json\n",
		"trust.roster_id":              "  roster_id: roster-a\n",
		"trust.floor_dir":              "  floor_dir: trust/floors\n",
		"operators.authenticator.kind": "  authenticator:\n    kind: roster\n",
		"operators.authorizer.kind":    "  authorizer:\n    kind: roster\n",
	} {
		t.Run(key, func(t *testing.T) {
			without := strings.Replace(signedBlock, line, "", 1)
			if without == signedBlock {
				t.Fatalf("the block holds no %q", line)
			}
			if _, err := Load(write(t, without), os.Environ()); err == nil || !strings.Contains(err.Error(), key+": the signed authority needs it") {
				t.Errorf("signed without %s: %v", key, err)
			}
			path := write(t, fileProvider)
			setEnv(t, key, "roster")
			if _, err := Load(path, os.Environ()); err == nil || !strings.Contains(err.Error(), key+": only the signed authority reads it") {
				t.Errorf("directory with %s: %v", key, err)
			}
		})
	}
}

// TestTheInboxStandsApartFromThePlanesDirectories: operators write the inbox,
// and the plane alone writes the records, the journal and the spool.
func TestTheInboxStandsApartFromThePlanesDirectories(t *testing.T) {
	for _, dir := range []string{"approvals", "holds", "spool", "holds/inbox"} {
		add := strings.Replace(signedBlock, "  inbox_dir: inbox\n", "  inbox_dir: "+dir+"\n", 1)
		if _, err := Load(write(t, add), os.Environ()); err == nil || !strings.Contains(err.Error(), "approvals.inbox_dir") {
			t.Errorf("an inbox at %s: %v", dir, err)
		}
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
			add := "\napprovals:\n  authority: directory\n  dir: approvals\n  hold_journal_dir: " + c.journal + "\n"
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

// TestADirectoryUnderTheMemoryProviderIsRefused: a directory the memory
// authority never reads would sit in the file looking like a store nobody wrote to.
func TestADirectoryUnderTheMemoryProviderIsRefused(t *testing.T) {
	for _, key := range []string{"approvals.dir", "approvals.hold_journal_dir"} {
		t.Run(key, func(t *testing.T) {
			path := write(t, "")
			setEnv(t, key, filepath.Join(t.TempDir(), "elsewhere"))
			if _, err := Load(path, os.Environ()); err == nil {
				t.Fatalf("%s was accepted under the memory authority", key)
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
	mcpRuns := compose("\nruns:\n  dir: runs\n" + fileProvider)
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
