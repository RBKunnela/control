//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/holdjournal"
)

// TestDoctorJudgesTheApprovalDirectoriesAsRunOpensThem: each directory the
// file provider names is refused by doctor where `run`'s open refuses it, a
// mode a group may write and another account's ownership, through a link as
// directly, and a link to a sound directory passes, as `run` follows one.
// Each refusal is first shown to be one the store's own open makes, and
// doctor's line carries that store's own refusal.
func TestDoctorJudgesTheApprovalDirectoriesAsRunOpensThem(t *testing.T) {
	for _, key := range []string{"approvals.dir", "approvals.hold_journal_dir"} {
		t.Run(key, func(t *testing.T) {
			groupWritable := storeRefusal(key, approvals.ErrPermissions, holdjournal.ErrPermissions) + ": mode 0770"
			t.Run("group-writable", func(t *testing.T) {
				tr := newTree(t)
				dir := tr.approvalDir(t, key)
				chmod(t, dir, 0o770)
				expectStoreRefuses(t, key, dir)
				expectDoctorRefuses(t, tr, key+": ", groupWritable)
			})
			t.Run("a link to a group-writable directory", func(t *testing.T) {
				tr := newTree(t)
				target := filepath.Join(tr.dir, "shared")
				if err := os.Mkdir(target, 0o750); err != nil {
					t.Fatal(err)
				}
				chmod(t, target, 0o770)
				link := tr.linkApprovalDir(t, key, target)
				expectStoreRefuses(t, key, link)
				expectDoctorRefuses(t, tr, key+": ", groupWritable)
			})
			t.Run("owned by another account", func(t *testing.T) {
				if os.Geteuid() == 0 {
					t.Skip("the root account owns the directory this case points at, so nothing here is another account's")
				}
				tr := newTree(t)
				tr.approvalDir(t, key)
				setEnv(t, key, "/usr")
				expectStoreRefuses(t, key, "/usr")
				expectDoctorRefuses(t, tr, key+": ", storeRefusal(key, approvals.ErrOwner, holdjournal.ErrOwner))
			})
			t.Run("a link to a sound directory", func(t *testing.T) {
				tr := newTree(t)
				target := filepath.Join(tr.dir, "elsewhere")
				if err := os.Mkdir(target, 0o750); err != nil {
					t.Fatal(err)
				}
				tr.linkApprovalDir(t, key, target)
				var out bytes.Buffer
				doctor(context.Background(), tr.config, &out, &out)
				if !strings.Contains(out.String(), "\nok      approvals ") {
					t.Errorf("a link to a directory run opens is refused:\n%s", out.String())
				}
			})
		})
	}
}

// TestDoctorJudgesTheSpentLedgerAsRunOpensIt: a ledger beside the hold
// journal that run refuses to open, by a damaged marker, a name it did not
// write or a mark that will not decode, fails doctor, which names the
// ledger; the intact ledger passes.
func TestDoctorJudgesTheSpentLedgerAsRunOpensIt(t *testing.T) {
	for _, c := range []struct {
		name   string
		damage func(t *testing.T, ledger string)
		why    string
	}{
		{"a damaged marker", func(t *testing.T, ledger string) {
			writeOver(t, filepath.Join(ledger, "ledger.meta"), "{\"schema_version\":\"1.0\",\"kind\":\"journal\"}\n")
		}, `the ledger's marker names kind "journal"`},
		{"a name the ledger did not write", func(t *testing.T, ledger string) {
			writeOver(t, filepath.Join(ledger, "notes.txt"), "x\n")
		}, `the ledger's "notes.txt"`},
		{"a mark that will not decode", func(t *testing.T, ledger string) {
			marks, err := filepath.Glob(filepath.Join(ledger, "*"))
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, m := range marks {
				if filepath.Base(m) != "ledger.meta" {
					writeOver(t, m, "not a mark\n")
					n++
				}
			}
			if n != 1 {
				t.Fatalf("the ledger holds %d mark(s), want the one this test spent", n)
			}
		}, "the spent ledger, which run opens and sweeps: the ledger's \""},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			_, holds := tr.fileProvider(t)
			spendOnce(t, holds)
			if line := doctorLine(t, tr, "ok      approvals "); !strings.Contains(line, "the spent ledger holds 1 mark(s)") {
				t.Fatalf("the intact ledger's line is %q, want it to count the one mark", line)
			}
			c.damage(t, filepath.Join(holds, "ledger"))
			if _, j, err := openJournal(tr.load(t)); err == nil {
				_ = j.Close()
				t.Fatal("run opens the damaged ledger, so the case is not one run refuses")
			}
			expectDoctorRefuses(t, tr, "approvals.hold_journal_dir: ", c.why)
		})
	}
}

// spendOnce makes the journal in holds and its ledger, and spends one
// approval in it, as a plane that resumed one hold leaves them.
func spendOnce(t *testing.T, holds string) {
	t.Helper()
	j, err := holdjournal.Open(holds)
	if err != nil {
		t.Fatalf("opening the journal: %v", err)
	}
	l, err := j.Ledger()
	if err != nil {
		t.Fatalf("opening the ledger: %v", err)
	}
	if err := l.Spend(context.Background(), approval.Binding("binding-a"), "req-1", "appr-1", "alice", time.Now()); err != nil {
		t.Fatalf("Spend: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("closing the journal: %v", err)
	}
}

func writeOver(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// approvalDir sets the tree up for the directory authority and returns the
// directory key names.
func (tr tree) approvalDir(t *testing.T, key string) string {
	t.Helper()
	records, holds := tr.fileProvider(t)
	if key == "approvals.dir" {
		return records
	}
	return holds
}

// linkApprovalDir sets the tree up for the directory authority and points key at a
// link to target.
func (tr tree) linkApprovalDir(t *testing.T, key, target string) string {
	t.Helper()
	tr.approvalDir(t, key)
	link := filepath.Join(tr.dir, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	setEnv(t, key, link)
	return link
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// expectStoreRefuses opens dir with the handle of key's store that takes no
// lock, which judges the directory as the plane's open does, and wants a
// refusal.
func expectStoreRefuses(t *testing.T, key, dir string) {
	t.Helper()
	var err error
	if key == "approvals.dir" {
		var a *approvals.Approver
		if a, err = approvals.OpenApprover(dir); err == nil {
			_ = a.Close()
		}
	} else {
		var j *holdjournal.Journal
		if j, err = holdjournal.OpenReadOnly(dir); err == nil {
			_ = j.Close()
		}
	}
	if err == nil {
		t.Fatalf("the store opens %s, so the case is not one run refuses", dir)
	}
}

// storeRefusal is the text of the refusal key's store makes.
func storeRefusal(key string, records, holds error) string {
	if key == "approvals.dir" {
		return records.Error()
	}
	return holds.Error()
}

// expectDoctorRefuses wants the approvals check to fail, naming key and why.
func expectDoctorRefuses(t *testing.T, tr tree, key, why string) {
	t.Helper()
	line := doctorLine(t, tr, "fail    approvals ")
	if !strings.Contains(line, key) || !strings.Contains(line, why) {
		t.Errorf("the approvals line is %q, want it to name %q and %q", line, key, why)
	}
}
