//go:build unix

package holdjournal_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/holdjournal"
)

// TestTheLedgerKeepsTheJournalsOwnershipAndMode: a ledger directory another
// account owns, or a group may write, is refused at open and at every call
// after, and so is a mark another account owns or a symbolic link put at the
// ledger's name. Each control is the same directory restored.
func TestTheLedgerKeepsTheJournalsOwnershipAndMode(t *testing.T) {
	dir := newDir(t)
	ledger := filepath.Join(dir, "ledger")
	j, l := openLedger(t, dir)
	ctx := context.Background()
	if err := l.Spend(ctx, ledgerBinding, "req-1", "appr-1", "p", base()); err != nil {
		t.Fatalf("Spend: %v", err)
	}

	if err := os.Chmod(ledger, 0o770); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	if _, err := l.Lookup(ctx, ledgerBinding, base()); !errors.Is(err, holdjournal.ErrPermissions) {
		t.Errorf("a lookup in a group-writable ledger: %v, want ErrPermissions", err)
	}
	if err := os.Chmod(ledger, 0o700); err != nil { //nolint:gosec // G302: owner-only
		t.Fatal(err)
	}
	if _, err := l.Lookup(ctx, ledgerBinding, base()); err != nil {
		t.Errorf("the same lookup with the mode restored: %v", err)
	}

	restore := holdjournal.SetOwnerWanted(func(info fs.FileInfo) int {
		if info.IsDir() || info.Name() == "ledger.meta" {
			return os.Geteuid()
		}
		return os.Geteuid() + 1
	})
	if _, err := l.Lookup(ctx, ledgerBinding, base()); !errors.Is(err, holdjournal.ErrOwner) {
		t.Errorf("a lookup of a mark another account owns: %v, want ErrOwner", err)
	}
	restore()

	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	expectTheLedgerDirectoryJudged(t, dir)
}

// expectTheLedgerDirectoryJudged holds a closed journal's ledger directory to
// being refused when another account owns it or a symbolic link stands at its
// name.
func expectTheLedgerDirectoryJudged(t *testing.T, dir string) {
	t.Helper()
	ledger := filepath.Join(dir, "ledger")
	restore := holdjournal.SetOwnerWanted(func(info fs.FileInfo) int {
		if info.Name() == "ledger" {
			return os.Geteuid() + 1
		}
		return os.Geteuid()
	})
	j := openJournal(t, dir)
	if _, err := j.Ledger(); !errors.Is(err, holdjournal.ErrOwner) {
		t.Errorf("a ledger directory another account owns: %v, want ErrOwner", err)
	}
	restore()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	moved := filepath.Join(t.TempDir(), "real")
	if err := os.Rename(ledger, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, ledger); err != nil {
		t.Fatal(err)
	}
	if _, err := holdjournal.Open(dir); !errors.Is(err, holdjournal.ErrForeignFile) {
		t.Errorf("a journal with a symbolic link at the ledger's name: %v, want ErrForeignFile", err)
	}
}
