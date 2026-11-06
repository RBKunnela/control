//go:build unix

package inbox_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/approvals/inbox"
)

// TestAnAnswerFileIsNeverReplaced: File links an answer into the inbox mode
// 0644 whatever the umask, refuses a second file of the same name and leaves
// the first as it was, and refuses a name the inbox would not read.
func TestAnAnswerFileIsNeverReplaced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "inbox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	in, err := inbox.OpenInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	name, err := inbox.AnswerFileName("APPROVAL1", "ed25519-0011223344556677-approve")
	if err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o077)
	err = in.File(name, []byte("first"))
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.File(name, []byte("second")); !errors.Is(err, approvals.ErrAnswerFiled) {
		t.Errorf("a second file of one name = %v, want ErrAnswerFiled", err)
	}
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the answer file: %v, %v; want mode 0644", info, err)
	}
	if got := readTestFile(t, filepath.Join(dir, name)); string(got) != "first" {
		t.Errorf("the answer file reads %q, want the first", got)
	}
	if err := in.File("APPROVAL1.answer", []byte("x")); !errors.Is(err, approvals.ErrRecordName) {
		t.Errorf("a name with no label = %v, want ErrRecordName", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("the inbox holds %d entries (%v), want the one answer", len(entries), err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file this test wrote
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
