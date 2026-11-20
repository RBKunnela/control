//go:build unix

package attempts

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func writeJournal(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJournalFileIsJudgedBeforeItIsRead(t *testing.T) {
	dir := t.TempDir()
	good := writeJournal(t, dir, "orders.jsonl", "{\"call\":\"read_order\"}\n", 0o600)
	if j, err := ReadJournal(good); err != nil || len(j.Lines) != 1 {
		t.Fatalf("a journal as a victim writes it: %v, %v", j, err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, "second.jsonl")
	if err := os.Link(writeJournal(t, dir, "first.jsonl", "", 0o600), second); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, path string }{
		{"a missing journal", filepath.Join(dir, "web.jsonl")},
		{"a symbolic link", link},
		{"a file with a second name", second},
		{"a journal others may read", writeJournal(t, dir, "open.jsonl", "{\"call\":\"a\"}\n", 0o604)},
		{"a journal its group may read", writeJournal(t, dir, "group.jsonl", "{\"call\":\"a\"}\n", 0o640)},
		{"a named pipe", fifo},
		{"a directory", dir},
	} {
		if _, err := ReadJournal(c.path); !errors.Is(err, ErrJournal) {
			t.Errorf("%s: %v, want %v", c.name, err, ErrJournal)
		}
	}
}
