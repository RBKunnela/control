//go:build unix

package pause

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestMergeRefusesASignedFile: a union of a signed file needs an operator's
// signature, so neither side may be one.
func TestMergeRefusesASignedFile(t *testing.T) {
	signed, err := signFile(header("alice", 1), Document{Entries: []Entry{globalEntry}}, signer("alice"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := Marshal(Document{Entries: []Entry{globalEntry}})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pause.json")
	if _, err := Merge(context.Background(), path, signed); !errors.Is(err, ErrSigned) {
		t.Fatalf("a signed backup: err = %v, want ErrSigned", err)
	}
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(context.Background(), path, unsigned); !errors.Is(err, ErrSigned) {
		t.Fatalf("a signed live file: err = %v, want ErrSigned", err)
	}
}
