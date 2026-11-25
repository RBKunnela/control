//go:build unix

package policykey_test

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/guardana/control/internal/policykey"
)

// A named pipe at the path is refused at once, never opened and waited on.
func TestWriteStatementRefusesANamedPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "statement.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policykey.WriteStatement(t.Context(), path, signedStatement(t)); !errors.Is(err, policykey.ErrStatementOut) {
		t.Fatalf("a named pipe: %v, want ErrStatementOut", err)
	}
}
