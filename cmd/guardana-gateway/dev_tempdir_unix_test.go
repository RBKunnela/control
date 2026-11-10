//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDevRefusesATemporaryDirectoryAtTheSocketBound: a TMPDIR under which the
// longest directory os.MkdirTemp can draw puts dev's collector socket at 104
// bytes is refused, and one that puts it at 103 is not. The drawn suffix is
// written out, ten digits, so the test holds dev's estimate to the real one.
func TestDevRefusesATemporaryDirectoryAtTheSocketBound(t *testing.T) {
	longest := len("/" + collectDirPrefix + "0000000000" + "/" + collectSocket)
	orig := os.TempDir()
	for _, tc := range []struct {
		socket int
		refuse bool
	}{{104, true}, {103, false}} {
		t.Setenv("TMPDIR", orig)
		base := shortTempDir(t)
		state := filepath.Join(shortTempDir(t), "state")
		dir := filepath.Join(base, strings.Repeat("e", tc.socket-longest-len(base)-1))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
		t.Setenv("TMPDIR", dir)
		err := checkDemo(devInputs{config: d.config}, state)
		if refused := err != nil && strings.Contains(err.Error(), "set TMPDIR"); refused != tc.refuse {
			t.Errorf("a TMPDIR of %d bytes, the longest socket %d: checkDemo = %v", len(dir), tc.socket, err)
		}
	}
}
