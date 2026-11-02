//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/brand"
)

// mkfifo makes a named pipe nobody writes to, which a blocking open or read
// would wait on for ever.
func mkfifo(t *testing.T, path string) string {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("making a pipe: %v", err)
	}
	return path
}

// within runs f and fails the test if it has not returned after a few
// seconds, so a read that waits on a pipe shows as a failure, not a hang.
func within[T any](t *testing.T, what string, f func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- f() }()
	select {
	case v := <-done:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s is waiting on a pipe with no writer", what)
		var zero T
		return zero
	}
}

// TestSignRefusesTheDocumentBeforeTheKey: the key is left readable by the
// group, so a document that got past its own read check would show as the
// key's refusal instead of the document's.
func TestSignRefusesTheDocumentBeforeTheKey(t *testing.T) {
	tr := newSignTree(t)
	if err := os.Chmod(tr.key, 0o640); err != nil { //nolint:gosec // G302: the key file mode sign must refuse
		t.Fatal(err)
	}
	pipe := mkfifo(t, filepath.Join(tr.dir, "policy.pipe"))
	over := filepath.Join(tr.dir, "over.json")
	if err := os.WriteFile(over, bytes.Repeat([]byte{' '}, 2097153), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"a named pipe":           {pipe, "document " + pipe + ": files: not a regular file: a named pipe"},
		"one byte over 2 MiB":    {over, "document " + over + ": files: over the size bound: limit 2097152"},
		"a directory, not a doc": {tr.dir, "document " + tr.dir + ": files: not a regular file: a directory"},
	} {
		o := within(t, "sign", func() outputs {
			code, stdout, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, c.doc)
			return outputs{code, stdout, stderr}
		})
		if o.code != exitFail || o.stdout != "" {
			t.Errorf("%s: exit %d, stdout %q", name, o.code, o.stdout)
		}
		if line, want := oneStderrLine(t, o.stderr), brand.CLI+": policy sign: "+c.want; line != want {
			t.Errorf("%s: stderr %q, want %q", name, line, want)
		}
	}
}

// TestLintAndTestRefuseAPipe: a named pipe given to policy lint, or reached as
// a case file by policy test, is refused at once as not a regular file.
func TestLintAndTestRefuseAPipe(t *testing.T) {
	pipe := mkfifo(t, filepath.Join(t.TempDir(), "policy.json"))
	o := within(t, "policy lint", func() outputs {
		code, stdout, stderr := invoke(t, "policy", "lint", pipe)
		return outputs{code, stdout, stderr}
	})
	if want := brand.CLI + ": policy lint: " + pipe + ": files: not a regular file: a named pipe"; o.code != exitFail || strings.TrimSuffix(o.stderr, "\n") != want {
		t.Errorf("policy lint of a pipe: exit %d, stderr %q; want %q", o.code, o.stderr, want)
	}
	type result struct {
		line string
		ok   bool
	}
	r := within(t, "a policy test case", func() result {
		line, ok := runCase(pipe)
		return result{line, ok}
	})
	if want := pipe + ": files: not a regular file: a named pipe"; r.ok || r.line != want {
		t.Errorf("a pipe as a case: %q, %v; want %q and a failure", r.line, r.ok, want)
	}
}

// TestPolicyTestRefusesACaseThatIsAPipe: a named pipe beside a passing case is
// refused by name before any case runs, never skipped while the rest pass.
func TestPolicyTestRefusesACaseThatIsAPipe(t *testing.T) {
	dir := caseDir(t, map[string]string{"case.json": base().json()})
	mkfifo(t, filepath.Join(dir, "deny-write.json"))
	o := within(t, "policy test", func() outputs {
		code, stdout, stderr := invoke(t, "policy", "test", dir)
		return outputs{code, stdout, stderr}
	})
	want := brand.CLI + ": policy test: " + dir + ": deny-write.json is not a regular file, so its case cannot run"
	if o.code != exitFail || o.stdout != "" || strings.TrimSuffix(o.stderr, "\n") != want {
		t.Errorf("exit %d, stdout %q, stderr %q; want %d, nothing and %q", o.code, o.stdout, o.stderr, exitFail, want)
	}
}
