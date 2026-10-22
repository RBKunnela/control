package docscheck

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A stand-in for shellcheck: it refuses the one planted script, so the test
// judges which files check-shell hands it, not what shellcheck makes of them.
const shellcheckStandIn = `#!/bin/bash
for arg in "$@"; do
  [[ "${arg}" != tools/run ]] || { echo "stand-in shellcheck: tools/run handed over"; exit 1; }
done
`

// TestCheckShellReadsAScriptNamedWithoutSh: a script without the .sh suffix is
// handed to shellcheck under every first line that names sh, bash, dash or
// ksh in /bin, /usr/bin or /usr/local/bin, directly or through env, and a
// file that names another interpreter, or none, is left alone.
func TestCheckShellReadsAScriptNamedWithoutSh(t *testing.T) {
	for _, first := range []string{
		"#!/bin/bash", "#!/bin/sh", "#!/usr/bin/env bash", "#!/bin/bash -eu", "#!/usr/bin/bash",
		"#!/usr/local/bin/bash", "#!/usr/bin/env -S bash -e", "#! /bin/bash", "#!/bin/dash", "#!/bin/ksh",
		"#!/bin/bash\r",
	} {
		out, err := runCheckShell(t, map[string]string{"tools/run": first + "\necho hi\n"})
		if err == nil || !strings.Contains(out, "tools/run handed over") {
			t.Errorf("%q: check-shell = %v, want tools/run handed to shellcheck:\n%s", first, err, out)
		}
	}
	for _, first := range []string{"#!/usr/bin/env python3", "#!/bin/bashful", "no first line of a script"} {
		if out, err := runCheckShell(t, map[string]string{"tools/run": first + "\necho hi\n"}); err != nil {
			t.Errorf("%q: check-shell = %v, want it left alone:\n%s", first, err, out)
		}
	}
}

// TestCheckShellRefusesAFileItCannotRead: a listed file whose first line
// cannot be read might be a script, so the check refuses rather than pass
// over it.
func TestCheckShellRefusesAFileItCannotRead(t *testing.T) {
	out, err := runCheckShell(t, map[string]string{"tools/locked": "#!/bin/bash\necho hi\n"}, "tools/locked")
	if err == nil || !strings.Contains(out, "could not read the first line") {
		t.Fatalf("check-shell = %v, want the unreadable file refused:\n%s", err, out)
	}
}

// runCheckShell runs check-shell over a tree with no .git that holds the
// script, its library, one workflow and the files given, with the stand-in
// shellcheck first on PATH; each path in unreadable is made unreadable, and
// the test skips when that does not hold, as it cannot for root.
func runCheckShell(t *testing.T, planted map[string]string, unreadable ...string) (string, error) {
	t.Helper()
	root := repoRoot(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scripts/check-shell.sh", "scripts/lib/repo-files.sh", ".github/workflows/pull-request.yml"} {
		data, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // G304: a file of this repository the test names
		if err != nil {
			t.Fatal(err)
		}
		place(t, dir, name, data, 0o600)
	}
	for name, content := range planted {
		place(t, dir, name, []byte(content), 0o600)
	}
	place(t, dir, "bin/shellcheck", []byte(shellcheckStandIn), 0o700)
	for _, name := range unreadable {
		path := filepath.Join(dir, name)
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		if f, err := os.Open(path); err == nil { //nolint:gosec // G304: a path under this test's own temporary directory
			_ = f.Close()
			t.Skipf("%s stays readable to this account, so there is nothing to refuse", name)
		}
	}
	cmd := exec.Command("/bin/bash", filepath.Join(dir, "scripts", "check-shell.sh")) //nolint:gosec // G204: the script this test staged
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return out.String(), err
}

func place(t *testing.T, dir, name string, data []byte, perm os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, perm); err != nil { //nolint:gosec // G703: a path under this test's own temporary directory
		t.Fatal(err)
	}
}
