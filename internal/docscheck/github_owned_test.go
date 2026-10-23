package docscheck

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const bootstrapScript = "scripts/github-bootstrap.sh"

// TestTheBootstrapPreflightRunsTheCodeownersGate: the bootstrap's preflight
// runs the test that gates CODEOWNERS, named by this package's function, and
// passes only on that test's own PASS line, never on a run that tested
// nothing.
func TestTheBootstrapPreflightRunsTheCodeownersGate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), bootstrapScript))
	if err != nil {
		t.Fatal(err)
	}
	name := runtime.FuncForPC(reflect.ValueOf(TestCodeownersCoverTheGuardedTrees).Pointer()).Name()
	name = name[strings.LastIndex(name, ".")+1:]
	if !regexp.MustCompile(`(?m)^CODEOWNERS_TEST="` + name + `"$`).Match(data) {
		t.Fatalf("%s does not set CODEOWNERS_TEST=%q", bootstrapScript, name)
	}
	preflight := regexp.MustCompile(`(?ms)^CODEOWNERS_TEST=.*?^require_security_owned\(\) \{.*?^\}$`).Find(data)
	if preflight == nil {
		t.Fatalf("%s: no require_security_owned after CODEOWNERS_TEST", bootstrapScript)
	}
	for _, c := range []struct {
		out  string
		rc   int
		pass bool
	}{
		{"=== RUN   " + name + "\n--- PASS: " + name + " (0.42s)\nPASS", 0, true},
		{"ok  \tgithub.com/guardana/control/internal/docscheck\t0.01s [no tests to run]", 0, false},
		{"--- SKIP: " + name + " (0.00s)\nPASS", 0, false},
		{"--- PASS: " + name + "Elsewhere (0.01s)\nPASS", 0, false},
		{"--- PASS: " + name + " (0.42s)\nFAIL", 1, false},
		{"--- FAIL: " + name + " (0.42s)\n    gives go.mod to [\"@all\"]\nFAIL", 1, false},
	} {
		out, call, err := runPreflight(t, string(preflight), c.out, c.rc)
		if passed := err == nil && strings.Contains(out, "preflight: every two-approval path is owned"); passed != c.pass {
			t.Errorf("go test printing %q, exit %d: preflight passed %v, want %v\n%s", c.out, c.rc, passed, c.pass, out)
		}
		if want := "test -count=1 -v -run ^" + name + "$ ./internal/docscheck"; call != want {
			t.Errorf("the preflight ran go %q, want go %q in REPO_ROOT", call, want)
		}
	}
}

// runPreflight runs require_security_owned, from a directory other than
// REPO_ROOT, with a go on PATH that prints out and exits with rc. It returns
// what the preflight printed and the arguments go was called with, when it
// was called in REPO_ROOT.
func runPreflight(t *testing.T, preflight, out string, rc int) (string, string, error) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH: %v", err)
	}
	bin, root := t.TempDir(), t.TempDir()
	call := filepath.Join(bin, "call")
	stub := "#!/bin/sh\n[ \"$PWD\" = \"$REPO_ROOT\" ] && echo \"$*\" >\"$GO_STUB_CALL\"\n" +
		"printf '%s\\n' \"$GO_STUB_OUT\"\nexit \"$GO_STUB_RC\"\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(stub), 0o700); err != nil { //nolint:gosec // G306, G703: an executable stub in this test's own directory
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "-c", "set -euo pipefail\n"+preflight+"\nrequire_security_owned") //nolint:gosec // G204: bash from PATH running this repository's own function
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"REPO_ROOT="+root, "GO_STUB_CALL="+call, "GO_STUB_OUT="+out, "GO_STUB_RC="+strconv.Itoa(rc))
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stdout
	err = cmd.Run()
	called, readErr := os.ReadFile(call) //nolint:gosec // G304: a file in this test's own directory
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		t.Fatal(readErr)
	}
	return stdout.String(), strings.TrimSuffix(string(called), "\n"), err
}
