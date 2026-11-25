package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// twoAccountsStandIns are the commands scripts/two-accounts.sh runs, as
// stand-ins: sudo runs its command, id names an account other than root, and
// go builds a test binary for a package whose path ends in a_b alone, as go
// test -c writes nothing for a package with no test files. test2json runs
// the binary, logs whose binary ran under which package, and reports a pass
// of every listed test; the checker of runs passes whatever it reads, so the
// script's own refusals are all that can fail the run.
var twoAccountsStandIns = map[string]string{
	"sudo": "#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n",
	"id":   "#!/bin/sh\necho 1000\n",
	"go": `#!/bin/bash
set -eu
case "$1 $2" in
  "test -c")
    out="" pkg="${*: -1}"
    while [[ $# -gt 0 ]]; do [[ "$1" == -o ]] && out="$2"; shift; done
    if [[ "${pkg}" == *_b ]]; then
      printf '#!/bin/sh\necho "binary of %s"\n' "${pkg}" >"${out}"
      chmod 0755 "${out}"
    fi
    ;;
  "list -f") pwd ;;
  "tool test2json")
    pkg="$5"
    shift 5
    printf '%s ran %s\n' "${pkg}" "$("$@" | tr -d '\n')" >>"${STAND_IN_LOG}"
    printf '{"Action":"run","Package":"%s","Test":"TestX"}\n{"Action":"pass","Package":"%s","Test":"TestX"}\n{"Action":"pass","Package":"%s"}\n' "${pkg}" "${pkg}" "${pkg}"
    ;;
  "run scripts/check-runs.go") cat >/dev/null ;;
  *) echo "stand-in go: unexpected arguments: $*" >&2; exit 64 ;;
esac
`,
}

// TestTwoAccountsRunsEachPackageItsOwnBinary: two packages whose import
// paths differ only by a slash and an underscore, the second with no test
// file in the tagged build, must not share one binary file name, so the
// first package's binary never runs labelled as the second.
func TestTwoAccountsRunsEachPackageItsOwnBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "two-accounts.sh"))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"scripts/two-accounts.sh":   string(script),
		"scripts/expected-runs.txt": "example.com/m/internal/a_b TestX\nexample.com/m/internal/a/b TestX\n",
	}
	for name, body := range twoAccountsStandIns {
		files["bin/"+name] = body
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { //nolint:gosec // G306: the stand-ins run as programs
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "ran.log")
	cmd := exec.Command("/bin/bash", filepath.Join(dir, "scripts", "two-accounts.sh")) //nolint:gosec // G204: a staged copy of the repository's script
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "STAND_IN_LOG="+log,
		"GUARDANA_TEST_OTHER_UID=1001", "GUARDANA_TEST_THIRD_UID=1002")
	out, err := cmd.CombinedOutput()
	ran := readMaybe(t, log)
	if strings.Contains(ran, "example.com/m/internal/a/b ran binary of example.com/m/internal/a_b") {
		t.Errorf("the binary of example.com/m/internal/a_b ran labelled example.com/m/internal/a/b:\n%s", ran)
	}
	if !strings.Contains(ran, "example.com/m/internal/a_b ran binary of example.com/m/internal/a_b") {
		t.Errorf("the binary of example.com/m/internal/a_b did not run under its own name, so the case examined nothing:\n%s", ran)
	}
	const want = "two-accounts: example.com/m/internal/a/b built no test binary"
	if err == nil || !strings.Contains(string(out), want) {
		t.Errorf("two-accounts.sh = %v, want a failure saying %q:\n%s", err, want, out)
	}
}
