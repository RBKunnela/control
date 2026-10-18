package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeWritingGh takes the calls scripts/lib/github-apply.sh makes. It logs
// each, with the body read from --input - after it, takes any write, and
// answers a read from a file named after the endpoint, through --jq when one
// is given; the endpoint FAKE_FAIL names is refused.
const fakeWritingGh = `#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == api ]] || { echo "fake gh: not an api call: $*" >&2; exit 64; }
shift
method=GET endpoint="" filter="" input=0 line="$*"
while (($#)); do
  case "$1" in
    --method) method="$2"; shift 2 ;;
    --jq) filter="$2"; shift 2 ;;
    --input) [[ "$2" == - ]] || exit 64; input=1; shift 2 ;;
    --paginate) shift ;;
    -*) echo "fake gh: refusing $1" >&2; exit 64 ;;
    *) endpoint="$1"; shift ;;
  esac
done
if ((input)); then line="${line} <<< $(cat)"; fi
printf '%s\n' "${line}" >>"${FAKE_DIR}/calls"
[[ "${method}" == GET ]] || exit 0
if [[ "${endpoint}" == "${FAKE_FAIL:-}" ]]; then
  echo "gh: Server Error (HTTP 500)" >&2
  exit 1
fi
file="${FAKE_DIR}/answers/$(printf '%s' "${endpoint}" | tr '/?&=' '____')"
[[ -f "${file}" ]] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
jq -r "${filter:-.}" <"${file}"
`

const githubApply = "scripts/lib/github-apply.sh"

// policiesEndpoint is where the fake serves the environment's policies.
const policiesEndpoint = "repos/acme/demo/environments/testpypi/deployment-branch-policies"

// applyEnvironment runs apply_environment for testpypi, wanting the branch
// policy main, against a fake gh that lists policies, and returns the output,
// the exit status and the calls made.
func applyEnvironment(t *testing.T, policies, fail string) (string, int, []string) {
	t.Helper()
	dir := t.TempDir()
	bin, answers := filepath.Join(dir, "bin"), filepath.Join(dir, "answers")
	for _, d := range []string{bin, answers} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"bash", "jq", "tr", "cat"} {
		if err := os.Symlink(settingsTool(t, tool), filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeWritingGh), 0o700); err != nil { //nolint:gosec // G306: the fake has to be executable
		t.Fatal(err)
	}
	writeAnswer(t, filepath.Join(answers, strings.ReplaceAll(policiesEndpoint, "/", "_")), rawAnswer(policies))
	script := `set -euo pipefail; . ` + githubSettings + `; . ` + githubApply + `; ` +
		`apply_environment testpypi '{"env":1}' '{"name":"main","type":"branch"}' branch main`
	cmd := exec.Command(settingsTool(t, "bash"), "-c", script) //nolint:gosec // G204: bash from PATH sourcing this repository's own scripts
	cmd.Dir = repoRoot(t)
	cmd.Env = append(slices.Clone(settingsEnv), "PATH="+bin, "FAKE_DIR="+dir, "FAKE_FAIL="+fail, "HOME="+dir)
	out, err := fileOutput(t, cmd, true)
	code := exitCode(t, err)
	calls, err := os.ReadFile(filepath.Join(dir, "calls")) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	return out, code, strings.Split(strings.TrimSuffix(string(calls), "\n"), "\n")
}

const (
	putEnvironment = `--method PUT repos/acme/demo/environments/testpypi --input - <<< {"env":1}`
	listPolicies   = `repos/acme/demo/environments/testpypi/deployment-branch-policies --paginate --jq .branch_policies[] | "\(.id) \(.type) \(.name)"`
	postPolicy     = `--method POST repos/acme/demo/environments/testpypi/deployment-branch-policies --input - <<< {"name":"main","type":"branch"}`
)

func deletePolicy(id string) string {
	return "--method DELETE repos/acme/demo/environments/testpypi/deployment-branch-policies/" + id
}

// TestAnEnvironmentKeepsOnlyItsDeclaredPolicy: apply_environment sets the
// environment, deletes every policy but the declared one, a policy of the
// declared name and another type included, and adds the declared policy only
// when the environment lacks it.
func TestAnEnvironmentKeepsOnlyItsDeclaredPolicy(t *testing.T) {
	for _, c := range []struct {
		name, policies string
		want           []string
		says           string
	}{
		{"the declared policy among others",
			`{"branch_policies":[{"id":1,"type":"branch","name":"main"},{"id":2,"type":"branch","name":"release/*"},{"id":3,"type":"tag","name":"main"}]}`,
			[]string{putEnvironment, listPolicies, deletePolicy("2"), deletePolicy("3")},
			"environment testpypi already takes the branch main"},
		{"no declared policy",
			`{"branch_policies":[{"id":5,"type":"tag","name":"v*"}]}`,
			[]string{putEnvironment, listPolicies, deletePolicy("5"), postPolicy}, ""},
		{"no policy at all",
			`{"branch_policies":[]}`,
			[]string{putEnvironment, listPolicies, postPolicy}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, code, calls := applyEnvironment(t, c.policies, "")
			if code != 0 || !slices.Equal(calls, c.want) {
				t.Fatalf("exit %d, calls\n%s\nwant\n%s\noutput:\n%s", code, strings.Join(calls, "\n"), strings.Join(c.want, "\n"), out)
			}
			if c.says != "" && !strings.Contains(out, c.says) {
				t.Errorf("the output does not say %q:\n%s", c.says, out)
			}
		})
	}
}

// TestAFailedPolicyListingStopsTheRun: a listing GitHub refuses ends the run
// before any policy is deleted or added, so a stray policy is never left in
// place behind a report of success.
func TestAFailedPolicyListingStopsTheRun(t *testing.T) {
	out, code, calls := applyEnvironment(t, `{"branch_policies":[{"id":2,"type":"branch","name":"release/*"}]}`, policiesEndpoint)
	if code == 0 || !slices.Equal(calls, []string{putEnvironment, listPolicies}) {
		t.Fatalf("exit %d, calls\n%s\nwant a failure after the listing\noutput:\n%s", code, strings.Join(calls, "\n"), out)
	}
}
