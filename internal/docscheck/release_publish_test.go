package docscheck

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// releaseStepRun is the run block of the step of that name in the release
// workflow's job, with the block's indentation removed.
func releaseStepRun(t *testing.T, jobName, name string) string {
	t.Helper()
	root, err := parseBlockYAML(readLines(t, repoFS(t), releaseWorkflowPath))
	if err != nil {
		t.Fatalf("%s: %v", releaseWorkflowPath, err)
	}
	var found []string
	for _, jobs := range root.children("jobs") {
		for _, job := range jobs.children(jobName) {
			for _, steps := range job.children("steps") {
				for _, step := range steps.kids {
					found = append(found, stepScripts(step, name)...)
				}
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: %d run block(s) of a %s step named %q, want 1", releaseWorkflowPath, len(found), jobName, name)
	}
	return found[0]
}

// stepScripts is the script of each run of step when the step has that name:
// a block without its indentation, or a one-line run.
func stepScripts(step *yamlNode, name string) []string {
	if !slices.ContainsFunc(step.children("name"), func(n *yamlNode) bool { return n.value == name }) {
		return nil
	}
	var scripts []string
	for _, run := range step.children("run") {
		switch {
		case run.value == "|":
			scripts = append(scripts, dedent(run.block))
		case run.value != "":
			scripts = append(scripts, run.value+"\n")
		}
	}
	return scripts
}

func dedent(lines []string) string {
	cut := -1
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if n := len(l) - len(strings.TrimLeft(l, " ")); cut < 0 || n < cut {
			cut = n
		}
	}
	var b strings.Builder
	for _, l := range lines {
		if len(l) >= cut && cut >= 0 {
			l = l[cut:]
		}
		b.WriteString(strings.TrimRight(l, " ") + "\n")
	}
	return b.String()
}

// releaseStandIns answer the calls the Publish, the image tag and the upload
// steps make, keeping the draft's tag, state and body in files under $STUB,
// and logging every call to gh, curl, the gate check and the upload in
// $STUB/calls. STUB_RETAG moves
// the draft to another tag once its assets are read, as a writer could;
// STUB_KEEP_TAG makes the publication leave the tag as it finds it; STUB_GATE
// set to refuse makes the gate check fail, as it does once main has moved.
var releaseStandIns = map[string]string{
	"bin/gh": `#!/bin/bash
set -eu
printf 'gh %s\n' "$*" >>"${STUB}/calls"
[[ "$1" == api ]] || exit 64
shift
case "$*" in
  "repos/${GITHUB_REPOSITORY}/releases?per_page=100 --paginate")
    printf '[{"id": 42, "draft": %s, "tag_name": "%s"}]\n' "$(cat "${STUB}/draft")" "$(cat "${STUB}/tag")"
    ;;
  "repos/${GITHUB_REPOSITORY}/releases/42/assets?per_page=100 --paginate --jq "*)
    for f in dist/*; do printf '%s sha256:%s\n' "${f#dist/}" "$(sha256sum "${f}" | cut -d' ' -f1)"; done
    if [[ -n "${STUB_RETAG:-}" && ! -e "${STUB}/retagged" ]]; then
      printf '%s' "${STUB_RETAG}" >"${STUB}/tag"
      : >"${STUB}/retagged"
    fi
    ;;
  "--method PATCH repos/${GITHUB_REPOSITORY}/releases/42 "*)
    for arg in "$@"; do
      case "${arg}" in
        tag_name=*) [[ -n "${STUB_KEEP_TAG:-}" ]] || printf '%s' "${arg#tag_name=}" >"${STUB}/tag" ;;
        draft=false) printf 'false' >"${STUB}/draft" ;;
        body=@*) cp "${arg#body=@}" "${STUB}/body" ;;
      esac
    done
    ;;
  "repos/${GITHUB_REPOSITORY}/releases/42 --jq .body") cat "${STUB}/body" ;;
  "repos/${GITHUB_REPOSITORY}/releases/42")
    jq -n --arg tag "$(cat "${STUB}/tag")" --argjson draft "$(cat "${STUB}/draft")" --rawfile body "${STUB}/body" \
      '{id: 42, tag_name: $tag, draft: $draft, body: $body}'
    ;;
  *) echo "stand-in gh: unexpected call: $*" >&2; exit 64 ;;
esac
`,
	"bin/curl":                       "#!/bin/sh\nprintf 'curl %s\\n' \"$*\" >>\"${STUB}/calls\"\nexit 22\n",
	"scripts/publish-python-dist.sh": "#!/bin/sh\nprintf 'upload %s\\n' \"$*\" >>\"${STUB}/calls\"\n",
	"scripts/check-gate-runs.sh": `#!/bin/sh
printf 'gate %s\n' "$*" >>"${STUB}/calls"
[ "${STUB_GATE:-}" != refuse ] || { echo "check-gate-runs: ${1} is not the head of main" >&2; exit 1; }
`,
}

// releaseRun is what one run of a release step printed and did: the calls
// it made and the tag the draft is left under.
type releaseRun struct {
	out, calls, tag string
	err             error
}

// runReleaseStep runs one release step's block as the workflow's shell runs
// it, in a directory holding dist/ and the stand-ins.
func runReleaseStep(t *testing.T, job, step string, env ...string) releaseRun {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub")
	for _, d := range []string{"bin", "scripts", "dist", "stub", "runner"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"dist/product_1.0.0_linux_amd64.tar.gz":          "archive",
		"dist/product_1.0.0_linux_amd64.tar.gz.cdx.json": "{}",
		"dist/checksums.txt":                             "sums",
		"dist/checksums.txt.sigstore.json":               "{}",
		"stub/tag":                                       "v1.0.0",
		"stub/draft":                                     "true",
		"stub/body":                                      "",
		"runner/notes.md":                                "The notes.\n",
		"step.sh":                                        releaseStepRun(t, job, step),
	}
	for name, body := range releaseStandIns {
		files[name] = body
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { //nolint:gosec // G306: the stand-ins run as programs
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-p", "-e", "-o", "pipefail", filepath.Join(dir, "step.sh")) //nolint:gosec // G204: a step of the repository's own workflow
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"), "STUB="+stub,
		"GITHUB_REPOSITORY=example/repo", "GITHUB_REF_NAME=v1.0.0", "GITHUB_SHA="+strings.Repeat("a", 40),
		"GITHUB_ACTOR=probe", "RUNNER_TEMP="+filepath.Join(dir, "runner"), "IMAGE=ghcr.io/example/probe",
		"DIGEST=sha256:"+strings.Repeat("0", 64), "DRAFT=42", "GH_TOKEN=x", "GITHUB_TOKEN=x")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return releaseRun{out: string(out), calls: readMaybe(t, filepath.Join(stub, "calls")), tag: readMaybe(t, filepath.Join(stub, "tag")), err: err}
}

// readMaybe is the content of a file a stand-in writes, empty when it wrote
// none; any other read error fails the test.
func readMaybe(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: a file under this test's own temporary directory
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return string(data)
}

// gateRightBefore reports whether the calls check the gate on the release
// commit and then make no call to gh before the one that publishes.
func gateRightBefore(calls string) bool {
	gate := strings.Index(calls, "gate "+strings.Repeat("a", 40))
	patch := strings.Index(calls, "gh api --method PATCH")
	return gate >= 0 && patch > gate && !strings.Contains(calls[gate:patch], "gh api")
}

// TestPublishPublishesTheVerifiedTagWhileItIsMainsHead: Publish releases the
// draft under the tag the run was started for, even when a writer moves the
// draft to another tag between the checks and the publication, since the
// request that publishes names the tag, and refuses
// loudly when the release reads back under another tag. It checks the gate
// again right before the publication, so a main that moved since the job's
// first check publishes nothing.
func TestPublishPublishesTheVerifiedTagWhileItIsMainsHead(t *testing.T) {
	r := runReleaseStep(t, "release", "Publish")
	if r.err != nil || r.tag != "v1.0.0" || !strings.Contains(r.out, "published release 42 for v1.0.0") {
		t.Fatalf("Publish of an untouched draft = %v, tag %q:\n%s\ncalls:\n%s", r.err, r.tag, r.out, r.calls)
	}
	if !gateRightBefore(r.calls) {
		t.Errorf("Publish did not check the gate right before it published:\n%s", r.calls)
	}

	r = runReleaseStep(t, "release", "Publish", "STUB_RETAG=v0.9.0")
	if r.err != nil || r.tag != "v1.0.0" || !strings.Contains(r.out, "published release 42 for v1.0.0") {
		t.Errorf("Publish of a draft moved to v0.9.0 = %v and left it under %q, want it published under v1.0.0:\n%s\ncalls:\n%s", r.err, r.tag, r.out, r.calls)
	}

	r = runReleaseStep(t, "release", "Publish", "STUB_RETAG=v0.9.0", "STUB_KEEP_TAG=1")
	const misfiled = "READS BACK UNDER TAG v0.9.0, DRAFT false, NOT AS THE PUBLISHED v1.0.0"
	if r.err == nil || !strings.Contains(r.out, misfiled) {
		t.Errorf("Publish read back under %q = %v, want a failure saying %q:\n%s\ncalls:\n%s", r.tag, r.err, misfiled, r.out, r.calls)
	}

	r = runReleaseStep(t, "release", "Publish", "STUB_GATE=refuse")
	if r.err == nil || strings.Contains(r.calls, "--method PATCH") {
		t.Errorf("Publish with main moved on = %v, and it published:\n%s\ncalls:\n%s", r.err, r.out, r.calls)
	}
}

// TestTheImageIsTaggedOnlyWhileItsCommitIsMainsHead: the version tag is not
// taken back, so the step checks the gate before it asks the registry for
// anything; with the gate passing it does reach the registry.
func TestTheImageIsTaggedOnlyWhileItsCommitIsMainsHead(t *testing.T) {
	r := runReleaseStep(t, "release", "Tag the verified image", "STUB_GATE=refuse")
	if r.err == nil || strings.Contains(r.calls, "curl ") {
		t.Errorf("the image tag step with main moved on = %v, and it called the registry:\n%s\ncalls:\n%s", r.err, r.out, r.calls)
	}
	r = runReleaseStep(t, "release", "Tag the verified image")
	if !strings.HasPrefix(r.calls, fmt.Sprintf("gate %s\ncurl ", strings.Repeat("a", 40))) {
		t.Errorf("the image tag step with the gate passing did not check it first and then call the registry:\n%s", r.calls)
	}
}

// TestTheClientIsUploadedOnlyFromAGatedCommit: an upload to the package index
// is not taken back, and the index job can wait for its approval long after
// the release job's checks, so a step of its own checks the released commit's
// gate runs right before the upload. It judges the commit, not main's head, so
// a re-run of the upload still works once main has moved.
func TestTheClientIsUploadedOnlyFromAGatedCommit(t *testing.T) {
	r := runReleaseStep(t, "index", "Check the gate again", "STUB_GATE=refuse")
	if r.err == nil {
		t.Errorf("the gate step with the commit's runs refused = <nil>:\n%s\ncalls:\n%s", r.out, r.calls)
	}
	r = runReleaseStep(t, "index", "Check the gate again")
	if r.err != nil || r.calls != fmt.Sprintf("gate --released %s\n", strings.Repeat("a", 40)) {
		t.Errorf("the gate step = %v, want one check of the released commit:\n%s\ncalls:\n%s", r.err, r.out, r.calls)
	}
}

// indexJob returns the index job's steps and whether it grants actions: read.
// indexJob returns the index job's steps, whether it grants actions: read,
// and the env entries every one of its steps inherits, from the workflow and
// from the job, that carry a token or a secret.
func indexJob(t *testing.T) (steps []*yamlNode, readScope bool, inherited []string) {
	t.Helper()
	root, err := parseBlockYAML(readLines(t, repoFS(t), releaseWorkflowPath))
	if err != nil {
		t.Fatalf("%s: %v", releaseWorkflowPath, err)
	}
	inherited = stepTokens(root)
	for _, jobs := range root.children("jobs") {
		for _, job := range jobs.children("index") {
			inherited = append(inherited, stepTokens(job)...)
			for _, list := range job.children("steps") {
				steps = append(steps, list.kids...)
			}
			for _, p := range job.children("permissions") {
				readScope = readScope || slices.ContainsFunc(p.children("actions"), func(n *yamlNode) bool { return n.value == "read" })
			}
		}
	}
	return steps, readScope, inherited
}

// stepTokens names the env entries of a workflow, a job or a step that carry
// a token or a secret. Expression contexts are case-insensitive, so the
// value is read in lower case.
func stepTokens(s *yamlNode) (names []string) {
	for _, env := range s.children("env") {
		for _, v := range env.kids {
			if value := strings.ToLower(v.value); strings.Contains(value, "token") || strings.Contains(value, "secrets") {
				names = append(names, v.key)
			}
		}
	}
	return names
}

// TestTheIndexUploadFollowsItsOwnGateCheck: the gate check is the step right
// before the upload, neither can be skipped past a refusal, the job can read
// the runs the check judges, and the check holds the token while the upload,
// whose tools would inherit it, holds none.
func TestTheIndexUploadFollowsItsOwnGateCheck(t *testing.T) {
	steps, readScope, inherited := indexJob(t)
	if !readScope {
		t.Errorf("%s: the index job does not grant actions: read, which the gate check reads the runs with", releaseWorkflowPath)
	}
	if len(inherited) != 0 {
		t.Errorf("%s: the index job's steps inherit %v from the workflow's or the job's env, so the upload's tools would hold it", releaseWorkflowPath, inherited)
	}
	at := slices.IndexFunc(steps, func(s *yamlNode) bool { return len(stepScripts(s, "Upload")) == 1 })
	if at < 1 || len(stepScripts(steps[at-1], "Check the gate again")) != 1 {
		t.Fatalf("%s: the index job's Upload does not follow a step named Check the gate again", releaseWorkflowPath)
	}
	for _, s := range steps[at-1 : at+1] {
		for _, key := range []string{"if", "continue-on-error"} {
			for _, n := range s.children(key) {
				t.Errorf("%s: line %d: a step of the gated upload sets %s, so the upload could run past a refusal", releaseWorkflowPath, n.line, key)
			}
		}
	}
	if got := stepTokens(steps[at-1]); !slices.Equal(got, []string{"GH_TOKEN"}) {
		t.Errorf("%s: the gate step's token is %v, want GH_TOKEN alone", releaseWorkflowPath, got)
	}
	if got := stepTokens(steps[at]); len(got) != 0 {
		t.Errorf("%s: the Upload step holds %v, which the upload's tools would inherit", releaseWorkflowPath, got)
	}
}
