package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

// The fakes of scripts/draft-release.sh: gh logs every call and answers each
// endpoint the script asks from the files and counters under FAKE_DIR, and
// sleep returns at once. Once the draft is made the release list names it
// after FAKE_LIST_LAG more reads, beside a second draft of its name when
// FAKE_RACE is set, and the upload host's probe fails its first
// FAKE_PROBE_FAILS calls, as a draft that is not served yet does. The draft's
// id and the probe's asset id are FAKE_MADE_ID and FAKE_ASSET where set.
// sleep logs how long it was asked to wait.
const (
	fakeDraftGh = `#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FAKE_DIR}/gh"
[[ "${1:-}" == api ]] || { echo "fake gh: not an api call: $*" >&2; exit 64; }
shift
method=GET; endpoint=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --method) method="$2"; shift 2 ;;
    --jq|-f|-F|-H|--input) shift 2 ;;
    --paginate) shift ;;
    -*) echo "fake gh: refusing $1" >&2; exit 64 ;;
    *) [[ -z "${endpoint}" ]] || { echo "fake gh: two endpoints" >&2; exit 64; }; endpoint="$1"; shift ;;
  esac
done
count() { local f="${FAKE_DIR}/count-$1" n=0; [[ -f "${f}" ]] && n="$(cat "${f}")"; n=$((n+1)); echo "${n}" >"${f}"; echo "${n}"; }
case "${method} ${endpoint}" in
  "GET repos/${FAKE_REPO}/releases?per_page=100")
    if [[ -f "${FAKE_DIR}/made" && "$(count list)" -gt "${FAKE_LIST_LAG:-0}" ]]; then
      jq -c --arg id "${FAKE_ID}" --arg tag "${FAKE_TAG}" --arg name "${FAKE_NAME}" --arg race "${FAKE_RACE:-}" \
        '. + [{id: ($id | tonumber), tag_name: $tag, draft: true, name: $name}]
           + (if $race == "" then [] else [{id: 99, tag_name: "v9.9.9", draft: true, name: $name}] end)' \
        "${FAKE_DIR}/releases.json"
    else
      cat "${FAKE_DIR}/releases.json"
    fi ;;
  "POST repos/${FAKE_REPO}/releases") : >"${FAKE_DIR}/made"; echo "${FAKE_MADE_ID:-${FAKE_ID}}" ;;
  "POST https://uploads.github.com/repos/${FAKE_REPO}/releases/${FAKE_ID}/assets?name=draft-probe.txt")
    [[ "$(count probe)" -gt "${FAKE_PROBE_FAILS:-0}" ]] || exit 1
    echo "${FAKE_ASSET:-777}" ;;
  "DELETE repos/${FAKE_REPO}/releases/assets/777") exit "${FAKE_DELETE_RC:-0}" ;;
  "GET repos/${FAKE_REPO}/releases/${FAKE_ID}/assets?per_page=100") printf '%s' "${FAKE_LEFT:-}" ;;
  *) echo "fake gh: unexpected ${method} ${endpoint}" >&2; exit 64 ;;
esac
`
	fakeDraftSleep = "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>\"${FAKE_DIR}/sleep\"\n"
)

var draftTools = []string{"bash", "jq", "mktemp", "rm", "paste", "cat", "seq"}

type draftRun struct {
	tag, commit, name string
	releases          string // the listing the API answers before the draft; "[]" when empty
	listLag           string
	race              string
	probeFails        string
	madeID, asset     string
	deleteRC          string
	left              string
}

const (
	draftRepo   = "example/control"
	draftID     = "431673868"
	draftCommit = "0abe60b1b2d74249c1b1edb12187ede30c14695b"
)

// runDraft runs the script with the fakes and returns its output, its exit
// status and the calls gh received.
func runDraft(t *testing.T, run draftRun) (string, int, []string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tool := range draftTools {
		if err := os.Symlink(settingsTool(t, tool), filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"gh": fakeDraftGh, "sleep": fakeDraftSleep} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // G306: the fake has to be executable
			t.Fatal(err)
		}
	}
	releases := run.releases
	if releases == "" {
		releases = "[]"
	}
	if err := os.WriteFile(filepath.Join(dir, "releases.json"), []byte(releases), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(settingsTool(t, "bash"), filepath.Join(repoRoot(t), "scripts", "draft-release.sh"), run.tag, run.commit, run.name) //nolint:gosec // G204: bash from PATH running this repository's own script
	cmd.Env = []string{
		"PATH=" + bin, "HOME=" + dir, "TMPDIR=" + dir, "GITHUB_REPOSITORY=" + draftRepo,
		"FAKE_DIR=" + dir, "FAKE_REPO=" + draftRepo, "FAKE_ID=" + draftID, "FAKE_TAG=" + run.tag, "FAKE_NAME=" + run.name,
		"FAKE_LIST_LAG=" + run.listLag, "FAKE_RACE=" + run.race, "FAKE_PROBE_FAILS=" + run.probeFails,
		"FAKE_DELETE_RC=" + run.deleteRC, "FAKE_LEFT=" + run.left, "FAKE_MADE_ID=" + run.madeID, "FAKE_ASSET=" + run.asset,
	}
	out, err := fileOutput(t, cmd, true)
	calls := fakeCalls(t, filepath.Join(dir, "gh"))
	for _, d := range fakeCalls(t, filepath.Join(dir, "sleep")) {
		calls = append(calls, "sleep "+d)
	}
	return out, exitCode(t, err), calls
}

func countCalls(calls []string, want string) int {
	n := 0
	for _, c := range calls {
		if strings.Contains(c, want) {
			n++
		}
	}
	return n
}

var freshDraft = draftRun{tag: "v0.16.0", commit: draftCommit, name: "Example 0.16.0"}

func TestDraftReleaseMakesOneDraftAndProvesBothHosts(t *testing.T) {
	out, code, calls := runDraft(t, freshDraft)
	if code != 0 || strings.TrimSpace(out) != draftID {
		t.Fatalf("exit %d, output %q, calls %q", code, out, calls)
	}
	want := []string{
		"api repos/" + draftRepo + "/releases?per_page=100 --paginate",
		"api --method POST repos/" + draftRepo + "/releases -f tag_name=v0.16.0 -f target_commitish=" + draftCommit + " -f name=Example 0.16.0 -F draft=true -F prerelease=false --jq .id",
		"api repos/" + draftRepo + "/releases?per_page=100 --paginate",
		"api --method POST https://uploads.github.com/repos/" + draftRepo + "/releases/" + draftID + "/assets?name=draft-probe.txt -H Content-Type: text/plain --input ",
		"api --method DELETE repos/" + draftRepo + "/releases/assets/777",
		"api repos/" + draftRepo + "/releases/" + draftID + "/assets?per_page=100 --paginate --jq .[].name",
	}
	if len(calls) != len(want) {
		t.Fatalf("gh got %d calls, want %d: %q", len(calls), len(want), calls)
	}
	for i, w := range want {
		if !strings.HasPrefix(calls[i], w) {
			t.Errorf("call %d is %q, want a prefix of %q", i, calls[i], w)
		}
	}
}

func TestDraftReleaseIsNotBarredByAnotherTagsRelease(t *testing.T) {
	other := freshDraft
	other.releases = `[{"id": 5, "tag_name": "v0.16.0-rc.1", "draft": true, "name": "Example 0.16.0-rc.1"}]`
	out, code, calls := runDraft(t, other)
	if code != 0 || strings.TrimSpace(out) != draftID || countCalls(calls, "--method POST repos/") != 1 {
		t.Fatalf("exit %d, output %q, calls %q", code, out, calls)
	}
}

func TestDraftReleaseDraftsAPreReleaseAsOne(t *testing.T) {
	pre := freshDraft
	pre.tag = "v0.16.0-rc.1"
	_, code, calls := runDraft(t, pre)
	if code != 0 || countCalls(calls, "-F prerelease=true") != 1 {
		t.Fatalf("exit %d, calls %q", code, calls)
	}
}

func TestDraftReleaseWaitsForAHostThatServesLate(t *testing.T) {
	late := freshDraft
	late.listLag, late.probeFails = "3", "2"
	_, code, calls := runDraft(t, late)
	if code != 0 || countCalls(calls, "releases?per_page") != 5 || countCalls(calls, "draft-probe.txt") != 3 {
		t.Fatalf("exit %d, calls %q", code, calls)
	}
	if countCalls(calls, "sleep 5") != 5 || countCalls(calls, "sleep ") != 5 {
		t.Fatalf("waited %d times for 5 s and %d in all, want 5 and 5: %q", countCalls(calls, "sleep 5"), countCalls(calls, "sleep "), calls)
	}
}

// draftRefusal is one way the script must refuse: what changes from a fresh
// run, whether a draft was made before the refusal, a call it must never
// reach, and whether it waited the whole minute for a host first.
type draftRefusal struct {
	change func(*draftRun)
	made   bool
	never  string
	minute bool
}

func TestDraftReleaseRefusesWhatItCannotProve(t *testing.T) {
	for name, c := range map[string]draftRefusal{
		"a draft for the tag exists":      {change: func(r *draftRun) { r.releases = `[{"id": 5, "tag_name": "v0.16.0", "draft": true, "name": "x"}]` }, never: "--method POST"},
		"a published release for the tag": {change: func(r *draftRun) { r.releases = `[{"id": 5, "tag_name": "v0.16.0", "draft": false, "name": "x"}]` }, never: "--method POST"},
		"a draft of the name for another tag": {change: func(r *draftRun) {
			r.releases = `[{"id": 5, "tag_name": "v9.9.9", "draft": true, "name": "Example 0.16.0"}]`
		}, never: "--method POST"},
		"the list never names the draft":     {change: func(r *draftRun) { r.listLag = "99" }, made: true, never: "draft-probe.txt", minute: true},
		"a second draft of the name appears": {change: func(r *draftRun) { r.race = "yes" }, made: true, never: "draft-probe.txt"},
		"the upload host never serves it":    {change: func(r *draftRun) { r.probeFails = "99" }, made: true, never: "--method DELETE", minute: true},
		"the probe cannot be removed":        {change: func(r *draftRun) { r.deleteRC = "1" }, made: true, never: "assets?per_page"},
		"an asset is left on the draft":      {change: func(r *draftRun) { r.left = "draft-probe.txt" }, made: true},
		"not a release tag":                  {change: func(r *draftRun) { r.tag = "v1.2" }, never: "api"},
		"not a commit":                       {change: func(r *draftRun) { r.commit = "0abe60b1" }, never: "api"},
		"an empty name":                      {change: func(r *draftRun) { r.name = "" }, never: "api"},
		"a draft id that is not a number":    {change: func(r *draftRun) { r.madeID = "12x" }, made: true, never: "sleep"},
		"an asset id that is not a number":   {change: func(r *draftRun) { r.asset = "x" }, made: true, never: "--method DELETE"},
	} {
		t.Run(name, func(t *testing.T) { checkDraftRefusal(t, c) })
	}
}

func checkDraftRefusal(t *testing.T, c draftRefusal) {
	t.Helper()
	run := freshDraft
	c.change(&run)
	out, code, calls := runDraft(t, run)
	if code == 0 {
		t.Fatalf("passed: %s\ncalls %q", out, calls)
	}
	if !strings.Contains(out, "draft-release:") {
		t.Fatalf("the refusal does not name the script: %s", out)
	}
	if made := countCalls(calls, "--method POST repos/") == 1; made != c.made {
		t.Errorf("a draft made: %v, want %v; calls %q", made, c.made, calls)
	}
	if c.never != "" && countCalls(calls, c.never) != 0 {
		t.Errorf("gh was still asked %q: %q", c.never, calls)
	}
	if countCalls(calls, "releases?per_page") > 13 || countCalls(calls, "draft-probe.txt") > 12 {
		t.Errorf("a host was asked more than 12 times: %q", calls)
	}
	if c.minute && (countCalls(calls, "sleep 5") != 12 || countCalls(calls, "sleep ") != 12) {
		t.Errorf("waited %d times for 5 s and %d in all, want 12 and 12: a minute", countCalls(calls, "sleep 5"), countCalls(calls, "sleep "))
	}
}

// The draft step, goreleaser and Publish agree only by what each file says:
// goreleaser takes an existing draft by the name its template renders, which
// the step has to pass, and Publish has to hold the one draft for the tag to
// the id the step made.
func TestTheReleaseWorkflowDraftsWhatGoreleaserTakes(t *testing.T) {
	fsys := repoFS(t)
	for _, want := range []struct{ file, line string }{
		{".goreleaser.yaml", "  use_existing_draft: true"},
		{".goreleaser.yaml", `  name_template: "` + brand.Name + ` {{ .Version }}"`},
		{releaseWorkflowPath, `          id="$(scripts/draft-release.sh "${GITHUB_REF_NAME}" "${GITHUB_SHA}" "` + brand.Name + ` ${GITHUB_REF_NAME#v}")"`},
		{releaseWorkflowPath, "          DRAFT: ${{ steps.draft.outputs.id }}"},
		{releaseWorkflowPath, `          if [[ "${id}" != "${DRAFT}" ]]; then`},
	} {
		if !slices.Contains(readLines(t, fsys, want.file), want.line) {
			t.Errorf("%s holds no line %q", want.file, want.line)
		}
	}
}
