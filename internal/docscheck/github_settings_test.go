package docscheck

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The items scripts/github-settings-check.sh reports, in its order, without the
// two-approval parts and the leftover item settingsItems adds. A check that
// silently dropped one would print one line fewer.
var settingsBaseItems = []string{
	"repository settings",
	"topics",
	"immutable releases",
	"actions permissions",
	"actions workflow permissions",
	"actions fork pull request approval",
	"team maintainers",
	"team security-maintainers",
	"other teams",
	"direct collaborators",
	"repository admins",
	"environment release",
	"environment release deployment policies",
	"environment pypi",
	"environment pypi deployment policies",
	"environment testpypi",
	"environment testpypi deployment policies",
	"ruleset main: history",
	"ruleset release tags: create",
	"ruleset other tags: create",
	"ruleset release tags: immutable",
	"ruleset main: merges",
	"ruleset main: pull requests",
	"labels",
	"labels retired",
	"milestones",
	"milestones retired",
	"code security configuration",
}

// settingsItems is every item the check reports for the declared paths: one
// ruleset per further part of at most gitHubPatternLimit paths, applied before
// "main: pull requests", and after it the item for parts left over.
func settingsItems(t *testing.T) []string {
	t.Helper()
	at := slices.Index(settingsBaseItems, "ruleset main: pull requests")
	var parts []string
	for i := 1; i < len(twoApprovalChunks(t)); i++ {
		parts = append(parts, "ruleset "+partName(i))
	}
	return slices.Concat(settingsBaseItems[:at], parts, settingsBaseItems[at:at+1], []string{"leftover two-approval parts"}, settingsBaseItems[at+1:])
}

func TestSettingsCheckPassesOnlyWhenEverythingMatches(t *testing.T) {
	t.Parallel()
	out, code, calls := runSettingsCheck(t, matchingAnswers(t), settingsRun{})
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	items := settingsItems(t)
	want := make([]string, len(items))
	for i, item := range items {
		want[i] = "ok " + item
	}
	if got := stdoutLines(out); !slices.Equal(got, want) {
		t.Errorf("lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if summary := fmt.Sprintf("github-settings-check: acme/demo: %d ok, 0 drift, 0 unknown", len(items)); !strings.Contains(out, summary) {
		t.Errorf("the summary does not name the repository it read:\n%s", out)
	}
	for _, call := range calls {
		if fields := strings.Fields(call); len(fields) < 2 || fields[0] != "api" || (len(fields) == 3 && fields[1] != "--paginate") || len(fields) > 3 {
			t.Errorf("the check called gh as %q, which is not a read", call)
		}
	}
}

func TestSettingsCheckNeverPassesWhatItCouldNotRead(t *testing.T) {
	t.Parallel()
	var rulesets, approvals []string
	for _, item := range settingsItems(t) {
		if strings.HasPrefix(item, "ruleset ") {
			rulesets = append(rulesets, item)
		}
		if item == "ruleset main: pull requests" || strings.HasPrefix(item, "ruleset main: two approvals, part ") {
			approvals = append(approvals, item)
		}
	}
	rulesets = append(rulesets, "leftover two-approval parts")
	cases := map[string]struct {
		run   settingsRun
		edit  func(*testing.T, answers)
		items []string
		says  string
	}{
		"a refused answer": {settingsRun{fail: "repos/acme/demo/topics"}, nil, []string{"topics"}, "HTTP 403"},
		"an answer that is not JSON": {settingsRun{}, func(_ *testing.T, a answers) { a["repos/acme/demo/immutable-releases"] = rawAnswer("<html>") },
			[]string{"immutable releases"}, "not the JSON expected"},
		"an absent answer": {settingsRun{}, func(_ *testing.T, a answers) { delete(a, "repos/acme/demo/actions/permissions") },
			[]string{"actions permissions"}, "HTTP 404"},
		"an answer with no content": {settingsRun{}, func(_ *testing.T, a answers) { a["repos/acme/demo/code-security-configuration"] = rawAnswer("") },
			[]string{"code security configuration"}, "no content"},
		"a page that is not a list": {settingsRun{}, func(_ *testing.T, a answers) { a[labelsPath] = pages{a[labelsPath].(pages)[0], nil} },
			[]string{"labels", "labels retired"}, "not the JSON expected"},
		"a setting the token may not see": {settingsRun{}, func(_ *testing.T, a answers) { delete(a.object("repos/acme/demo"), "allow_merge_commit") },
			[]string{"repository settings"}, "absent from the answer"},
		"immutable releases off for a token without admin": {settingsRun{}, func(_ *testing.T, a answers) {
			delete(a, "repos/acme/demo/immutable-releases")
			a.object("repos/acme/demo")["permissions"] = map[string]any{"admin": false}
		}, []string{"immutable releases"}, "HTTP 404"},
		"hidden bypass actors with a rule missing": {settingsRun{}, func(t *testing.T, a answers) {
			delete(a.ruleset(t, "main: history"), "bypass_actors")
			a.dropRule(t, "main: history", "non_fast_forward")
		}, []string{"ruleset main: history"}, "absent from the answer"},
		"the ruleset list refused": {settingsRun{fail: rulesetsPath}, nil, rulesets, "HTTP 403"},
		"the reviewing team unreadable": {settingsRun{fail: "orgs/acme/teams/security-maintainers"}, nil,
			append([]string{"team security-maintainers"}, approvals...), "HTTP 403|id could not be read"},
		"the approving team unreadable": {settingsRun{fail: "orgs/acme/teams/maintainers"}, nil,
			[]string{"team maintainers", "environment release", "environment pypi"}, "HTTP 403|id could not be read"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := matchingAnswers(t)
			if tc.edit != nil {
				tc.edit(t, a)
			}
			out, code, _ := runSettingsCheck(t, a, tc.run)
			if code != 2 {
				t.Fatalf("exit %d, want 2:\n%s", code, out)
			}
			want := map[string]string{}
			for _, item := range tc.items {
				want[item] = "unknown"
			}
			expectVerdicts(t, out, want, tc.says)
		})
	}
}

// A failure the check has no branch for still ends as unknown with status 2,
// never as the status of whatever failed.
func TestSettingsCheckStopsAsUnknownOnAnUnexpectedFailure(t *testing.T) {
	t.Parallel()
	a := matchingAnswers(t)
	a["orgs/acme/teams/maintainers/members?per_page=100"] = []any{"octo"}
	out, code, _ := runSettingsCheck(t, a, settingsRun{})
	if code != 2 || !strings.Contains(out, "unknown all: the run stopped early") {
		t.Fatalf("exit %d, want 2 and an unknown line for the whole run:\n%s", code, out)
	}
}

func TestSettingsCheckDriftOutranksUnknown(t *testing.T) {
	t.Parallel()
	a := matchingAnswers(t)
	a.addLabel("help-wanted", "008672", "old")
	out, code, _ := runSettingsCheck(t, a, settingsRun{fail: "repos/acme/demo/topics"})
	if code != 1 {
		t.Fatalf("exit %d, want 1 when one item drifted and another is unknown:\n%s", code, out)
	}
	expectVerdicts(t, out, map[string]string{"labels retired": "drift", "topics": "unknown"}, "help-wanted|HTTP 403")
}

func TestSettingsCheckWithoutGhIsUnknown(t *testing.T) {
	t.Parallel()
	out, code, calls := runSettingsCheck(t, matchingAnswers(t), settingsRun{noGh: true})
	if code != 2 || !strings.Contains(out, "unknown all: gh is not on PATH") || strings.Contains(out, "ok ") {
		t.Fatalf("exit %d, want 2 and only an unknown line:\n%s", code, out)
	}
	if len(calls) != 0 {
		t.Errorf("gh was called %d time(s) though it was not on PATH", len(calls))
	}
}

func TestSettingsCheckSavesWhatItRead(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "record")
	out, code, _ := runSettingsCheck(t, matchingAnswers(t), settingsRun{args: []string{"--save", dir}})
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the record directory: %v, mode %v, want 0700", err, info)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "repos_acme_demo_rulesets_6.json")) //nolint:gosec // G304: the test's own temporary directory
	if err != nil || !strings.Contains(string(saved), `"main: pull requests"`) {
		t.Fatalf("the pull request ruleset was not saved: %v\n%s", err, saved)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"a record that is not empty": dir, "a link": link} {
		out, code, calls := runSettingsCheck(t, matchingAnswers(t), settingsRun{args: []string{"--save", target}})
		if code != 2 || len(calls) != 0 {
			t.Errorf("%s: exit %d after %d call(s), want 2 and none:\n%s", name, code, len(calls), out)
		}
	}
}

// expectVerdicts fails unless every item the check reports has the verdict
// want gives it, ok when want names it not, and the text of each item want
// names matches says.
func expectVerdicts(t *testing.T, out string, want map[string]string, says string) {
	t.Helper()
	settingsItems := settingsItems(t)
	got := map[string][2]string{}
	for _, line := range stdoutLines(out) {
		verdict, rest, _ := strings.Cut(line, " ")
		item := ""
		for _, known := range settingsItems {
			if (rest == known || strings.HasPrefix(rest, known+": ")) && len(known) > len(item) {
				item = known
			}
		}
		if item == "" {
			t.Errorf("a line names no item: %q", line)
			continue
		}
		got[item] = [2]string{verdict, strings.TrimPrefix(strings.TrimPrefix(rest, item), ": ")}
	}
	pattern := regexp.MustCompile(says)
	for _, item := range settingsItems {
		verdict, named := want[item]
		if !named {
			verdict = "ok"
		}
		switch {
		case got[item][0] != verdict:
			t.Errorf("%s: %q %q, want %s", item, got[item][0], got[item][1], verdict)
		case named && !pattern.MatchString(got[item][1]):
			t.Errorf("%s: %q does not say %q", item, got[item][1], says)
		}
	}
}

// stdoutLines drops the summary the check writes to standard error, which
// the run interleaves with standard output.
func stdoutLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "github-settings-check: ") {
			lines = append(lines, line)
		}
	}
	return lines
}

// settingsEnv names a repository that is not this one, so no answer the
// fake gh serves can be mistaken for the live one.
var settingsEnv = []string{"OWNER=acme", "REPO_NAME=demo", "ADMIN_LOGIN=octo"}

// settingsValues prints a value of the sourced declarations, one per line.
func settingsValues(t *testing.T, expr string) []string {
	t.Helper()
	cmd := exec.Command(settingsTool(t, "bash"), "-c", `set -euo pipefail; . `+githubSettings+`; `+expr) //nolint:gosec // G204: bash from PATH sourcing this repository's own script
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), settingsEnv...)
	out, err := fileOutput(t, cmd, false)
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		t.Fatalf("%s printed nothing", expr)
	}
	return lines
}

func settingsTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s is not on PATH, which scripts/github-settings-check.sh needs: %v", name, err)
	}
	return p
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	t.Fatalf("the check did not run: %v", err)
	return -1
}
