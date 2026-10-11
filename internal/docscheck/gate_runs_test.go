package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	gateRunsSHA = "1111111111111111111111111111111111111111"
	gateMainSHA = "3333333333333333333333333333333333333333"
)

// stubGH answers `gh api <url> --jq <filter>` with the canned answer for the
// URL, evaluated with jq as gh would evaluate it, and logs every URL it was
// asked for. The branch and the comparison are matched exactly, so a request
// that names main any other way is refused.
const stubGH = `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == api && "$3" == --jq && $# -eq 4 ]] || { echo "stub gh: unexpected arguments: $*" >&2; exit 64; }
printf '%s\n' "$2" >>"${STUB_DIR}/urls"
case "$2" in
  "repos/owner/name/git/ref/heads/main") answer="${STUB_DIR}/ref.json" ;;
  "repos/owner/name/compare/${STUB_MAIN}...${STUB_SHA}") answer="${STUB_DIR}/compare.json" ;;
  */workflows/ci.yml/runs\?*) answer="${STUB_DIR}/ci.json" ;;
  */workflows/security.yml/runs\?*) answer="${STUB_DIR}/security.json" ;;
  "repos/owner/name/code-scanning/alerts?ref=refs/heads/main&state=open&per_page=100") answer="${STUB_DIR}/alerts.json" ;;
  "repos/owner/name/code-scanning/analyses?tool_name=CodeQL&ref=refs/heads/main&sort=created&direction=desc&per_page=1") answer="${STUB_DIR}/analyses.json" ;;
  *) echo "stub gh: unexpected url $2" >&2; exit 64 ;;
esac
if [[ "$(head -c 5 "${answer}")" == "HTTP " ]]; then
  cat "${answer}" >&2
  exit 1
fi
exec jq -r "$4" "${answer}"
`

// gateAnswers are the stub's answers; an empty ref or compare is replaced by
// main at gateMainSHA and a comparison that finds the commit identical, empty
// alerts by an empty list, and empty analyses by one CodeQL analysis of
// gateRunsSHA on main. An answer that starts with "HTTP " is a gh failure: the
// stub prints it and exits 1.
type gateAnswers struct {
	ci, security, ref, compare, alerts, analyses string
}

func gateAnalysis(sha, ref, tool, analysisErr string) string {
	return `{"id":7,"commit_sha":"` + sha + `","ref":"` + ref + `","tool":{"name":"` + tool + `","version":"2.0.0"},` +
		`"category":"/language:go","error":"` + analysisErr + `","results_count":0}`
}

func gateRun(sha, event, branch, conclusion string) string {
	field := func(v string) string {
		if v == "" {
			return "null"
		}
		return `"` + v + `"`
	}
	return `{"head_sha":` + field(sha) + `,"event":` + field(event) + `,"head_branch":` + field(branch) +
		`,"status":"completed","conclusion":` + field(conclusion) + `}`
}

func gateRuns(runs ...string) string {
	return gateRunsCounted(len(runs), runs...)
}

func gateRunsCounted(total int, runs ...string) string {
	return `{"total_count":` + strconv.Itoa(total) + `,"workflow_runs":[` + strings.Join(runs, ",") + `]}`
}

func gateCompare(status string) string {
	return `{"status":"` + status + `","ahead_by":0,"behind_by":0}`
}

func TestCheckGateRunsReadsTheRunItCounts(t *testing.T) {
	bash, script := gateRunsTools(t)

	good := gateRuns(gateRun(gateRunsSHA, "push", "main", "success"))
	cases := map[string]struct {
		ci   string
		pass bool
		want string
	}{
		"a successful push run on main": {good, true, "security.yml passed on " + gateRunsSHA},
		"a push run beside a pull request run": {
			gateRuns(gateRun(gateRunsSHA, "pull_request", "feature", "failure"), gateRun(gateRunsSHA, "push", "main", "success")),
			true, "ci.yml passed on " + gateRunsSHA,
		},
		"only a pull_request run": {
			gateRuns(gateRun(gateRunsSHA, "pull_request", "feature", "success")), false,
			"ci.yml has no successful push run on main for " + gateRunsSHA + "; GitHub listed: a pull_request run on feature (conclusion success)",
		},
		"a pull_request run from a fork's main": {
			gateRuns(gateRun(gateRunsSHA, "pull_request", "main", "success")), false,
			"GitHub listed: a pull_request run on main (conclusion success)",
		},
		"a push run on another branch": {
			gateRuns(gateRun(gateRunsSHA, "push", "feature", "success")), false,
			"GitHub listed: a push run on feature (conclusion success)",
		},
		"a successful push run of another commit": {
			gateRuns(gateRun("2222222222222222222222222222222222222222", "push", "main", "success")), false,
			"GitHub listed: no run of this commit; 1 run(s) of other commits",
		},
		"a failed push run": {
			gateRuns(gateRun(gateRunsSHA, "push", "main", "failure")), false,
			"GitHub listed: a push run on main (conclusion failure)",
		},
		"a skipped push run": {
			gateRuns(gateRun(gateRunsSHA, "push", "main", "skipped")), false,
			"GitHub listed: a push run on main (conclusion skipped)",
		},
		"a neutral push run": {
			gateRuns(gateRun(gateRunsSHA, "push", "main", "neutral")), false,
			"GitHub listed: a push run on main (conclusion neutral)",
		},
		"a push run still in progress": {
			gateRuns(gateRun(gateRunsSHA, "push", "main", "")), false,
			"GitHub listed: a push run on main (conclusion none)",
		},
		"an empty list": {gateRuns(), false, "ci.yml has no successful push run on main for " + gateRunsSHA + "; GitHub listed: no run of this commit"},
		"more runs than one page, the passing one among those read": {
			gateRunsCounted(101, gateRun(gateRunsSHA, "push", "main", "success")), false,
			"ci.yml: GitHub counts 101 run(s) of " + gateRunsSHA + " and answered 1; more runs than one page; refusing rather than guessing",
		},
		"an answer with no total_count": {
			`{"workflow_runs":[` + gateRun(gateRunsSHA, "push", "main", "success") + `]}`, false,
			"could not read ci.yml's runs on " + gateRunsSHA,
		},
		"malformed JSON":                {`{"workflow_runs":[`, false, "could not read ci.yml's runs on " + gateRunsSHA},
		"an answer with no runs array":  {`{"message":"Not Found"}`, false, "could not read ci.yml's runs on " + gateRunsSHA},
		"a runs field that is no array": {`{"total_count":1,"workflow_runs":{"head_sha":"` + gateRunsSHA + `"}}`, false, "could not read ci.yml's runs"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, urls, err := runCheckGateRuns(t, bash, script, gateAnswers{ci: tc.ci, security: good})
			checkGateVerdict(t, out, err, tc.pass, tc.want)
			want := "repos/owner/name/actions/workflows/ci.yml/runs?head_sha=" + gateRunsSHA + "&event=push&branch=main&per_page=100"
			if !slices.Contains(urls, want) {
				t.Errorf("the script never asked for %q; it asked for %q", want, urls)
			}
		})
	}

	t.Run("Security failed where CI passed", func(t *testing.T) {
		out, _, err := runCheckGateRuns(t, bash, script, gateAnswers{ci: good, security: gateRuns(gateRun(gateRunsSHA, "push", "main", "cancelled"))})
		checkGateVerdict(t, out, err, false, "security.yml has no successful push run on main for "+gateRunsSHA)
	})
}

// A run whose head_branch is main is not enough: a push of a tag named main
// carries that head_branch too, for any commit. The commit itself has to be
// main's branch head; an older commit of main is refused, since main's alerts
// describe a later one.
func TestCheckGateRunsRefusesACommitNotOnMain(t *testing.T) {
	bash, script := gateRunsTools(t)

	good := gateRuns(gateRun(gateRunsSHA, "push", "main", "success"))
	ref := `{"ref":"refs/heads/main","object":{"sha":"` + gateMainSHA + `","type":"commit"}}`
	cases := map[string]struct {
		ref, compare string
		pass         bool
		want         string
	}{
		"main's head itself":      {ref, gateCompare("identical"), true, "security.yml passed on " + gateRunsSHA},
		"an ancestor of main":     {ref, gateCompare("behind"), false, gateRunsSHA + " is not main's head: compared with main's head " + gateMainSHA + ", GitHub says 'behind'"},
		"a commit ahead of main":  {ref, gateCompare("ahead"), false, gateRunsSHA + " is not main's head: compared with main's head " + gateMainSHA + ", GitHub says 'ahead'"},
		"a commit beside main":    {ref, gateCompare("diverged"), false, "is not main's head: compared with main's head " + gateMainSHA + ", GitHub says 'diverged'"},
		"a comparison not found":  {ref, `{"message":"Not Found"}`, false, "could not compare " + gateRunsSHA + " with main's head " + gateMainSHA},
		"a malformed comparison":  {ref, `{"status":`, false, "could not compare " + gateRunsSHA + " with main's head"},
		"main not found":          {`{"message":"Not Found"}`, gateCompare("identical"), false, "could not read the head of main"},
		"a list of matching refs": {`[` + ref + `]`, gateCompare("identical"), false, "could not read the head of main"},
		"another branch's ref": {
			`{"ref":"refs/heads/main-old","object":{"sha":"` + gateMainSHA + `","type":"commit"}}`, gateCompare("identical"), false,
			"could not read the head of main",
		},
		"a head that is no commit id": {
			`{"ref":"refs/heads/main","object":{"sha":"main","type":"commit"}}`, gateCompare("identical"), false,
			"GitHub answered 'main' for the head of main",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, _, err := runCheckGateRuns(t, bash, script, gateAnswers{ci: good, security: good, ref: tc.ref, compare: tc.compare})
			checkGateVerdict(t, out, err, tc.pass, tc.want)
		})
	}
}

func gateAlert(number int, state, level string) string {
	return toolAlert(number, state, level, "CodeQL")
}

func toolAlert(number int, state, level, tool string) string {
	severity := "null"
	if level != "" {
		severity = `"` + level + `"`
	}
	return `{"number":` + strconv.Itoa(number) + `,"state":"` + state + `","rule":{"id":"go/rule-` + strconv.Itoa(number) +
		`","severity":"error","security_severity_level":` + severity + `},"tool":{"name":"` + tool + `"}}`
}

// The analysis step succeeds whatever CodeQL raises, so an open alert blocks
// a release only here.
func TestCheckGateRunsRefusesAnOpenSevereAlert(t *testing.T) {
	bash, script := gateRunsTools(t)

	good := gateRuns(gateRun(gateRunsSHA, "push", "main", "success"))
	fullPage := make([]string, 100)
	for i := range fullPage {
		fullPage[i] = gateAlert(i+1, "open", "low")
	}
	cases := map[string]struct {
		alerts string
		pass   bool
		want   string
	}{
		"no open alert": {"[]", true, "no open high or critical CodeQL alert on main (0 alert(s) read), whose newest CodeQL analysis is of " + gateRunsSHA},
		"an open high Scorecard alert, which judges the repository": {"[" + toolAlert(2, "open", "high", "Scorecard") + "]", true, "no open high or critical CodeQL alert on main (1 alert(s) read)"},
		"an alert with no tool": {`[{"number":1,"state":"open","rule":{"security_severity_level":"high"}}]`, false, "could not read the open code scanning alerts on main"},
		"open medium and low alerts, and one with no security severity": {
			"[" + gateAlert(1, "open", "medium") + "," + gateAlert(2, "open", "low") + "," + gateAlert(3, "open", "") + "]", true,
			"no open high or critical CodeQL alert on main (3 alert(s) read)",
		},
		"a dismissed high alert listed anyway": {"[" + gateAlert(4, "dismissed", "high") + "]", true, "no open high or critical"},
		"an open high alert": {
			"[" + gateAlert(1, "open", "medium") + "," + gateAlert(7, "open", "high") + "]", false,
			"main has open CodeQL alerts of severity high or critical: #7 high (go/rule-7)",
		},
		"an open critical alert": {"[" + gateAlert(9, "open", "critical") + "]", false, "#9 critical (go/rule-9)"},
		"one alert short of a page": {
			"[" + strings.Join(fullPage[:99], ",") + "]", true, "no open high or critical CodeQL alert on main (99 alert(s) read)",
		},
		"a full page of alerts": {
			"[" + strings.Join(fullPage, ",") + "]", false,
			"GitHub answered a full page of 100 open code scanning alerts on main; more alerts than one page; refusing rather than guessing",
		},
		"an answer that is no list": {
			`{"message":"no analysis found"}`, false, "could not read the open code scanning alerts on main; refusing rather than guessing",
		},
		"an alert with no rule":       {`[{"number":1,"state":"open"}]`, false, "could not read the open code scanning alerts on main"},
		"an alert with no number":     {`[{"state":"open","rule":{"security_severity_level":"high"}}]`, false, "could not read the open code scanning alerts"},
		"malformed JSON":              {`[{"number":`, false, "could not read the open code scanning alerts on main"},
		"a refused request":           {"HTTP 403: Resource not accessible by integration", false, "could not read the open code scanning alerts on main"},
		"a code scanning API missing": {"HTTP 404: no analysis found", false, "could not read the open code scanning alerts on main"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, urls, err := runCheckGateRuns(t, bash, script, gateAnswers{ci: good, security: good, alerts: tc.alerts})
			checkGateVerdict(t, out, err, tc.pass, tc.want)
			want := "repos/owner/name/code-scanning/alerts?ref=refs/heads/main&state=open&per_page=100"
			if !slices.Contains(urls, want) {
				t.Errorf("the script never asked for %q; it asked for %q", want, urls)
			}
		})
	}
}

// Main's alerts judge main's newest analysis, so they say something about the
// released commit only when that analysis is of it.
func TestCheckGateRunsRefusesAlertsOfAnotherCommit(t *testing.T) {
	bash, script := gateRunsTools(t)

	good := gateRuns(gateRun(gateRunsSHA, "push", "main", "success"))
	const main = "refs/heads/main"
	cases := map[string]struct {
		analyses string
		pass     bool
		want     string
	}{
		"the newest analysis is of the commit": {"[" + gateAnalysis(gateRunsSHA, main, "CodeQL", "") + "]", true, "whose newest CodeQL analysis is of " + gateRunsSHA},
		"the newest analysis is of another commit": {
			"[" + gateAnalysis(gateMainSHA, main, "CodeQL", "") + "]", false,
			"main's newest CodeQL analysis is of " + gateMainSHA + ", not " + gateRunsSHA + ", so main's alerts do not judge this commit",
		},
		"an older analysis of the commit after a newer one": {
			"[" + gateAnalysis(gateMainSHA, main, "CodeQL", "") + "," + gateAnalysis(gateRunsSHA, main, "CodeQL", "") + "]", false,
			"main's newest CodeQL analysis is of " + gateMainSHA,
		},
		"no analysis":                        {"[]", false, "GitHub lists no CodeQL analysis on main; refusing rather than guessing"},
		"an analysis that failed":            {"[" + gateAnalysis(gateRunsSHA, main, "CodeQL", "extraction failed") + "]", false, "main's newest CodeQL analysis, of " + gateRunsSHA + ", reports an error: extraction failed"},
		"an analysis of another branch":      {"[" + gateAnalysis(gateRunsSHA, "refs/heads/feature", "CodeQL", "") + "]", false, "GitHub answered an analysis by 'CodeQL' on 'refs/heads/feature'"},
		"an analysis by another tool":        {"[" + gateAnalysis(gateRunsSHA, main, "Scorecard", "") + "]", false, "GitHub answered an analysis by 'Scorecard' on 'refs/heads/main'"},
		"an analysis without a commit":       {`[{"ref":"refs/heads/main","tool":{"name":"CodeQL"},"error":""}]`, false, "could not read main's newest CodeQL analysis"},
		"an analysis without an error field": {`[{"commit_sha":"` + gateRunsSHA + `","ref":"refs/heads/main","tool":{"name":"CodeQL"}}]`, false, "could not read main's newest CodeQL analysis"},
		"an answer that is no list":          {`{"message":"no analysis found"}`, false, "could not read main's newest CodeQL analysis; refusing rather than guessing"},
		"malformed JSON":                     {`[{"commit_sha":`, false, "could not read main's newest CodeQL analysis"},
		"a refused request":                  {"HTTP 403: Resource not accessible by integration", false, "could not read main's newest CodeQL analysis"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, urls, err := runCheckGateRuns(t, bash, script, gateAnswers{ci: good, security: good, analyses: tc.analyses})
			checkGateVerdict(t, out, err, tc.pass, tc.want)
			want := "repos/owner/name/code-scanning/analyses?tool_name=CodeQL&ref=refs/heads/main&sort=created&direction=desc&per_page=1"
			if !slices.Contains(urls, want) {
				t.Errorf("the script never asked for %q; it asked for %q", want, urls)
			}
		})
	}
}

func gateRunsTools(t *testing.T) (bash, script string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH, so scripts/check-gate-runs.sh cannot be tested: %v", err)
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("jq is not on PATH, and the stub gh evaluates the script's --jq filter with it: %v", err)
	}
	return bash, filepath.Join(repoRoot(t), "scripts", "check-gate-runs.sh")
}

func checkGateVerdict(t *testing.T, out string, err error, pass bool, want string) {
	t.Helper()
	if pass && err != nil {
		t.Fatalf("refused, want a pass: %v\n%s", err, out)
	}
	if !pass && err == nil {
		t.Fatalf("passed, want a refusal:\n%s", out)
	}
	if !strings.Contains(out, want) {
		t.Errorf("output does not say %q:\n%s", want, out)
	}
}

// runCheckGateRuns runs the script with the stub gh first on PATH and returns
// its output, the URLs the stub was asked for in order, and its error.
func runCheckGateRuns(t *testing.T, bash, script string, a gateAnswers) (string, []string, error) {
	t.Helper()
	if a.ref == "" {
		a.ref = `{"ref":"refs/heads/main","object":{"sha":"` + gateMainSHA + `","type":"commit"}}`
	}
	if a.compare == "" {
		a.compare = gateCompare("identical")
	}
	if a.alerts == "" {
		a.alerts = "[]"
	}
	if a.analyses == "" {
		a.analyses = "[" + gateAnalysis(gateRunsSHA, "refs/heads/main", "CodeQL", "") + "]"
	}
	dir := t.TempDir()
	for file, content := range map[string]string{
		"ci.json": a.ci, "security.json": a.security, "ref.json": a.ref, "compare.json": a.compare, "alerts.json": a.alerts,
		"analyses.json": a.analyses,
	} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(stubGH), 0o700); err != nil { //nolint:gosec // G306: the stub has to be executable
		t.Fatal(err)
	}
	cmd := exec.Command(bash, script, gateRunsSHA) //nolint:gosec // G204: bash from PATH running this repository's own script
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_DIR="+dir,
		"STUB_MAIN="+gateMainSHA,
		"STUB_SHA="+gateRunsSHA,
		"GITHUB_REPOSITORY=owner/name",
	)
	out, runErr := cmd.CombinedOutput()
	urls, err := os.ReadFile(filepath.Join(dir, "urls")) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatalf("the stub gh was never asked: %v\n%s", err, out)
	}
	return string(out), strings.Fields(string(urls)), runErr
}
