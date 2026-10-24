package docscheck

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var roadmapOutcome = regexp.MustCompile(`^## [0-9]+\. (.+)$`)

// The milestones are ROADMAP.md's numbered outcomes, in its order and without
// their numbers; its 1.0 section is not an outcome.
func TestMilestonesFollowTheRoadmap(t *testing.T) {
	var outcomes []string
	for _, line := range readLines(t, repoFS(t), "ROADMAP.md") {
		if m := roadmapOutcome.FindStringSubmatch(line); m != nil {
			outcomes = append(outcomes, m[1])
		}
	}
	if len(outcomes) == 0 {
		t.Fatal("ROADMAP.md holds no `## N. Title` heading, so nothing was compared")
	}
	if got := settingsValues(t, `printf '%s\n' "${MILESTONES[@]}"`); !slices.Equal(got, outcomes) {
		t.Errorf("%s: MILESTONES = %q\nROADMAP.md outcomes = %q", githubSettings, got, outcomes)
	}
}

var arrayDeclaration = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=\($`)

// Bash keeps the last assignment of an array and the gate's text reader the
// first, so each array the declarations hold is assigned exactly once, there,
// and the sourced value is the one the reader sees.
func TestSettingsArraysAreAssignedOnce(t *testing.T) {
	fsys := repoFS(t)
	files := []string{githubSettings, "scripts/lib/github-bodies.sh", "scripts/lib/github-rulesets.sh", "scripts/github-bootstrap.sh", "scripts/github-settings-check.sh"}
	var names []string
	for _, line := range readLines(t, fsys, githubSettings) {
		if m := arrayDeclaration.FindStringSubmatch(line); m != nil && !slices.Contains(names, m[1]) {
			names = append(names, m[1])
		}
	}
	if len(names) < 5 {
		t.Fatalf("%s declares %d array(s) this test can find, want at least 5", githubSettings, len(names))
	}
	for _, name := range names {
		if count := assignments(t, fsys, files, name); count != 1 {
			t.Errorf("%s is assigned %d time(s) across %q, want once, in %s", name, count, files, githubSettings)
		}
	}
	parsed, err := quotedArray(readLines(t, fsys, githubSettings), "TWO_APPROVAL_PATHS")
	if err != nil {
		t.Fatal(err)
	}
	if sourced := settingsValues(t, `printf '%s\n' "${TWO_APPROVAL_PATHS[@]}"`); !slices.Equal(parsed, sourced) {
		t.Errorf("TWO_APPROVAL_PATHS read as text = %q\nas bash sources it = %q", parsed, sourced)
	}
}

// GitHub refuses a required reviewer with more than gitHubPatternLimit file
// patterns and a team named twice in one ruleset, halfway through a bootstrap
// run. Every declared ruleset body stays within both, and the bodies together
// carry each declared path once.
func TestRulesetBodiesStayWithinGitHubsLimits(t *testing.T) {
	var union []string
	for _, name := range settingsValues(t, `ruleset_names`) {
		var body struct {
			Rules []struct {
				Type       string `json:"type"`
				Parameters struct {
					RequiredReviewers []struct {
						FilePatterns []string `json:"file_patterns"`
						Reviewer     struct {
							ID   int    `json:"id"`
							Type string `json:"type"`
						} `json:"reviewer"`
					} `json:"required_reviewers"`
				} `json:"parameters"`
			} `json:"rules"`
		}
		text := strings.Join(settingsValues(t, `ruleset_json "`+name+`" 42`), "\n")
		if err := json.Unmarshal([]byte(text), &body); err != nil {
			t.Fatalf("%s: the body is not JSON: %v", name, err)
		}
		seen := map[string]bool{}
		for _, rule := range body.Rules {
			for _, r := range rule.Parameters.RequiredReviewers {
				key := fmt.Sprintf("%s %d", r.Reviewer.Type, r.Reviewer.ID)
				if n := len(r.FilePatterns); n > gitHubPatternLimit {
					t.Errorf("%s: %s holds %d file patterns, GitHub takes at most %d", name, key, n, gitHubPatternLimit)
				}
				if seen[key] {
					t.Errorf("%s: %s is a required reviewer twice", name, key)
				}
				seen[key] = true
				union = append(union, r.FilePatterns...)
			}
		}
	}
	want := settingsValues(t, `printf '%s\n' "${TWO_APPROVAL_PATHS[@]}"`)
	if slices.Sort(union); !slices.Equal(union, slices.Sorted(slices.Values(want))) {
		t.Errorf("the rulesets carry %d pattern(s) %q, want the %d of TWO_APPROVAL_PATHS once each", len(union), union, len(want))
	}
	if got := settingsValues(t, `reviewer_limit_problems 15; REVIEWER_PATTERN_LIMIT=16; reviewer_limit_problems 15`); len(got) == 0 || !strings.Contains(got[0], "holds 16 file patterns") {
		t.Errorf("the bootstrap's preflight passes a reviewer of 16 patterns: %q", got)
	}
	doubled := settingsValues(t, `eval "original_$(declare -f ruleset_json)"
ruleset_json() { original_ruleset_json "$@" | jq -c '(.rules[]? | select(.type == "pull_request") | .parameters.required_reviewers) |= (. + .)'; }
reviewer_limit_problems 99`)
	if joined := strings.Join(doubled, "\n"); !strings.Contains(joined, "is a required reviewer 2 times") || !strings.Contains(joined, "not the "+strconv.Itoa(len(want))+" of TWO_APPROVAL_PATHS") {
		t.Errorf("the bootstrap's preflight passes a team named twice and every path twice: %q", doubled)
	}
}

// assignments counts the lines of files outside comments that assign to the
// array name or name it to a builtin that can.
func assignments(t *testing.T, fsys fs.FS, files []string, name string) int {
	t.Helper()
	writes := regexp.MustCompile(`(^|[^A-Za-z0-9_])` + name + `(\[[^]]*\])?\+?=|\b(unset|declare|typeset|readonly|local|read|readarray|mapfile|export|eval)\b.*\b` + name + `\b`)
	count := 0
	for _, file := range files {
		for _, line := range readLines(t, fsys, file) {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") && writes.MatchString(line) {
				count++
			}
		}
	}
	return count
}
