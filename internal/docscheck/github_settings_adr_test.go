package docscheck

import (
	"path"
	"regexp"
	"strings"
	"testing"
)

const branchingRecord = "docs/adr/0008-branching-and-release-policy.md"

// TestTwoApprovalPathsHoldTheGateInputsTheRecordNames: every path ADR-0008
// lists as the decision paths and the files the gate is built from is under a
// TWO_APPROVAL_PATHS pattern, as ADR-0025 and GOVERNANCE.md promise. The list
// is read from the record, so a path added there without its pattern fails.
func TestTwoApprovalPathsHoldTheGateInputsTheRecordNames(t *testing.T) {
	fsys := repoFS(t)
	listed, err := recordGateInputs(strings.Join(readLines(t, fsys, branchingRecord), "\n"))
	if err != nil {
		t.Fatalf("%s: %v", branchingRecord, err)
	}
	patterns, err := quotedArray(readLines(t, fsys, githubSettings), "TWO_APPROVAL_PATHS")
	if err != nil {
		t.Fatalf("%s: %v", githubSettings, err)
	}
	for _, p := range listed {
		if !twoApprovalCovers(patterns, p) {
			t.Errorf("%s names %q; no TWO_APPROVAL_PATHS pattern in %s covers it", branchingRecord, p, githubSettings)
		}
	}
}

var (
	gateInputsFrom = "also needs a\ncode-owner review from the security maintainers:"
	gateInputsTo   = "`.github/CODEOWNERS` is the list."
	recordPath     = regexp.MustCompile("`([^`]+)`")
)

// recordGateInputs is every backticked path between the sentence that opens
// the record's list and the one that closes it; finding fewer than ten says
// the record was reworded and the test reads nothing.
func recordGateInputs(record string) ([]string, error) {
	start := strings.Index(record, gateInputsFrom)
	end := strings.Index(record, gateInputsTo)
	if start < 0 || end < start {
		return nil, errUnreadableList
	}
	var out []string
	for _, m := range recordPath.FindAllStringSubmatch(record[start:end], -1) {
		out = append(out, m[1])
	}
	if len(out) < 10 {
		return nil, errUnreadableList
	}
	return out, nil
}

type listError string

func (e listError) Error() string { return string(e) }

const errUnreadableList listError = "the list of paths under code-owner review is not where this test reads it"

// twoApprovalCovers reports whether a pattern covers p: a directory (`x` or
// `x/`) by `x/**` or a pattern above it, a file by itself, a glob or a
// directory pattern above it.
func twoApprovalCovers(patterns []string, p string) bool {
	p = strings.TrimSuffix(p, "/")
	for _, pat := range patterns {
		if tree, ok := strings.CutSuffix(pat, "/**"); ok {
			if p == tree || strings.HasPrefix(p, tree+"/") {
				return true
			}
			continue
		}
		if ok, err := path.Match(pat, p); err == nil && ok {
			return true
		}
	}
	return false
}
