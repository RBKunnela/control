package docscheck

import (
	"fmt"
	"os/exec"
	"path"
	"slices"
	"strings"
	"testing"
)

const securityTeam = "@guardana/security-maintainers"

// The gate's own Go code, held to the review the scripts beside it are.
var gateTrees = []string{"internal/testreport", "internal/docscheck"}

// Trees outside the dependency rule that carry authorization semantics or
// cryptography: route and lift signatures and the stop judge, the policy and
// route floors and their refresh, the owner and mode checks of the
// configuration and of every store, the runs a stop names and the findings a
// stop rests on, the external decision point's answer, which may only veto,
// the MCP adapter, which classifies a tool, sends the authorized bytes under
// their obligations, names a call's run and withholds answers, and the
// enforcement API adapter, which builds a tool's envelope from the operator's
// table, resolves a run token and hands out single-use handles, and what
// both adapters read a call's resource and run token through.
var authorizationTrees = []string{
	"internal/reaction", "internal/policystate", "internal/gatewayconfig", "internal/files", "internal/policywatch",
	"internal/runs", "internal/findinglog", "adapters/authzen", "adapters/mcp", "adapters/enforce", "internal/adapterkit",
}

const githubSettings = "scripts/lib/github-settings.sh"

// Every tree the dependency rule guards, the gate's Go trees and the other
// authorization trees need the security maintainers' two approvals in the
// ruleset scripts/lib/github-settings.sh declares, and every file under a two-approval path
// is theirs in CODEOWNERS. A guarded tree added to
// scripts/lib/dependency-rule.sh without both fails here, and so does a later
// CODEOWNERS rule that gives one file of such a tree to someone else.
func TestCodeownersCoverTheGuardedTrees(t *testing.T) {
	fsys := repoFS(t)
	guarded, err := bareArray(readLines(t, fsys, "scripts/lib/dependency-rule.sh"), "guarded")
	if err != nil {
		t.Fatalf("scripts/lib/dependency-rule.sh: %v", err)
	}
	rules, err := codeownersRules(readLines(t, fsys, ".github/CODEOWNERS"))
	if err != nil {
		t.Fatalf(".github/CODEOWNERS: %v", err)
	}
	twoApproval, err := quotedArray(readLines(t, fsys, githubSettings), "TWO_APPROVAL_PATHS")
	if err != nil {
		t.Fatalf("%s: %v", githubSettings, err)
	}
	required := slices.Concat(guarded, gateTrees, authorizationTrees)
	for _, tree := range required {
		if !slices.Contains(twoApproval, tree+"/**") {
			t.Errorf("%s: TWO_APPROVAL_PATHS holds no %q", githubSettings, tree+"/**")
		}
	}
	for _, problem := range ownershipProblems(rules, repoFileList(t), required, twoApproval) {
		t.Errorf(".github/CODEOWNERS: %s", problem)
	}
}

// ownershipProblems names every file under a required tree or a two-approval
// path whose last matching CODEOWNERS rule is not the security maintainers',
// and a required tree or a two-approval pattern that holds no file, which
// would leave nothing checked. A two-approval tree, dir/**, that holds no file
// yet is judged by a file it could hold; any other entry is a path.Match
// pattern over the files, judged by every file it matches.
func ownershipProblems(rules []codeownersRule, files, required, twoApproval []string) []string {
	trees, patterns, problems := splitTwoApproval(required, twoApproval)
	problems = append(problems, treeProblems(rules, files, required, trees)...)
	return append(problems, patternProblems(rules, files, patterns)...)
}

// splitTwoApproval returns the required trees followed by every two-approval
// dir/** tree not already among them, the other two-approval entries as
// patterns, and an entry that is neither as a problem.
func splitTwoApproval(required, twoApproval []string) (trees, patterns, problems []string) {
	trees = slices.Clone(required)
	for _, entry := range twoApproval {
		tree, isTree := strings.CutSuffix(entry, "/**")
		switch {
		case isTree && !strings.Contains(tree, "*"):
			if !slices.Contains(trees, tree) {
				trees = append(trees, tree)
			}
		case strings.Contains(entry, "**"):
			problems = append(problems, fmt.Sprintf("two-approval path %q is neither dir/** nor a pattern without **", entry))
		default:
			patterns = append(patterns, entry)
		}
	}
	return trees, patterns, problems
}

func treeProblems(rules []codeownersRule, files, required, trees []string) []string {
	var problems []string
	for _, p := range trees {
		under := slices.DeleteFunc(slices.Clone(files), func(f string) bool { return f != p && !strings.HasPrefix(f, p+"/") })
		switch {
		case len(under) == 0 && slices.Contains(required, p):
			problems = append(problems, fmt.Sprintf("%s holds no file, so its ownership was not checked", p))
		case len(under) == 0:
			under = []string{p + "/file.go"}
		}
		problems = append(problems, ownedElsewhere(rules, under)...)
	}
	return problems
}

func patternProblems(rules []codeownersRule, files, patterns []string) []string {
	var problems []string
	for _, pattern := range patterns {
		matched, err := matchFiles(pattern, files)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("two-approval path %q: %v", pattern, err))
		case len(matched) == 0:
			problems = append(problems, fmt.Sprintf("two-approval path %s matches no file, so its ownership was not checked", pattern))
		}
		problems = append(problems, ownedElsewhere(rules, matched)...)
	}
	return problems
}

// ownedElsewhere names every file whose last matching rule is not the
// security maintainers'.
func ownedElsewhere(rules []codeownersRule, files []string) []string {
	var problems []string
	for _, f := range files {
		if owners := ownersOf(rules, f); !slices.Contains(owners, securityTeam) {
			problems = append(problems, fmt.Sprintf("gives %s to %q, not to %s", f, owners, securityTeam))
		}
	}
	return problems
}

func matchFiles(pattern string, files []string) ([]string, error) {
	var matched []string
	for _, f := range files {
		ok, err := path.Match(pattern, f)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, f)
		}
	}
	return matched, nil
}

// repoFileList lists the repository's files the way the gate's scripts do:
// git's tracked and unignored files in a work tree, the commit's own list or a
// walk in an export.
func repoFileList(t *testing.T) []string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH, so scripts/lib/repo-files.sh cannot list the files: %v", err)
	}
	cmd := exec.Command(bash, "-c", `. scripts/lib/repo-files.sh && repo_files`) //nolint:gosec // G204: bash from PATH sourcing this repository's own script
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("repo_files failed: %v", err)
	}
	files := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(files) < minRepoFiles {
		t.Fatalf("repo_files listed %d file(s), want at least %d; the listing stopped working", len(files), minRepoFiles)
	}
	return files
}

// Far fewer files than the repository holds means the listing broke.
const minRepoFiles = 500

func TestOwnershipProblemsJudgesEveryFile(t *testing.T) {
	rules, err := codeownersRules([]string{
		"*                 @all",
		"/internal/a/      " + securityTeam,
		"/internal/a/x.go  @all",
		"/internal/b/      " + securityTeam,
		"/reserved/        " + securityTeam,
		"/cmd/route*.go    " + securityTeam,
		"/cmd/route.go     @all",
		"/cmd/stops.go     " + securityTeam,
		"/cmd/gone.go      " + securityTeam,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := []string{
		"cmd/route.go", "cmd/route_test.go", "cmd/routes/x.go", "cmd/stops.go", "internal/a/w.go", "internal/a/x.go", "internal/a/y.go",
		"internal/b/z.go", "internal/c/v.go", "loose.go",
	}
	got := ownershipProblems(rules, files, []string{"internal/a", "internal/empty"}, []string{
		"internal/b/**", "internal/c/**", "reserved/**", "loose.go", "cmd/route*.go", "cmd/stops.go", "cmd/gone.go", "cmd/**/x.go", "cmd/[.go",
	})
	want := []string{
		`two-approval path "cmd/**/x.go" is neither dir/** nor a pattern without **`,
		`gives internal/a/x.go to ["@all"], not to ` + securityTeam,
		"internal/empty holds no file, so its ownership was not checked",
		`gives internal/c/v.go to ["@all"], not to ` + securityTeam,
		`gives loose.go to ["@all"], not to ` + securityTeam,
		`gives cmd/route.go to ["@all"], not to ` + securityTeam,
		"two-approval path cmd/gone.go matches no file, so its ownership was not checked",
		`two-approval path "cmd/[.go": syntax error in pattern`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("problems = %q\nwant       %q", got, want)
	}
}

func TestOwnersOfTakesTheLastMatchingRule(t *testing.T) {
	rules, err := codeownersRules([]string{
		"# a comment",
		"*            @all",
		"/internal/a/ @a",
		"/Makefile    @make",
		"/.lint.*     @lint",
		"/internal/   @internal",
		"/internal/b/ @b # a reason",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"internal/a/x.go":     "@internal",
		"internal/b/c/x.go":   "@b",
		"internal/ab/x.go":    "@internal",
		"Makefile":            "@make",
		"Makefile/x":          "@make",
		"docs/Makefile":       "@all",
		".lint.yml":           "@lint",
		"sub/.lint.yml":       "@all",
		"README.md":           "@all",
		"internal/b":          "@internal",
		"internalx/b/file.go": "@all",
	}
	for file, want := range cases {
		if got := ownersOf(rules, file); !slices.Equal(got, []string{want}) {
			t.Errorf("ownersOf(%q) = %q, want [%s]", file, got, want)
		}
	}
	if got := ownersOf(rules[1:2], "README.md"); got != nil {
		t.Errorf("a file no rule matches is owned by %q", got)
	}
	for _, line := range []string{
		"internal/a/ @a", "/docs/**/x @a", "/docs/ ", "!/docs/ @a", "/internal/** @a", "/** @a", "/internal/*/ @a",
		"/x/re?c/ @a", "/a/m[c]p/ @a", `/a\ b @a`,
	} {
		if _, err := codeownersRules([]string{line}); err == nil {
			t.Errorf("codeownersRules read %q without an error", line)
		}
	}
}

func TestAGlobIsReadAgainstTheSecurityMaintainers(t *testing.T) {
	rules, err := codeownersRules([]string{
		"*              @all",
		"/internal/     " + securityTeam,
		"/internal/re*  @x",
		"/tools/*       " + securityTeam,
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		"internal/reaction.go":       "@x",
		"internal/reaction/x.go":     "@x",
		"internal/reaction/sub/y.go": "@x",
		"internal/core/x.go":         securityTeam,
		"tools/a.go":                 securityTeam,
		"tools/sub/a.go":             "@all",
	} {
		if got := ownersOf(rules, file); !slices.Equal(got, []string{want}) {
			t.Errorf("ownersOf(%q) = %q, want [%s]", file, got, want)
		}
	}
}

func TestArrayReadersRefuseWhatTheyCannotRead(t *testing.T) {
	if got, err := quotedArray([]string{"X=(", `  "a/**"`, "  # c", "", `  "b"`, ")"}, "X"); err != nil || !slices.Equal(got, []string{"a/**", "b"}) {
		t.Errorf("quotedArray = %q, %v; want [a/** b]", got, err)
	}
	if got, err := bareArray([]string{"X=(", "  a/b", "  # c", "  c", ")"}, "X"); err != nil || !slices.Equal(got, []string{"a/b", "c"}) {
		t.Errorf("bareArray = %q, %v; want [a/b c]", got, err)
	}
	for name, lines := range map[string][]string{
		"no array":       {"Y=(", `"a"`, ")"},
		"never closed":   {"X=(", `"a"`},
		"empty":          {"X=(", ")"},
		"an unquoted":    {"X=(", "a", ")"},
		"two on a line":  {"X=(", `"a" "b"`, ")"},
		"an expansion":   {"X=(", `"${A}"`, ")"},
		"single-quoted":  {"X=(", `'a'`, ")"},
		"an open string": {"X=(", `"a`, ")"},
	} {
		if got, err := quotedArray(lines, "X"); err == nil {
			t.Errorf("quotedArray read %s as %q without an error", name, got)
		}
	}
	for name, lines := range map[string][]string{
		"empty":   {"X=(", ")"},
		"quoted":  {"X=(", `"a"`, ")"},
		"a space": {"X=(", "a b", ")"},
	} {
		if got, err := bareArray(lines, "X"); err == nil {
			t.Errorf("bareArray read %s as %q without an error", name, got)
		}
	}
}

type codeownersRule struct {
	pattern string
	owners  []string
}

// codeownersRules reads the forms this file uses: "*", an anchored directory
// "/dir/" with no glob in it, and an anchored path "/name" whose last element
// alone may carry * or ?. Any other form, ** and [ ] among them, is an error
// rather than a rule matched differently from GitHub.
func codeownersRules(lines []string) ([]codeownersRule, error) {
	var rules []codeownersRule
	for _, line := range lines {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pattern := fields[0]
		if len(fields) < 2 {
			return nil, fmt.Errorf("%q names no owner", pattern)
		}
		if pattern != "*" && !readableForm(pattern) {
			return nil, fmt.Errorf("%q is not a form this reader matches", pattern)
		}
		rules = append(rules, codeownersRule{pattern: pattern, owners: fields[1:]})
	}
	return rules, nil
}

func readableForm(pattern string) bool {
	dir, last := path.Split(strings.TrimPrefix(pattern, "/"))
	switch {
	case !strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, `[]\`) || strings.Contains(pattern, "**"):
		return false
	case strings.HasSuffix(pattern, "/"):
		return !strings.ContainsAny(pattern, "*?")
	default:
		return last != "" && !strings.ContainsAny(dir, "*?")
	}
}

// ownersOf returns the owners of the last rule that matches file, a
// repository-relative slash path, or nil when none does. A glob in a last
// element names what lies at that level, as GitHub's docs/* example reads;
// a rule that does not give a file to the security maintainers is read as
// also taking what lies under a directory its glob names, so a reading GitHub
// might not share never counts in their favour.
func ownersOf(rules []codeownersRule, file string) []string {
	var owners []string
	for _, r := range rules {
		anchored := strings.TrimPrefix(r.pattern, "/")
		var match bool
		switch {
		case r.pattern == "*":
			match = true
		case strings.HasSuffix(anchored, "/"):
			match = strings.HasPrefix(file, anchored)
		default:
			ok, err := path.Match(anchored, file)
			match = (err == nil && ok) || strings.HasPrefix(file, anchored+"/") ||
				(!slices.Contains(r.owners, securityTeam) && globsAnAncestor(anchored, file))
		}
		if match {
			owners = r.owners
		}
	}
	return owners
}

func globsAnAncestor(pattern, file string) bool {
	for dir := path.Dir(file); dir != "."; dir = path.Dir(dir) {
		if ok, err := path.Match(pattern, dir); err == nil && ok {
			return true
		}
	}
	return false
}

// quotedArray returns the entries of the bash array `name=( ... )`, one
// double-quoted string per line with no expansion in it, blank lines and
// comments skipped. Any other shape is an error, never a shorter list.
func quotedArray(lines []string, name string) ([]string, error) {
	return readArray(lines, name, func(entry string) (string, bool) {
		inner, ok := strings.CutPrefix(entry, `"`)
		inner, closed := strings.CutSuffix(inner, `"`)
		return inner, ok && closed && inner != "" && !strings.ContainsAny(inner, "\"'$`\\ \t")
	})
}

// bareArray returns the entries of the bash array `name=( ... )`, one bare word
// per line with no quote, space, expansion or glob character.
func bareArray(lines []string, name string) ([]string, error) {
	return readArray(lines, name, func(entry string) (string, bool) {
		return entry, !strings.ContainsAny(entry, " \t\"'$`\\(){}*?[]")
	})
}

func readArray(lines []string, name string, word func(string) (string, bool)) ([]string, error) {
	var words []string
	inArray := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case !inArray:
			inArray = trimmed == name+"=("
		case trimmed == ")":
			if len(words) == 0 {
				return nil, fmt.Errorf("array %s is empty", name)
			}
			return words, nil
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
		default:
			w, ok := word(trimmed)
			if !ok {
				return nil, fmt.Errorf("array %s: %q is not an entry this reader reads", name, trimmed)
			}
			words = append(words, w)
		}
	}
	return nil, fmt.Errorf("no array %s=( ... ) closed by a line holding only \")\"", name)
}
