package core_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The other two mechanisms, read as text by the tests in this file.
const (
	lintConfig = ".golangci.yml"
	ruleScript = "scripts/lib/dependency-rule.sh"
)

// Packages a test in a guarded tree may not import either. A test reads
// fixtures and runs the go command, so os and os/exec are allowed to it; the
// network, system calls, randomness, unsafe and plugins are not. testing/quick
// is here because it draws from math/rand; seeded property tests use
// pgregory.net/rapid.
var neverAllowedInTests = []string{"net", "syscall", "crypto/rand", "math/rand", "testing/quick", "unsafe", "plugin"}

// Modules outside the standard library that a test in a guarded tree may
// import. Written out, so an entry for any other module fails whatever it is
// called.
var testOnlyModules = []string{"pgregory.net/rapid"}

// The exclusions of .golangci.yml, written out whole. Each line can switch the
// rule off without touching the depguard rules or the forbidigo patterns the
// other tests compare: a path or a rule stops reporting what it matches, and a
// generated mode other than disable skips every file whose header claims it
// was generated. The probe catches such a line only where it plants a file,
// and it cannot plant at a path no package holds yet; this catches it
// anywhere.
var wantExclusions = []string{
	`    generated: disable`,
	`    paths:`,
	`      - "^api/gen/"`,
	`      - "(^|/)testdata/"`,
	`    rules:`,
	`      - linters: [forbidigo]`,
	`        text: "guarded tree: "`,
	`        path-except: "^(internal/core|internal/policy|internal/canon|internal/evidence|pkg/contract|internal/supervise|internal/channel|internal/observe|internal/trailchain)/"`,
	`      - linters: [forbidigo]`,
	"        text: \"use of `time.Local` forbidden\"",
	`        path: "^internal/core/property_test\\.go$"`,
}

// What .golangci.yml may hold at its top level and under run. issues can
// report only the lines a revision changed, run can stop the analysis of test
// files or build under other tags, and output can send the report elsewhere;
// each makes `make lint` pass over a violation.
var (
	wantTopLevel = []string{`version: "2"`, "run:", "linters:", "formatters:"}
	wantRun      = []string{"  timeout: 5m"}
)

// The lists are written out in three places that are edited independently. A
// comment asking the next editor to keep them in step is what let them drift
// apart in the first place, so the agreement is a test.
func TestAllThreeMechanismsAllowTheSameSet(t *testing.T) {
	modulePath, moduleDir := mainModule(t)
	lint, script := readMechanisms(t, moduleDir)
	core, tests := mustRule(t, lint, "core"), mustRule(t, lint, "core-tests")

	for _, c := range []struct {
		where      string
		have, want []string
	}{
		{ruleScript + ": stdlib", mustArray(t, script, "stdlib"), allowedStdlib},
		{ruleScript + ": modules", mustArray(t, script, "modules"), acceptedModules},
		{ruleScript + ": denied", mustArray(t, script, "denied"), deniedInModule},
		{ruleScript + ": generated", mustArray(t, script, "generated"), generatedInModule},
		{ruleScript + ": refused_files", mustArray(t, script, "refused_files"), refusedFileLists},
		{ruleScript + ": foreign_platform", mustArray(t, script, "foreign_platform"), foreignPlatform},
		{lintConfig + ": depguard rule core, allow", core.allow, depguardAllow(modulePath)},
		{lintConfig + ": depguard rule core, deny", core.deny, depguardDeny(modulePath)},
		{lintConfig + ": depguard rule core-tests, deny", tests.deny, depguardDeny(modulePath)},
	} {
		sameSet(t, c.where, c.have, c.want)
	}

	// In depguard's lax and original modes a package in neither list is
	// allowed, which would turn the allowlist back into a deny list.
	for _, rule := range []depguardRule{core, tests} {
		if rule.listMode != "strict" {
			t.Errorf("%s: depguard rule %s has list-mode %q, want strict", lintConfig, rule.name, rule.listMode)
		}
	}
	for _, problem := range testAllowanceProblems(core.allow, tests.allow) {
		t.Errorf("%s: %s", lintConfig, problem)
	}
}

// The guarded tree list lives in the same files as the allowed set. Until the
// two were compared, the files could disagree about which trees the rule
// applies to at all, and every gate would still report green: a rule that
// guards nothing looks exactly like a rule with nothing to report.
func TestAllThreeMechanismsGuardTheSameTrees(t *testing.T) {
	_, moduleDir := mainModule(t)
	lint, script := readMechanisms(t, moduleDir)

	prod, err := treesFromGlobs(mustRule(t, lint, "core").files, "/**", "!$test")
	if err != nil {
		t.Fatalf("%s: depguard rule core: %v", lintConfig, err)
	}
	tests, err := treesFromGlobs(mustRule(t, lint, "core-tests").files, "/**_test.go", "")
	if err != nil {
		t.Fatalf("%s: depguard rule core-tests: %v", lintConfig, err)
	}
	scope, err := forbidigoScope(lint)
	if err != nil {
		t.Fatalf("%s: %v", lintConfig, err)
	}

	// The directories themselves are one more side: a list of five that all
	// agree on a tree the module no longer holds guards four.
	for _, c := range []struct {
		where string
		have  []string
	}{
		{ruleScript + ": guarded", mustArray(t, script, "guarded")},
		{lintConfig + ": depguard rule core, files", prod},
		{lintConfig + ": depguard rule core-tests, files", tests},
		{"the module's directories", treeDirectories(t, moduleDir, guardedTrees)},
	} {
		sameSet(t, c.where, c.have, guardedTrees)
	}

	// forbidigo's name refusals cover the reached trees as well; depguard reads
	// each file's own imports and has no use for them.
	sameSet(t, ruleScript+": reached", mustArray(t, script, "reached"), reachedTrees)
	sameSet(t, "the module's directories", treeDirectories(t, moduleDir, reachedTrees), reachedTrees)
	sameSet(t, lintConfig+": the exclusion rule that scopes forbidigo", scope, slices.Concat(guardedTrees, reachedTrees))
	for _, tree := range reachedTrees {
		if slices.ContainsFunc(guardedTrees, func(guarded string) bool { return underPath(tree, guarded) || underPath(guarded, tree) }) {
			t.Errorf("reachedTrees holds %s, which overlaps a guarded tree", tree)
		}
	}
}

// The forbidigo patterns that carry the name refusals, written out whole: an
// edit to one changes what the rule refuses, and the probe plants only the
// names it knows.
var wantGuardedPatterns = []string{
	`^(time\.(Now|Since|Until|After|AfterFunc|Tick|NewTicker|NewTimer|Sleep)|timestamppb\.Now|context\.With(Deadline|Timeout)(Cause)?)$`,
	`^(fmt\.Scan(f|ln)?|time\.(LoadLocation|Local|Time\.(Local|Zone|ZoneBounds|IsDST)))$`,
	`^ed25519\.GenerateKey$`,
}

// The names layering_names_test.go refuses are the names forbidigo refuses in
// the same packages: each is matched by a guarded pattern, and each guarded
// pattern matches one of them.
func TestNameRefusalsAgreeWithForbidigo(t *testing.T) {
	_, moduleDir := mainModule(t)
	lint, _ := readMechanisms(t, moduleDir)
	patterns, err := guardedPatterns(lint)
	if err != nil {
		t.Fatalf("%s: %v", lintConfig, err)
	}
	sameSet(t, lintConfig+": the guarded forbidigo patterns", patterns, wantGuardedPatterns)

	var names []string
	for path, refused := range refusedNames {
		for _, name := range refused {
			names = append(names, path[strings.LastIndex(path, "/")+1:]+"."+name)
		}
	}
	for _, method := range refusedMethods {
		names = append(names, "time.Time."+method)
	}
	matched := make([]bool, len(patterns))
	for _, name := range names {
		found := false
		for i, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("%s: pattern %q: %v", lintConfig, pattern, err)
			}
			if re.MatchString(name) {
				found, matched[i] = true, true
			}
		}
		if !found {
			t.Errorf("layering_names_test.go refuses %s, which no guarded forbidigo pattern matches", name)
		}
	}
	for i, pattern := range patterns {
		if !matched[i] {
			t.Errorf("%s: guarded pattern %q matches no name layering_names_test.go refuses", lintConfig, pattern)
		}
	}
}

// guardedPatterns reads each forbidigo pattern whose message starts with
// "guarded tree: ". The pattern is the line before the message, written as
// "- pattern: '<regexp>'"; any other shape is an error.
func guardedPatterns(lines []string) ([]string, error) {
	var patterns []string
	previous := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, `msg: "guarded tree: `) {
			pattern, ok := strings.CutPrefix(previous, "- pattern: '")
			if ok {
				pattern, ok = strings.CutSuffix(pattern, "'")
			}
			if !ok || pattern == "" || strings.Contains(pattern, "'") {
				return nil, fmt.Errorf("the line before %q is %q, not - pattern: '<regexp>'", trimmed, previous)
			}
			patterns = append(patterns, pattern)
		}
		previous = trimmed
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf(`no forbidigo pattern carries a message starting "guarded tree: "`)
	}
	return patterns, nil
}

// treeDirectories returns each of trees that is a directory of the module, so
// a missing one shows up as a tree the directories lack.
func treeDirectories(t *testing.T, moduleDir string, trees []string) []string {
	t.Helper()
	var present []string
	for _, tree := range trees {
		info, err := os.Stat(filepath.Join(moduleDir, filepath.FromSlash(tree)))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			t.Fatalf("stat %s: %v", tree, err)
		case info.IsDir():
			present = append(present, tree)
		}
	}
	return present
}

// Everything in .golangci.yml besides the rule's own lists that could stop
// `make lint` from reporting a violation of it. The probe proves that the
// configuration as it stands refuses its fixture; this proves the parts the
// fixture cannot reach are what they are today.
func TestLintConfigurationLeavesTheRuleOn(t *testing.T) {
	_, moduleDir := mainModule(t)
	lint, _ := readMechanisms(t, moduleDir)

	if top := topLevel(lint); !slices.Equal(top, wantTopLevel) {
		t.Errorf("%s holds the top-level lines %q, want %q", lintConfig, top, wantTopLevel)
	}
	for _, c := range []struct {
		path []string
		want []string
	}{
		{[]string{"run"}, wantRun},
		{[]string{"linters", "exclusions"}, wantExclusions},
	} {
		have, err := yamlBlock(lint, c.path...)
		switch {
		case err != nil:
			t.Errorf("%s: %v", lintConfig, err)
		case !slices.Equal(have, c.want):
			t.Errorf("%s: %s holds\n%s\nwant\n%s", lintConfig, strings.Join(c.path, "."),
				strings.Join(have, "\n"), strings.Join(c.want, "\n"))
		}
	}

	enabled, err := yamlBlock(lint, "linters", "enable")
	if err != nil {
		t.Fatalf("%s: %v", lintConfig, err)
	}
	for _, linter := range []string{"depguard", "forbidigo"} {
		if !slices.Contains(enabled, "    - "+linter) {
			t.Errorf("%s: linters.enable lacks %s, which carries the dependency rule", lintConfig, linter)
		}
	}

	// A linter named under both enable and disable is off, and golangci-lint
	// does not object, so disable may not appear at all.
	linters, err := yamlBlock(lint, "linters")
	if err != nil {
		t.Fatalf("%s: %v", lintConfig, err)
	}
	for _, line := range linters {
		if strings.HasPrefix(line, "  disable:") {
			t.Errorf("%s: linters holds %q, which switches a linter off whatever enable says", lintConfig, line)
		}
	}
}

// testAllowanceProblems holds the test rule to the production rule: a test may
// import whatever the code it tests may, plus standard library packages that
// never reach the network, system calls, randomness, unsafe or plugins, and the
// modules testOnlyModules names. It returns one line per breach.
func testAllowanceProblems(prod, tests []string) []string {
	var problems []string
	if missing := notIn(prod, tests); len(missing) > 0 {
		problems = append(problems, fmt.Sprintf("depguard rule core-tests lacks %v, which rule core allows", missing))
	}
	for _, entry := range notIn(tests, prod) {
		name, exact := strings.CutSuffix(entry, "$")
		if !exact {
			var prefix bool
			if name, prefix = strings.CutSuffix(entry, "/"); !prefix {
				problems = append(problems, fmt.Sprintf("core-tests entry %q ends in neither \"$\" nor \"/\", so depguard reads it as a raw prefix", entry))
				continue
			}
		}
		// No standard library path has a dot in its first element, and every
		// module path outside it does.
		if first, _, _ := strings.Cut(name, "/"); strings.Contains(first, ".") {
			if !slices.ContainsFunc(testOnlyModules, func(module string) bool { return underPath(name, module) }) {
				problems = append(problems, fmt.Sprintf("core-tests entry %q admits a module outside the standard library that %v does not name", entry, testOnlyModules))
			}
			continue
		}
		for _, root := range neverAllowedInTests {
			if underPath(name, root) || (!exact && underPath(root, name)) {
				problems = append(problems, fmt.Sprintf("core-tests entry %q admits %s, which no test in a guarded tree may import", entry, root))
			}
		}
	}
	return problems
}

// depguardAllow is the allow list the other two mechanisms imply for the
// depguard rule core. depguard compares raw strings: an entry ending in "$"
// matches exactly and any other entry is a prefix, so each prefix is written
// both ways to match whole segments only, as underPath does.
func depguardAllow(modulePath string) []string {
	var allow []string
	for _, base := range append([]string{modulePath}, acceptedModules...) {
		allow = append(allow, base+"$", base+"/")
	}
	for _, pkg := range allowedStdlib {
		allow = append(allow, pkg+"$")
	}
	return allow
}

// depguardDeny is the deny list the other two mechanisms imply: each denied
// tree as itself and as the prefix of every package below it.
func depguardDeny(modulePath string) []string {
	deny := make([]string, 0, 2*len(deniedInModule))
	for _, rel := range deniedInModule {
		deny = append(deny, modulePath+"/"+rel+"$", modulePath+"/"+rel+"/")
	}
	return deny
}

func sameSet(t *testing.T, where string, have, want []string) {
	t.Helper()
	if missing := notIn(want, have); len(missing) > 0 {
		t.Errorf("%s lacks %v, which this test holds", where, missing)
	}
	if extra := notIn(have, want); len(extra) > 0 {
		t.Errorf("%s holds %v, which this test does not", where, extra)
	}
}

// notIn returns the elements of want that are absent from have.
func notIn(want, have []string) []string {
	var missing []string
	for _, path := range want {
		if !slices.Contains(have, path) {
			missing = append(missing, path)
		}
	}
	return missing
}

func readMechanisms(t *testing.T, moduleDir string) (lint, script []string) {
	t.Helper()
	// Rooted at the module directory, so a name in this test cannot send it
	// reading somewhere else, and gosec does not have to guess that.
	repo := os.DirFS(moduleDir)
	return readLines(t, repo, lintConfig), readLines(t, repo, ruleScript)
}

func readLines(t *testing.T, fsys fs.FS, name string) []string {
	t.Helper()
	content, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return strings.Split(string(content), "\n")
}

func mustRule(t *testing.T, lint []string, name string) depguardRule {
	t.Helper()
	rule, err := readDepguardRule(lint, name)
	if err != nil {
		t.Fatalf("%s: %v", lintConfig, err)
	}
	return rule
}

func mustArray(t *testing.T, script []string, name string) []string {
	t.Helper()
	words, err := shellArray(script, name)
	if err != nil {
		t.Fatalf("%s: %v", ruleScript, err)
	}
	return words
}

// The readers below scan text and never guess. A shape they do not know is an
// error rather than a shorter list: a reader that skipped a line it could not
// parse would compare against less than the file says, and agree with it.

// shellArray returns the words of the bash array `name=( ... )`, one bare word
// per line, blank lines and comments skipped. A quote, a space, a "$" or a
// glob character is refused, because the shell would read a different word
// than this test does.
func shellArray(lines []string, name string) ([]string, error) {
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
		case strings.ContainsAny(trimmed, " \t\"'$`\\(){}*?[]"):
			return nil, fmt.Errorf("array %s: %q is not one bare word", name, trimmed)
		default:
			words = append(words, trimmed)
		}
	}
	return nil, fmt.Errorf("no array %s=( ... ) closed by a line holding only \")\"", name)
}

// topLevel returns the lines at indentation zero, comments and blank lines left
// out.
func topLevel(lines []string) []string {
	var top []string
	for _, line := range lines {
		if !blankOrComment(line) && indentOf(line) == 0 {
			top = append(top, strings.TrimRight(line, " \t"))
		}
	}
	return top
}

// yamlBlock returns the lines of the block under the key path, comments and
// blank lines left out. Each key must stand alone as "key:" on exactly one line
// at the indentation of its level, two spaces per level; a flow mapping, an
// inline value or a repeated key is an error.
func yamlBlock(lines []string, path ...string) ([]string, error) {
	block := lines
	for depth, key := range path {
		var err error
		if block, err = childBlock(block, 2*depth, key); err != nil {
			return nil, err
		}
	}
	return contentLines(block), nil
}

// childBlock returns the lines below the one line of block that holds "key:"
// at indent: everything up to the next content line at that indentation or
// less.
func childBlock(block []string, indent int, key string) ([]string, error) {
	var at []int
	for i, line := range block {
		if indentOf(line) == indent && strings.TrimSpace(line) == key+":" {
			at = append(at, i)
		}
	}
	if len(at) != 1 {
		return nil, fmt.Errorf("found %q at indentation %d %d time(s), want once", key+":", indent, len(at))
	}
	end := at[0] + 1
	for end < len(block) && (blankOrComment(block[end]) || indentOf(block[end]) > indent) {
		end++
	}
	return block[at[0]+1 : end], nil
}

// contentLines returns the lines that are neither blank nor a comment,
// trailing space dropped.
func contentLines(block []string) []string {
	var kept []string
	for _, line := range block {
		if !blankOrComment(line) {
			kept = append(kept, strings.TrimRight(line, " \t"))
		}
	}
	return kept
}

func blankOrComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

// depguardRule is one rule of the depguard block in .golangci.yml.
type depguardRule struct {
	name               string
	listMode           string
	files, allow, deny []string
}

// readDepguardRule reads the rule called name out of .golangci.yml. Scanned as
// text rather than parsed as YAML: the module has no YAML dependency and a
// test is not a reason to take one.
func readDepguardRule(lines []string, name string) (depguardRule, error) {
	rule := depguardRule{name: name}
	start := slices.IndexFunc(lines, func(line string) bool { return strings.TrimSpace(line) == name+":" })
	if start < 0 {
		return rule, fmt.Errorf("no depguard rule %q", name)
	}
	ruleIndent, keyIndent, key := indentOf(lines[start]), -1, ""
	for _, line := range lines[start+1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indentOf(line) <= ruleIndent {
			break // the rule ended; the next rule's lists are not this one's
		}
		if keyIndent < 0 {
			keyIndent = indentOf(line)
		}
		var err error
		if indentOf(line) == keyIndent && !strings.HasPrefix(trimmed, "- ") {
			key, err = rule.setKey(trimmed)
		} else {
			err = rule.addItem(key, trimmed)
		}
		if err != nil {
			return rule, fmt.Errorf("depguard rule %s: %w", name, err)
		}
	}
	return rule, rule.complete()
}

func (r *depguardRule) setKey(line string) (string, error) {
	key, value, _ := strings.Cut(line, ":")
	value = strings.TrimSpace(value)
	switch key {
	case "list-mode":
		r.listMode = value
	case "files", "allow", "deny":
		if value != "" {
			return "", fmt.Errorf("%s is not written as a block list", key)
		}
	default:
		return "", fmt.Errorf("unexpected key %q", key)
	}
	return key, nil
}

func (r *depguardRule) addItem(key, line string) error {
	item, isItem := strings.CutPrefix(line, "- ")
	switch {
	case !isItem && key == "deny" && strings.HasPrefix(line, "desc:"):
		return nil // the reason depguard prints with a deny entry
	case !isItem:
		return fmt.Errorf("cannot read %q under %s", line, key)
	case key == "files":
		return appendQuoted(&r.files, item)
	case key == "allow":
		return appendQuoted(&r.allow, item)
	case key == "deny":
		pkg, ok := strings.CutPrefix(item, "pkg:")
		if !ok {
			return fmt.Errorf("deny entry %q names no pkg", item)
		}
		return appendQuoted(&r.deny, pkg)
	default:
		return fmt.Errorf("list item %q outside files, allow and deny", item)
	}
}

func (r depguardRule) complete() error {
	if r.listMode == "" || len(r.files) == 0 || len(r.allow) == 0 || len(r.deny) == 0 {
		return fmt.Errorf("depguard rule %s lacks list-mode, files, allow or deny", r.name)
	}
	return nil
}

func appendQuoted(dst *[]string, s string) error {
	value, ok := quoted(s)
	if !ok {
		return fmt.Errorf("%q is not a double-quoted string", strings.TrimSpace(s))
	}
	*dst = append(*dst, value)
	return nil
}

// treesFromGlobs turns depguard file globs of the form "**/<tree><suffix>"
// back into tree paths. negation, when not empty, must appear exactly once, and
// it is the only entry allowed another form: any other "!" entry would exempt
// files from the rule.
func treesFromGlobs(globs []string, suffix, negation string) ([]string, error) {
	var trees []string
	negations := 0
	for _, glob := range globs {
		if negation != "" && glob == negation {
			negations++
			continue
		}
		// Checked, not trimmed. strings.TrimPrefix is a no-op when the prefix
		// is absent, so trimming would read "pkg/contract/**" and
		// "**/pkg/contract/**" as the same tree, while depguard matches the
		// glob against an absolute path and only the second matches anything.
		// Dropping the "**/" is the single edit that turns the rule off for a
		// tree, and it is the one edit this comparison exists to catch.
		tree, ok := strings.CutPrefix(glob, "**/")
		if ok {
			tree, ok = strings.CutSuffix(tree, suffix)
		}
		if !ok || tree == "" || strings.ContainsAny(tree, "*?[]{}!") {
			return nil, fmt.Errorf("glob %q is not of the form \"**/<tree>%s\"", glob, suffix)
		}
		trees = append(trees, tree)
	}
	if negation != "" && negations != 1 {
		return nil, fmt.Errorf("files holds %q %d time(s), want once", negation, negations)
	}
	return trees, nil
}

// forbidigoScope reads the tree list out of the exclusion rule that confines
// the "guarded tree:" forbidigo patterns to the guarded trees. The rule is
// written as three lines in a fixed order; any other shape is an error.
func forbidigoScope(lines []string) ([]string, error) {
	const (
		head = "- linters: [forbidigo]"
		text = `text: "guarded tree: "`
	)
	var at []int
	for i, line := range lines {
		if strings.TrimSpace(line) == text {
			at = append(at, i)
		}
	}
	if len(at) != 1 {
		return nil, fmt.Errorf("found %d exclusion rule(s) holding %s, want 1", len(at), text)
	}
	i := at[0]
	if i == 0 || i+1 == len(lines) || strings.TrimSpace(lines[i-1]) != head {
		return nil, fmt.Errorf("the exclusion rule holding %s does not start with %q", text, head)
	}
	return scopeTrees(strings.TrimSpace(lines[i+1]))
}

// scopeTrees reads the trees out of `path-except: "^(<tree>|<tree>)/"`.
func scopeTrees(line string) ([]string, error) {
	const prefix, suffix = `path-except: "^(`, `)/"`
	inner, ok := strings.CutPrefix(line, prefix)
	if ok {
		inner, ok = strings.CutSuffix(inner, suffix)
	}
	if !ok || inner == "" {
		return nil, fmt.Errorf("%q is not of the form %s<tree>|<tree>%s", line, prefix, suffix)
	}
	trees := strings.Split(inner, "|")
	for _, tree := range trees {
		if tree == "" || strings.ContainsAny(tree, `^$()[]{}*+?.\|`) {
			return nil, fmt.Errorf("path-except alternative %q is not a plain tree path", tree)
		}
	}
	return trees, nil
}

// quoted returns the contents of a double-quoted token, ignoring surrounding
// space and anything after the closing quote.
func quoted(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		return "", false
	}
	s = s[1:]
	end := strings.Index(s, `"`)
	if end < 0 {
		return "", false
	}
	return s[:end], true
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// A rule in the shape .golangci.yml uses, for the reader tests below.
const sampleRule = `      rules:
        core:
          list-mode: strict
          files:
            - "**/a/**"
            - "!$test"
          allow:
            - "b$"
            - "c/"
          deny:
            - pkg: "d$"
              desc: "no"
        other:
          list-mode: lax
`

// A configuration in the shape .golangci.yml uses, for the block readers.
const sampleConfig = `version: "2"
# a comment
run:
  timeout: 5m
linters:
  # a comment
  exclusions:
    paths:
      - "a"

  enable:
    - x
formatters:
  enable:
    - y
`

func TestRuleReaderReadsTheShapeItKnows(t *testing.T) {
	rule, err := readDepguardRule(strings.Split(sampleRule, "\n"), "core")
	if err != nil {
		t.Fatalf("readDepguardRule: %v", err)
	}
	if rule.listMode != "strict" ||
		!slices.Equal(rule.files, []string{"**/a/**", "!$test"}) ||
		!slices.Equal(rule.allow, []string{"b$", "c/"}) ||
		!slices.Equal(rule.deny, []string{"d$"}) {
		t.Errorf("readDepguardRule read %+v", rule)
	}
}

func TestListReadersReadTheShapesTheyKnow(t *testing.T) {
	words, err := shellArray([]string{"x=(", "  # a comment", "  a/b", "", "  c", ")"}, "x")
	if err != nil || !slices.Equal(words, []string{"a/b", "c"}) {
		t.Errorf("shellArray = %q, %v", words, err)
	}

	trees, err := treesFromGlobs([]string{"**/a/b/**", "!$test", "**/c/**"}, "/**", "!$test")
	if err != nil || !slices.Equal(trees, []string{"a/b", "c"}) {
		t.Errorf("treesFromGlobs = %q, %v", trees, err)
	}

	patterns, err := guardedPatterns([]string{
		`        - pattern: '^panic$'`,
		`          msg: "no panic"`,
		`        - pattern: '^a\.B$'`,
		`          # a comment`,
		`          msg: "guarded tree: x"`,
	})
	if err != nil || !slices.Equal(patterns, []string{`^a\.B$`}) {
		t.Errorf("guardedPatterns = %q, %v", patterns, err)
	}

	scope, err := forbidigoScope([]string{
		`      - linters: [forbidigo]`,
		`        text: "guarded tree: "`,
		`        path-except: "^(a/b|c)/"`,
	})
	if err != nil || !slices.Equal(scope, []string{"a/b", "c"}) {
		t.Errorf("forbidigoScope = %q, %v", scope, err)
	}
}

func TestBlockReadersReadTheShapesTheyKnow(t *testing.T) {
	config := strings.Split(sampleConfig, "\n")
	if top := topLevel(config); !slices.Equal(top, []string{`version: "2"`, "run:", "linters:", "formatters:"}) {
		t.Errorf("topLevel = %q", top)
	}
	for _, c := range []struct {
		path []string
		want []string
	}{
		{[]string{"run"}, []string{"  timeout: 5m"}},
		{[]string{"linters", "exclusions"}, []string{"    paths:", `      - "a"`}},
		{[]string{"linters", "enable"}, []string{"    - x"}},
		{[]string{"formatters", "enable"}, []string{"    - y"}},
	} {
		if got, err := yamlBlock(config, c.path...); err != nil || !slices.Equal(got, c.want) {
			t.Errorf("yamlBlock(%q) = %q, %v; want %q", c.path, got, err, c.want)
		}
	}
}

// Each case is a shape one plausible edit produces, and each must be an error
// rather than a shorter or different list.
func TestReadersRefuseShapesTheyDoNotKnow(t *testing.T) {
	rule := func(old, replacement string) func() error {
		return func() error {
			lines := strings.Split(strings.Replace(sampleRule, old, replacement, 1), "\n")
			_, err := readDepguardRule(lines, "core")
			return err
		}
	}
	array := func(text string) func() error {
		return func() error {
			_, err := shellArray(strings.Split(text, "\n"), "x")
			return err
		}
	}
	globs := func(negation string, globs ...string) func() error {
		return func() error {
			_, err := treesFromGlobs(globs, "/**", negation)
			return err
		}
	}
	scope := func(lines ...string) func() error {
		return func() error {
			_, err := forbidigoScope(lines)
			return err
		}
	}
	block := func(old, replacement string, path ...string) func() error {
		return func() error {
			_, err := yamlBlock(strings.Split(strings.Replace(sampleConfig, old, replacement, 1), "\n"), path...)
			return err
		}
	}
	patterns := func(lines ...string) func() error {
		return func() error {
			_, err := guardedPatterns(lines)
			return err
		}
	}
	const head, text = `- linters: [forbidigo]`, `text: "guarded tree: "`
	const guardedMsg = `msg: "guarded tree: x"`

	cases := map[string]func() error{
		"rule absent":                     rule("core:", "kernel:"),
		"rule without list-mode":          rule("list-mode: strict\n", ""),
		"rule with an unknown key":        rule("list-mode: strict", "list-mode: strict\n          extra: true"),
		"rule with a flow list":           rule("allow:", `allow: ["b$"]`),
		"rule with an unquoted entry":     rule(`- "b$"`, "- b$"),
		"rule with a deny entry, no pkg":  rule(`- pkg: "d$"`, `- "d$"`),
		"rule with a stray line":          rule(`- "c/"`, "c/"),
		"array absent":                    array("y=(\n  a\n)"),
		"array never closed":              array("x=(\n  a"),
		"array empty":                     array("x=(\n)"),
		"array with a quoted word":        array("x=(\n  \"a\"\n)"),
		"array with a variable":           array("x=(\n  ${module}/a\n)"),
		"array with a trailing comment":   array("x=(\n  a # b\n)"),
		"glob without the leading **/":    globs("", "a/**"),
		"glob with another negation":      globs("!$test", "**/a/**", "!$test", "!**/a/b/**"),
		"glob list without its negation":  globs("!$test", "**/a/**"),
		"glob with a wildcard in a tree":  globs("", "**/a/*/**"),
		"scope absent":                    scope(),
		"scope twice":                     scope(head, text, `path-except: "^(a)/"`, head, text, `path-except: "^(a)/"`),
		"scope not in a forbidigo rule":   scope("- linters: [depguard]", text, `path-except: "^(a)/"`),
		"scope as path, not path-except":  scope(head, text, `path: "^(a)/"`),
		"scope holding a regexp":          scope(head, text, `path-except: "^(internal/.*)/"`),
		"scope with an empty alternative": scope(head, text, `path-except: "^(a||b)/"`),
		"no guarded pattern":              patterns(`- pattern: '^panic$'`, `msg: "no panic"`),
		"guarded message without pattern": patterns(`- linters: [x]`, guardedMsg),
		"guarded pattern double-quoted":   patterns(`- pattern: "^a$"`, guardedMsg),
		"guarded pattern empty":           patterns(`- pattern: ''`, guardedMsg),
		"block absent":                    block("exclusions:", "excluded:", "linters", "exclusions"),
		"block as a flow mapping":         block("  exclusions:", "  exclusions: {paths: [a]}", "linters", "exclusions"),
		"block with a comment on its key": block("  exclusions:", "  exclusions: # x", "linters", "exclusions"),
		"block key given twice":           block("run:", "run:\nrun:", "run"),
		"block key at another indent":     block("  exclusions:", "   exclusions:", "linters", "exclusions"),
	}
	for name, read := range cases {
		if err := read(); err == nil {
			t.Errorf("%s: read without an error", name)
		}
	}
}

// Each extra entry is one a plausible edit to core-tests adds, and each must
// be reported; the first rule admits nothing the tests do not already use.
func TestTestAllowanceProblems(t *testing.T) {
	prod := []string{"fmt$", "example.invalid/m/"}
	good := append(slices.Clone(prod), "os$", "os/exec$", "testing$", "pgregory.net/rapid$", "go/ast$")
	if problems := testAllowanceProblems(prod, good); len(problems) != 0 {
		t.Errorf("a test rule within the bounds reported %q", problems)
	}
	for _, extra := range []string{
		"golang.org/x/net/", "golang.org/x/net$", "pgregory.net/", "example.invalid/other$",
		"net/http$", "net/", "syscall$", "math/rand$", "math/rand/v2$", "crypto/rand$",
		"testing/", "testing/quick$", "unsafe$", "plugin$", "net",
	} {
		if problems := testAllowanceProblems(prod, append(slices.Clone(good), extra)); len(problems) == 0 {
			t.Errorf("core-tests entry %q reported nothing", extra)
		}
	}
	if problems := testAllowanceProblems(prod, []string{"example.invalid/m/"}); len(problems) == 0 {
		t.Error("a test rule lacking what rule core allows reported nothing")
	}
}
