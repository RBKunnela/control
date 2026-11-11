package docscheck

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/guardana/control/internal/testreport"
)

const (
	expectedRunsPath  = "scripts/expected-runs.txt"
	expectedSkipsPath = "scripts/expected-skips.txt"
	twoAccountsTag    = "twoaccounts"
	// twoAccountsHelper is the test a tagged binary runs as in its child
	// processes; it skips on its own, so it is never listed.
	twoAccountsHelper = "TestHelperActsAsAnotherAccount"
	needsRootSkip     = "needs root"
)

// twoAccountSources is what the coverage of the "Two accounts" job is judged
// from: the module's path, its test files by repository-relative path, and
// the two lists.
type twoAccountSources struct {
	module string
	files  map[string][]byte
	skips  []byte
	runs   []byte
}

// twoAccountGaps names each top-level test of a file the twoaccounts tag
// brings in, and each test expected-skips.txt skips as needing root, that
// expected-runs.txt leaves out, since the job runs only what the list names;
// and each list entry that names neither, or a test no file declares.
func twoAccountGaps(src twoAccountSources) ([]string, error) {
	listed, err := testreport.ParseExpectedRuns(src.runs)
	if err != nil {
		return nil, err
	}
	declared, tagged, err := testsOfFiles(src.module, src.files)
	if err != nil {
		return nil, err
	}
	root, err := needsRootTests(src.skips)
	if err != nil {
		return nil, err
	}
	return append(unlisted(listed, tagged, root), strays(listed, declared, tagged, root)...), nil
}

// unlisted names each test the job has to run that the list leaves out.
func unlisted(listed testreport.ExpectedRuns, tagged map[testreport.Run]string, root []testreport.Run) []string {
	var gaps []string
	for _, r := range sortedRuns(tagged) {
		if r.Test != twoAccountsHelper && !slices.Contains(listed, r) {
			gaps = append(gaps, fmt.Sprintf("%s %s, a test of %s, runs in no job: %s does not name it", r.Package, r.Test, tagged[r], expectedRunsPath))
		}
	}
	for _, r := range root {
		if !slices.Contains(listed, r) {
			gaps = append(gaps, fmt.Sprintf("%s %s, which %s skips as needing root, runs in no job: %s does not name it", r.Package, r.Test, expectedSkipsPath, expectedRunsPath))
		}
	}
	return gaps
}

// strays names each list entry that is the helper, names a test no file
// declares, or one the job has no reason to run.
func strays(listed testreport.ExpectedRuns, declared map[testreport.Run]bool, tagged map[testreport.Run]string, root []testreport.Run) []string {
	var gaps []string
	for _, r := range listed {
		_, isTagged := tagged[r]
		switch {
		case r.Test == twoAccountsHelper:
			gaps = append(gaps, fmt.Sprintf("%s names %s, which skips unless a test starts it", expectedRunsPath, twoAccountsHelper))
		case !declared[r]:
			gaps = append(gaps, fmt.Sprintf("%s names %s %s, which no test file declares", expectedRunsPath, r.Package, r.Test))
		case !isTagged && !slices.Contains(root, r):
			gaps = append(gaps, fmt.Sprintf("%s names %s %s, which is neither in a %s file nor skipped as needing root", expectedRunsPath, r.Package, r.Test, twoAccountsTag))
		}
	}
	return gaps
}

// testsOfFiles reads every top-level test the files declare, and the file
// of each that the twoaccounts tag alone brings into a build.
func testsOfFiles(module string, files map[string][]byte) (map[testreport.Run]bool, map[testreport.Run]string, error) {
	declared := map[testreport.Run]bool{}
	tagged := map[testreport.Run]string{}
	for rel, src := range files {
		f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		onlyTagged, err := needsTwoAccountsTag(src)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", rel, err)
		}
		pkg := module
		if dir := path.Dir(rel); dir != "." {
			pkg += "/" + dir
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !isTestName(fn.Name.Name) {
				continue
			}
			r := testreport.Run{Package: pkg, Test: fn.Name.Name}
			declared[r] = true
			if onlyTagged {
				tagged[r] = rel
			}
		}
	}
	return declared, tagged, nil
}

// needsTwoAccountsTag reports whether the file's //go:build line holds on
// Linux with the twoaccounts tag and not without it.
func needsTwoAccountsTag(src []byte) (bool, error) {
	sc := bufio.NewScanner(bytes.NewReader(src))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return false, err
		}
		on := func(with bool) bool {
			return expr.Eval(func(tag string) bool {
				return tag == "linux" || tag == "unix" || tag == "amd64" || tag == "gc" || (with && tag == twoAccountsTag)
			})
		}
		return on(true) && !on(false), nil
	}
	return false, sc.Err()
}

// isTestName is go test's rule for a test function's name.
func isTestName(name string) bool {
	rest, ok := strings.CutPrefix(name, "Test")
	if !ok || name == "TestMain" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return rest == "" || !unicode.IsLower(r)
}

// needsRootTests is every entry of expected-skips.txt whose message is
// "needs root".
func needsRootTests(skips []byte) ([]testreport.Run, error) {
	var root []testreport.Run
	for _, line := range strings.Split(string(skips), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s: %q is not <import path> <test name> <message>", expectedSkipsPath, line)
		}
		if fields[2] == needsRootSkip {
			root = append(root, testreport.Run{Package: fields[0], Test: fields[1]})
		}
	}
	return root, nil
}

func sortedRuns(m map[testreport.Run]string) []testreport.Run {
	runs := make([]testreport.Run, 0, len(m))
	for r := range m {
		runs = append(runs, r)
	}
	slices.SortFunc(runs, func(a, b testreport.Run) int {
		return strings.Compare(a.Package+" "+a.Test, b.Package+" "+b.Test)
	})
	return runs
}

// repositoryTestFiles reads every test file of the root module: none under
// a testdata directory or in a nested module.
func repositoryTestFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	all := repoFiles(t, root)
	var nested []string
	for _, rel := range all {
		if path.Base(rel) == "go.mod" && rel != "go.mod" {
			nested = append(nested, path.Dir(rel)+"/")
		}
	}
	fsys := os.DirFS(root)
	files := map[string][]byte{}
	for _, rel := range all {
		if !strings.HasSuffix(rel, "_test.go") || strings.Contains("/"+rel, "/testdata/") ||
			slices.ContainsFunc(nested, func(dir string) bool { return strings.HasPrefix(rel, dir) }) {
			continue
		}
		src, err := fs.ReadFile(fsys, rel)
		if err != nil {
			t.Fatal(err)
		}
		files[rel] = src
	}
	return files
}

func moduleOf(t *testing.T, root string) string {
	t.Helper()
	gomod, err := fs.ReadFile(os.DirFS(root), "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(gomod), "\n") {
		if m, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(m)
		}
	}
	t.Fatal("go.mod names no module")
	return ""
}

// TestTheTwoAccountsJobRunsEveryTestThatNeedsIt: scripts/expected-runs.txt,
// the "Two accounts" job's only source of what to run, names every
// top-level test of a twoaccounts file but the helper, and every test
// expected-skips.txt skips as needing root, and nothing else. The gate never
// builds the tag, so the files are parsed, not compiled.
func TestTheTwoAccountsJobRunsEveryTestThatNeedsIt(t *testing.T) {
	root := repoRoot(t)
	src := twoAccountSources{module: moduleOf(t, root), files: repositoryTestFiles(t, root)}
	var err error
	if src.skips, err = fs.ReadFile(repoFS(t), expectedSkipsPath); err != nil {
		t.Fatal(err)
	}
	if src.runs, err = fs.ReadFile(repoFS(t), expectedRunsPath); err != nil {
		t.Fatal(err)
	}
	_, tagged, err := testsOfFiles(src.module, src.files)
	if err != nil {
		t.Fatal(err)
	}
	if len(tagged) < 2 {
		t.Fatalf("%d top-level tests found in %s files; the parse examined nothing", len(tagged), twoAccountsTag)
	}
	gaps, err := twoAccountGaps(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gaps {
		t.Error(g)
	}
}

// TestTwoAccountGapsRefusesWhatTheListMisses is the check's negative
// control over planted sources.
func TestTwoAccountGapsRefusesWhatTheListMisses(t *testing.T) {
	const (
		mod    = "example.com/m"
		tagged = "//go:build twoaccounts && unix\n\npackage p\n\nimport \"testing\"\n\n" +
			"func TestA(t *testing.T) {}\n\nfunc TestHelperActsAsAnotherAccount(t *testing.T) {}\n\nfunc helper() {}\n"
		ordinary = "//go:build unix\n\npackage p\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {}\n\nfunc TestRoot(t *testing.T) {}\n"
		skips    = "# header\nexample.com/m/p TestRoot needs root\nexample.com/m/p TestB another reason\n"
	)
	files := map[string][]byte{"p/a_twoaccounts_test.go": []byte(tagged), "p/b_test.go": []byte(ordinary)}
	complete := "example.com/m/p TestA\nexample.com/m/p TestRoot\n"
	for _, c := range []struct {
		name, runs, extra, want string
	}{
		{"a complete list", complete, "", ""},
		{"a tagged test missing", "example.com/m/p TestRoot\n", "", "example.com/m/p TestA, a test of p/a_twoaccounts_test.go, runs in no job"},
		{"a planted tagged test missing", complete, "func TestPlanted(t *testing.T) {}\n", "example.com/m/p TestPlanted, a test of p/a_twoaccounts_test.go, runs in no job"},
		{"a needs-root skip missing", "example.com/m/p TestA\n", "", "example.com/m/p TestRoot, which scripts/expected-skips.txt skips as needing root, runs in no job"},
		{"a line naming nothing", complete + "example.com/m/p TestNowhere\n", "", "names example.com/m/p TestNowhere, which no test file declares"},
		{"a line naming another package's test", complete + "example.com/m/q TestA\n", "", "names example.com/m/q TestA, which no test file declares"},
		{"a line naming an ordinary test", complete + "example.com/m/p TestB\n", "", "names example.com/m/p TestB, which is neither in a twoaccounts file nor skipped as needing root"},
		{"the helper listed", complete + "example.com/m/p TestHelperActsAsAnotherAccount\n", "", "names TestHelperActsAsAnotherAccount, which skips unless a test starts it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			planted := map[string][]byte{"p/b_test.go": files["p/b_test.go"], "p/a_twoaccounts_test.go": []byte(tagged + c.extra)}
			gaps, err := twoAccountGaps(twoAccountSources{module: mod, files: planted, skips: []byte(skips), runs: []byte(c.runs)})
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(gaps, "\n")
			if c.want == "" && len(gaps) != 0 || c.want != "" && (len(gaps) != 1 || !strings.Contains(joined, c.want)) {
				t.Errorf("gaps = %q; want only one holding %q", gaps, c.want)
			}
		})
	}
	if _, err := twoAccountGaps(twoAccountSources{module: mod, files: files, skips: []byte(skips), runs: []byte("# none\n")}); err == nil {
		t.Error("a list naming no test was taken")
	}
}

// TestOnlyTheTwoAccountsTagMarksATaggedFile: a file is the job's when the tag
// alone brings it into a Linux build.
func TestOnlyTheTwoAccountsTagMarksATaggedFile(t *testing.T) {
	for src, want := range map[string]bool{
		"//go:build twoaccounts && unix\n\npackage p\n":    true,
		"//go:build twoaccounts\n\npackage p\n":            true,
		"//go:build unix\n\npackage p\n":                   false,
		"package p\n":                                      false,
		"//go:build twoaccounts || unix\n\npackage p\n":    false,
		"//go:build twoaccounts && windows\n\npackage p\n": false,
		"//go:build !twoaccounts\n\npackage p\n":           false,
	} {
		got, err := needsTwoAccountsTag([]byte(src))
		if err != nil || got != want {
			t.Errorf("%q: %v, %v; want %v", src, got, err, want)
		}
	}
}
