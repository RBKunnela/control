package docscheck

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/guardana/control/internal/docscheck/frontmatter"
)

const (
	genScriptPrefix = "scripts/gen-"
	genTestPrefix   = "go test "
	markerClose     = " -->"
)

// genRun is one line of the docs-gen recipe: the generator it runs and the
// page it writes with -o.
type genRun struct {
	script, page string
}

// generatedProblems judges what a page says about its generator: a rendered
// page names a script docs-gen runs onto it, or a `go test` pin whose
// package exists; a hand-written page's generated blocks pair, do not nest
// and are each claimed.
func generatedProblems(files []string, tests testIndex, runs []genRun, claims []blockClaim, p parsedPage) []string {
	var problems []string
	switch g := p.meta.Generated; {
	case g == "":
	case strings.HasPrefix(g, genScriptPrefix):
		if !slices.Contains(files, g) {
			problems = append(problems, fmt.Sprintf("generated %s names no file", g))
		}
		if !slices.Contains(runs, genRun{g, p.path}) {
			problems = append(problems, fmt.Sprintf("the %s recipe does not run %s -o %s", docsGenTarget, g, p.path))
		}
	case strings.HasPrefix(g, genTestPrefix):
		if problem := testPinProblem(files, tests, g); problem != "" {
			problems = append(problems, problem)
		}
	}
	return append(problems, markerProblems(claims, p)...)
}

// testPinProblem checks a `go test <pkg> -run <Test>` pin names a package
// directory of the walk and one Test function that package declares by its
// exact name, so a pin cannot name a test that never runs.
func testPinProblem(files []string, tests testIndex, pin string) string {
	fields := strings.Fields(pin)
	if len(fields) != 5 || fields[3] != "-run" || !testName.MatchString(fields[4]) {
		return fmt.Sprintf("generated %q is not `go test <pkg> -run <Test>`", pin)
	}
	dir := strings.TrimPrefix(fields[2], "./")
	if !slices.ContainsFunc(files, func(f string) bool { return strings.HasPrefix(f, dir+"/") }) {
		return fmt.Sprintf("generated %q names package %s, which holds no file", pin, dir)
	}
	if !slices.Contains(tests[dir], fields[4]) {
		return fmt.Sprintf("generated %q names no test %s in %s", pin, fields[4], dir)
	}
	return ""
}

// markerProblems walks the generated markers outside fenced code: an open
// marker inside an open block nests, a close with no open or an open with
// no close is unpaired, and an open marker no claim covers is unclaimed.
func markerProblems(claims []blockClaim, p parsedPage) []string {
	var problems []string
	fenced, open := false, 0
	for i, line := range strings.Split(string(p.body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```"):
			fenced = !fenced
		case fenced:
		case strings.HasPrefix(trimmed, frontmatter.GeneratedOpen):
			generator := strings.TrimSuffix(strings.TrimPrefix(trimmed, frontmatter.GeneratedOpen), markerClose)
			switch {
			case !strings.HasSuffix(trimmed, markerClose) || generator == "":
				problems = append(problems, fmt.Sprintf("line %d: marker %q does not name a generator", i+1, trimmed))
			case open > 0:
				problems = append(problems, fmt.Sprintf("line %d: generated block %s opens inside another", i+1, generator))
			case !slices.Contains(claims, blockClaim{p.path, generator}):
				problems = append(problems, fmt.Sprintf("line %d: generated block %s is claimed by nobody", i+1, generator))
			}
			open = 1
		case trimmed == frontmatter.GeneratedClose:
			if open == 0 {
				problems = append(problems, fmt.Sprintf("line %d: a generated block closes and none is open", i+1))
			}
			open = 0
		}
	}
	if open > 0 {
		problems = append(problems, "a generated block is never closed")
	}
	return problems
}

// claimProblems is the registry's other direction: every claim names a page
// of the walk whose body opens a generated block naming exactly that
// generator, outside fenced code. A claim on a page with no such marker
// covers nothing, and would let the marker appear later unreviewed.
func claimProblems(claims []blockClaim, pages []parsedPage) []string {
	var problems []string
	for _, claim := range claims {
		i := slices.IndexFunc(pages, func(p parsedPage) bool { return p.path == claim.page })
		switch {
		case i < 0:
			problems = append(problems, fmt.Sprintf("the registry claims a block of %s on %s, which is no page of the walk", claim.generator, claim.page))
		case !slices.Contains(openMarkers(pages[i].body), claim.generator):
			problems = append(problems, fmt.Sprintf("the registry claims a block of %s on %s and the page opens no such block", claim.generator, claim.page))
		}
	}
	return problems
}

// openMarkers lists the generator each open marker outside fenced code
// names, in page order.
func openMarkers(body []byte) []string {
	var generators []string
	fenced := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```"):
			fenced = !fenced
		case !fenced && strings.HasPrefix(trimmed, frontmatter.GeneratedOpen) && strings.HasSuffix(trimmed, markerClose):
			generators = append(generators, strings.TrimSuffix(strings.TrimPrefix(trimmed, frontmatter.GeneratedOpen), markerClose))
		}
	}
	return generators
}

// docsGenRuns reads the docs-gen recipe of the Makefile: each line runs one
// scripts/gen-<x>.go with -o and a page, and a line of any other shape is
// a problem, because a generator run nobody can pin is a page nobody checks.
func docsGenRuns(makefile []string) ([]genRun, []string) {
	recipe, err := makeRecipe(makefile, docsGenTarget)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var runs []genRun
	var problems []string
	for _, line := range recipe {
		fields := strings.Fields(line)
		i := slices.IndexFunc(fields, func(f string) bool { return strings.HasPrefix(f, genScriptPrefix) && strings.HasSuffix(f, ".go") })
		if i < 0 || i+2 >= len(fields) || fields[i+1] != "-o" {
			problems = append(problems, fmt.Sprintf("%s line %q runs no scripts/gen-<x>.go -o <page>", docsGenTarget, strings.TrimSpace(line)))
			continue
		}
		runs = append(runs, genRun{fields[i], fields[i+2]})
	}
	if len(runs) == 0 {
		problems = append(problems, fmt.Sprintf("%s runs no generator", docsGenTarget))
	}
	return runs, problems
}

// makeRecipe returns the tab-indented lines under target's one rule, with
// backslash continuations joined.
func makeRecipe(lines []string, target string) ([]string, error) {
	var recipe []string
	rules := 0
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], target+":") {
			continue
		}
		rules++
		for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "\t") {
			i++
			line := lines[i]
			for strings.HasSuffix(line, `\`) && i+1 < len(lines) {
				i++
				line = strings.TrimSuffix(line, `\`) + " " + strings.TrimSpace(lines[i])
			}
			recipe = append(recipe, line)
		}
	}
	if rules != 1 {
		return nil, fmt.Errorf("found %d rule(s) for %s, want 1", rules, target)
	}
	return recipe, nil
}

// renderedFiles registers the docs-gen runs that write a file which is not a
// docs page, each with the one script that writes it. The site test and the
// Python table's own test pin what such a file holds.
var renderedFiles = []genRun{
	{"scripts/gen-site.go", "site/index.html"},
	{"scripts/gen-pyschema.go", "clients/python/src/guardana_control/enforce/_schema.py"},
}

// recipeProblems is the other direction: every docs-gen run lands on a page
// that names its script, in its frontmatter or through a claimed block, or on
// a registered rendered file.
func recipeProblems(runs []genRun, pages []parsedPage, claims []blockClaim) []string {
	var problems []string
	for _, run := range runs {
		i := slices.IndexFunc(pages, func(p parsedPage) bool { return p.path == run.page })
		switch {
		case slices.Contains(renderedFiles, run):
		case i < 0:
			problems = append(problems, fmt.Sprintf("%s runs %s -o %s, which is no page of the walk", docsGenTarget, run.script, run.page))
		case pages[i].meta.Generated == run.script:
		case slices.Contains(claims, blockClaim{run.page, run.script}) && strings.Contains(string(pages[i].body), frontmatter.GeneratedOpen+run.script+markerClose):
		default:
			problems = append(problems, fmt.Sprintf("%s runs %s -o %s and the page does not name it", docsGenTarget, run.script, run.page))
		}
	}
	return problems
}

// testIndex holds the Test functions each package directory declares in its
// _test.go files.
type testIndex map[string][]string

var testName = regexp.MustCompile(`^Test\w*$`)

// gatePlatforms are the platforms the gate runs go test on: CI's and the
// maintainers' machines.
var gatePlatforms = [][2]string{{"linux", "amd64"}, {"darwin", "arm64"}}

// add indexes the top-level functions go test runs from one file's syntax
// tree, so a test name written in a string or a comment indexes nothing, and
// a file whose build constraint or name leaves it out on every platform the
// gate runs, as `//go:build ignore` does, indexes nothing either. A file that
// does not parse is an error rather than a file with no tests.
func (ix testIndex) add(rel string, data []byte) error {
	built, err := builtOnTheGate(rel, data)
	if err != nil || !built {
		return err
	}
	file, err := parser.ParseFile(token.NewFileSet(), rel, data, parser.SkipObjectResolution)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", rel, err)
	}
	pkg := testingName(file)
	dir := path.Dir(rel)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && isGoTest(fn, pkg) {
			ix[dir] = append(ix[dir], fn.Name.Name)
		}
	}
	return nil
}

// builtOnTheGate reports whether go test builds the file rel, holding data,
// on any of gatePlatforms.
func builtOnTheGate(rel string, data []byte) (bool, error) {
	for _, p := range gatePlatforms {
		ctxt := build.Default
		ctxt.GOOS, ctxt.GOARCH = p[0], p[1]
		ctxt.OpenFile = func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
		match, err := ctxt.MatchFile(path.Dir(rel), path.Base(rel))
		if err != nil {
			return false, fmt.Errorf("reading the build constraints of %s: %w", rel, err)
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// testingName is the name a file refers to package testing by.
func testingName(file *ast.File) string {
	for _, imp := range file.Imports {
		if imp.Path.Value == `"testing"` && imp.Name != nil {
			return imp.Name.Name
		}
	}
	return "testing"
}

// isGoTest reports the shape go test runs: func TestXxx(*testing.T), no
// receiver, no type parameters, no results, and no lower-case letter after
// Test.
func isGoTest(fn *ast.FuncDecl, pkg string) bool {
	name, ok := strings.CutPrefix(fn.Name.Name, "Test")
	if !ok || fn.Recv != nil || fn.Type.TypeParams != nil || fn.Type.Results != nil {
		return false
	}
	if r, _ := utf8.DecodeRuneInString(name); name != "" && unicode.IsLower(r) {
		return false
	}
	return takesTestingT(fn.Type.Params.List, pkg)
}

// takesTestingT reports a parameter list that is one *testing.T, with
// testing spelled pkg.
func takesTestingT(params []*ast.Field, pkg string) bool {
	if len(params) != 1 || len(params[0].Names) > 1 {
		return false
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg && sel.Sel.Name == "T"
}

func TestTestIndexHoldsOnlyDeclaredTests(t *testing.T) {
	src := "package thing\n\nimport tt \"testing\"\n\n" +
		"func TestDeclared(t *tt.T) {}\n" +
		"var text = `\nfunc TestInAString(t *testing.T) {}\n`\n" +
		"/*\nfunc TestInAComment(t *testing.T) {}\n*/\n" +
		"func TestTwoParams(t *tt.T, n int) {}\n" +
		"func Testlower(t *tt.T) {}\n" +
		"func TestGeneric[P any](t *tt.T) {}\n" +
		"func TestBench(b *tt.B) {}\n" +
		"func TestResult(t *tt.T) error { return nil }\n" +
		"func (s suite) TestMethod(t *tt.T) {}\n" +
		"func Test(t *tt.T) {}\n"
	ix := testIndex{}
	if err := ix.add("internal/thing/a_test.go", []byte(src)); err != nil {
		t.Fatal(err)
	}
	if want := (testIndex{"internal/thing": {"TestDeclared", "Test"}}); !maps.EqualFunc(ix, want, slices.Equal) {
		t.Errorf("tests = %q, want %q", ix, want)
	}
	if err := ix.add("internal/thing/b_test.go", []byte("package thing\nfunc TestCut(t *testing.T) {\n")); err == nil {
		t.Error("a test file that does not parse was indexed without an error")
	}
	for name, text := range map[string]string{
		"internal/thing/c_test.go":         "//go:build ignore\n\npackage thing\n\nimport \"testing\"\n\nfunc TestIgnored(t *testing.T) {}\n",
		"internal/thing/d_windows_test.go": "package thing\n\nimport \"testing\"\n\nfunc TestWindowsOnly(t *testing.T) {}\n",
		"internal/thing/e_test.go":         "//go:build linux\n\npackage thing\n\nimport \"testing\"\n\nfunc TestLinuxOnly(t *testing.T) {}\n",
	} {
		if err := ix.add(name, []byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"TestDeclared", "Test", "TestLinuxOnly"}; !slices.Equal(ix["internal/thing"], want) {
		t.Errorf("after files the gate builds and leaves out, tests = %q, want %q", ix["internal/thing"], want)
	}
}
