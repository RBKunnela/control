package docscheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const (
	receiversPage    = "docs/contracts.md"
	receiversHeading = "## Signed files and their project checks"
)

// receiversColumns is the table's header; the last two columns hold only
// code spans: a Go file followed by functions declared in it, and a package
// directory followed by tests of that directory.
var receiversColumns = []string{"Receiver", "What it takes", "Tenant and project check", "Where", "Pinned by"}

var citedSpan = regexp.MustCompile("`([^`]+)`")

// receiverProblems holds the receiver table of receiversPage in fsys to the
// tree: present, of at least one row, and every function and test a row
// cites declared where it says.
func receiverProblems(fsys fs.FS) []string {
	rows, problem := receiverRows(fsys)
	if problem != "" {
		return []string{problem}
	}
	var problems []string
	for _, row := range rows {
		name := row[0]
		if strings.TrimSpace(row[2]) == "" {
			problems = append(problems, fmt.Sprintf("%s: row %q says nothing of its tenant and project check", receiversPage, name))
		}
		for _, p := range citedFunctions(fsys, row[3]) {
			problems = append(problems, fmt.Sprintf("%s: row %q: %s", receiversPage, name, p))
		}
		for _, p := range citedTests(fsys, row[4]) {
			problems = append(problems, fmt.Sprintf("%s: row %q: %s", receiversPage, name, p))
		}
	}
	return problems
}

// receiverRows returns the cells of each row of the first table under
// receiversHeading, or why there is no such table.
func receiverRows(fsys fs.FS) ([][]string, string) {
	data, err := fs.ReadFile(fsys, receiversPage)
	if err != nil {
		return nil, err.Error()
	}
	_, section, found := strings.Cut(string(data), "\n"+receiversHeading+"\n")
	if !found {
		return nil, fmt.Sprintf("%s holds no section %q", receiversPage, receiversHeading)
	}
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	var table [][]string
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "|") {
			table = append(table, tableCells(line))
		} else if len(table) > 0 {
			break
		}
	}
	switch {
	case len(table) == 0:
		return nil, fmt.Sprintf("%s: the section %q holds no table", receiversPage, receiversHeading)
	case !slices.Equal(table[0], receiversColumns):
		return nil, fmt.Sprintf("%s: the receiver table's header is %q, want %q", receiversPage, table[0], receiversColumns)
	case len(table) < 3:
		return nil, fmt.Sprintf("%s: the receiver table holds no row", receiversPage)
	}
	for _, row := range table[2:] {
		if len(row) != len(receiversColumns) {
			return nil, fmt.Sprintf("%s: a receiver row has %d cells, want %d: %q", receiversPage, len(row), len(receiversColumns), row)
		}
	}
	return table[2:], ""
}

// citedFunctions holds each function span of cell to the Go file span
// before it: a non-test file of fsys declaring that function, or that method
// as "Type.Method".
func citedFunctions(fsys fs.FS, cell string) []string {
	var problems []string
	file, functions := "", 0
	var decls map[string]bool
	for _, m := range citedSpan.FindAllStringSubmatch(cell, -1) {
		span := m[1]
		if strings.HasSuffix(span, ".go") {
			file = span
			var err error
			if decls, err = declaredFunctions(fsys, file); err != nil {
				problems = append(problems, err.Error())
			}
			continue
		}
		functions++
		switch {
		case file == "":
			problems = append(problems, fmt.Sprintf("function %s is cited before any file", span))
		case decls != nil && !decls[span]:
			problems = append(problems, fmt.Sprintf("%s declares no function %s", file, span))
		}
	}
	if functions == 0 {
		problems = append(problems, "cites no function that makes the check")
	}
	return problems
}

// declaredFunctions names every function of the Go file rel, a method as
// "Type.Method".
func declaredFunctions(fsys fs.FS, rel string) (map[string]bool, error) {
	if strings.HasSuffix(rel, "_test.go") {
		return nil, fmt.Errorf("%s is a test file, not the code that makes the check", rel)
	}
	src, err := fs.ReadFile(fsys, rel)
	if err != nil {
		return nil, err
	}
	file, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			name = receiverType(fn.Recv.List[0].Type) + "." + name
		}
		names[name] = true
	}
	return names, nil
}

func receiverType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return receiverType(t.X)
	case *ast.IndexExpr:
		return receiverType(t.X)
	case *ast.IndexListExpr:
		return receiverType(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// citedTests holds each test span of cell to the package directory span
// before it: one of that directory's _test.go files declares it.
func citedTests(fsys fs.FS, cell string) []string {
	var problems []string
	dir, tests := "", 0
	for _, m := range citedSpan.FindAllStringSubmatch(cell, -1) {
		span := m[1]
		if !strings.HasPrefix(span, "Test") {
			dir = span
			continue
		}
		tests++
		if dir == "" {
			problems = append(problems, fmt.Sprintf("test %s is cited before any package", span))
			continue
		}
		if !declaresTest(fsys, dir, span) {
			problems = append(problems, fmt.Sprintf("no _test.go file of %s declares %s", dir, span))
		}
	}
	if tests == 0 {
		problems = append(problems, "cites no test that pins the check")
	}
	return problems
}

func declaresTest(fsys fs.FS, dir, name string) bool {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err == nil && strings.Contains(string(src), "\nfunc "+name+"(") {
			return true
		}
	}
	return false
}

func TestTheReceiverTableCitesCodeAndTestsThatExist(t *testing.T) {
	for _, problem := range receiverProblems(repoFS(t)) {
		t.Error(problem)
	}
	rows, problem := receiverRows(repoFS(t))
	if problem != "" || len(rows) < 8 {
		t.Errorf("the receiver table holds %d row(s), %s; the roster, the answer, the pause, the run record, the route, the header, the lines and the lift each need one", len(rows), problem)
	}
}

// receiverStage is a tree of one page and the two files its table cites.
func receiverStage(table string) fstest.MapFS {
	return fstest.MapFS{
		receiversPage:              {Data: []byte("# Wire contracts\n\n" + receiversHeading + "\n\nWhat a plane takes.\n\n" + table + "\nAfter.\n\n## Next\n")},
		"internal/p/judge.go":      {Data: []byte("package p\n\ntype A struct{}\n\nfunc (a *A) Judge() {}\n\nfunc vouched() {}\n")},
		"internal/p/judge_test.go": {Data: []byte("package p\n\nimport \"testing\"\n\nfunc TestAnotherProjectIsRefused(t *testing.T) {}\n")},
	}
}

const receiverHeader = "| Receiver | What it takes | Tenant and project check | Where | Pinned by |\n| --- | --- | --- | --- | --- |\n"

func TestTheReceiverCheckRefusesWhatTheTreeDoesNotHold(t *testing.T) {
	good := receiverHeader + "| Pause | a file | the plane's | `internal/p/judge.go` `A.Judge`, `vouched` | `internal/p` `TestAnotherProjectIsRefused` |\n"
	if problems := receiverProblems(receiverStage(good)); len(problems) != 0 {
		t.Fatalf("the control, a table whose citations all exist: %q", problems)
	}
	for _, c := range []struct{ name, table, want string }{
		{"a test the package does not declare", strings.Replace(good, "`TestAnotherProjectIsRefused`", "`TestAnotherProjectIsTaken`", 1), "no _test.go file of internal/p declares TestAnotherProjectIsTaken"},
		{"a test of another package", strings.Replace(good, "`internal/p` `Test", "`internal/q` `Test", 1), "no _test.go file of internal/q declares TestAnotherProjectIsRefused"},
		{"no test", strings.Replace(good, "`internal/p` `TestAnotherProjectIsRefused`", "none", 1), "cites no test that pins the check"},
		{"a method the file does not declare", strings.Replace(good, "`A.Judge`", "`B.Judge`", 1), "internal/p/judge.go declares no function B.Judge"},
		{"a function the file does not declare", strings.Replace(good, "`vouched`", "`vouchedWithin`", 1), "internal/p/judge.go declares no function vouchedWithin"},
		{"a file the tree does not hold", strings.Replace(good, "judge.go", "gone.go", 1), "internal/p/gone.go"},
		{"a test file cited as the check", strings.Replace(good, "judge.go", "judge_test.go", 1), "is a test file"},
		{"no function", strings.Replace(good, "`internal/p/judge.go` `A.Judge`, `vouched`", "none", 1), "cites no function that makes the check"},
		{"no rows", receiverHeader, "the receiver table holds no row"},
		{"another header", strings.Replace(good, "| Where |", "| File |", 1), "the receiver table's header is"},
		{"a row of four cells", receiverHeader + "| Pause | a file | `internal/p/judge.go` `A.Judge` | `internal/p` `TestAnotherProjectIsRefused` |\n", "a receiver row has 4 cells"},
		{"an empty check", strings.Replace(good, "the plane's", "", 1), "says nothing of its tenant and project check"},
		{"no table", "", "holds no table"},
	} {
		problems := receiverProblems(receiverStage(c.table))
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, c.want) }) {
			t.Errorf("%s: problems %q, want one saying %q", c.name, problems, c.want)
		}
	}
	stage := receiverStage(good)
	delete(stage, receiversPage)
	stage["docs/other.md"] = &fstest.MapFile{Data: []byte(receiversHeading + "\n\n" + good)}
	if problems := receiverProblems(stage); len(problems) == 0 {
		t.Error("a tree without the page passes")
	}
	stage[receiversPage] = &fstest.MapFile{Data: []byte("# Wire contracts\n\n## Another section\n\n" + good)}
	if problems := receiverProblems(stage); len(problems) != 1 || !strings.Contains(problems[0], "holds no section") {
		t.Errorf("a page whose table sits under another heading: %q", problems)
	}
}
