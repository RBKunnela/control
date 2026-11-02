package core_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// decisionPackage is the frozen v1 wire package, relative to the module.
const decisionPackage = "api/gen/go/guardana/control/v1"

// TestAdaptersBuildNoDecision refuses a non-test Go file under adapters/,
// whatever its build constraints, that composes a v1 Decision through a
// composite literal or new: an adapter forwards the core's decision and never
// makes one. It reads syntax only, in every file whatever its constraints;
// internal/docscheck's TestAdaptersHoldNoDecisionValue type-checks the files
// this platform builds. scripts/check-imports-probe.sh plants one of each.
func TestAdaptersBuildNoDecision(t *testing.T) {
	modulePath, moduleDir := mainModule(t)
	mustExist(t, moduleDir, "adapters")
	clause, err := parser.ParseFile(token.NewFileSet(), "", mustRead(t, filepath.Join(moduleDir, decisionPackage, "decision.pb.go")), parser.PackageClauseOnly)
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	for _, rel := range treeSources(t, os.DirFS(moduleDir), "adapters") {
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		read++
		problems, err := decisionBuilds(rel, mustRead(t, filepath.Join(moduleDir, rel)), modulePath+"/"+decisionPackage, clause.Name.Name)
		if err != nil {
			t.Fatalf("parsing %s: %v", rel, err)
		}
		for _, problem := range problems {
			t.Error(problem)
		}
	}
	if read == 0 {
		t.Fatal("adapters/ holds no production Go file, so nothing was examined")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	src, err := os.ReadFile(path) //nolint:gosec // G304: a file of this repository
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// decisionNames is how one file names the Decision type: through the import
// names bound to its package, or bare under a dot import.
type decisionNames struct {
	bound map[string]bool
	dot   bool
}

func namesOf(file *ast.File, pkg, name string) decisionNames {
	d := decisionNames{bound: map[string]bool{}}
	for _, spec := range file.Imports {
		if path, err := strconv.Unquote(spec.Path.Value); err != nil || path != pkg {
			continue
		}
		switch {
		case spec.Name == nil:
			d.bound[name] = true
		case spec.Name.Name == ".":
			d.dot = true
		default:
			d.bound[spec.Name.Name] = true
		}
	}
	return d
}

// is reports whether e names the Decision type or a pointer to it.
func (d decisionNames) is(e ast.Expr) bool {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	switch e := e.(type) {
	case *ast.SelectorExpr:
		x, ok := e.X.(*ast.Ident)
		return ok && d.bound[x.Name] && e.Sel.Name == "Decision"
	case *ast.Ident:
		return d.dot && e.Name == "Decision"
	}
	return false
}

// how says how n composes a Decision, or returns "".
func (d decisionNames) how(n ast.Node) string {
	switch n := n.(type) {
	case *ast.CompositeLit:
		if n.Type != nil && d.is(n.Type) {
			return "by a composite literal"
		}
		if arr, ok := n.Type.(*ast.ArrayType); ok && d.is(arr.Elt) && slices.ContainsFunc(n.Elts, elided) {
			return "by a composite literal whose type is elided"
		}
	case *ast.CallExpr:
		if fn, ok := n.Fun.(*ast.Ident); ok && fn.Name == "new" && len(n.Args) == 1 && d.is(n.Args[0]) {
			return "by new"
		}
	}
	return ""
}

// decisionBuilds names each place in one Go file that composes a Decision of
// the package at pkg, whose package clause is name.
func decisionBuilds(rel string, src []byte, pkg, name string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	names := namesOf(file, pkg, name)
	var problems []string
	ast.Inspect(file, func(n ast.Node) bool {
		if how := names.how(n); how != "" {
			problems = append(problems, fset.Position(n.Pos()).String()+": composes a v1 Decision "+how)
		}
		return true
	})
	return problems, nil
}

func elided(e ast.Expr) bool {
	if u, ok := e.(*ast.UnaryExpr); ok {
		e = u.X
	}
	lit, ok := e.(*ast.CompositeLit)
	return ok && lit.Type == nil
}

// Each case is a way to compose a Decision, or a near miss that is not one.
func TestDecisionBuilds(t *testing.T) {
	const pkg = "example.com/m/api/v1"
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"literal", `import controlv1 "example.com/m/api/v1"; var d = controlv1.Decision{}`, []string{"a.go:1:61: composes a v1 Decision by a composite literal"}},
		{"pointer to a literal", `import controlv1 "example.com/m/api/v1"; var d = &controlv1.Decision{Verdict: 1}`, []string{"a.go:1:62: composes a v1 Decision by a composite literal"}},
		{"new", `import controlv1 "example.com/m/api/v1"; var d = new(controlv1.Decision)`, []string{"a.go:1:61: composes a v1 Decision by new"}},
		{"the package clause's name", `import "example.com/m/api/v1"; var d = controlv1.Decision{}`, []string{"a.go:1:51: composes a v1 Decision by a composite literal"}},
		{"renamed", `import w "example.com/m/api/v1"; var d = w.Decision{}`, []string{"a.go:1:53: composes a v1 Decision by a composite literal"}},
		{"dot import", `import . "example.com/m/api/v1"; var d = new(Decision)`, []string{"a.go:1:53: composes a v1 Decision by new"}},
		{"elided in a slice", `import controlv1 "example.com/m/api/v1"; var d = []*controlv1.Decision{{}}`, []string{"a.go:1:61: composes a v1 Decision by a composite literal whose type is elided"}},
		{"a type of the same name elsewhere", `import other "example.com/m/other"; var d = other.Decision{}`, nil},
		{"a declared value, not composed", `import controlv1 "example.com/m/api/v1"; func f(d *controlv1.Decision) string { return d.GetDecisionId() }`, nil},
		{"another type of the package", `import controlv1 "example.com/m/api/v1"; var d = controlv1.Request{}`, nil},
		{"an empty slice", `import controlv1 "example.com/m/api/v1"; var d = []*controlv1.Decision{}`, nil},
	} {
		got, err := decisionBuilds("a.go", []byte("package a; "+c.src), pkg, "controlv1")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
