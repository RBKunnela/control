package docscheck

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// decisionPkg is the frozen v1 wire package, relative to the module.
const decisionPkg = "api/gen/go/guardana/control/v1"

// adapterTypes is the type-checked view of the adapters: the module path, the
// export data of every package they reach, and their packages.
type adapterTypes struct {
	module   string
	export   map[string]string
	packages [][3]string // import path, directory, non-test Go files joined by tabs
}

func goOut(t *testing.T, root string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", args...) //nolint:gosec // G204: fixed arguments, the go command on PATH
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

func loadAdapterTypes(t *testing.T, root string) adapterTypes {
	t.Helper()
	a := adapterTypes{module: goOut(t, root, "list", "-m")[0], export: map[string]string{}}
	for _, line := range goOut(t, root, "list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}", "./adapters/...") {
		if path, file, ok := strings.Cut(line, "\t"); ok && file != "" {
			a.export[path] = file
		}
	}
	for _, line := range goOut(t, root, "list", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \"\\t\"}}", "./adapters/...") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) == 3 {
			a.packages = append(a.packages, [3]string{parts[0], parts[1], parts[2]})
		}
	}
	if len(a.packages) == 0 || a.export[a.module+"/"+decisionPkg] == "" {
		t.Fatalf("go list named %d adapter package(s) and no export data for %s, so nothing would be checked", len(a.packages), decisionPkg)
	}
	return a
}

func (a adapterTypes) importer(fset *token.FileSet) types.Importer {
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := a.export[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file) //nolint:gosec // G304: a file the go command named
	})
}

// holdsDecision reports whether a value of t holds a Decision itself rather
// than through a pointer. A named type other than Decision is not opened: one
// an adapter defines is judged where its fields are declared.
func holdsDecision(t, decision types.Type) bool {
	t = types.Unalias(t)
	if types.Identical(t, decision) {
		return true
	}
	switch u := t.(type) {
	case *types.Slice:
		return holdsDecision(u.Elem(), decision)
	case *types.Array:
		return holdsDecision(u.Elem(), decision)
	case *types.Chan:
		return holdsDecision(u.Elem(), decision)
	case *types.Map:
		return holdsDecision(u.Key(), decision) || holdsDecision(u.Elem(), decision)
	case *types.Struct:
		return anyHolds(u.NumFields(), func(i int) types.Type { return u.Field(i).Type() }, decision)
	case *types.Tuple:
		return anyHolds(u.Len(), func(i int) types.Type { return u.At(i).Type() }, decision)
	}
	return false
}

func anyHolds(n int, at func(int) types.Type, decision types.Type) bool {
	for i := range n {
		if holdsDecision(at(i), decision) {
			return true
		}
	}
	return false
}

// decisionValues names, once per line, each place in files that composes a
// Decision or holds one by value: a composite literal of it, aliases resolved
// and elided types included; a value expression, variable, field, parameter
// or result whose type holds one; new over such a type; and a generic
// instantiation with one as a type argument.
func decisionValues(fset *token.FileSet, info *types.Info, decision types.Type) []string {
	lines := map[string]bool{}
	mark := func(pos token.Pos) {
		p := fset.Position(pos)
		lines[fmt.Sprintf("%s:%d", filepath.ToSlash(p.Filename), p.Line)] = true
	}
	markExprs(info, decision, mark)
	markDefs(info, decision, mark)
	for id, inst := range info.Instances {
		for i := range inst.TypeArgs.Len() {
			if holdsDecision(inst.TypeArgs.At(i), decision) {
				mark(id.Pos())
			}
		}
	}
	found := make([]string, 0, len(lines))
	for line := range lines {
		found = append(found, line+": composes or holds a v1 Decision by value")
	}
	slices.Sort(found)
	return found
}

// markExprs marks each value expression whose type holds a Decision, each
// composite literal of one or of a pointer to one, and each new over a type
// that holds one.
func markExprs(info *types.Info, decision types.Type, mark func(token.Pos)) {
	for expr, tv := range info.Types {
		if (tv.IsValue() && holdsDecision(tv.Type, decision)) || isCompositeOf(expr, tv.Type, decision) {
			mark(expr.Pos())
		}
		if call, ok := expr.(*ast.CallExpr); ok && isBuiltin(info, call.Fun, "new") {
			if p, ok := tv.Type.(*types.Pointer); ok && holdsDecision(p.Elem(), decision) {
				mark(call.Pos())
			}
		}
	}
}

// markDefs marks each variable, field or parameter whose type holds a
// Decision, and each function whose signature holds one.
func markDefs(info *types.Info, decision types.Type, mark func(token.Pos)) {
	for id, obj := range info.Defs {
		switch obj := obj.(type) {
		case *types.Var:
			if holdsDecision(obj.Type(), decision) {
				mark(id.Pos())
			}
		case *types.Func:
			sig := obj.Type().(*types.Signature)
			if holdsDecision(sig.Params(), decision) || holdsDecision(sig.Results(), decision) {
				mark(id.Pos())
			}
		}
	}
}

func isCompositeOf(expr ast.Expr, t, decision types.Type) bool {
	if _, ok := expr.(*ast.CompositeLit); !ok {
		return false
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	return types.Identical(types.Unalias(t), decision)
}

func isBuiltin(info *types.Info, fun ast.Expr, name string) bool {
	id, ok := ast.Unparen(fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	return ok && b.Name() == name
}

// checkDecisionValues type-checks one package's files, named by their
// repository-relative paths, and returns what decisionValues finds.
func checkDecisionValues(a adapterTypes, fset *token.FileSet, imp types.Importer, path string, names []string, srcs [][]byte) ([]string, error) {
	files := make([]*ast.File, 0, len(names))
	for i, name := range names {
		f, err := parser.ParseFile(fset, name, srcs[i], parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{},
		Uses: map[*ast.Ident]types.Object{}, Instances: map[*ast.Ident]types.Instance{},
	}
	if _, err := (&types.Config{Importer: imp}).Check(path, fset, files, info); err != nil {
		return nil, err
	}
	v1, err := imp.Import(a.module + "/" + decisionPkg)
	if err != nil {
		return nil, err
	}
	return decisionValues(fset, info, v1.Scope().Lookup("Decision").Type()), nil
}

// TestAdaptersHoldNoDecisionValue type-checks every package under adapters/
// as this platform builds it and refuses, in a non-test file, a v1 Decision
// composed or held by value; a pointer the core hands over is allowed. A
// Decision made by reflection (ProtoReflect().New(), dynamicpb) is out of
// reach of a source check, and a file this platform does not build is held
// only by internal/core's syntactic TestAdaptersBuildNoDecision.
func TestAdaptersHoldNoDecisionValue(t *testing.T) {
	root := repoRoot(t)
	a := loadAdapterTypes(t, root)
	fset := token.NewFileSet()
	imp := a.importer(fset)
	files := 0
	for _, p := range a.packages {
		var names []string
		var srcs [][]byte
		for _, base := range strings.Split(p[2], "\t") {
			if base == "" {
				continue
			}
			src, err := os.ReadFile(filepath.Join(p[1], base)) //nolint:gosec // G304: a file go list named
			if err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(root, filepath.Join(p[1], base))
			if err != nil {
				t.Fatal(err)
			}
			names, srcs = append(names, filepath.ToSlash(rel)), append(srcs, src)
		}
		files += len(names)
		problems, err := checkDecisionValues(a, fset, imp, p[0], names, srcs)
		if err != nil {
			t.Fatalf("type-checking %s: %v", p[0], err)
		}
		for _, problem := range problems {
			t.Error(problem)
		}
	}
	if files == 0 {
		t.Fatal("no production Go file under adapters/ was type-checked")
	}
}

// Each case is a way to compose or hold a Decision by value, or one that is
// allowed or out of reach. The expected lines are written out.
func TestDecisionValues(t *testing.T) {
	root := repoRoot(t)
	a := loadAdapterTypes(t, root)
	head := "package a\n\nimport controlv1 \"" + a.module + "/" + decisionPkg + "\"\n\n"
	const by = ": composes or holds a v1 Decision by value"
	for _, c := range []struct {
		name, body string
		want       []int
	}{
		{"a literal", "var X = &controlv1.Decision{}\n", []int{5}},
		{"an alias", "type D = controlv1.Decision\n\nfunc Alias() *D { return &D{DecisionId: \"x\"} }\n", []int{7}},
		{"a variable", "func Value() *controlv1.Decision {\n\tvar d controlv1.Decision\n\treturn &d\n}\n", []int{6, 7}},
		{"generic new", "func mk[T any]() *T { return new(T) }\n\nfunc Generic() *controlv1.Decision { return mk[controlv1.Decision]() }\n", []int{7}},
		{"new of a parenthesised type", "func Paren() *controlv1.Decision { return new((controlv1.Decision)) }\n", []int{5}},
		{"elided in a map", "var M = map[string]*controlv1.Decision{\"a\": {DecisionId: \"x\"}}\n", []int{5}},
		{"elided in a keyed slice", "var K = []*controlv1.Decision{0: {DecisionId: \"x\"}}\n", []int{5}},
		{"an embedded field", "func Embedded() *controlv1.Decision {\n\td := new(struct{ controlv1.Decision })\n\treturn &d.Decision\n}\n", []int{6, 7}},
		{"a field", "type S struct {\n\tD controlv1.Decision\n}\n", []int{6}},
		{"an unnamed result", "func R() controlv1.Decision { panic(0) }\n", []int{5}},
		{"a slice of values", "var V = make([]controlv1.Decision, 1)\n", []int{5}},
		{"a pointer from the core", "func F(d *controlv1.Decision) string { return d.GetDecisionId() }\n", nil},
		{"pointers in a slice", "func G(ds []*controlv1.Decision) int { return len(ds) }\n", nil},
		{"reflection, out of reach", "func Reflect() *controlv1.Decision {\n\treturn (*controlv1.Decision)(nil).ProtoReflect().New().Interface().(*controlv1.Decision)\n}\n", nil},
	} {
		fset := token.NewFileSet()
		got, err := checkDecisionValues(a, fset, a.importer(fset), "example.com/a", []string{"a.go"}, [][]byte{[]byte(head + c.body)})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var want []string
		for _, line := range c.want {
			want = append(want, fmt.Sprintf("a.go:%d%s", line, by))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %q, want %q", c.name, got, want)
		}
	}
}
