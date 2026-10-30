package ingest_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	observePath    = "github.com/guardana/control/internal/observe"
	descriptorType = "SourceDescriptor"
)

// descriptorReads names each place in src that reads a source descriptor
// without ReadDescriptor: a call of observe's neutral half, or an Unmarshal
// into a SourceDescriptor, either a literal or a variable bound to one.
func descriptorReads(t *testing.T, name string, src []byte) []string {
	t.Helper()
	r := &reads{fset: token.NewFileSet(), observe: map[string]bool{}, bound: map[string]bool{}}
	f, err := parser.ParseFile(r.fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == observePath {
			n := "observe"
			if imp.Name != nil {
				n = imp.Name.Name
			}
			r.observe[n] = true
		}
	}
	ast.Inspect(f, r.visit)
	return r.found
}

// reads is one file's search: the names observe is imported under, the
// variables bound to a descriptor, and what was found.
type reads struct {
	fset    *token.FileSet
	observe map[string]bool
	bound   map[string]bool
	found   []string
}

func (r *reads) visit(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.AssignStmt:
		for i, rhs := range n.Rhs {
			if id, ok := lhsIdent(n.Lhs, i); ok && isDescriptor(rhs) {
				r.bound[id] = true
			}
		}
	case *ast.ValueSpec:
		sel, typed := n.Type.(*ast.SelectorExpr)
		for i, id := range n.Names {
			if (typed && sel.Sel.Name == descriptorType) || (i < len(n.Values) && isDescriptor(n.Values[i])) {
				r.bound[id.Name] = true
			}
		}
	case *ast.CallExpr:
		r.call(n)
	}
	return true
}

func lhsIdent(lhs []ast.Expr, i int) (string, bool) {
	if i >= len(lhs) {
		return "", false
	}
	id, ok := lhs[i].(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

func (r *reads) call(n *ast.CallExpr) {
	sel, ok := n.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	at := r.fset.Position(n.Pos()).String()
	if pkg, ok := sel.X.(*ast.Ident); ok && r.observe[pkg.Name] && (sel.Sel.Name == "ReadNeutral" || sel.Sel.Name == "CheckNeutral") {
		r.found = append(r.found, at+": "+pkg.Name+"."+sel.Sel.Name)
	}
	if strings.Contains(sel.Sel.Name, "Unmarshal") && slices.ContainsFunc(n.Args, func(a ast.Expr) bool { return isDescriptor(a) || names(a, r.bound) }) {
		r.found = append(r.found, at+": "+sel.Sel.Name+" into a "+descriptorType)
	}
}

// isDescriptor reports &x.SourceDescriptor{...}, x.SourceDescriptor{...} or
// new(x.SourceDescriptor).
func isDescriptor(e ast.Expr) bool {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	switch e := e.(type) {
	case *ast.CompositeLit:
		sel, ok := e.Type.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == descriptorType
	case *ast.CallExpr:
		id, ok := e.Fun.(*ast.Ident)
		if !ok || id.Name != "new" || len(e.Args) != 1 {
			return false
		}
		sel, ok := e.Args[0].(*ast.SelectorExpr)
		return ok && sel.Sel.Name == descriptorType
	}
	return false
}

func names(e ast.Expr, bound map[string]bool) bool {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	id, ok := e.(*ast.Ident)
	return ok && bound[id.Name]
}

// TestTheRuleFindsADescriptorRead: the rule's own negative and positive
// controls.
func TestTheRuleFindsADescriptorRead(t *testing.T) {
	const head = "package p\nimport (\n\tob \"" + observePath + "\"\n\tobservev1 \"x/observe/v1alpha1\"\n\t\"google.golang.org/protobuf/encoding/protojson\"\n)\n"
	for name, c := range map[string]struct {
		body  string
		found int
	}{
		"neutral read":          {"func f(b []byte) { ob.ReadNeutral(b) }", 1},
		"neutral check":         {"func f(d *observev1.SourceDescriptor) { _ = ob.CheckNeutral(d) }", 1},
		"unmarshal a literal":   {"func f(b []byte) { _ = protojson.Unmarshal(b, &observev1.SourceDescriptor{}) }", 1},
		"unmarshal a variable":  {"func f(b []byte) { d := &observev1.SourceDescriptor{}; _ = protojson.Unmarshal(b, d) }", 1},
		"unmarshal a new":       {"func f(b []byte) { d := new(observev1.SourceDescriptor); _ = protojson.Unmarshal(b, d) }", 1},
		"unmarshal a value var": {"func f(b []byte) { var d observev1.SourceDescriptor; _ = protojson.Unmarshal(b, &d) }", 1},
		"unmarshal a record":    {"func f(b []byte) { r := &observev1.Record{}; _ = protojson.Unmarshal(b, r) }", 0},
		"build a descriptor":    {"func f() { _ = &observev1.SourceDescriptor{SourceId: \"s\"} }", 0},
		"another ReadNeutral":   {"func f(b []byte) { other.ReadNeutral(b) }", 0},
	} {
		if got := descriptorReads(t, name+".go", []byte(head+c.body+"\n")); len(got) != c.found {
			t.Errorf("%s: found %q, want %d", name, got, c.found)
		}
	}
}

// moduleGoFiles reads each Go file of the module at root outside the
// directories allowed, keyed by its path relative to root.
func moduleGoFiles(t *testing.T, root string, allowed []string) map[string][]byte {
	t.Helper()
	skipped := []string{".git", "node_modules", "testdata"}
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		switch {
		case d.IsDir() && (slices.Contains(skipped, d.Name()) || slices.Contains(allowed, rel)):
			return filepath.SkipDir
		case d.IsDir() || !strings.HasSuffix(path, ".go"):
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // G304: a Go file of this module
		out[rel] = src
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestNoDescriptorIsReadOutsideTheEntryPoint: outside internal/ingest and
// internal/observe, a source descriptor is read from bytes only through
// ingest.ReadDescriptor, so no caller can stop at the neutral half.
func TestNoDescriptorIsReadOutsideTheEntryPoint(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("no module root at %s: %v", root, err)
	}
	files := moduleGoFiles(t, root, []string{filepath.Join("internal", "ingest"), filepath.Join("internal", "observe"), "api", "clients"})
	if len(files) < 100 {
		t.Fatalf("the walk read %d Go files under %s, too few to have searched the module", len(files), root)
	}
	for rel, src := range files {
		for _, read := range descriptorReads(t, rel, src) {
			t.Errorf("%s: a source descriptor read outside ingest.ReadDescriptor", read)
		}
	}
}
