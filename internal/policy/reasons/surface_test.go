// Two pins on what leaves this package, which is a different job from the
// tests of what the table holds: registry_test.go checks the content, this file
// checks the shape the package hands out.
//
// TestPackageExportsNoVerdictFunction keeps this package from offering a way to
// reach a verdict from a reason code. A verdict comes from the matcher and from
// deny-overrides precedence (ADR-0003), never from the reason attached to it
// afterwards. The pin's scope is exactly this directory: it cannot stop a
// sibling package from wrapping Lookup, and it does not pretend to. The guard
// that matters for a decision is in the matcher's and the kernel's own
// packages: nothing on the decision path imports this one (ADR-0012).
package reasons_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/policy/reasons"
)

// The signatures of the two blessed functions, pinned twice.
//
// At compile time, so that a parameter added to either one fails the build
// rather than the assertion below. A variadic verdict parameter is the shape
// this catches: `func Lookup(id string, out ...*controlv1.Verdict) (Code, bool)`
// keeps the pinned name, returns the pinned types, and hands a caller a verdict.
var (
	_ func(string) (reasons.Code, bool) = reasons.Lookup
	_ func() []reasons.Code             = reasons.All
)

// And as source, so the failure names what changed, and so the exported set is
// pinned by the same table that pins the shapes. Adding a name here is a
// decision about what the matcher can reach for, not an edit that arrives with
// a feature.
var wantSignatures = map[string]string{
	"Lookup": "func(id string) (Code, bool)",
	"All":    "func() []Code",
}

// The package exports one type and no variable or constant at all.
var wantExportedTypes = []string{"Code"}

// Code's fields, pinned the way the functions above are.
//
// A struct field is the same short circuit as a parameter, one grammatical
// position further along: a second column such as `Escalation
// controlv1.Verdict` populated on one row hands the kernel a verdict, and it
// is worse than Lookup(id).Verdict, because a field the reference page does not
// render and wantTriples does not pin is an undocumented verdict travelling
// under a documented code.
var wantCodeFields = map[string]string{
	"ID":      "string",
	"Num":     "uint32",
	"Verdict": "controlv1.Verdict",
	"Summary": "string",
}

// wantVerdictFields is how many of those fields may name a Verdict. One: the
// documented one, which wantTriples pins and the page renders.
const wantVerdictFields = 1

// The door this package keeps shut, within this directory. Four things are
// pinned, because a verdict can leave a package in four grammatical positions:
// the exported function set and each one's exact signature, the exported type
// set, Code's exact field set (TestExportedTypeFieldsArePinned below), and the
// absence of any exported variable or constant, which is where a function-typed
// variable would otherwise hide.
func TestPackageExportsNoVerdictFunction(t *testing.T) {
	var funcs, exportedTypes, values []string
	for name, file := range packageFiles(t) {
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				if !ast.IsExported(typed.Name.Name) {
					continue
				}
				funcs = append(funcs, typed.Name.Name)
				checkExportedFunc(t, name, typed)
			case *ast.GenDecl:
				declaredTypes, declaredValues := exportedNames(typed)
				exportedTypes = append(exportedTypes, declaredTypes...)
				values = append(values, declaredValues...)
			}
		}
	}

	slices.Sort(funcs)
	wantFuncs := slices.Sorted(maps.Keys(wantSignatures))
	if !slices.Equal(funcs, wantFuncs) {
		t.Errorf("exported functions are %v, want %v", funcs, wantFuncs)
	}
	slices.Sort(exportedTypes)
	if !slices.Equal(exportedTypes, wantExportedTypes) {
		t.Errorf("exported types are %v, want %v", exportedTypes, wantExportedTypes)
	}
	if len(values) != 0 {
		t.Errorf("the package exports the variables or constants %v; a function-typed variable is how a verdict lookup comes back without being a function declaration", values)
	}
}

// The field-level half of the same door. The exported type set being {Code} is
// not enough: Code itself can grow a column, and a second verdict field is an
// undocumented verdict, because nothing renders it on the page and nothing pins
// it in wantTriples.
func TestExportedTypeFieldsArePinned(t *testing.T) {
	specs := exportedTypeSpecs(t)
	if len(specs) == 0 {
		t.Fatal("found no exported type; this check would examine nothing")
	}

	for name, spec := range specs {
		if name != "Code" {
			// The type set is pinned elsewhere; this says what an extra type
			// would be doing here if the other assertion were ever relaxed.
			if mentionsVerdict(spec.Type) {
				t.Errorf("exported type %s names a Verdict; only Code documents one", name)
			}
			continue
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok {
			t.Fatalf("Code is %s, not a struct; this check can no longer read it", types.ExprString(spec.Type))
		}
		checkCodeFields(t, structType)
	}
}

// checkCodeFields compares Code's fields with wantCodeFields by name and by
// type, and counts the ones that name a Verdict.
func checkCodeFields(t *testing.T, structType *ast.StructType) {
	t.Helper()

	got := make(map[string]string, len(wantCodeFields))
	verdicts := 0
	for _, field := range structType.Fields.List {
		fieldType := types.ExprString(field.Type)
		if mentionsVerdict(field.Type) {
			verdicts++
		}
		if len(field.Names) == 0 {
			// An embedded field carries whatever the embedded type carries,
			// and has no name of its own to compare; report it as itself.
			got[fieldType] = fieldType
			continue
		}
		for _, name := range field.Names {
			got[name.Name] = fieldType
		}
	}

	for name, want := range wantCodeFields {
		switch have, ok := got[name]; {
		case !ok:
			t.Errorf("Code has no field %s, which the registry and the page both read", name)
		case have != want:
			t.Errorf("Code.%s is %s, want %s", name, have, want)
		}
	}
	for name, have := range got {
		if _, pinned := wantCodeFields[name]; !pinned {
			t.Errorf("Code has an unpinned field %s %s; a field is a verdict's fourth way out of this package", name, have)
		}
	}
	if verdicts != wantVerdictFields {
		t.Errorf("Code has %d field(s) naming a Verdict, want %d; a second one is a verdict no page renders and no test pins",
			verdicts, wantVerdictFields)
	}
}

// exportedTypeSpecs returns every exported type declaration in the package.
func exportedTypeSpecs(t *testing.T) map[string]*ast.TypeSpec {
	t.Helper()
	specs := make(map[string]*ast.TypeSpec)
	for _, file := range packageFiles(t) {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				if typeSpec, ok := spec.(*ast.TypeSpec); ok && ast.IsExported(typeSpec.Name.Name) {
					specs[typeSpec.Name.Name] = typeSpec
				}
			}
		}
	}
	return specs
}

// checkExportedFunc fails an exported function that is named for a verdict,
// mentions one anywhere in its signature, or no longer has the exact shape
// wantSignatures pins.
func checkExportedFunc(t *testing.T, file string, fn *ast.FuncDecl) {
	t.Helper()
	if strings.Contains(fn.Name.Name, "Verdict") {
		t.Errorf("%s: exported %s; nothing here may be named for a verdict", file, fn.Name.Name)
	}

	// Parameters as well as results. A variadic *Verdict parameter is an out
	// parameter: it hands the caller a verdict while the result types stay
	// exactly what this test used to accept.
	for where, list := range map[string]*ast.FieldList{
		"parameters":      fn.Type.Params,
		"results":         fn.Type.Results,
		"type parameters": fn.Type.TypeParams,
	} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			if mentionsVerdict(field.Type) {
				t.Errorf("%s: exported %s mentions a Verdict in its %s; the verdict comes from the matcher",
					file, fn.Name.Name, where)
			}
		}
	}
	if fn.Type.TypeParams != nil {
		t.Errorf("%s: exported %s is generic; a type parameter can carry a verdict past a signature comparison",
			file, fn.Name.Name)
	}

	want, pinned := wantSignatures[fn.Name.Name]
	if !pinned {
		return // an unpinned name is reported by the set comparison above
	}
	if got := types.ExprString(fn.Type); got != want {
		t.Errorf("%s: %s has signature %s, want %s", file, fn.Name.Name, got, want)
	}
}

// mentionsVerdict reports whether a type expression names Verdict anywhere: as
// the type itself, behind a pointer, or inside a slice, map or variadic.
func mentionsVerdict(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			if typed.Sel.Name == "Verdict" {
				found = true
			}
		case *ast.Ident:
			if typed.Name == "Verdict" {
				found = true
			}
		}
		return !found
	})
	return found
}

// exportedNames splits a declaration's exported names into types and into
// variables and constants.
func exportedNames(decl *ast.GenDecl) (typeNames, valueNames []string) {
	for _, spec := range decl.Specs {
		switch typed := spec.(type) {
		case *ast.TypeSpec:
			if ast.IsExported(typed.Name.Name) {
				typeNames = append(typeNames, typed.Name.Name)
			}
		case *ast.ValueSpec:
			for _, name := range typed.Names {
				if ast.IsExported(name.Name) {
					valueNames = append(valueNames, name.Name)
				}
			}
		}
	}
	return typeNames, valueNames
}

// packageFiles parses the package's own source, test files excluded. A run that
// parsed nothing is fatal: the check above would then report a package with no
// exported function at all as clean. Subdirectories are not read, and the
// comment on the test says so rather than implying a wider scope.
func packageFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	dir := filepath.Dir(selfPath(t))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	files := make(map[string]*ast.File, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = file
	}
	if len(files) == 0 {
		t.Fatalf("parsed no source file in %s; the check would examine nothing", dir)
	}
	return files
}

// selfPath is this file's own compiled-in path. The pins resolve the package
// from it rather than from the working directory, which a caller can change.
// Under `go test -trimpath` it resolves to nothing and the pins fail loudly.
func selfPath(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this file's own path; refusing to fall back on the working directory")
	}
	return self
}
