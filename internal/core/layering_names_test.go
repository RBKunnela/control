package core_test

import (
	"fmt"
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

// The names the rule refuses in a package a guarded tree reaches, by import
// path: the functions of allowed packages that read the clock, standard input
// or the zone database, or draw on the system's randomness. The timer types
// are refused whole: Reset schedules from the clock, and a Reset selector
// cannot be told from a buffer's without the receiver's type. A timer held
// through an interface of its Reset alone names neither type: a read no name
// reveals, which no name refusal can catch. .golangci.yml refuses the same
// names through forbidigo, and layering_agreement_test.go holds the two to
// each other.
var refusedNames = map[string][]string{
	"time": {
		"Now", "Since", "Until", "After", "AfterFunc", "Tick", "NewTicker", "NewTimer", "Sleep",
		"Timer", "Ticker", "LoadLocation", "Local",
	},
	"google.golang.org/protobuf/types/known/timestamppb": {"Now"},
	"context":        {"WithDeadline", "WithTimeout", "WithDeadlineCause", "WithTimeoutCause"},
	"fmt":            {"Scan", "Scanf", "Scanln"},
	"crypto/ed25519": {"GenerateKey"},
}

// The methods of time.Time that read the local zone. Without type checking a
// receiver's type is unknown, so a selector with one of these names is refused
// whatever it selects from, except a package other than time.
var refusedMethods = []string{"Local", "Zone", "ZoneBounds", "IsDST"}

// TestReachedPackagesReadNothingByName reads every Go file of the non-test
// build of each package of this module a guarded tree reaches, guarded
// packages included, and refuses each name above. forbidigo resolves names
// through the type checker and also reads test files; this reads the source
// alone, so that removing forbidigo or its scope does not remove the refusal.
func TestReachedPackagesReadNothingByName(t *testing.T) {
	modulePath, moduleDir := mainModule(t)
	patterns := make([]string, 0, len(guardedTrees))
	for _, tree := range guardedTrees {
		mustExist(t, moduleDir, tree)
		patterns = append(patterns, "./"+tree+"/...")
	}
	const format = "{{.ImportPath}}\t{{.Dir}}{{range .GoFiles}}\t{{.}}{{end}}" +
		"{{range .CgoFiles}}\t{{.}}{{end}}{{range .IgnoredGoFiles}}\t{{.}}{{end}}"

	repo := os.DirFS(moduleDir)
	packages, files := 0, 0
	for _, line := range goList(t, moduleDir, append([]string{"-deps", "-f", format}, patterns...)...) {
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			t.Fatalf("go list printed %q, which names no package and directory", line)
		}
		if !heldToRule(modulePath, parts[0]) {
			continue
		}
		packages++
		dir, err := filepath.Rel(moduleDir, parts[1])
		if err != nil {
			t.Fatalf("go list named %s, outside %s: %v", parts[1], moduleDir, err)
		}
		for _, name := range parts[2:] {
			files++
			rel := filepath.ToSlash(filepath.Join(dir, name))
			src, err := fs.ReadFile(repo, rel)
			if err != nil {
				t.Fatalf("reading %s: %v", rel, err)
			}
			for _, problem := range namedReads(t, rel, src) {
				t.Error(problem)
			}
		}
	}
	if files == 0 {
		t.Fatalf("%d package(s) of this module reached and not one Go file among them, so no name was looked for", packages)
	}
	t.Logf("%d Go file(s) of %d reached package(s) of this module read for names the rule refuses", files, packages)
}

// namedReads returns a message for each refused name the file selects, and
// for each dot import of a package that holds one, which would let the name
// appear unqualified.
func namedReads(t *testing.T, rel string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", rel, err)
	}
	var problems []string
	report := func(pos token.Pos, what string) {
		problems = append(problems, fmt.Sprintf("%s:%d: %s, which the dependency rule refuses by name in every package a guarded tree reaches",
			rel, fset.Position(pos).Line, what))
	}

	imported := importNames(t, rel, file, report)
	ast.Inspect(file, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if what := selectedRead(imported, sel); what != "" {
				report(sel.Sel.Pos(), what)
			}
		}
		return true
	})
	return problems
}

// importNames maps each name the file binds an import to onto its path, and
// reports a dot import of a package that holds a refused name.
func importNames(t *testing.T, rel string, file *ast.File, report func(token.Pos, string)) map[string]string {
	t.Helper()
	imported := make(map[string]string)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("%s: import %s: %v", rel, spec.Path.Value, err)
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		switch _, refused := refusedNames[path]; {
		case name == "." && refused:
			report(spec.Pos(), "imports "+path+" with a dot")
		case name != "_" && name != ".":
			imported[name] = path
		}
	}
	return imported
}

// selectedRead says what refused read sel names, or returns "" when it names
// none. A selector on an imported package is judged by that package's names
// alone; any other selector by refusedMethods.
func selectedRead(imported map[string]string, sel *ast.SelectorExpr) string {
	if ident, isIdent := sel.X.(*ast.Ident); isIdent {
		if path, isImport := imported[ident.Name]; isImport {
			if slices.Contains(refusedNames[path], sel.Sel.Name) {
				return "names " + path + "." + sel.Sel.Name
			}
			return ""
		}
	}
	if slices.Contains(refusedMethods, sel.Sel.Name) {
		return "names the method " + sel.Sel.Name
	}
	return ""
}

// Each case is a way to write a refused read, or a near miss that is not one.
// The expected messages are written out, not built from refusedNames.
func TestNamedReads(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"plain", `import "time"; var _ = time.Now()`, []string{"names time.Now"}},
		{"renamed", `import clock "time"; var _ = clock.Since(clock.Time{})`, []string{"names time.Since"}},
		{"value", `import "time"; var f = time.Now`, []string{"names time.Now"}},
		{"zone variable", `import "time"; var _ = time.Local`, []string{"names time.Local"}},
		{"zone database", `import "time"; var _, _ = time.LoadLocation("UTC")`, []string{"names time.LoadLocation"}},
		{"timestamp", `import "google.golang.org/protobuf/types/known/timestamppb"; var _ = timestamppb.Now()`,
			[]string{"names google.golang.org/protobuf/types/known/timestamppb.Now"}},
		{"renamed timestamp", `import ts "google.golang.org/protobuf/types/known/timestamppb"; var _ = ts.Now()`,
			[]string{"names google.golang.org/protobuf/types/known/timestamppb.Now"}},
		{"deadline", `import "context"; var _, _ = context.WithTimeoutCause(nil, 0, nil)`, []string{"names context.WithTimeoutCause"}},
		{"input", `import "fmt"; var _, _ = fmt.Scanf("")`, []string{"names fmt.Scanf"}},
		{"randomness", `import "crypto/ed25519"; var _, _, _ = ed25519.GenerateKey(nil)`, []string{"names crypto/ed25519.GenerateKey"}},
		{"method", `import "time"; func f(t time.Time) { _ = t.Local() }`, []string{"names the method Local"}},
		{"method through a call", `func f() { _, _ = g().Zone() }`, []string{"names the method Zone"}},
		{"method expression", `import "time"; var _ = time.Time.IsDST`, []string{"names the method IsDST"}},
		{"promoted method", `import "time"; type s struct{ time.Time }; func f(v s) { _, _ = v.ZoneBounds() }`,
			[]string{"names the method ZoneBounds"}},
		{"dot import", `import . "time"; var _ = Now()`, []string{"imports time with a dot"}},
		{"timer reset", `import "time"; func f(t *time.Timer) { t.Reset(0) }`, []string{"names time.Timer"}},
		{"ticker reset", `import "time"; func f(k *time.Ticker) { k.Reset(1) }`, []string{"names time.Ticker"}},
		{"timer field", `import clock "time"; type s struct{ t clock.Timer }`, []string{"names time.Timer"}},

		{"allowed function", `import "time"; var _ = time.Unix(0, 0)`, nil},
		{"allowed type", `import "time"; var _ time.Duration`, nil},
		{"refused name of another package", `import "example.invalid/m/clock"; var _ = clock.Now()`, nil},
		{"method name of another package", `import "example.invalid/m/zones"; var _ = zones.Local`, nil},
		{"time shadowed by another import", `import time "example.invalid/m/clock"; var _ = time.Now()`, nil},
		{"blank import", `import _ "time"`, nil},
		{"dot import of another package", `import . "strings"; var _ = ToUpper("")`, nil},
		{"name in a string", `var _ = "time.Now"`, nil},
	}
	for _, c := range cases {
		problems := namedReads(t, "x.go", []byte("package x; "+c.src))
		if len(problems) != len(c.want) {
			t.Errorf("%s: namedReads = %q, want %d problem(s) naming %q", c.name, problems, len(c.want), c.want)
			continue
		}
		for i, want := range c.want {
			if !strings.Contains(problems[i], "x.go:1: "+want+", ") {
				t.Errorf("%s: problem %q does not say %q", c.name, problems[i], want)
			}
		}
	}
}
