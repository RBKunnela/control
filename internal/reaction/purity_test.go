package reaction_test

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
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/runs"
)

// allowedStdlib are the standard library packages this package's own files
// may import. None reads a file, the network, a process or the environment,
// or draws randomness, except through a name impureNames refuses.
var allowedStdlib = []string{
	"bytes", "context", "crypto/ed25519", "crypto/sha256", "encoding/base64", "encoding/hex", "encoding/json",
	"errors", "fmt", "hash", "maps", "math", "path", "slices", "strconv", "strings", "time", "unicode/utf8",
}

// allowedModule are the packages of this module those files may import. Each
// is in a tree the dependency rule guards or generates, but policykey, which
// reads and writes key files and so is held to the names onlyNames lists.
var allowedModule = []string{
	"/api/gen/go/guardana/control/v1", "/internal/canon", "/internal/policy", "/internal/policy/bundle",
	"/internal/policy/strictjson", "/internal/policykey", "/pkg/contract",
}

// onlyNames are, for an allowed package that also reads or writes files, the
// names this package may use of it.
var onlyNames = map[string][]string{
	brand.ModulePath + "/internal/policykey": {"FormatPublic", "KeyID", "MarshalEnvelope", "ParseEnvelope", "ParsePublic", "SameKey"},
}

// impureNames are the names of an allowed package that read the clock, the
// zone database or standard input, start a deadline, write standard output,
// or draw randomness.
var impureNames = map[string][]string{
	"time": {
		"Now", "Since", "Until", "After", "AfterFunc", "Tick", "NewTicker", "NewTimer", "Sleep",
		"LoadLocation", "Local",
	},
	"context":        {"WithDeadline", "WithTimeout", "WithDeadlineCause", "WithTimeoutCause"},
	"fmt":            {"Scan", "Scanf", "Scanln", "Print", "Printf", "Println"},
	"crypto/ed25519": {"GenerateKey"},
}

// impureMethods read the local zone, whatever value they are called on.
var impureMethods = []string{"Local", "Zone", "ZoneBounds", "IsDST"}

func allowedImport(path string) bool {
	return slices.Contains(allowedStdlib, path) ||
		slices.ContainsFunc(allowedModule, func(p string) bool { return path == brand.ModulePath+p })
}

// impureReads returns a message for each import or name of src this package
// may not use.
func impureReads(t *testing.T, name string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	var problems []string
	report := func(pos token.Pos, what string) {
		problems = append(problems, fmt.Sprintf("%s:%d: %s", name, fset.Position(pos).Line, what))
	}
	imported := impureImports(t, name, file, report)
	ast.Inspect(file, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if what := impureSelector(imported, sel); what != "" {
				report(sel.Sel.Pos(), what)
			}
		}
		return true
	})
	return problems
}

// impureImports reports each import of file not on the lists, and each dot
// import, and maps the name each other import is bound to onto its path.
func impureImports(t *testing.T, name string, file *ast.File, report func(token.Pos, string)) map[string]string {
	t.Helper()
	imported := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("%s: import %s: %v", name, spec.Path.Value, err)
		}
		local := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			local = spec.Name.Name
		}
		switch {
		case !allowedImport(path):
			report(spec.Pos(), "imports "+path)
		case local == ".":
			report(spec.Pos(), "imports "+path+" with a dot")
		case local != "_":
			imported[local] = path
		}
	}
	return imported
}

// impureSelector says what refused read sel names, or "". A selector on an
// imported package is judged by that package's names alone.
func impureSelector(imported map[string]string, sel *ast.SelectorExpr) string {
	if ident, isIdent := sel.X.(*ast.Ident); isIdent {
		if path, isImport := imported[ident.Name]; isImport {
			if slices.Contains(impureNames[path], sel.Sel.Name) {
				return "names " + path + "." + sel.Sel.Name
			}
			if only, held := onlyNames[path]; held && !slices.Contains(only, sel.Sel.Name) {
				return "names " + path + "." + sel.Sel.Name + ", which is not listed"
			}
			return ""
		}
	}
	if slices.Contains(impureMethods, sel.Sel.Name) {
		return "names the method " + sel.Sel.Name
	}
	return ""
}

// TestPackageReadsNoClockFileProcessOrRandomness holds every non-test Go file
// of this package, whatever its build constraints, to the lists above.
func TestPackageReadsNoClockFileProcessOrRandomness(t *testing.T) {
	pkg := os.DirFS(".")
	names, err := fs.Glob(pkg, "*.go")
	if err != nil {
		t.Fatal(err)
	}
	var read []string
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := fs.ReadFile(pkg, name)
		if err != nil {
			t.Fatal(err)
		}
		read = append(read, name)
		for _, problem := range impureReads(t, name, src) {
			t.Error(problem)
		}
	}
	// A glob that missed the package's own files examined nothing.
	for _, want := range []string{"doc.go", "route.go", "envelope.go", "judge.go"} {
		if !slices.Contains(read, want) {
			t.Fatalf("read %v, which lacks %s", read, want)
		}
	}
}

// TestAllowedModulePackagesAreGuarded: every module package on the list but
// those held to their names is in a tree the dependency rule guards or
// generates, so the rule keeps it free of what this package may not read.
func TestAllowedModulePackagesAreGuarded(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "lib", "dependency-rule.sh"))
	if err != nil {
		t.Fatal(err)
	}
	trees := append(shellArray(t, string(raw), "guarded"), shellArray(t, string(raw), "generated")...)
	for _, p := range allowedModule {
		if _, held := onlyNames[brand.ModulePath+p]; held {
			continue
		}
		pkg := strings.TrimPrefix(p, "/")
		if !slices.ContainsFunc(trees, func(tree string) bool { return pkg == tree || strings.HasPrefix(pkg, tree+"/") }) {
			t.Errorf("%s is in no tree of %v", pkg, trees)
		}
	}
}

// shellArray is the bare words of the array name=( ... ) in script.
func shellArray(t *testing.T, script, name string) []string {
	t.Helper()
	_, body, found := strings.Cut(script, "\n"+name+"=(\n")
	body, _, closed := strings.Cut(body, "\n)")
	if !found || !closed {
		t.Fatalf("no array %s in the dependency rule", name)
	}
	var words []string
	for _, line := range strings.Split(body, "\n") {
		if w := strings.TrimSpace(line); w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		t.Fatalf("the array %s is empty", name)
	}
	return words
}

// The bounds this package holds as its own, so it links no runs code, are the
// runs directory's.
func TestBoundsAreTheRunsDirectorys(t *testing.T) {
	if reaction.MaxLifetime != runs.MaxTTL {
		t.Errorf("MaxLifetime = %s, runs.MaxTTL = %s", reaction.MaxLifetime, runs.MaxTTL)
	}
	if reaction.MaxTenantIDBytes != runs.MaxIdentityBytes {
		t.Errorf("MaxTenantIDBytes = %d, runs.MaxIdentityBytes = %d", reaction.MaxTenantIDBytes, runs.MaxIdentityBytes)
	}
	if reaction.MaxLifetime != 720*time.Hour || reaction.MaxTenantIDBytes != 256 {
		t.Errorf("MaxLifetime = %s, MaxTenantIDBytes = %d; want 720h and 256", reaction.MaxLifetime, reaction.MaxTenantIDBytes)
	}
}
