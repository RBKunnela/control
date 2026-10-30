package approval_test

import (
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
)

// TestProductionImportsOnlyCanonAndTheContract: from this module the package
// needs the canonical form, the generated contract and the contract's
// identifier rule, and nothing else. The reason-code registry least of all,
// since nothing on the decision path imports it (ADR-0012).
func TestProductionImportsOnlyCanonAndTheContract(t *testing.T) {
	self := reflect.TypeFor[approval.Binding]().PkgPath()
	module := strings.TrimSuffix(self, "/internal/core/approval")
	if module == self {
		t.Fatalf("cannot find the module path in %q", self)
	}
	allowed := []string{reflect.TypeFor[controlv1.ActionEnvelope]().PkgPath(), module + "/internal/canon", module + "/pkg/contract"}
	for _, imp := range productionImports(t) {
		if (imp == module || strings.HasPrefix(imp, module+"/")) && !slices.Contains(allowed, imp) {
			t.Errorf("the package imports %s; only %q are allowed from this module", imp, allowed)
		}
	}
}

// productionImports returns the imports of the package's non-test files.
func productionImports(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	var imports []string
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: import %s: %v", name, imp.Path.Value, err)
			}
			imports = append(imports, path)
		}
	}
	// A directory with no production file would pass while examining nothing.
	if files == 0 || len(imports) == 0 {
		t.Fatalf("read %d production file(s) and %d import(s); nothing was examined", files, len(imports))
	}
	return imports
}
