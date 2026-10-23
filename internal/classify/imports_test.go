package classify_test

import (
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

// TestTheClassificationImportsOnlyTheContract: the configuration loader, which
// the approver's binary links, reads a classification through this package,
// so it imports nothing but the standard library, the protobuf runtime, the
// generated contract and pkg/contract, and reaches neither the gateway nor
// evidence. Each platform's files are listed: an import only a file for
// another platform carries would escape a listing of this one.
func TestTheClassificationImportsOnlyTheContract(t *testing.T) {
	for _, goos := range []string{runtime.GOOS, "windows"} {
		imports, deps := goList(t, goos)
		if !slices.Contains(imports, brand.ModulePath+"/pkg/contract") {
			t.Fatalf("GOOS=%s: the listing names %d import(s) and not pkg/contract; nothing was examined", goos, len(imports))
		}
		for _, path := range imports {
			if !allowedImport(path) {
				t.Errorf("GOOS=%s: this package imports %s", goos, path)
			}
		}
		for _, dep := range deps {
			for _, tree := range []string{"/internal/gateway", "/internal/evidence", "/adapters"} {
				if dep == brand.ModulePath+tree || strings.HasPrefix(dep, brand.ModulePath+tree+"/") {
					t.Errorf("GOOS=%s: this package reaches %s", goos, dep)
				}
			}
		}
	}
}

// TestTheImportRuleRefusesWhatItShould is the negative control: the
// predicate the listing is read with refuses the module's other trees and
// any other module.
func TestTheImportRuleRefusesWhatItShould(t *testing.T) {
	for _, path := range []string{brand.ModulePath + "/internal/gateway", brand.ModulePath + "/internal/adapterkit",
		brand.ModulePath + "/api/gen/go", "google.golang.org/grpc", "example.com/x"} {
		if allowedImport(path) {
			t.Errorf("allowedImport(%s) = true", path)
		}
	}
}

// allowedImport is the standard library, the protobuf runtime, the generated
// contract and pkg/contract.
func allowedImport(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	switch {
	case !strings.Contains(first, "."):
		return true
	case path == brand.ModulePath+"/pkg/contract":
		return true
	case strings.HasPrefix(path, brand.ModulePath+"/api/gen/go/"):
		return true
	case strings.HasPrefix(path, "google.golang.org/protobuf/"):
		return true
	}
	return false
}

// goList is the package's imports and its dependencies as GOOS builds it.
func goList(t *testing.T, goos string) (imports, deps []string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \" \"}}|{{join .Deps \" \"}}", ".")
	cmd.Env = append(os.Environ(), "GOOS="+goos)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("GOOS=%s go list: %v", goos, err)
	}
	direct, all, ok := strings.Cut(strings.TrimSpace(string(out)), "|")
	if !ok {
		t.Fatalf("GOOS=%s go list printed %q, not the two lists", goos, out)
	}
	return strings.Fields(direct), strings.Fields(all)
}
