package brand

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrandConstantsAreConsistent(t *testing.T) {
	if Slug != "guardana-control" || Name != "Guardana Control" {
		t.Fatalf("brand defaults changed without the rename script: %q %q", Name, Slug)
	}
	if EnvPrefix != "GUARDANA_CONTROL_" {
		t.Fatalf("env prefix must derive from the slug: %q", EnvPrefix)
	}
	if got := Env("LOG_LEVEL"); got != "GUARDANA_CONTROL_LOG_LEVEL" {
		t.Fatalf("Env() = %q", got)
	}
	if OTelNamespace != "guardana.control" || ProtoPackage != "guardana.control.v1" {
		t.Fatalf("namespaces drifted: %q %q", OTelNamespace, ProtoPackage)
	}
	if PythonPackage != "guardana_control" {
		t.Fatalf("the Python package must be the slug with underscores: %q", PythonPackage)
	}
}

// The package directory is a path no compiler reads; a renamed constant
// beside an unmoved directory would leave the client unimportable.
func TestThePythonPackageDirectoryIsNamedAsTheConstant(t *testing.T) {
	info, err := fs.Stat(repo(), path.Join("clients", "python", "src", PythonPackage))
	if err != nil || !info.IsDir() {
		t.Fatalf("clients/python/src holds no directory %s: %v", PythonPackage, err)
	}
}

// repo is the repository root. go test runs in the package directory, and
// rooting reads at an fs.FS keeps every path below it a literal.
func repo() fs.FS {
	return os.DirFS(filepath.Join("..", ".."))
}

// ModulePath is a copy of go.mod's module directive that no compiler checks,
// and rename-product.sh reads it as the old value to replace. A drifted copy
// makes a rename rewrite everything except the module path, and report success.
func TestModulePathMatchesGoMod(t *testing.T) {
	data, err := fs.ReadFile(repo(), "go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	var modules []string
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "module" {
			modules = append(modules, strings.Trim(fields[1], `"`))
		}
	}
	if len(modules) != 1 {
		t.Fatalf("go.mod holds %d module directive(s), want 1: %q", len(modules), modules)
	}
	if modules[0] != ModulePath {
		t.Errorf("go.mod declares module %q, brand.ModulePath is %q", modules[0], ModulePath)
	}
}

// ProtoPackage is written by hand beside the package line of every .proto file,
// and the rename rewrites both in one pass; nothing else compares them.
func TestProtoPackageMatchesTheProtoFiles(t *testing.T) {
	fsys := repo()
	files := 0
	err := fs.WalkDir(fsys, "api/proto", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !strings.HasSuffix(name, ".proto") {
			return walkErr
		}
		files++
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		pkgs := protoPackages(string(data))
		if len(pkgs) != 1 || !protoPackageFits(name, pkgs[0]) {
			t.Errorf("%s declares package %q; brand.ProtoPackage is %q, and any other package sits under %q in its own directory", name, pkgs, ProtoPackage, OTelNamespace)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking api/proto: %v", err)
	}
	// A walk that found nothing compared nothing.
	if files == 0 {
		t.Fatal("found no .proto file under api/proto")
	}
}

// protoPackageFits reports whether the proto file at name declares pkg as
// the layout requires: the wire contract's directory holds ProtoPackage, and
// any other package, such as an unstable sibling contract, is under the
// product's namespace in the directory its name spells.
func protoPackageFits(name, pkg string) bool {
	dir := path.Dir(name)
	if dir == "api/proto/"+strings.ReplaceAll(ProtoPackage, ".", "/") {
		return pkg == ProtoPackage
	}
	return strings.HasPrefix(pkg, OTelNamespace+".") && dir == "api/proto/"+strings.ReplaceAll(pkg, ".", "/")
}

// protoPackages returns the name of every `package x.y.z;` line in src.
func protoPackages(src string) []string {
	var pkgs []string
	for _, line := range strings.Split(src, "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "package" {
			pkgs = append(pkgs, strings.TrimSuffix(fields[1], ";"))
		}
	}
	return pkgs
}

func TestProtoPackagesReadsOnlyPackageLines(t *testing.T) {
	src := "syntax = \"proto3\";\n// package in a comment\npackage a.b.v1;\noption go_package = \"x\";\n"
	if got := protoPackages(src); len(got) != 1 || got[0] != "a.b.v1" {
		t.Errorf("protoPackages = %q, want [a.b.v1]", got)
	}
}
