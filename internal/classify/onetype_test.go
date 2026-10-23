package classify_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// classificationFields are the fields only a classification has. A struct
// that declares one outside this package is a second copy of the type, which
// a check added here would not reach.
var classificationFields = []string{"ResourceFrom", "ReturnsTrust", "ReturnsSensitivity"}

// TestTheClassificationIsDeclaredOnce: no non-test Go file of the module
// outside this package declares a struct field a classification has.
func TestTheClassificationIsDeclaredOnce(t *testing.T) {
	root := moduleRoot(t)
	found, files, err := classificationCopies(root, filepath.Join("internal", "classify"))
	if err != nil {
		t.Fatal(err)
	}
	// The module holds hundreds of Go files; a walk that read a handful
	// started somewhere else and would pass whatever it missed.
	if files < 200 {
		t.Fatalf("the walk from %s parsed %d Go files; nothing was examined", root, files)
	}
	for _, f := range found {
		t.Errorf("%s declares a field of a classification; embed classify.Classification or classify.Spelling instead", f)
	}
}

// TestTheDeclaredOnceRuleFindsAPlantedCopy is the negative control: a file
// that declares the field, in a struct, an embedded struct literal type and a
// field list of several names, is reported each time, and a test file or one
// in the allowed package is not.
func TestTheDeclaredOnceRuleFindsAPlantedCopy(t *testing.T) {
	root := t.TempDir()
	plant := func(rel, src string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plant("a/copy.go", "package a\ntype T struct{ Name string; ResourceFrom string }\n")
	plant("b/nested.go", "package b\nvar V struct{ Inner struct{ ReturnsTrust int } }\n")
	plant("c/list.go", "package c\ntype U struct{ A, ReturnsSensitivity int }\n")
	plant("d/copy_test.go", "package d\ntype T struct{ ResourceFrom string }\n")
	plant("allowed/x.go", "package allowed\ntype T struct{ ResourceFrom string }\n")
	plant("e/use.go", "package e\nfunc f(t struct{ X int }) { _ = T{ResourceFrom: \"/a\"} }\n")
	found, files, err := classificationCopies(root, "allowed")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a/copy.go: ResourceFrom", "b/nested.go: ReturnsTrust", "c/list.go: ReturnsSensitivity"}
	if files != 4 || !slices.Equal(found, want) {
		t.Errorf("parsed %d files and found %v; want 4 and %v", files, found, want)
	}
}

// classificationCopies parses every non-test Go file under root, skipping
// hidden directories, testdata, generated code and the allowed directory, and
// names each field of a classification declared in a struct type.
func classificationCopies(root, allowed string) ([]string, int, error) {
	var found []string
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipped(rel, d.Name(), allowed) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		names, err := declaredFields(path)
		for _, name := range names {
			found = append(found, filepath.ToSlash(rel)+": "+name)
		}
		return err
	})
	return found, files, err
}

func skipped(rel, name, allowed string) bool {
	return rel != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "node_modules" ||
		rel == allowed || rel == filepath.Join("api", "gen"))
}

// declaredFields names each field of a classification a struct type in the
// file at path declares.
func declaredFields(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var names []string
	ast.Inspect(file, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				if slices.Contains(classificationFields, name.Name) {
					names = append(names, name.Name)
				}
			}
		}
		return true
	})
	return names, nil
}

// moduleRoot is the nearest directory above this one holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package directory")
		}
		dir = parent
	}
}
