package approval_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// constructorName is the one function that spells the reserved prefix,
// written here rather than taken from the package, so a rename is a failure.
const constructorName = "AuthenticatedApproverID"

// prefixSpellings are what spells the prefix without the constructor: its
// constant, and a string literal that begins with it in any case.
var prefixSpellings = []string{"AuthnPrefix", `"authn:`, "`authn:"}

// mayCallTheConstructor is every directory, relative to the module root,
// whose sources may name the constructor: the package that declares it and
// the plane's pipeline, which builds an approver id from an authentication.
var mayCallTheConstructor = []string{"internal/core/approval", "internal/gateway"}

// maySpellThePrefix is the one directory whose non-test sources may spell the
// prefix: the constructor's own. A test elsewhere spells it as a claim to be
// refused, which no build of the plane carries.
const maySpellThePrefix = "internal/core/approval"

// reachingTheReserved returns every Go or assembly source under root that
// names the constructor outside the directories allowed to, or spells the
// prefix in a non-test source outside its package, and how many sources it
// read. Any spelling counts, a call, a method value, an alias's selector, a
// linkname or a comment, because none of them leaves the name out. It is a
// substring tripwire, not an analysis: a name assembled at run time, or
// reached through reflection, passes it.
func reachingTheReserved(t *testing.T, root string) (found []string, read int) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && notCompiled(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".go" && ext != ".s" {
			return nil
		}
		rel, src, err := readSource(root, path)
		if err != nil {
			return err
		}
		read++
		if reachesTheReserved(rel, src) {
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return found, read
}

// reachesTheReserved reports whether the source at rel names the constructor
// outside the directories allowed to, or spells the prefix where it may not.
func reachesTheReserved(rel string, src []byte) bool {
	dir := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel)))
	if bytes.Contains(src, []byte(constructorName)) && !slices.Contains(mayCallTheConstructor, dir) {
		return true
	}
	return dir != maySpellThePrefix && !strings.HasSuffix(rel, "_test.go") && spellsThePrefix(src)
}

func spellsThePrefix(src []byte) bool {
	lower := bytes.ToLower(src)
	for _, s := range prefixSpellings {
		if bytes.Contains(lower, bytes.ToLower([]byte(s))) {
			return true
		}
	}
	return false
}

// notCompiled is a directory the go command never builds from.
func notCompiled(name string) bool {
	return name == "testdata" || name == "node_modules" || strings.HasPrefix(name, ".")
}

// readSource reads one source and returns it beside its slash-separated path
// under root.
func readSource(root, path string) (string, []byte, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", nil, err
	}
	src, err := os.ReadFile(path) //nolint:gosec // G304: a source file under the module root
	if err != nil {
		return "", nil, err
	}
	return filepath.ToSlash(rel), src, nil
}

// moduleRoot is the directory of the go.mod above this package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package")
		}
		dir = parent
	}
}

// TestOnlyThePipelineNamesTheConstructor: outside this package and
// internal/gateway, no source of the module names the one function that
// spells the reserved prefix, and outside this package no non-test source
// spells the prefix itself, so no other package can hand a person's input to
// the constructor or build the prefix past it.
func TestOnlyThePipelineNamesTheConstructor(t *testing.T) {
	root := moduleRoot(t)
	found, read := reachingTheReserved(t, root)
	if len(found) > 0 {
		t.Errorf("sources name %s outside %v or spell the prefix outside %s: %v", constructorName, mayCallTheConstructor, maySpellThePrefix, found)
	}
	// The walk must have reached the declaration and a good part of the tree,
	// or a walk that read nothing would pass.
	if src, err := os.ReadFile(filepath.Join(root, "internal", "core", "approval", "authn.go")); err != nil || //nolint:gosec // G304: a source file under the module root
		!bytes.Contains(src, []byte("func "+constructorName+"(")) {
		t.Fatalf("the declaration is not where the test looks: %v", err)
	}
	if read < 500 {
		t.Fatalf("the walk read %d sources; it cannot have covered the module", read)
	}
}

// TestTheReachWalkFindsACallerOutsideThePipeline is the walk's negative
// control: a tree with a caller under an alias, one in a directory whose name
// only begins like the pipeline's, one in assembly, and sources that spell the
// prefix by its constant or as a literal in either case, reports each, and
// leaves the pipeline's own caller, a claim in a test, the package's own
// literal and a fixture under testdata alone.
func TestTheReachWalkFindsACallerOutsideThePipeline(t *testing.T) {
	root := t.TempDir()
	for rel, src := range map[string]string{
		"internal/gateway/ok.go":         "package gateway\n\nvar _ = approval." + constructorName + "\n",
		"internal/core/approval/x.go":    "package approval\n\nfunc " + constructorName + "() {}\n",
		"internal/approvals/bad.go":      "package approvals\n\nimport ap \"m/internal/core/approval\"\n\nvar _ = ap." + constructorName + "\n",
		"internal/gatewayx/bad.go":       "package gatewayx\n\nvar _ = approval." + constructorName + "\n",
		"internal/console/bad.s":         "TEXT \u00b7" + constructorName + "(SB),0,$0\n",
		"internal/console/testdata/f.go": "package f\n\nvar _ = approval." + constructorName + "\n",
		"internal/console/clean.go":      "package console\n",
		"internal/gateway/prefix.go":     "package gateway\n\nvar _ = approval.AuthnPrefix\n",
		"internal/console/lit.go":        "package console\n\nvar _ = \"authn:\" + \"x\"\n",
		"internal/console/raw.go":        "package console\n\nvar _ = `AUTHN:x`\n",
		"internal/console/lit_test.go":   "package console\n\nvar _ = \"authn:x\"\n",
		"internal/core/approval/y.go":    "package approval\n\nconst p = \"authn:\"\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	found, read := reachingTheReserved(t, root)
	slices.Sort(found)
	want := []string{
		"internal/approvals/bad.go", "internal/console/bad.s", "internal/console/lit.go", "internal/console/raw.go",
		"internal/gateway/prefix.go", "internal/gatewayx/bad.go",
	}
	if !slices.Equal(found, want) || read != 11 {
		t.Errorf("the walk found %v after reading %d sources; want %v after 11", found, read, want)
	}
}
