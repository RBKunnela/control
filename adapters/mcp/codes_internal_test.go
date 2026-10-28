package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/guardana/control/internal/policy/reasons"
)

// codeShaped is the shape of a reason code: a string literal all capitals.
var codeShaped = regexp.MustCompile(`^[A-Z][A-Z0-9_]{3,}$`)

// TestTheAdapterSpellsOnlyRegisteredCodes reads the package's production
// source for every string literal shaped like a reason code, and holds each to
// the registry. The verdict mark a shaped list carries is the one such literal
// that is no code, and it is named by its own constant.
func TestTheAdapterSpellsOnlyRegisteredCodes(t *testing.T) {
	found := adapterCodeLiterals(t)
	for _, own := range []string{codeUnclassified, codeInvalidFieldValue, codeApprovalPending, codeExecutedArgsMismatch, codeObligationNotApplied, codeEvidenceUnavailable} {
		if !slices.Contains(found, own) {
			t.Fatalf("the source spells %q and not the constant %q; the wrong source was examined", found, own)
		}
	}
	for _, code := range found {
		if code == markDecidedPerCall {
			continue
		}
		if _, ok := reasons.Lookup(code); !ok {
			t.Errorf("the adapter spells %s, which is not in the registry", code)
		}
	}
}

// adapterCodeLiterals returns, sorted and once each, the code-shaped string
// literals of the package's production files.
func adapterCodeLiterals(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var found []string
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil && codeShaped.MatchString(s) {
					found = append(found, s)
				}
			}
			return true
		})
	}
	if files < 5 {
		t.Fatalf("read %d production file(s); the source was not examined", files)
	}
	slices.Sort(found)
	return slices.Compact(found)
}
