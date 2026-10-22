// Package reasondoc renders the reason-code reference page from the registry.
//
// It is a package rather than a function inside the generator script, so that
// vet, the linters and the tests see it: a `//go:build ignore` file is invisible
// to `go list ./...` and to golangci-lint, and the refusal branches below would
// be code nothing ever runs. It is a separate package from reasons, not a third
// exported function there, because that package's exported set is deliberately
// two functions wide and pinned that way.
//
// Rendering is a pure function of the registry. No clock, no filesystem, no
// subprocess: scripts/gen-reason-codes.go is the thin writer that puts the
// result on disk, and the test that pins the committed page calls Page directly.
package reasondoc

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/docscheck/frontmatter"
	"github.com/guardana/control/internal/policy/reasons"
)

// meta is the page's frontmatter: what the documentation checks read to place
// the page, and covers is the code whose change makes it suspect.
var meta = frontmatter.Meta{
	Title:     "Reason codes",
	Summary:   "Every reason code a decision may carry, with its number and the verdict it usually accompanies.",
	Type:      "reference",
	Covers:    []string{"internal/policy/reasons/**", "internal/docscheck/reasondoc/**"},
	Generated: "scripts/gen-reason-codes.go",
}

// The intro answers one question: what a reason code on a decision means. It
// states neither more nor less than that, and points at docs/status.md rather
// than repeating a status claim the project keeps in one inventory.
const header = "\n# Reason codes\n" +
	"\n" +
	"A reason code is the machine-readable answer to why a call received the\n" +
	"verdict it did, and it travels in `Decision.reason_codes` and in the\n" +
	"evidence record. The verdict column records the verdict a code normally\n" +
	"accompanies, and it is documentation: a verdict comes from the matcher and\n" +
	"from deny-overrides precedence\n" +
	"([ADR-0003](../adr/0003-policy-model-and-external-pdp.md)), never from the\n" +
	"code attached to it afterwards.\n" +
	"\n" +
	"A decision may carry several codes, and the column does not compose: where\n" +
	"there is more than one, the verdict is the one deny-overrides precedence\n" +
	"reaches and not anything read off a single row. What is built and what is\n" +
	"not is in [status.md](../status.md).\n" +
	"\n" +
	"Rendered from the table in `internal/policy/reasons/codes.go`. Rebuild it\n" +
	"with `make docs-gen`; an edit made here does not survive the next run.\n" +
	"\n" +
	"| Code | Number | Usual verdict | Summary |\n" +
	"| --- | --- | --- | --- |\n"

// verdictPrefix is dropped from the enum value name: the column heading
// already says these are verdicts, and VERDICT_DENY in every row is noise.
const verdictPrefix = "VERDICT_"

// Page renders the reference page for the whole registry.
func Page() ([]byte, error) { return render(reasons.All()) }

// render builds the page in memory, so a code it refuses leaves the previous
// page on disk rather than truncating it. It takes the codes as an argument so
// that its refusals can be tested with a registry that cannot exist.
func render(codes []reasons.Code) ([]byte, error) {
	if len(codes) == 0 {
		return nil, errors.New("the registry is empty; refusing to render a page listing no codes")
	}

	front, err := frontmatter.Render(meta)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(front)
	buf.WriteString(header)
	for _, code := range codes {
		if err := checkRow(code); err != nil {
			return nil, err
		}
		verdict, err := verdictName(code.Verdict)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", code.ID, err)
		}
		fmt.Fprintf(&buf, "| `%s` | %d | `%s` | %s |\n", code.ID, code.Num, verdict, code.Summary)
	}
	return buf.Bytes(), nil
}

// verdictName reports the short form of a declared verdict. An undeclared
// number and VERDICT_UNSPECIFIED are both errors: the first means the registry
// names a verdict the frozen contract does not have, and the second reads as
// "nothing was decided", which no code documents.
func verdictName(verdict controlv1.Verdict) (string, error) {
	name, ok := controlv1.Verdict_name[int32(verdict)]
	if !ok {
		return "", fmt.Errorf("verdict %d is not declared by the v1 contract", int32(verdict))
	}
	if verdict == controlv1.Verdict_VERDICT_UNSPECIFIED {
		return "", errors.New("verdict is UNSPECIFIED, which reads as nothing decided")
	}
	return strings.TrimPrefix(name, verdictPrefix), nil
}

// checkRow refuses a value that would change the shape of the table instead of
// appearing in it, or change what a row says without changing its shape: a
// pipe ends the cell early and a newline ends the row, and both produce a page
// that still renders and no longer says what the registry holds.
//
// Every control character is refused, not the two obvious ones, and so is
// every format character and both Unicode separators. A carriage return renders
// as nothing and travels into evidence as a byte nobody sees; a vertical tab, a
// form feed, NEL and U+2028 are line breaks to some readers and not to others;
// a C1 control can be a command to a terminal; a zero width space or a
// bidirectional override is invisible, or reorders the text around it. A
// summary is a sentence, so none of them has any business in one.
func checkRow(code reasons.Code) error {
	// A slice, not a map: iteration order decides which field a row with two
	// bad cells reports, and the same registry has to produce the same error.
	cells := []struct{ field, value string }{
		{"id", code.ID},
		{"summary", code.Summary},
	}
	for _, cell := range cells {
		// Named by code point: most of these runes cannot be seen, and several
		// are more than one byte long.
		if i := strings.IndexFunc(cell.value, breaksTheRow); i >= 0 {
			r, _ := utf8.DecodeRuneInString(cell.value[i:])
			return fmt.Errorf("%s: %s holds %U at byte %d, which a table row cannot carry",
				code.ID, cell.field, r, i)
		}
	}
	return nil
}

// breaksTheRow reports the characters a cell may not hold: the pipe that ends
// a cell, every control character (C0, DEL and C1), every format character,
// and the line and paragraph separators.
func breaksTheRow(r rune) bool {
	return r == '|' || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}
