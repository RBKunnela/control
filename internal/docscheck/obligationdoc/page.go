// Package obligationdoc renders the obligation reference page from the
// catalogue internal/policy/rules exports and from who applies each type.
//
// Rendering is a pure function of the catalogue and the appliers. No clock,
// no filesystem: scripts/gen-obligations.go is the thin writer that puts the
// result on disk, and the test that pins the committed page calls Page
// directly.
package obligationdoc

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/docscheck/frontmatter"
	"github.com/guardana/control/internal/policy/rules"
)

// meta is the page's frontmatter: what the documentation checks read to place
// the page, and covers is the code whose change makes it suspect.
var meta = frontmatter.Meta{
	Title:   "Obligations",
	Summary: "The catalogue of obligation types a policy rule may name, the parameters each takes, and what the tree does with one.",
	Type:    "reference",
	Covers: []string{"internal/policy/rules/catalogue.go", "internal/policy/rules/obligations.go", "internal/gateway/rewrite.go",
		"adapters/mcp/obligations.go", "internal/docscheck/obligationdoc/**"},
	Generated: "scripts/gen-obligations.go",
}

// The intro answers one question: what an obligation type on a rule or a
// decision is, and what the tree does with one. Status labels are the
// project's three, and the page points at docs/status.md for the rest.
const header = "\n# Obligations\n" +
	"\n" +
	"An obligation is a condition on a call that proceeds. It travels on a\n" +
	"decision in `Decision.obligations`, under `ALLOW_WITH_OBLIGATIONS` and\n" +
	"under `REQUIRE_APPROVAL` once the approval is given. A policy rule names an\n" +
	"obligation by its type, with string parameters and an `advisory` flag that\n" +
	"is false by default: false means the call proceeds only if the obligation is\n" +
	"applied ([ADR-0011](../adr/0011-contract-corrections-before-publication.md)).\n" +
	"\n" +
	"The table below is the catalogue, the closed set of types a policy document\n" +
	"may name, with the parameters each type takes and who in this build applies\n" +
	"it. Recognising a type is `implemented`: the parser and `policy lint` refuse\n" +
	"a document naming a type outside it, and the kernel refuses a configuration\n" +
	"whose applicable types include one outside it. The gateway rewrites the\n" +
	"arguments for its types before the decision it records, and an adapter\n" +
	"applies the types it declares to the call it sends. A decision carrying a\n" +
	"non-advisory obligation that nothing here applies is `DENY` with\n" +
	"`OBLIGATION_NOT_UNDERSTOOD`, and no fail-open setting relieves that; an\n" +
	"advisory one is skipped.\n" +
	"\n" +
	"Checking parameters is `implemented`: `policy lint`, `policy test`,\n" +
	"`policy sign` and `" + brand.Gateway + " dev` refuse a parameter the type does\n" +
	"not declare, a required one that is missing, and a value outside the\n" +
	"grammar its row states\n" +
	"([ADR-0061](../adr/0061-an-obligations-parameters-are-the-catalogues.md)).\n" +
	"A type nothing in this build applies takes no parameters. The first two\n" +
	"refusals read\n" +
	"`rules: a parameter the obligation's type does not declare or requires`,\n" +
	"at `rules[0].obligations[0].params[1].key` for a key or at\n" +
	"`rules[0].obligations[0].params` for one missing, and the third\n" +
	"`rules: a parameter value the obligation's type cannot apply`, at\n" +
	"`rules[0].obligations[0].params[0]`: a parameter is named by its position in\n" +
	"sorted key order, never by its key or value. `policy explain` and loading a\n" +
	"bundle do not check parameters, so a bundle signed elsewhere still loads and\n" +
	"is explained. Its applier reads only the parameters the type declares and\n" +
	"parses each value itself, and an obligation it cannot apply as written is\n" +
	"not applied: a non-advisory one stops the call and an advisory one is\n" +
	"skipped. What is built and what is not is in [status.md](../status.md).\n" +
	"\n" +
	"Rendered from the catalogue in `internal/policy/rules/catalogue.go` and the\n" +
	"types the gateway and the MCP adapter declare. Rebuild it with\n" +
	"`make docs-gen`; an edit made here does not survive the next run.\n" +
	"\n" +
	"| Type | Applied by | Parameter | Required | Value |\n" +
	"| --- | --- | --- | --- | --- |\n"

// unapplied is the cell of a type nothing in this build applies.
const unapplied = "`planned`: nothing in this build"

// Page renders the reference page from the catalogue and from appliers: one
// row for each parameter of a type, or one row saying none, each naming every
// applier that declares the type. It builds the page in memory, so a
// catalogue it refuses leaves the previous page on disk rather than
// truncating it.
func Page(specs []rules.ObligationSpec, appliers []Applier) ([]byte, error) {
	if err := checkSpecs(specs); err != nil {
		return nil, err
	}
	if err := checkAppliers(specs, appliers); err != nil {
		return nil, err
	}
	front, err := frontmatter.Render(meta)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(front)
	buf.WriteString(header)
	for _, s := range specs {
		by := appliedBy(s.Type, appliers)
		if len(s.Params) == 0 {
			fmt.Fprintf(&buf, "| `%s` | %s | none |  |  |\n", s.Type, by)
			continue
		}
		for _, p := range s.Params {
			fmt.Fprintf(&buf, "| `%s` | %s | `%s` | %s | %s |\n", s.Type, by, p.Name, required(s, p), p.Grammar.Describe())
		}
	}
	return buf.Bytes(), nil
}

// required is the Required cell of one parameter.
func required(s rules.ObligationSpec, p rules.Param) string {
	if slices.Contains(s.OneOf, p.Name) {
		names := make([]string, len(s.OneOf))
		for i, n := range s.OneOf {
			names[i] = "`" + n + "`"
		}
		return "one of " + strings.Join(names, ", ")
	}
	if p.Required {
		return "yes"
	}
	return "no"
}

// checkSpecs refuses a catalogue the page could not state truthfully: none
// at all, a type twice, a name a cell in code font cannot carry, a parameter
// twice or with no grammar to describe, and a grammar whose description would
// break the row.
func checkSpecs(specs []rules.ObligationSpec) error {
	if len(specs) == 0 {
		return errors.New("the catalogue is empty; refusing to render a page listing no types")
	}
	for i, s := range specs {
		if err := checkName(s.Type); err != nil {
			return fmt.Errorf("type %d: %w", i, err)
		}
		if slices.ContainsFunc(specs[:i], func(o rules.ObligationSpec) bool { return o.Type == s.Type }) {
			return fmt.Errorf("%q is in the catalogue twice", s.Type)
		}
		if err := checkParams(s); err != nil {
			return err
		}
	}
	return nil
}

func checkParams(s rules.ObligationSpec) error {
	for j, p := range s.Params {
		if err := checkName(p.Name); err != nil {
			return fmt.Errorf("%s: parameter %d: %w", s.Type, j, err)
		}
		if slices.ContainsFunc(s.Params[:j], func(o rules.Param) bool { return o.Name == p.Name }) {
			return fmt.Errorf("%s: parameter %q twice", s.Type, p.Name)
		}
		value := p.Grammar.Describe()
		if value == "" {
			return fmt.Errorf("%s: parameter %q has no grammar", s.Type, p.Name)
		}
		if strings.ContainsRune(value, '|') || strings.IndexFunc(value, breaksALine) >= 0 {
			return fmt.Errorf("%s: parameter %q: its grammar's description cannot sit in a row", s.Type, p.Name)
		}
	}
	for _, n := range s.OneOf {
		if !slices.ContainsFunc(s.Params, func(p rules.Param) bool { return p.Name == n }) {
			return fmt.Errorf("%s: one of names %q, which it does not declare", s.Type, n)
		}
	}
	return nil
}

// checkName refuses a name a table cell in code font cannot carry as it is:
// the pipe that ends the cell, the backtick that ends the code span, and
// every control, format or separator character, which is invisible or a
// line break to some readers.
func checkName(name string) error {
	if name == "" {
		return errors.New("an empty name")
	}
	if i := strings.IndexFunc(name, func(r rune) bool { return r == '|' || r == '`' || breaksALine(r) }); i >= 0 {
		return fmt.Errorf("%q holds %U at byte %d, which a table row cannot carry", name, []rune(name[i:])[0], i)
	}
	return nil
}

func breaksALine(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}

// appliedBy is the cell of one type: every applier that declares it, in the
// order given, or the planned label when none does.
func appliedBy(name string, appliers []Applier) string {
	var by []string
	for _, a := range appliers {
		if slices.Contains(a.Types, name) {
			by = append(by, a.Name)
		}
	}
	if len(by) == 0 {
		return unapplied
	}
	return strings.Join(by, ", ")
}
