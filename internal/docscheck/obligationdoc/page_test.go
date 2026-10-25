package obligationdoc

import (
	"strings"
	"testing"

	"github.com/guardana/control/internal/policy/rules"
)

// specs is a small catalogue: a type with a required and an optional
// parameter, one with a set of which one is required, and one with none.
func specs() []rules.ObligationSpec {
	return []rules.ObligationSpec{
		{Type: "cap_amount", Params: []rules.Param{
			{Name: "max", Required: true, Grammar: rules.GrammarInteger},
			{Name: "field", Grammar: rules.GrammarMemberName},
		}},
		{Type: "restrict_resources", Params: []rules.Param{
			{Name: "ids", Grammar: rules.GrammarIdentifiers},
			{Name: "prefix", Grammar: rules.GrammarResourcePrefix},
		}, OneOf: []string{"ids", "prefix"}},
		{Type: "emit_alert"},
	}
}

// appliers apply every type of specs that declares parameters.
func appliers() []Applier {
	return []Applier{
		{Name: "the gateway", Types: []string{"cap_amount"}},
		{Name: "the adapter", Types: []string{"cap_amount", "restrict_resources"}},
	}
}

func TestPageOneRowPerParameterInOrder(t *testing.T) {
	page, err := Page(specs(), appliers())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	text := string(page)
	rows := []string{
		"| `cap_amount` | the gateway, the adapter | `max` | yes | a base-10 integer from -9007199254740991 to 9223372036854775807, with an optional sign |\n",
		"| `cap_amount` | the gateway, the adapter | `field` | no | the exact name of one top-level member |\n",
		"| `restrict_resources` | the adapter | `ids` | one of `ids`, `prefix` | comma-separated resource ids, none empty and each one the identifier rule admits |\n",
		"| `restrict_resources` | the adapter | `prefix` | one of `ids`, `prefix` | an identifier whose last `/`-separated segment is printable ASCII without `%`, `;`, `?`, `#` or `\\` |\n",
		"| `emit_alert` | " + unapplied + " | none |  |  |\n",
	}
	last := -1
	for _, row := range rows {
		at := strings.Index(text, row)
		if at < 0 {
			t.Fatalf("page has no row %q:\n%s", row, text)
		}
		if at < last {
			t.Errorf("row %q is out of the catalogue's order", row)
		}
		last = at
	}
	if got := strings.Count(text, "\n| `"); got != len(rows) {
		t.Errorf("page holds %d rows, want %d", got, len(rows))
	}
	for _, label := range []string{"`implemented`", "`planned`"} {
		if !strings.Contains(text, label) {
			t.Errorf("page has no %s label", label)
		}
	}
	if !strings.HasSuffix(text, "|\n") {
		t.Errorf("page does not end in the last row's newline: %q", text[max(0, len(text)-20):])
	}
}

func TestPageIsDeterministic(t *testing.T) {
	first, err := Page(specs(), appliers())
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	second, err := Page(specs(), appliers())
	if err != nil {
		t.Fatalf("Page, second call: %v", err)
	}
	if string(first) != string(second) {
		t.Error("two calls to Page produced different bytes")
	}
}

// A page that listed an applier for a type the catalogue lacks would state a
// capability the kernel refuses at start, and a row the table cannot carry
// would state something else; the renderer refuses both first.
func TestPageRefusesWhatItCannotState(t *testing.T) {
	with := func(edit func([]rules.ObligationSpec) []rules.ObligationSpec) []rules.ObligationSpec {
		return edit(specs())
	}
	for name, tc := range map[string]struct {
		specs    []rules.ObligationSpec
		appliers []Applier
	}{
		"an empty catalogue": {nil, appliers()},
		"a type twice": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			return append(s, rules.ObligationSpec{Type: "emit_alert"})
		}), appliers()},
		"an empty type":    {with(func(s []rules.ObligationSpec) []rules.ObligationSpec { s[2].Type = ""; return s }), appliers()},
		"a pipe in a type": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec { s[2].Type = "a|b"; return s }), appliers()},
		"a backtick in a type": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			s[2].Type = "a`b"
			return s
		}), appliers()},
		"a control character in a type": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			s[2].Type = "a\nb"
			return s
		}), appliers()},
		"a parameter a cell cannot carry": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			s[0].Params[1].Name = "a|b"
			return s
		}), appliers()},
		"a parameter twice": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			s[0].Params[1].Name = "max"
			return s
		}), appliers()},
		"a parameter with no grammar": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			s[0].Params[1].Grammar = 0
			return s
		}), appliers()},
		"one of an undeclared parameter": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			s[1].OneOf = []string{"ids", "path"}
			return s
		}), appliers()},
		"parameters on a type nothing applies": {with(func(s []rules.ObligationSpec) []rules.ObligationSpec {
			s[2].Params = []rules.Param{{Name: "per_minute", Grammar: rules.GrammarInteger}}
			return s
		}), appliers()},
		"an applier of a type outside the catalogue": {specs(), []Applier{{Name: "the adapter", Types: []string{"cap_rate"}}}},
		"an applier with no name":                    {specs(), []Applier{{Types: []string{"cap_amount"}}}},
		"an applier name a cell cannot carry":        {specs(), []Applier{{Name: "a|b", Types: []string{"cap_amount"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			page, err := Page(tc.specs, tc.appliers)
			if err == nil {
				t.Fatalf("Page accepted the catalogue and returned %d bytes", len(page))
			}
			if page != nil {
				t.Errorf("%d bytes beside the error", len(page))
			}
		})
	}
}

// Appliers reads each applier's own declaration; an empty one would render
// every type as planned and still pin.
func TestAppliersDeclareSomething(t *testing.T) {
	for _, a := range Appliers() {
		if len(a.Types) == 0 {
			t.Errorf("%s declares no obligation type", a.Name)
		}
	}
}
