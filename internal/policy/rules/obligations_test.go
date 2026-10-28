package rules

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// paramsWant is each type's parameters, written out in the catalogue's order.
// The five types nothing applies take none.
var paramsWant = map[string][]string{
	"redact_fields":           {"fields"},
	"read_only":               {},
	"restrict_resources":      {"ids", "prefix"},
	"require_idempotency_key": {},
	"cap_amount":              {"max", "field"},
	"cap_rate":                {},
	"require_sandbox":         {},
	"second_approver":         {},
	"emit_alert":              {},
	"shorten_timeout":         {"ms"},
	"deny_external_sink":      {},
}

// checkSpecs refuses a catalogue a reader could not hold an obligation to: a
// parameter with no grammar or with a name twice, and a OneOf name the type
// does not declare.
func checkSpecs(specs []ObligationSpec) error {
	for _, s := range specs {
		for i, p := range s.Params {
			if p.Grammar.Describe() == "" {
				return fmt.Errorf("%s.%s carries no grammar", s.Type, p.Name)
			}
			if slices.ContainsFunc(s.Params[:i], func(q Param) bool { return q.Name == p.Name }) {
				return fmt.Errorf("%s declares %s twice", s.Type, p.Name)
			}
		}
		for _, name := range s.OneOf {
			if !slices.ContainsFunc(s.Params, func(q Param) bool { return q.Name == name && !q.Required }) {
				return fmt.Errorf("%s: OneOf names %s, which it does not declare as optional", s.Type, name)
			}
		}
	}
	return nil
}

func TestCatalogueDeclaresEveryParameterWithAGrammar(t *testing.T) {
	t.Parallel()
	if err := checkSpecs(Obligations()); err != nil {
		t.Fatal(err)
	}
	for name, specs := range map[string][]ObligationSpec{
		"no grammar":     {{Type: "x", Params: []Param{{Name: "a"}}}},
		"a name twice":   {{Type: "x", Params: []Param{{Name: "a", Grammar: GrammarInteger}, {Name: "a", Grammar: GrammarInteger}}}},
		"an unknown one": {{Type: "x", Params: []Param{{Name: "a", Grammar: GrammarInteger}}, OneOf: []string{"b"}}},
		"a required one": {{Type: "x", Params: []Param{{Name: "a", Required: true, Grammar: GrammarInteger}}, OneOf: []string{"a"}}},
	} {
		if checkSpecs(specs) == nil {
			t.Errorf("%s: the catalogue check accepted %+v", name, specs)
		}
	}
}

func TestObligationsListTheCatalogueAndCopy(t *testing.T) {
	t.Parallel()
	specs := Obligations()
	if len(specs) != len(catalogueWant) {
		t.Fatalf("Obligations holds %d types, want %d", len(specs), len(catalogueWant))
	}
	for i, s := range specs {
		if s.Type != catalogueWant[i] {
			t.Errorf("Obligations()[%d] = %s, want %s", i, s.Type, catalogueWant[i])
		}
	}
	specs[0].Type = "changed"
	specs[2].Params[0].Name = "changed"
	specs[2].OneOf[0] = "changed"
	again := Obligations()
	if again[0].Type != "redact_fields" || again[2].Params[0].Name != "ids" || again[2].OneOf[0] != "ids" {
		t.Errorf("a change to one result reached the next: %+v", again[:3])
	}
}

func TestParamNamesAreTheCatalogues(t *testing.T) {
	t.Parallel()
	for _, typ := range catalogueWant {
		got, ok := ParamNames(typ)
		if !ok || got == nil || !slices.Equal(got, paramsWant[typ]) {
			t.Errorf("ParamNames(%s) = %v, %v; want %v, true", typ, got, ok, paramsWant[typ])
		}
	}
	for _, near := range []string{"", "Cap_amount", "cap_amount ", "per_minute"} {
		if got, ok := ParamNames(near); ok || got != nil {
			t.Errorf("ParamNames(%q) = %v, %v; want nil, false", near, got, ok)
		}
	}
	got, _ := ParamNames("cap_amount")
	got[0] = "changed"
	if again, _ := ParamNames("cap_amount"); again[0] != "max" {
		t.Errorf("a change to one result reached the next: %v", again)
	}
}

// grammarCases holds each grammar at the values on either side of each of
// its rules.
var grammarCases = []struct {
	g       Grammar
	accept  []string
	refuses []string
}{
	{GrammarMemberNames,
		[]string{"ssn", "ssn,id", "é", "a-b_c", "A"},
		[]string{"", ",", "ssn,", ",ssn", "a,,b", "a.b", "a/b", "a b", "a\tb", "a" + noBreakSpace + "b", "a" + lineSeparator}},
	{GrammarMemberName,
		[]string{"amount", "", "a.b", "a b", "é"},
		nil},
	{GrammarInteger,
		[]string{"0", "10000", "-1", "+1", "007", "9223372036854775807", "-9007199254740991"},
		[]string{"", " 1", "1 ", "1.5", "1e3", "0x10", "1_000", "9223372036854775808", "-9007199254740992", "-9223372036854775808", "-9223372036854775809", "+", "-"}},
	{GrammarIdentifiers,
		[]string{"ord-1", "ord-1,ord-2", "a b", strings.Repeat("x", 1024)},
		[]string{"", ",", "a,", ",a", "a,,b", "a, b", "a ,b", "a," + zeroWidthSpace, strings.Repeat("x", 1025)}},
	{GrammarResourcePrefix,
		[]string{"files/", "a", "a%2F/b", "a;b/c", "a/%/b", "a/..", "a/ x", strings.Repeat("x", 1023) + "/", strings.Repeat("x", 1020) + "/..", strings.Repeat("x", 1022) + "/a"},
		[]string{"", "a%", "a/b;", "a/b?", "a/b#", "a/b\\", "a/é", "a/\x7f", "é", strings.Repeat("x", 1021) + "/..", strings.Repeat("x", 1020) + "/. .",
			"a/" + strings.Repeat("x", 1019) + "/..",
			strings.Repeat("x", 1025), strings.Repeat("x", 2000), "a\x01b/c", " a/b", "a/b" + zeroWidthSpace + "/c"}},
	{GrammarMilliseconds,
		[]string{"1", "500", "+5", "0005", "9223372036854"},
		[]string{"", "0", "-1", "-0", "1.5", "9223372036855", "9223372036854775807", " 5", "5ms"}},
}

func TestGrammarsAtTheirEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range grammarCases {
		for _, s := range tc.accept {
			if !tc.g.accepts(s) {
				t.Errorf("grammar %d refused %q", tc.g, s)
			}
		}
		for _, s := range tc.refuses {
			if tc.g.accepts(s) {
				t.Errorf("grammar %d accepted %q", tc.g, s)
			}
		}
	}
	for _, g := range []Grammar{0, GrammarMilliseconds + 1, 255} {
		if g.Describe() != "" || g.accepts("1") || g.accepts("") {
			t.Errorf("Grammar(%d) is no grammar and describes %q or accepts a value", g, g.Describe())
		}
	}
}

// obliged is a document whose one rule carries obligations.
func obliged(obligations string) string {
	return docWithRules(`{"id":"r","effect":"REQUIRE_APPROVAL","obligations":[` + obligations + `],"when":{"action":{"name":["refund"]}}}`)
}

// checkParsed parses doc, which must parse, and returns what CheckObligations
// says of it.
func checkParsed(t *testing.T, doc string) error {
	t.Helper()
	return CheckObligations(expectAccepted(t, doc))
}

func expectParamRefusal(t *testing.T, doc string, want refusal) {
	t.Helper()
	err := checkParsed(t, doc)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("CheckObligations = %v (%T), want an *Error wrapping %v", err, err, want.err)
	}
	matched := 0
	for _, s := range sentinels {
		if errors.Is(err, s) {
			matched++
		}
	}
	if !errors.Is(err, want.err) || matched != 1 || e.Field != want.field || e.Rule != want.rule {
		t.Fatalf("refusal {Rule %q, Field %q, Err %v} (%d sentinels), want {Rule %q, Field %q, Err %v}",
			e.Rule, e.Field, e.Err, matched, want.rule, want.field, want.err)
	}
}

// TestCheckObligationsRefusals: each refusal beside the twin it differs from
// by one parameter, which the check accepts.
func TestCheckObligationsRefusals(t *testing.T) {
	t.Parallel()
	const key0, val0, params = "rules[0].obligations[0].params[0].key", "rules[0].obligations[0].params[0]", "rules[0].obligations[0].params"
	cases := []struct {
		name, refused, twin string
		want                refusal
	}{
		{"an undeclared parameter", `{"type":"cap_amount","params":{"currency":"EUR","max":"1"}}`, `{"type":"cap_amount","params":{"field":"EUR","max":"1"}}`,
			refusal{ErrObligationParam, key0, "r"}},
		{"a case variant of a declared one", `{"type":"cap_amount","params":{"Max":"1"}}`, `{"type":"cap_amount","params":{"max":"1"}}`,
			refusal{ErrObligationParam, key0, "r"}},
		{"a parameter on read_only", `{"type":"read_only","params":{"x":"1"}}`, `{"type":"read_only"}`,
			refusal{ErrObligationParam, key0, "r"}},
		{"a parameter on a type nothing applies", `{"type":"cap_rate","params":{"per_minute":"60"},"advisory":true}`, `{"type":"cap_rate","advisory":true}`,
			refusal{ErrObligationParam, key0, "r"}},
		{"an empty value on a type with none", `{"type":"emit_alert","params":{"channel":""}}`, `{"type":"emit_alert"}`,
			refusal{ErrObligationParam, key0, "r"}},
		{"max missing", `{"type":"cap_amount","params":{"field":"total"}}`, `{"type":"cap_amount","params":{"field":"total","max":"5"}}`,
			refusal{ErrObligationParam, params, "r"}},
		{"max missing, no params", `{"type":"cap_amount"}`, `{"type":"cap_amount","params":{"max":"5"}}`,
			refusal{ErrObligationParam, params, "r"}},
		{"fields missing", `{"type":"redact_fields"}`, `{"type":"redact_fields","params":{"fields":"ssn"}}`,
			refusal{ErrObligationParam, params, "r"}},
		{"ms missing", `{"type":"shorten_timeout"}`, `{"type":"shorten_timeout","params":{"ms":"1"}}`,
			refusal{ErrObligationParam, params, "r"}},
		{"restrict_resources with neither", `{"type":"restrict_resources"}`, `{"type":"restrict_resources","params":{"prefix":"files/"}}`,
			refusal{ErrObligationParam, params, "r"}},
		{"a bad ms", `{"type":"shorten_timeout","params":{"ms":"0"}}`, `{"type":"shorten_timeout","params":{"ms":"1"}}`,
			refusal{ErrObligationValue, val0, "r"}},
		{"ms past a duration", `{"type":"shorten_timeout","params":{"ms":"9223372036855"}}`, `{"type":"shorten_timeout","params":{"ms":"9223372036854"}}`,
			refusal{ErrObligationValue, val0, "r"}},
		{"max not an integer", `{"type":"cap_amount","params":{"max":"10.5"}}`, `{"type":"cap_amount","params":{"max":"10"}}`,
			refusal{ErrObligationValue, val0, "r"}},
		{"a path in fields", `{"type":"redact_fields","params":{"fields":"a.b"}}`, `{"type":"redact_fields","params":{"fields":"a,b"}}`,
			refusal{ErrObligationValue, val0, "r"}},
		{"an empty id", `{"type":"restrict_resources","params":{"ids":"a,,b"}}`, `{"type":"restrict_resources","params":{"ids":"a,b"}}`,
			refusal{ErrObligationValue, val0, "r"}},
		{"an empty prefix beside ids", `{"type":"restrict_resources","params":{"ids":"a","prefix":""}}`, `{"type":"restrict_resources","params":{"ids":"a","prefix":"b"}}`,
			refusal{ErrObligationValue, "rules[0].obligations[0].params[1]", "r"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expectParamRefusal(t, obliged(tc.refused), tc.want)
			if err := checkParsed(t, obliged(tc.twin)); err != nil {
				t.Fatalf("the twin was refused: %v", err)
			}
		})
	}
}

// TestCheckObligationsNamesTheFirstInDocumentOrder: the refusal is the first
// one, in rule order then obligation order, under the rule's id.
func TestCheckObligationsNamesTheFirstInDocumentOrder(t *testing.T) {
	t.Parallel()
	first := `{"id":"a","effect":"REQUIRE_APPROVAL","obligations":[{"type":"read_only"}],"when":{"action":{"name":["x"]}}}`
	second := `{"id":"b","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"read_only"},{"type":"shorten_timeout","params":{"ms":"x"}},{"type":"cap_rate","params":{"n":"1"}}],"when":{"action":{"name":["y"]}}}`
	expectParamRefusal(t, docWithRules(first, second), refusal{ErrObligationValue, "rules[1].obligations[1].params[0]", "b"})
}

func TestCheckObligationsRefusesNoDocument(t *testing.T) {
	t.Parallel()
	if err := CheckObligations(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("CheckObligations(nil) = %v, want ErrEmpty", err)
	}
}

// TestCheckObligationsLeavesParseAlone: a document CheckObligations refuses
// still parses, so a bundle signed without the check still loads.
func TestCheckObligationsLeavesParseAlone(t *testing.T) {
	t.Parallel()
	doc := obliged(`{"type":"cap_amount","params":{"currency":"EUR","max":"1"}}`)
	if _, _, err := Parse([]byte(doc)); err != nil {
		t.Fatalf("Parse refused what only the parameter check refuses: %v", err)
	}
}

// TestSampleDocumentsPassTheParameterCheck: the samples Sign signs in other
// packages' tests are documents an author could sign.
func TestSampleDocumentsPassTheParameterCheck(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"example.json", "every-field.json"} {
		doc, _, err := Parse(sampleDocument(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := CheckObligations(doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
