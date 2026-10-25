package gateway

import (
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/rules"
)

// catalogueAccepts reports whether the catalogue's parameter check passes one
// obligation of typ carrying params.
func catalogueAccepts(typ string, params map[string]string) bool {
	doc := &rules.Document{Rules: []rules.Rule{{ID: "r", Obligations: []rules.Obligation{{Type: typ, Params: params}}}}}
	return rules.CheckObligations(doc) == nil
}

// paramValue draws a value near the edges of the gateway's grammars: any
// string, a signed number around the int64 bounds, and member-name lists
// built from pieces each grammar treats differently.
func paramValue() *rapid.Generator[string] {
	piece := rapid.SampledFrom([]string{"a", "ssn", "amount", "é", "K", ".", "/", " ", "\t", " ", ",", "+", "-", "0", "1", "9"})
	return rapid.OneOf(
		rapid.String(),
		rapid.StringMatching(`[+-]?0*[0-9]{1,19}`),
		rapid.SampledFrom([]string{"9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", ""}),
		rapid.Custom(func(t *rapid.T) string { return strings.Join(rapid.SliceOfN(piece, 0, 6).Draw(t, "pieces"), "") }),
	)
}

func TestGatewayParametersAreTheCatalogues(t *testing.T) {
	for typ, want := range map[string][]string{
		obligationRedactFields: {paramFields},
		obligationCapAmount:    {paramMax, paramField},
	} {
		if got, ok := rules.ParamNames(typ); !ok || !slices.Equal(got, want) {
			t.Errorf("%s: the catalogue declares %v, %v; the gateway reads %v", typ, got, ok, want)
		}
	}
	if len(rewriting) != 2 {
		t.Errorf("the gateway rewrites %v; the test above covers two types", rewriting)
	}
}

// TestRedactFieldsAppliesExactlyWhatTheCatalogueAccepts: a fields value the
// grammar accepts is applied, removing every member it names, and one it
// refuses is refused by the applier too.
func TestRedactFieldsAppliesExactlyWhatTheCatalogueAccepts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := paramValue().Draw(t, "fields")
		params := map[string]string{paramFields: v}
		doc := map[string]any{"keep": int64(1)}
		for name := range strings.SplitSeq(v, ",") {
			doc[name] = int64(2)
		}
		err := redactFields(doc, params)
		accepted := catalogueAccepts(obligationRedactFields, params)
		if accepted != (err == nil) {
			t.Fatalf("fields %q: the catalogue accepts it %v, the applier says %v", v, accepted, err)
		}
		if !accepted {
			return
		}
		for name := range strings.SplitSeq(v, ",") {
			for key := range doc {
				if canon.FoldKey(key) == canon.FoldKey(name) {
					t.Fatalf("fields %q: member %q is still there", v, key)
				}
			}
		}
	})
}

// TestCapAmountAppliesWhatTheCatalogueAccepts: a max the grammar accepts is
// applied and one it refuses is refused; the applier caps the member any field
// names, so the grammar accepts every field.
func TestCapAmountAppliesWhatTheCatalogueAccepts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := paramValue().Draw(t, "max")
		params := map[string]string{paramMax: v}
		err := capAmount(map[string]any{"amount": int64(7)}, params)
		if accepted := catalogueAccepts(obligationCapAmount, params); accepted != (err == nil) {
			t.Fatalf("max %q: the catalogue accepts it %v, the applier says %v", v, accepted, err)
		}
		field := paramValue().Draw(t, "field")
		params = map[string]string{paramMax: "1", paramField: field}
		doc := map[string]any{field: int64(7)}
		if err := capAmount(doc, params); err != nil || doc[field] != int64(1) {
			t.Fatalf("field %q: the applier says %v and left %v", field, err, doc[field])
		}
		if !catalogueAccepts(obligationCapAmount, params) {
			t.Fatalf("field %q: the applier caps the member it names and the catalogue refuses it", field)
		}
	})
}
