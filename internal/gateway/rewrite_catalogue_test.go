package gateway

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
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
		rapid.SampledFrom([]string{
			"9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "",
			"9007199254740991", "9007199254740992", "-9007199254740991", "-9007199254740992",
		}),
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
// applied through the whole rewrite, canonicalization included, to every
// amount canon admits, and one it refuses is refused; the applier caps the
// member any field names, so the grammar accepts every field.
func TestCapAmountAppliesWhatTheCatalogueAccepts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := paramValue().Draw(t, "max")
		amount := rapid.OneOf(
			rapid.Int64Range(-(1<<53-1), 1<<53-1),
			rapid.SampledFrom([]int64{-(1<<53 - 1), 0, 1<<53 - 1}),
		).Draw(t, "amount")
		params := map[string]string{paramMax: v}
		args := []byte(`{"amount":` + strconv.FormatInt(amount, 10) + `}`)
		out, _, err := rewrite(args, []*controlv1.Obligation{{Type: obligationCapAmount, Params: params}})
		accepted := catalogueAccepts(obligationCapAmount, params)
		if accepted != (err == nil) {
			t.Fatalf("max %q, amount %d: the catalogue accepts it %v, the rewrite says %v", v, amount, accepted, err)
		}
		if accepted {
			want := amount
			if limit, _ := strconv.ParseInt(v, 10, 64); limit < amount {
				want = limit
			}
			if got := `{"amount":` + strconv.FormatInt(want, 10) + `}`; string(out) != got {
				t.Fatalf("max %q, amount %d: the rewrite sent %s, want %s", v, amount, out, got)
			}
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

// TestCapAmountMaxStopsAtCanonsSmallestInteger: the smallest max the grammar
// takes is the smallest integer canon writes, so a call capped to it still
// canonicalizes; one below it would deny every call the rule matched.
func TestCapAmountMaxStopsAtCanonsSmallestInteger(t *testing.T) {
	t.Parallel()
	smallest := map[string]string{paramMax: "-9007199254740991"}
	out, _, err := rewrite([]byte(`{"amount":0}`), []*controlv1.Obligation{{Type: obligationCapAmount, Params: smallest}})
	if err != nil || string(out) != `{"amount":-9007199254740991}` || !catalogueAccepts(obligationCapAmount, smallest) {
		t.Errorf("max %s: the rewrite sent %s, %v; the catalogue accepts it %v", smallest[paramMax], out, err, catalogueAccepts(obligationCapAmount, smallest))
	}
	below := map[string]string{paramMax: "-9007199254740992"}
	if _, _, err := rewrite([]byte(`{"amount":0}`), []*controlv1.Obligation{{Type: obligationCapAmount, Params: below}}); err == nil {
		t.Errorf("max %s: the rewrite canonicalized an integer canon refuses", below[paramMax])
	}
	if catalogueAccepts(obligationCapAmount, below) {
		t.Errorf("max %s: the catalogue accepts a max no capped call survives", below[paramMax])
	}
}
