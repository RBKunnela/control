package mcp

import (
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/guardana/control/internal/policy/rules"
)

// catalogueAccepts reports whether the catalogue's parameter check passes one
// obligation of typ carrying params.
func catalogueAccepts(typ string, params map[string]string) bool {
	doc := &rules.Document{Rules: []rules.Rule{{ID: "r", Obligations: []rules.Obligation{{Type: typ, Params: params}}}}}
	return rules.CheckObligations(doc) == nil
}

// edgeValues sit at the grammar's bounds: the neighbours of the duration
// bound and the empty value.
var edgeValues = []string{"9223372036854", "9223372036855", "0", "-0", ""}

// paramValue draws a value near the edges of the adapter's grammar: any
// string, a signed number around the duration bound, the edge values, and
// strings built from pieces a number reader treats differently.
func paramValue() *rapid.Generator[string] {
	piece := rapid.SampledFrom([]string{
		"a", "ord-1", "files", "/", ".", "..", " ", ",", "%", "%2F", ";", "?", "#", "\\", "é", "\x7f", "+", "-", "0", "9",
	})
	return rapid.OneOf(
		rapid.String(),
		rapid.StringMatching(`[+-]?0*[0-9]{1,19}`),
		rapid.SampledFrom(edgeValues),
		rapid.Custom(func(t *rapid.T) string { return strings.Join(rapid.SliceOfN(piece, 0, 8).Draw(t, "pieces"), "") }),
	)
}

func TestAdapterParametersAreTheCatalogues(t *testing.T) {
	want := map[string][]string{
		obligationShortenTimeout: {paramMS},
	}
	for _, typ := range applies {
		if got, ok := rules.ParamNames(typ); !ok || !slices.Equal(got, want[typ]) {
			t.Errorf("%s: the catalogue declares %v, %v; the adapter reads %v", typ, got, ok, want[typ])
		}
	}
	if len(applies) != len(want) {
		t.Errorf("the adapter applies %v; the table above covers %d types", applies, len(want))
	}
}

// TestShortenAppliesExactlyWhatTheCatalogueAccepts: an ms the grammar
// accepts sets the timeout, and one it refuses is refused by the applier too.
func TestShortenAppliesExactlyWhatTheCatalogueAccepts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := paramValue().Draw(t, "ms")
		params := map[string]string{paramMS: v}
		var out applied
		err := shorten(params, &out)
		if accepted := catalogueAccepts(obligationShortenTimeout, params); accepted != (err == nil) {
			t.Fatalf("ms %q: the catalogue accepts it %v, the applier says %v", v, accepted, err)
		}
		if err == nil && out.timeout <= 0 {
			t.Fatalf("ms %q: applied as timeout %v", v, out.timeout)
		}
	})
}
