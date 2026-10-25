package mcp

import (
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// catalogueAccepts reports whether the catalogue's parameter check passes one
// obligation of typ carrying params.
func catalogueAccepts(typ string, params map[string]string) bool {
	doc := &rules.Document{Rules: []rules.Rule{{ID: "r", Obligations: []rules.Obligation{{Type: typ, Params: params}}}}}
	return rules.CheckObligations(doc) == nil
}

// paramValue draws a value near the edges of the adapter's grammars: any
// string, a signed number around the duration bound, and paths built from
// the pieces a resolver reads differently.
func paramValue() *rapid.Generator[string] {
	piece := rapid.SampledFrom([]string{
		"a", "ord-1", "files", "/", ".", "..", " ", ",", "%", "%2F", ";", "?", "#", "\\", "é", "\x7f", "+", "-", "0", "9",
	})
	return rapid.OneOf(
		rapid.String(),
		rapid.StringMatching(`[+-]?0*[0-9]{1,19}`),
		rapid.SampledFrom([]string{"9223372036854", "9223372036855", "0", "-0", "",
			strings.Repeat("x", 1023) + "/", strings.Repeat("x", 1021) + "/..", strings.Repeat("x", 1020) + "/..", strings.Repeat("x", 1024)}),
		rapid.Custom(func(t *rapid.T) string { return strings.Join(rapid.SliceOfN(piece, 0, 8).Draw(t, "pieces"), "") }),
	)
}

func TestAdapterParametersAreTheCatalogues(t *testing.T) {
	want := map[string][]string{
		obligationReadOnly:          {},
		obligationRestrictResources: {paramIDs, paramPrefix},
		obligationShortenTimeout:    {paramMS},
		obligationDenyExternalSink:  {},
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

// TestRestrictResourcesAppliesWhatTheCatalogueAccepts: every entry of an ids
// value the grammar accepts is a resource id an envelope can carry and the
// applier lets through, and a prefix the grammar accepts, of the spelling and
// length the parser admits, lets through an id an envelope can carry.
func TestRestrictResourcesAppliesWhatTheCatalogueAccepts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ids := paramValue().Draw(t, "ids")
		params := map[string]string{paramIDs: ids}
		if catalogueAccepts(obligationRestrictResources, params) {
			for id := range strings.SplitSeq(ids, ",") {
				if carriable(id) != nil || !resourceAllowed(id, params) {
					t.Fatalf("ids %q: entry %q is accepted and never let through (%v)", ids, id, carriable(id))
				}
			}
		}
		prefix := paramValue().Draw(t, "prefix")
		params = map[string]string{paramPrefix: prefix}
		if carriable(prefix) != nil || !catalogueAccepts(obligationRestrictResources, params) {
			return
		}
		id := prefix + "x"
		if len(prefix) >= contract.MaxStringBytes {
			id = prefix
		}
		if carriable(id) != nil || !resourceAllowed(id, params) {
			t.Fatalf("prefix %q is accepted and does not let %q through (%v)", prefix, id, carriable(id))
		}
	})
}

// carriable is what the contract requires of an envelope's resource id.
func carriable(id string) error {
	if len(id) > contract.MaxStringBytes {
		return contract.ErrInvalidValue
	}
	return contract.CheckIdentifier(id)
}
