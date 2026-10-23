package classify_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/guardana/control/internal/classify"
)

// FuzzParse holds Parse to its contract over spellings nobody chose: an
// accepted spelling is a classification Check accepts, each enum spelled as
// one of the listed names or left empty, and a refusal is the zero
// classification beside an *Error naming one of the six keys.
func FuzzParse(f *testing.F) {
	for _, seed := range []classify.Spelling{
		{Effect: "READ", ResourceType: "order"},
		{Effect: "WRITE", ResourceType: "order", ResourceFrom: "/id", TrustZone: "PARTNER", ReturnsTrust: "TRUSTED_INTERNAL", ReturnsSensitivity: "SECRET"},
		{Effect: "COMMUNICATE", ResourceType: "mailbox", ResourceFrom: "/to"},
		{Effect: "UNSPECIFIED", ResourceType: "order"},
		{Effect: "READ", ResourceType: " order", ResourceFrom: "/a~2", TrustZone: "UNSPECIFIED"},
	} {
		f.Add(seed.Effect, seed.ResourceType, seed.ResourceFrom, seed.TrustZone, seed.ReturnsTrust, seed.ReturnsSensitivity)
	}
	keys := []string{"effect", "resource_type", "resource_from", "trust_zone", "returns.trust", "returns.sensitivity"}
	f.Fuzz(func(t *testing.T, effect, resourceType, resourceFrom, zone, returnsZone, returnsLevel string) {
		s := classify.Spelling{Effect: effect, ResourceType: resourceType, ResourceFrom: resourceFrom,
			TrustZone: zone, ReturnsTrust: returnsZone, ReturnsSensitivity: returnsLevel}
		c, err := classify.Parse(s)
		if err != nil {
			var ce *classify.Error
			if !errors.As(err, &ce) || !slices.Contains(keys, ce.Key) {
				t.Fatalf("Parse(%+v) = %v, not an *Error naming a key", s, err)
			}
			if c != (classify.Classification{}) {
				t.Fatalf("Parse(%+v) refused and returned %+v", s, c)
			}
			return
		}
		if err := c.Check(); err != nil {
			t.Fatalf("Parse(%+v) = %+v, which Check refuses: %v", s, c, err)
		}
		for _, e := range []struct {
			spelled string
			names   []string
		}{
			{effect, classify.EffectNames()},
			{zone, append(classify.ZoneNames(), "")},
			{returnsZone, append(classify.ZoneNames(), "")},
			{returnsLevel, append(classify.SensitivityNames(), "")},
		} {
			if !slices.Contains(e.names, e.spelled) {
				t.Fatalf("Parse(%+v) accepted %q, which is not a listed spelling", s, e.spelled)
			}
		}
	})
}
