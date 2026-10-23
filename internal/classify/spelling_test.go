package classify_test

import (
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
)

// The spellings as the contract's names read without their prefixes, written
// out rather than read from the descriptor the package reads.
var (
	wantEffects       = []string{"READ", "WRITE", "DELETE", "EXECUTE", "COMMUNICATE", "TRANSACT", "IDENTITY_OR_ACCESS", "CONFIGURE", "SPAWN_OR_DELEGATE"}
	wantZones         = []string{"TRUSTED_INTERNAL", "PARTNER", "UNTRUSTED_EXTERNAL", "USER_CONTROLLED", "MODEL_GENERATED"}
	wantSensitivities = []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"}
)

func TestTheNamesAreTheContractsInItsOrder(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want []string
	}{
		{"EffectNames", classify.EffectNames(), wantEffects},
		{"ZoneNames", classify.ZoneNames(), wantZones},
		{"SensitivityNames", classify.SensitivityNames(), wantSensitivities},
	} {
		if !slices.Equal(tc.got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	classify.ZoneNames()[0] = "EDITED"
	if classify.ZoneNames()[0] != wantZones[0] {
		t.Error("an edit of one list reached the next")
	}
}

func TestParseReadsEverySpelling(t *testing.T) {
	for i, effect := range wantEffects {
		for j, zone := range wantZones {
			s := classify.Spelling{Effect: effect, ResourceType: "order", ResourceFrom: "/id", TrustZone: zone,
				ReturnsTrust: zone, ReturnsSensitivity: wantSensitivities[j]}
			c, err := classify.Parse(s)
			if err != nil {
				t.Errorf("Parse(%+v) = %v", s, err)
				continue
			}
			want := classify.Classification{
				Effect: controlv1.EffectClass(i + 1), ResourceType: "order", ResourceFrom: "/id",
				TrustZone: controlv1.TrustZone(j + 1), ReturnsTrust: controlv1.TrustZone(j + 1), ReturnsSensitivity: controlv1.Sensitivity(j + 1),
			}
			if c != want {
				t.Errorf("Parse(%+v) = %+v, want %+v", s, c, want)
			}
		}
	}
	c, err := classify.Parse(classify.Spelling{Effect: "READ", ResourceType: "order"})
	if err != nil || c != (classify.Classification{Effect: effectRead, ResourceType: "order"}) {
		t.Errorf("the empty zones: %+v, %v", c, err)
	}
}

func TestParseRefusesASpellingTheContractDoesNotHave(t *testing.T) {
	base := classify.Spelling{Effect: "WRITE", ResourceType: "order", ResourceFrom: "/id", TrustZone: "PARTNER"}
	for name, tc := range map[string]struct {
		edit func(*classify.Spelling)
		key  string
		want error
	}{
		"no effect":                      {func(s *classify.Spelling) { s.Effect = "" }, "effect", classify.ErrEffect},
		"the zero effect":                {func(s *classify.Spelling) { s.Effect = "UNSPECIFIED" }, "effect", classify.ErrEffect},
		"a prefixed effect":              {func(s *classify.Spelling) { s.Effect = "EFFECT_CLASS_WRITE" }, "effect", classify.ErrEffect},
		"a lower-case effect":            {func(s *classify.Spelling) { s.Effect = "write" }, "effect", classify.ErrEffect},
		"the zero zone":                  {func(s *classify.Spelling) { s.TrustZone = "UNSPECIFIED" }, "trust_zone", classify.ErrEnum},
		"a prefixed zone":                {func(s *classify.Spelling) { s.TrustZone = "TRUST_ZONE_PARTNER" }, "trust_zone", classify.ErrEnum},
		"the zero returned zone":         {func(s *classify.Spelling) { s.ReturnsTrust = "UNSPECIFIED" }, "returns.trust", classify.ErrEnum},
		"a sensitivity as a zone":        {func(s *classify.Spelling) { s.ReturnsTrust = "SECRET" }, "returns.trust", classify.ErrEnum},
		"the zero sensitivity":           {func(s *classify.Spelling) { s.ReturnsSensitivity = "UNSPECIFIED" }, "returns.sensitivity", classify.ErrEnum},
		"a zone as a sensitivity":        {func(s *classify.Spelling) { s.ReturnsSensitivity = "PARTNER" }, "returns.sensitivity", classify.ErrEnum},
		"a write with no pointer":        {func(s *classify.Spelling) { s.ResourceFrom = "" }, "resource_from", classify.ErrRequired},
		"a padded resource type":         {func(s *classify.Spelling) { s.ResourceType = "order " }, "resource_type", classify.ErrString},
		"a pointer that is not RFC 6901": {func(s *classify.Spelling) { s.ResourceFrom = "/a~2" }, "resource_from", classify.ErrPointer},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := classify.Parse(base); err != nil {
				t.Fatalf("the base spelling is refused, so the case proves nothing: %v", err)
			}
			s := base
			tc.edit(&s)
			c, err := classify.Parse(s)
			refusedFor(t, err, tc.key, tc.want)
			if c != (classify.Classification{}) {
				t.Errorf("a refusal returned %+v; want the zero classification", c)
			}
		})
	}
}
