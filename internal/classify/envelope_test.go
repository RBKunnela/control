package classify_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/pkg/contract"
)

// carrying is an envelope complete in everything a classification does not
// supply, holding what c supplies the way both adapters put it there: the
// resource type as it is, an id only where a pointer names one, and a
// destination only for a zone other than the zero one. It is built here by
// hand, so nothing of the package under test decides what it holds.
func carrying(c classify.Classification) *controlv1.ActionEnvelope {
	env := &controlv1.ActionEnvelope{
		SchemaVersion: "1.0",
		RequestId:     "req-1",
		ProjectId:     "proj-1",
		TenantId:      "tenant-1",
		Environment:   "prod",
		OccurredAt:    timestamppb.New(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)),
		Principal:     &controlv1.Principal{Id: "user-1", TenantId: "tenant-1"},
		Agent:         &controlv1.Agent{Id: "agent-1"},
		Delegation: []*controlv1.Delegation{{
			From: "user-1", To: "agent-1",
			IssuedAt:  timestamppb.New(time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC)),
			ExpiresAt: timestamppb.New(time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC)),
		}},
		Action:    &controlv1.Action{Name: "tool", Effect: c.Effect, Provider: "orders"},
		Resource:  &controlv1.Resource{Type: c.ResourceType, TenantId: "tenant-1", Environment: "prod"},
		Arguments: &controlv1.Arguments{CanonicalHash: "sha256:" + strings.Repeat("0a", 32)},
	}
	if c.ResourceFrom != "" {
		env.Resource.Id = "ord-1"
	}
	if c.TrustZone != controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED {
		env.Destination = &controlv1.Destination{TrustZone: c.TrustZone}
	}
	return env
}

// TestCheckAcceptsExactlyWhatValidateAccepts is the rule the loader refuses
// by: a classification Check accepts never makes Validate refuse the envelope
// it supplies, and one Check refuses always does. A resource type is non-empty
// here, since the loader's table requires one, and a pointer is valid or
// empty, since Validate never sees a pointer.
func TestCheckAcceptsExactlyWhatValidateAccepts(t *testing.T) {
	types := []string{"order", "a b", strings.Repeat("r", 1024), strings.Repeat("r", 1025), " order", "order\t", "or\u200bder", "\u00a0", "\xff"}
	rapid.Check(t, func(rt *rapid.T) {
		c := classify.Classification{
			Effect:             controlv1.EffectClass(rapid.Int32Range(0, 10).Draw(rt, "effect")),
			ResourceType:       rapid.OneOf(rapid.SampledFrom(types), rapid.StringN(1, 8, -1)).Draw(rt, "type"),
			ResourceFrom:       rapid.SampledFrom([]string{"", "/id", "/a/0"}).Draw(rt, "from"),
			TrustZone:          controlv1.TrustZone(rapid.Int32Range(0, 6).Draw(rt, "zone")),
			ReturnsTrust:       controlv1.TrustZone(rapid.Int32Range(0, 5).Draw(rt, "returnsZone")),
			ReturnsSensitivity: controlv1.Sensitivity(rapid.Int32Range(0, 5).Draw(rt, "returnsLevel")),
		}
		checked, validated := c.Check(), contract.Validate(carrying(c))
		if (checked == nil) != (validated == nil) {
			rt.Fatalf("Check = %v, Validate = %v for %+v", checked, validated, c)
		}
	})
}

// TestCheckRefusesAMissingFieldWhereValidateDoes: each class without a
// pointer or a zone is refused by Check exactly where Validate refuses its
// envelope, naming the key that supplies the field Validate names.
func TestCheckRefusesAMissingFieldWhereValidateDoes(t *testing.T) {
	keyOf := map[string]string{"resource.id": "resource_from", "destination.trust_zone": "trust_zone", "action.effect": "effect"}
	for number := range int32(10) {
		effect := controlv1.EffectClass(number)
		for _, c := range []classify.Classification{
			{Effect: effect, ResourceType: "order", TrustZone: zonePartner},
			{Effect: effect, ResourceType: "order", ResourceFrom: "/id"},
		} {
			want := ""
			var ve *contract.ValidationError
			if err := contract.Validate(carrying(c)); errors.As(err, &ve) {
				want = keyOf[ve.Field]
				if want == "" {
					t.Errorf("%s: Validate refuses %s, which no classification key supplies: %v", effect, ve.Field, err)
				}
			}
			got := ""
			var ce *classify.Error
			if err := c.Check(); errors.As(err, &ce) {
				got = ce.Key
			}
			if got != want {
				t.Errorf("%s %+v: Check names %q, Validate's refusal is %q's", effect, c, got, want)
			}
		}
	}
}

// TestRequiresDelegationIsValidates: an envelope complete but for its
// delegation is refused for it exactly when RequiresDelegation says so.
func TestRequiresDelegationIsValidates(t *testing.T) {
	for number := int32(1); number < 10; number++ {
		effect := controlv1.EffectClass(number)
		env := carrying(complete(effect))
		if err := contract.Validate(env); err != nil {
			t.Fatalf("%s: the complete envelope is refused, so the case below proves nothing: %v", effect, err)
		}
		env.Delegation = nil
		var ve *contract.ValidationError
		refused := errors.As(contract.Validate(env), &ve) && ve.Field == "delegation"
		if refused != classify.RequiresDelegation(effect) {
			t.Errorf("%s: Validate refuses no delegation %v, RequiresDelegation %v", effect, refused, classify.RequiresDelegation(effect))
		}
	}
}
