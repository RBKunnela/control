package classify_test

import (
	"errors"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
)

const (
	effectRead        = controlv1.EffectClass_EFFECT_CLASS_READ
	effectWrite       = controlv1.EffectClass_EFFECT_CLASS_WRITE
	effectDelete      = controlv1.EffectClass_EFFECT_CLASS_DELETE
	effectConfigure   = controlv1.EffectClass_EFFECT_CLASS_CONFIGURE
	effectExecute     = controlv1.EffectClass_EFFECT_CLASS_EXECUTE
	effectCommunicate = controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE
	effectTransact    = controlv1.EffectClass_EFFECT_CLASS_TRANSACT
	effectIdentity    = controlv1.EffectClass_EFFECT_CLASS_IDENTITY_OR_ACCESS
	effectSpawn       = controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE
	zonePartner       = controlv1.TrustZone_TRUST_ZONE_PARTNER
)

// complete is a classification of the given class with every key a value, a
// resource pointer and a destination among them.
func complete(effect controlv1.EffectClass) classify.Classification {
	return classify.Classification{
		Effect: effect, ResourceType: "order", ResourceFrom: "/id", TrustZone: zonePartner,
		ReturnsTrust: controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL, ReturnsSensitivity: controlv1.Sensitivity_SENSITIVITY_INTERNAL,
	}
}

// refusedFor reports a refusal that is not an *Error naming key and wrapping
// want.
func refusedFor(t *testing.T, err error, key string, want error) {
	t.Helper()
	var ce *classify.Error
	switch {
	case err == nil:
		t.Errorf("accepted; want %s refused with %v", key, want)
	case !errors.As(err, &ce):
		t.Errorf("%v is not a *classify.Error", err)
	case ce.Key != key:
		t.Errorf("refusal names %q, want %q: %v", ce.Key, key, err)
	case !errors.Is(err, want):
		t.Errorf("refusal %v does not wrap %v", err, want)
	}
}

func TestTheZeroClassificationIsRefused(t *testing.T) {
	refusedFor(t, classify.Classification{}.Check(), "effect", classify.ErrEffect)
}

// TestEveryDeclaredClassIsAcceptedWhenComplete is the positive control for the
// refusals below: each of them changes one key of a classification this
// accepts.
func TestEveryDeclaredClassIsAcceptedWhenComplete(t *testing.T) {
	for _, effect := range []controlv1.EffectClass{effectRead, effectWrite, effectDelete, effectConfigure, effectExecute,
		effectCommunicate, effectTransact, effectIdentity, effectSpawn} {
		if err := complete(effect).Check(); err != nil {
			t.Errorf("%s: %v", effect, err)
		}
	}
}

func TestCheckRefusesWhatNoEnvelopeCarries(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*classify.Classification)
		key  string
		want error
	}{
		"an undeclared effect":           {func(c *classify.Classification) { c.Effect = 99 }, "effect", classify.ErrEffect},
		"no resource type":               {func(c *classify.Classification) { c.ResourceType = "" }, "resource_type", classify.ErrString},
		"a resource type past the bound": {func(c *classify.Classification) { c.ResourceType = strings.Repeat("r", 1025) }, "resource_type", classify.ErrString},
		"a resource type led by a space": {func(c *classify.Classification) { c.ResourceType = " order" }, "resource_type", classify.ErrString},
		"a zero-width resource type":     {func(c *classify.Classification) { c.ResourceType = "or\u200bder" }, "resource_type", classify.ErrString},
		"a pointer without its slash":    {func(c *classify.Classification) { c.ResourceFrom = "id" }, "resource_from", classify.ErrPointer},
		"an undeclared zone":             {func(c *classify.Classification) { c.TrustZone = 6 }, "trust_zone", classify.ErrEnum},
		"an undeclared returned zone":    {func(c *classify.Classification) { c.ReturnsTrust = 6 }, "returns.trust", classify.ErrEnum},
		"an undeclared sensitivity":      {func(c *classify.Classification) { c.ReturnsSensitivity = 6 }, "returns.sensitivity", classify.ErrEnum},
		"a negative sensitivity":         {func(c *classify.Classification) { c.ReturnsSensitivity = -1 }, "returns.sensitivity", classify.ErrEnum},
	} {
		t.Run(name, func(t *testing.T) {
			c := complete(effectRead)
			tc.edit(&c)
			refusedFor(t, c.Check(), tc.key, tc.want)
		})
	}
}

// TestTheBoundsAreTheContracts: a resource type of exactly 1024 bytes and a
// pointer at both of its bounds are accepted, one byte or token more is not.
func TestTheBoundsAreTheContracts(t *testing.T) {
	c := complete(effectRead)
	c.ResourceType = strings.Repeat("r", 1024)
	c.ResourceFrom = strings.Repeat("/"+strings.Repeat("t", 64), 8)
	if err := c.Check(); err != nil {
		t.Fatalf("at the bounds: %v", err)
	}
	c.ResourceFrom += "/t"
	refusedFor(t, c.Check(), "resource_from", classify.ErrPointer)
}

// TestTheZeroZonesAreAccepted: an unset destination, an untrusted result and
// an unknown sensitivity are what absence means, and a read needs none of
// them.
func TestTheZeroZonesAreAccepted(t *testing.T) {
	c := classify.Classification{Effect: effectRead, ResourceType: "order"}
	if err := c.Check(); err != nil {
		t.Errorf("a read with the zero zones: %v", err)
	}
}

// TestAClassWhoseEnvelopeNeedsAResourceNeedsItsPointer: the classes whose
// envelope requires resource.id are refused without resource_from, the others
// are not; COMMUNICATE alone needs a destination.
func TestAClassWhoseEnvelopeNeedsAResourceNeedsItsPointer(t *testing.T) {
	needsID := map[controlv1.EffectClass]bool{effectWrite: true, effectDelete: true, effectConfigure: true, effectTransact: true, effectIdentity: true}
	for _, effect := range []controlv1.EffectClass{effectRead, effectWrite, effectDelete, effectConfigure, effectExecute,
		effectCommunicate, effectTransact, effectIdentity, effectSpawn} {
		c := complete(effect)
		c.ResourceFrom = ""
		if needsID[effect] {
			refusedFor(t, c.Check(), "resource_from", classify.ErrRequired)
		} else if err := c.Check(); err != nil {
			t.Errorf("%s without resource_from: %v", effect, err)
		}
		c = complete(effect)
		c.TrustZone = controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED
		if effect == effectCommunicate {
			refusedFor(t, c.Check(), "trust_zone", classify.ErrRequired)
		} else if err := c.Check(); err != nil {
			t.Errorf("%s without trust_zone: %v", effect, err)
		}
	}
}

func TestRequiresDelegationIsSpawnAlone(t *testing.T) {
	for _, effect := range []controlv1.EffectClass{0, effectRead, effectWrite, effectDelete, effectConfigure, effectExecute,
		effectCommunicate, effectTransact, effectIdentity, effectSpawn, 99} {
		if got := classify.RequiresDelegation(effect); got != (effect == effectSpawn) {
			t.Errorf("RequiresDelegation(%s) = %v", effect, got)
		}
	}
}

func TestCheckEnvelopeString(t *testing.T) {
	for _, s := range []string{"x", "order", "a b", strings.Repeat("\u00e9", 512)} {
		if err := classify.CheckEnvelopeString(s); err != nil {
			t.Errorf("CheckEnvelopeString(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"", strings.Repeat("\u00e9", 512) + "x", "order ", "\torder", "a\u00a0b", "a\u2028b", "a\x00b", "\xff"} {
		if err := classify.CheckEnvelopeString(s); !errors.Is(err, classify.ErrString) {
			t.Errorf("CheckEnvelopeString(%q) = %v, want ErrString", s, err)
		}
	}
}

// TestARefusalNeverRepeatsTheValue: what a configuration holds can be
// anything an operator pasted, and a refusal is printed and logged.
func TestARefusalNeverRepeatsTheValue(t *testing.T) {
	const pasted = "SECRETVALUE"
	for _, c := range []classify.Classification{
		{Effect: effectRead, ResourceType: pasted + "\u200b"},
		{Effect: effectRead, ResourceType: "order", ResourceFrom: pasted},
		{Effect: effectRead, ResourceType: "order", ResourceFrom: "/" + pasted + "~"},
	} {
		if err := c.Check(); err == nil || strings.Contains(err.Error(), pasted) {
			t.Errorf("Check = %v; want a refusal that does not repeat the value", err)
		}
	}
}
