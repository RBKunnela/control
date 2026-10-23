package classify

import (
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// The prefixes the contract's value names carry and a spelling leaves off.
const (
	zonePrefix        = "TRUST_ZONE_"
	sensitivityPrefix = "SENSITIVITY_"
)

// Spelling is a classification as a configuration file writes it: each enum by
// the contract's name without its prefix. Effect is required; the empty string
// is the zero value for the zones and the sensitivity, which no spelling may
// name.
type Spelling struct {
	Effect             string
	ResourceType       string
	ResourceFrom       string
	TrustZone          string
	ReturnsTrust       string
	ReturnsSensitivity string
}

// Parse reads a spelling through the contract's descriptors, as the policy
// catalogue does, and returns the classification Check accepts, or the zero
// classification beside an *Error naming the key. An explicit "UNSPECIFIED"
// is refused: nothing arrives at the zero value by choosing it.
func Parse(s Spelling) (Classification, error) {
	effect, err := contract.ParseEffect(s.Effect)
	if err != nil {
		return Classification{}, &Error{Key: KeyEffect, Err: fmt.Errorf("%w: want one of %s", ErrEffect, strings.Join(EffectNames(), ", "))}
	}
	zone, err := spelled(controlv1.TrustZone(0).Descriptor(), zonePrefix, KeyTrustZone, s.TrustZone)
	if err != nil {
		return Classification{}, err
	}
	returnsZone, err := spelled(controlv1.TrustZone(0).Descriptor(), zonePrefix, KeyReturnsTrust, s.ReturnsTrust)
	if err != nil {
		return Classification{}, err
	}
	level, err := spelled(controlv1.Sensitivity(0).Descriptor(), sensitivityPrefix, KeyReturnsSensitivity, s.ReturnsSensitivity)
	if err != nil {
		return Classification{}, err
	}
	c := Classification{
		Effect: effect, ResourceType: s.ResourceType, ResourceFrom: s.ResourceFrom,
		TrustZone: controlv1.TrustZone(zone), ReturnsTrust: controlv1.TrustZone(returnsZone),
		ReturnsSensitivity: controlv1.Sensitivity(level),
	}
	if err := c.Check(); err != nil {
		return Classification{}, err
	}
	return c, nil
}

// spelled is the number a name spells, the empty name being the zero value.
func spelled(d protoreflect.EnumDescriptor, prefix, key, name string) (protoreflect.EnumNumber, error) {
	if name == "" {
		return 0, nil
	}
	if v := d.Values().ByName(protoreflect.Name(prefix + name)); v != nil && v.Number() != 0 {
		return v.Number(), nil
	}
	return 0, &Error{Key: key, Err: fmt.Errorf("%w: want one of %s", ErrEnum, strings.Join(names(d, prefix), ", "))}
}

// EffectNames is every effect class the contract declares but the zero one, in
// its declared order and spelled as Parse takes it. The list is a copy.
func EffectNames() []string {
	return names(controlv1.EffectClass(0).Descriptor(), "EFFECT_CLASS_")
}

// ZoneNames is every trust zone the contract declares but the zero one, in its
// declared order and spelled as Parse takes it. The list is a copy.
func ZoneNames() []string {
	return names(controlv1.TrustZone(0).Descriptor(), zonePrefix)
}

// SensitivityNames is every sensitivity the contract declares but the zero
// one, in its declared order and spelled as Parse takes it. The list is a copy.
func SensitivityNames() []string {
	return names(controlv1.Sensitivity(0).Descriptor(), sensitivityPrefix)
}

func names(d protoreflect.EnumDescriptor, prefix string) []string {
	values := d.Values()
	out := make([]string, 0, values.Len())
	for i := range values.Len() {
		if v := values.Get(i); v.Number() != 0 {
			out = append(out, strings.TrimPrefix(string(v.Name()), prefix))
		}
	}
	return slices.Clip(out)
}
