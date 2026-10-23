package classify

import (
	"fmt"
	"slices"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// The keys of a classification as a configuration file spells them. A refusal
// names one, and each caller adds only where the entry sits.
const (
	KeyEffect             = "effect"
	KeyResourceType       = "resource_type"
	KeyResourceFrom       = "resource_from"
	KeyTrustZone          = "trust_zone"
	KeyReturnsTrust       = "returns.trust"
	KeyReturnsSensitivity = "returns.sensitivity"
)

// Sentinel is a refusal by this package, matched with errors.Is.
type Sentinel string

// Error returns the refusal's text.
func (s Sentinel) Error() string { return string(s) }

// The refusals of a classification.
const (
	// ErrEffect is an effect class the contract does not declare, or none.
	ErrEffect Sentinel = "classify: no effect class the contract declares"
	// ErrEnum is a trust zone or a sensitivity the contract does not declare.
	ErrEnum Sentinel = "classify: a value the contract does not declare"
	// ErrString is a string no envelope can carry: empty, past the contract's
	// bound, or refused by its identifier rule.
	ErrString Sentinel = "classify: not a string an envelope carries"
	// ErrRequired is a field the effect class needs and only the
	// classification supplies, left out.
	ErrRequired Sentinel = "classify: the effect class needs a field this classification leaves out"
)

// Error is a refusal of one key of a classification. Key is the key as the
// configuration file spells it.
type Error struct {
	Key string
	Err error
}

// Error returns the key and the refusal.
func (e *Error) Error() string { return e.Key + ": " + e.Err.Error() }

// Unwrap returns the refusal, so errors.Is finds its sentinel.
func (e *Error) Unwrap() error { return e.Err }

// Classification is the operator's classification of one tool. The zero value
// declares no effect class and is refused.
type Classification struct {
	// Effect is the effect class of a call to the tool.
	Effect controlv1.EffectClass
	// ResourceType is the envelope's resource.type.
	ResourceType string
	// ResourceFrom is an RFC 6901 pointer into the call's arguments, whose
	// string or integer value is the envelope's resource.id. Empty means the
	// call names no resource, which Check refuses for a class that needs one.
	ResourceFrom string
	// TrustZone is the destination's, for a tool that sends data somewhere.
	// It says nothing about what the tool returns; UNSPECIFIED, the zero
	// value, sets no destination.
	TrustZone controlv1.TrustZone
	// ReturnsTrust is the trust zone of what the tool's results contain;
	// UNSPECIFIED, the zero value, is untrusted.
	ReturnsTrust controlv1.TrustZone
	// ReturnsSensitivity is the highest sensitivity the tool's results can
	// hold; UNSPECIFIED, the zero value, is unknown. It is never copied into
	// the envelope's data labels, which say what a call carries (ADR-0021).
	ReturnsSensitivity controlv1.Sensitivity
}

// Check refuses a classification no envelope could carry, as an *Error naming
// the key: an effect class that is not declared or is the zero one, a
// resource type CheckEnvelopeString refuses, a pointer CheckPointer refuses, a
// trust zone or sensitivity that is not declared, and a class whose envelope
// needs a resource id or a destination the classification leaves out. The
// zones and the sensitivity may be the zero value.
func (c Classification) Check() error {
	if _, ok := controlv1.EffectClass_name[int32(c.Effect)]; !ok || c.Effect == controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
		return &Error{Key: KeyEffect, Err: fmt.Errorf("%w: want one of %s", ErrEffect, strings.Join(EffectNames(), ", "))}
	}
	if err := CheckEnvelopeString(c.ResourceType); err != nil {
		return &Error{Key: KeyResourceType, Err: err}
	}
	if err := CheckPointer(c.ResourceFrom); err != nil {
		return &Error{Key: KeyResourceFrom, Err: err}
	}
	for _, e := range []struct {
		key   string
		names map[int32]string
		n     int32
	}{
		{KeyTrustZone, controlv1.TrustZone_name, int32(c.TrustZone)},
		{KeyReturnsTrust, controlv1.TrustZone_name, int32(c.ReturnsTrust)},
		{KeyReturnsSensitivity, controlv1.Sensitivity_name, int32(c.ReturnsSensitivity)},
	} {
		if _, ok := e.names[e.n]; !ok {
			return &Error{Key: e.key, Err: fmt.Errorf("%w: %d", ErrEnum, e.n)}
		}
	}
	return c.checkRequirements()
}

// checkRequirements holds the classification to what the contract requires of
// its effect class, for the fields the classification is the only source of:
// an envelope's resource.id is read through ResourceFrom and its destination
// is TrustZone, so a class that needs either is refused on every call without
// it.
func (c Classification) checkRequirements() error {
	class := strings.TrimPrefix(c.Effect.String(), "EFFECT_CLASS_")
	for _, path := range contract.EffectRequires(c.Effect) {
		switch {
		case path == "resource.id" && c.ResourceFrom == "":
			return &Error{Key: KeyResourceFrom, Err: fmt.Errorf("%w: %s needs resource.id, which only %s names", ErrRequired, class, KeyResourceFrom)}
		case path == "destination.trust_zone" && c.TrustZone == controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED:
			return &Error{Key: KeyTrustZone, Err: fmt.Errorf("%w: %s needs destination.trust_zone, which only %s sets", ErrRequired, class, KeyTrustZone)}
		}
	}
	return nil
}

// CheckEnvelopeString refuses a string a classification puts in an envelope
// that no envelope can carry: empty, longer than contract.MaxStringBytes, or
// refused by contract.CheckIdentifier. The refusal never repeats the string.
func CheckEnvelopeString(s string) error {
	switch {
	case s == "":
		return fmt.Errorf("%w: empty", ErrString)
	case len(s) > contract.MaxStringBytes:
		return fmt.Errorf("%w: %d bytes, past the %d an envelope's string takes", ErrString, len(s), contract.MaxStringBytes)
	}
	if err := contract.CheckIdentifier(s); err != nil {
		return fmt.Errorf("%w: %w", ErrString, err)
	}
	return nil
}

// RequiresDelegation reports whether the contract requires a delegation of an
// envelope of class e. A channel that carries none, such as the enforcement
// API, cannot have a call of that class decided.
func RequiresDelegation(e controlv1.EffectClass) bool {
	return slices.Contains(contract.EffectRequires(e), "delegation")
}
