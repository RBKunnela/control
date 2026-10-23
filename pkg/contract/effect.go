package contract

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// effectNamePrefix is what the declared enum value names carry and the spelling
// this package parses does not.
const effectNamePrefix = "EFFECT_CLASS_"

// ParseEffect maps the wire spelling of an effect class to the enum: "READ"
// through "SPAWN_OR_DELEGATE". Anything else is ErrInvalidEnum, and the class
// returned with it is EFFECT_CLASS_UNSPECIFIED, which IsMaterial reads as
// material: a caller that drops the error still holds the restrictive value.
//
// The prefixed spelling "EFFECT_CLASS_READ" is refused, though it is what
// protojson writes on the wire. One spelling per class, and the choice is made
// in the strict direction because it is the reversible one: accepting a second
// spelling later is additive, withdrawing one that was accepted breaks whoever
// wrote it. The wire form is handled by protojson, on the path where it
// belongs.
//
// "UNSPECIFIED" is refused too. Zero is what a producer that said nothing
// leaves behind, and nothing may arrive at it by choosing it: a policy rule
// that named the zero value would key on every envelope that declared no
// effect at all.
//
// The lookup goes through the descriptor rather than a table here, so a class
// added in a later minor parses as soon as the generated code carries it,
// rather than being refused until someone finds the second table.
func ParseEffect(s string) (controlv1.EffectClass, error) {
	value := controlv1.EffectClass(0).Descriptor().Values().ByName(protoreflect.Name(effectNamePrefix + s))
	if value == nil || value.Number() == 0 {
		// The refused spelling is the caller's own string and is not repeated
		// back into an error this project turns into a record.
		return controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, &ValidationError{
			Err: fmt.Errorf("%w: want an effect class name without the %s prefix", ErrInvalidEnum, effectNamePrefix),
		}
	}
	return controlv1.EffectClass(value.Number()), nil
}

// IsMaterial reports whether an effect changes the world.
//
// Written as "not a declared read" rather than as a list of the classes that
// are material, so both open cases fall out of the one line.
// EFFECT_CLASS_UNSPECIFIED is material, because an effect nobody declared
// cannot be assumed harmless, and a class this build has never heard of is
// material for the same reason: neither of them is a read.
func IsMaterial(e controlv1.EffectClass) bool {
	return e != controlv1.EffectClass_EFFECT_CLASS_READ
}

// EffectRequires lists the wire paths Validate requires of an envelope of
// class e beyond those every envelope needs: action.provider for a material
// class, then the class's own row, in the order Validate checks them. The zero
// class starts with action.effect, the field Validate refuses it for, so a
// reader that checks the list in order refuses what Validate does. A class
// this build does not declare gets the material default alone. The list is a
// fresh copy on every call, so a caller cannot change what Validate requires.
func EffectRequires(e controlv1.EffectClass) []string {
	var out []string
	if e == controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
		out = append(out, "action.effect")
	}
	if IsMaterial(e) {
		out = append(out, "action.provider")
	}
	return append(out, effectRequirements()[e]...)
}

// effectRequirements is the contract's table, as data: a switch with a branch
// per class puts the same rule in two places the day a class is added.
//
// No row names a field every envelope requires already: that check has run by
// then, and on the page a repeat reads as something the class needs. The two
// classes that cross a tenant boundary need both sides of the cross-tenant
// comparison, because with both absent "" == "" passes. The mutating classes
// need the resource's environment, which the environment boundary reads, and
// keep the envelope's, which records where the request was received (ADR-0011).
func effectRequirements() map[controlv1.EffectClass][]string {
	mutating := []string{"resource.type", "resource.id", "environment", "resource.environment"}
	return map[controlv1.EffectClass][]string{
		controlv1.EffectClass_EFFECT_CLASS_READ:               {"resource.type"},
		controlv1.EffectClass_EFFECT_CLASS_WRITE:              mutating,
		controlv1.EffectClass_EFFECT_CLASS_DELETE:             mutating,
		controlv1.EffectClass_EFFECT_CLASS_CONFIGURE:          mutating,
		controlv1.EffectClass_EFFECT_CLASS_EXECUTE:            {"resource.type", "arguments.canonical_hash"},
		controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE:        {"destination.trust_zone"},
		controlv1.EffectClass_EFFECT_CLASS_TRANSACT:           {"resource.id", "arguments.canonical_hash", "principal.tenant_id", "resource.tenant_id"},
		controlv1.EffectClass_EFFECT_CLASS_IDENTITY_OR_ACCESS: {"resource.id", "principal.tenant_id", "resource.tenant_id"},
		controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE:  {"agent.id", "delegation"},
	}
}
