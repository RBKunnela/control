package contract

import (
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// Decode parses binary protobuf and validates the result. It keeps unknown
// fields: a message parsed with DiscardUnknown is indistinguishable from a
// clean one, so only a decode that keeps them can refuse them.
//
// It reads the bytes before the Protobuf runtime does, and nothing should hand
// untrusted bytes to the runtime first: the runtime copies a packed field once
// per run, so its parse of a field sent as many short runs is quadratic, and
// the pre-scan's count is what stops that.
//
// On a validation failure it returns the parsed message as well as the error:
// a refused envelope still names a request, and the decision and evidence about
// it need those identifiers. Bytes refused before or by the parse (too long,
// refused by the pre-scan, not wire format) come back with no message, so a
// non-nil message is not a valid one and err == nil is the only test for that.
func Decode(b []byte) (*controlv1.ActionEnvelope, error) {
	if len(b) > MaxEnvelopeBytes {
		return nil, tooLarge(len(b))
	}
	// Before the parse, which merges what arrives twice, truncates an enum to
	// 32 bits, drops what a map entry holds besides its key and value, and
	// builds every element before any bound is checked.
	if err := prescan(b); err != nil {
		return nil, err
	}
	env := &controlv1.ActionEnvelope{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(b, env); err != nil {
		return nil, &ValidationError{Err: &codecError{reason: binaryDecodeReason, cause: err}}
	}
	return env, Validate(env)
}

// binaryDecodeReason is the one sentence a binary codec refusal renders, from
// the parse or the pre-scan alike (see codecError).
const binaryDecodeReason = "decode: the bytes do not parse as an ActionEnvelope"

// DecodeJSON parses protojson strictly and validates the result. protojson
// refuses an unknown field and an unknown enum name by itself; it accepts an
// undeclared enum number, which Validate catches. Its size check is on the JSON
// document; Validate's is on the encoded message.
func DecodeJSON(b []byte) (*controlv1.ActionEnvelope, error) {
	if len(b) > MaxEnvelopeBytes {
		return nil, tooLarge(len(b))
	}
	env := &controlv1.ActionEnvelope{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(b, env); err != nil {
		return nil, &ValidationError{Err: &codecError{reason: "decode json: the document does not parse as an ActionEnvelope", cause: err}}
	}
	return env, Validate(env)
}

// Validate refuses an envelope that is malformed, out of bounds or missing what
// its effect class requires, and returns the first failure as a
// *ValidationError naming the field in wire spelling.
//
// It cannot tell a clean message from one whose unknown fields were discarded,
// and it cannot see what a parse erased: a field sent twice, an enum number
// truncated to 32 bits, one key sent in two entries of a map, a field inside a
// map entry. A caller that decoded elsewhere gets every check here and not
// those, which only Decode and DecodeJSON perform.
//
// Pure, and the order of the checks is fixed, so the same bytes always name the
// same field.
func Validate(env *controlv1.ActionEnvelope) error {
	return validate(env, true)
}

// ValidateUnclassified refuses what Validate refuses of an envelope, in the
// same order, except an absent effect class and the fields an effect class
// requires. It is for a receiver that holds an envelope nothing classified:
// Validate stops at the missing effect before the values it checks after it,
// such as the delegation chain, the host, the labels and the arguments, so its
// refusal there says nothing about the rest. An envelope that does carry an
// effect is not held to what that effect requires either.
func ValidateUnclassified(env *controlv1.ActionEnvelope) error {
	return validate(env, false)
}

// validate is Validate's order of checks; classified is whether the effect
// class and what it requires are among them.
func validate(env *controlv1.ActionEnvelope, classified bool) error {
	if env == nil {
		return &ValidationError{Err: ErrMissingField}
	}
	if size := proto.Size(env); size > MaxEnvelopeBytes {
		return tooLarge(size)
	}
	if err := checkSchemaVersion(env.GetSchemaVersion()); err != nil {
		return err
	}
	// Before the walk: its generic MaxLabels bound would pass a ninth hop.
	if n := len(env.GetDelegation()); n > MaxDelegationDepth {
		return &ValidationError{Field: "delegation", Err: fmt.Errorf("%w: %d hops", ErrTooLarge, n)}
	}
	if err := walk(env.ProtoReflect(), "", 0); err != nil {
		return err
	}
	return checkSemantics(env, classified)
}

func checkSemantics(env *controlv1.ActionEnvelope, classified bool) error {
	for _, path := range []string{"request_id", "project_id", "tenant_id", "principal.id", "action.name", "occurred_at"} {
		if err := requirePresent(env, path); err != nil {
			return err
		}
	}
	// Presence is not enough here: a zero Timestamp is 1970, not a proposal.
	if ts := env.GetOccurredAt(); ts.GetSeconds() == 0 && ts.GetNanos() == 0 {
		return &ValidationError{Field: "occurred_at", Err: ErrMissingField}
	}
	if classified {
		if err := checkEffect(env); err != nil {
			return err
		}
	}
	return checkValues(env)
}

// checkEffect refuses an envelope with no effect class, or without a field
// its effect class requires.
func checkEffect(env *controlv1.ActionEnvelope) error {
	effect := env.GetAction().GetEffect()
	if effect == controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
		return &ValidationError{Field: "action.effect", Err: ErrMissingField}
	}
	for _, path := range EffectRequires(effect) {
		if err := requirePresent(env, path); err != nil {
			return err
		}
	}
	return nil
}

// tooLarge refuses the message rather than a field, so Field stays empty.
func tooLarge(size int) error {
	return &ValidationError{Err: fmt.Errorf("%w: %d bytes", ErrTooLarge, size)}
}

// checkSchemaVersion refuses anything but MAJOR.MINOR on the major this build
// implements. Absent or malformed is refused rather than read as the current
// version: a producer that says nothing must not be the one most trusted.
func checkSchemaVersion(version string) error {
	refuse := func(reason string) error {
		return &ValidationError{Field: "schema_version", Err: fmt.Errorf("%w: %s", ErrUnsupportedSchema, reason)}
	}
	major, minor, ok := strings.Cut(version, ".")
	switch {
	case !ok || !isDigits(major) || !isDigits(minor):
		return refuse("want MAJOR.MINOR")
	case major != supportedMajor():
		return refuse("this build implements major " + supportedMajor())
	}
	return nil
}

// supportedMajor reads the major out of the Protobuf package the generated
// types carry, so a build generated from a v2 contract refuses 1.x.
func supportedMajor() string {
	pkg := string((&controlv1.ActionEnvelope{}).ProtoReflect().Descriptor().ParentFile().Package())
	return strings.TrimPrefix(pkg[strings.LastIndex(pkg, ".")+1:], "v")
}

// isDigits is ParseUint rather than a loop because ParseUint permits no sign,
// no underscore and no empty string at base 10, which is exactly the rule.
func isDigits(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// requirePresent refuses a path the producer did not set. The path is resolved
// through the descriptors, so a path the tables name and the contract does not
// have refuses too, rather than passing unchecked.
func requirePresent(env *controlv1.ActionEnvelope, path string) error {
	if set, err := isSet(env.ProtoReflect(), path); err != nil || !set {
		return &ValidationError{Field: path, Err: ErrMissingField}
	}
	return nil
}

// isSet walks a dotted wire path. Protobuf presence answers it for every kind
// the tables use: an empty string, an unset message, an UNSPECIFIED enum and an
// empty list are absent, as "absence is never more permissive" requires.
func isSet(m protoreflect.Message, path string) (bool, error) {
	name, rest, nested := strings.Cut(path, ".")
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(name))
	if fd == nil || (nested && fd.Kind() != protoreflect.MessageKind) {
		return false, fmt.Errorf("%w: no such path %q", ErrMissingField, path)
	}
	if !m.Has(fd) {
		return false, nil
	}
	if !nested {
		return true, nil
	}
	return isSet(m.Get(fd).Message(), rest)
}
