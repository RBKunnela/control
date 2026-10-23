package contract_test

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// The prefix the generated value names carry, spelled out here rather than read
// from the package: a test that borrowed the implementation's constant would
// still pass if that constant changed.
const effectPrefix = "EFFECT_CLASS_"

// materialityUnderTest is the rule as the contract states it, one row per
// declared class. A copy on purpose: reading the implementation's own
// expression would make every case below assert that the code agrees with
// itself, and the point of the table is that a wrong row is visible as text.
func materialityUnderTest() map[controlv1.EffectClass]bool {
	return map[controlv1.EffectClass]bool{
		// An effect nobody declared cannot be assumed harmless.
		controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED:        true,
		controlv1.EffectClass_EFFECT_CLASS_READ:               false,
		controlv1.EffectClass_EFFECT_CLASS_WRITE:              true,
		controlv1.EffectClass_EFFECT_CLASS_DELETE:             true,
		controlv1.EffectClass_EFFECT_CLASS_EXECUTE:            true,
		controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE:        true,
		controlv1.EffectClass_EFFECT_CLASS_TRANSACT:           true,
		controlv1.EffectClass_EFFECT_CLASS_IDENTITY_OR_ACCESS: true,
		controlv1.EffectClass_EFFECT_CLASS_CONFIGURE:          true,
		controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE:  true,
	}
}

// TestIsMaterialCoversEveryDeclaredClass checks the rule in both directions: a
// class the contract declares and this table does not name fails, which is what
// catches an effect class added later, and a row naming a class the contract
// does not declare fails too, which catches a table that drifted.
func TestIsMaterialCoversEveryDeclaredClass(t *testing.T) {
	table := materialityUnderTest()
	declared := declaredValues(t, controlv1.EffectClass(0).Descriptor().Values())

	for _, value := range declared {
		effect := controlv1.EffectClass(value.Number())
		want, ok := table[effect]
		if !ok {
			t.Errorf("%s is declared in the contract and this table has no row for it: decide whether it is material and add one",
				value.Name())
			continue
		}
		if got := contract.IsMaterial(effect); got != want {
			t.Errorf("IsMaterial(%s) = %t, want %t", value.Name(), got, want)
		}
	}

	numbers := make(map[protoreflect.EnumNumber]bool, len(declared))
	for _, value := range declared {
		numbers[value.Number()] = true
	}
	for effect := range table {
		if !numbers[protoreflect.EnumNumber(effect)] {
			t.Errorf("this table has a row for %d, which the contract does not declare", effect)
		}
	}
}

// TestIsMaterialUndeclaredNumber covers the number a later minor sends and this
// build cannot name. Validate refuses such an envelope, so this is the second
// line: a class nobody here can classify is not a read, and nothing may
// authorize what it cannot classify.
func TestIsMaterialUndeclaredNumber(t *testing.T) {
	for _, number := range []int32{10, 99, 2147483647, -1} {
		if !contract.IsMaterial(controlv1.EffectClass(number)) {
			t.Errorf("IsMaterial(EffectClass(%d)) = false; an undeclared class is not a read", number)
		}
	}
}

// TestParseEffectAcceptsEveryDeclaredSpelling walks the descriptor, so a class
// added in a later minor is exercised here without anyone editing a table. The
// zero value is checked from the same loop, and it is refused rather than
// parsed.
func TestParseEffectAcceptsEveryDeclaredSpelling(t *testing.T) {
	for _, value := range declaredValues(t, controlv1.EffectClass(0).Descriptor().Values()) {
		name := string(value.Name())
		short, ok := strings.CutPrefix(name, effectPrefix)
		if !ok {
			t.Errorf("%s does not carry the %s prefix this package parses off", name, effectPrefix)
			continue
		}
		got, err := contract.ParseEffect(short)
		if value.Number() == 0 {
			// Zero is what absence leaves behind; nothing may select it.
			assertRefused(t, err, contract.ErrInvalidEnum, "")
			continue
		}
		if err != nil {
			t.Errorf("ParseEffect(%q) = %v, want %s", short, err, name)
			continue
		}
		if want := controlv1.EffectClass(value.Number()); got != want {
			t.Errorf("ParseEffect(%q) = %s, want %s", short, got, want)
		}
	}
}

// TestParseEffectRefusals is the negative half, and it includes the prefixed
// spelling: this package accepts one spelling per class, so "EFFECT_CLASS_READ"
// is refused even though protojson writes exactly that on the wire.
func TestParseEffectRefusals(t *testing.T) {
	for _, spelling := range []string{
		"",                         // said nothing at all
		"UNSPECIFIED",              // named the value absence leaves behind
		"EFFECT_CLASS_UNSPECIFIED", // the same, prefixed
		"EFFECT_CLASS_READ",        // the wire spelling; protojson's path, not this one
		"read",                     // the case is part of the name
		"Read",
		"READ ",
		" READ",
		"READ\n",
		"READ\x00",
		"WRITE\nREAD",
		"QUANTUM_ENTANGLE", // declared in a later minor, absent from this build
		strings.Repeat("READ", 512),
	} {
		got, err := contract.ParseEffect(spelling)
		assertRefused(t, err, contract.ErrInvalidEnum, "")
		if got != controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
			t.Errorf("ParseEffect(%q) = %s with an error; a refusal returns the restrictive value", spelling, got)
		}
	}
}

// TestParseEffectRefusalCarriesNoCallerText pins the rule that keeps caller
// text out of a record: the refusal names what this package accepts, not what
// it was handed. Every refusal in this package becomes evidence, and a string
// the caller chose has no place in one.
func TestParseEffectRefusalCarriesNoCallerText(t *testing.T) {
	const spelling = "TENANT_ACME_TOKEN_HUNTER2"

	_, err := contract.ParseEffect(spelling)
	if err == nil {
		t.Fatal("accepted a spelling the contract does not declare")
	}
	if strings.Contains(err.Error(), spelling) {
		t.Errorf("the refusal repeats the caller's string: %v", err)
	}
}

// TestParseEffectRefusesEverythingItDoesNotDeclare is the property behind the
// two tables above, over strings nobody chose: the accepted set is exactly the
// declared short names minus the zero value, an accepted string maps to its own
// class, and a refusal always carries the restrictive value.
func TestParseEffectRefusesEverythingItDoesNotDeclare(t *testing.T) {
	accepted := make(map[string]controlv1.EffectClass)
	spellings := []string{"", "READ", "read", "EFFECT_CLASS_READ", "UNSPECIFIED", "SPAWN_OR_DELEGATE"}
	for _, value := range declaredValues(t, controlv1.EffectClass(0).Descriptor().Values()) {
		short := strings.TrimPrefix(string(value.Name()), effectPrefix)
		spellings = append(spellings, short, string(value.Name()), strings.ToLower(short))
		if value.Number() != 0 {
			accepted[short] = controlv1.EffectClass(value.Number())
		}
	}

	rapid.Check(t, func(rt *rapid.T) {
		spelling := rapid.OneOf(rapid.SampledFrom(spellings), rapid.String()).Draw(rt, "spelling")

		got, err := contract.ParseEffect(spelling)
		want, isDeclared := accepted[spelling]
		switch {
		case isDeclared && err != nil:
			rt.Fatalf("ParseEffect(%q) = %v, want %s", spelling, err, want)
		case isDeclared && got != want:
			rt.Fatalf("ParseEffect(%q) = %s, want %s", spelling, got, want)
		case !isDeclared && err == nil:
			rt.Fatalf("ParseEffect(%q) = %s and no error; that spelling is not a declared class", spelling, got)
		case !isDeclared && got != controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED:
			rt.Fatalf("ParseEffect(%q) = %s with an error; a refusal returns the restrictive value", spelling, got)
		}
	})
}

// declaredValues reads an enum's values off the descriptor and refuses to
// return an empty set: every table in these files is checked against this, so a
// lookup that silently found nothing would turn each of them into a loop over
// zero rows that passes.
func declaredValues(t *testing.T, values protoreflect.EnumValueDescriptors) []protoreflect.EnumValueDescriptor {
	t.Helper()

	if values.Len() < 2 {
		t.Fatalf("the descriptor holds %d value(s); these tests read their subject from there", values.Len())
	}
	out := make([]protoreflect.EnumValueDescriptor, 0, values.Len())
	for i := range values.Len() {
		out = append(out, values.Get(i))
	}
	return out
}

// TestEffectRequiresIsWhatValidateRequires: the export lists, per declared
// class, the provider a material class needs and then the class's row, and a
// class this build cannot name gets the material default alone. Each list is
// held to Validate both ways: an envelope carrying the list and nothing more
// is accepted, and one missing any entry is refused naming that entry.
func TestEffectRequiresIsWhatValidateRequires(t *testing.T) {
	for effect, row := range effectsUnderTest() {
		want := row
		if materialityUnderTest()[effect] {
			want = append([]string{"action.provider"}, row...)
		}
		got := contract.EffectRequires(effect)
		if !slices.Equal(got, want) {
			t.Errorf("EffectRequires(%s) = %v, want %v", effect, got, want)
		}
		env := satisfying(effect, row)
		if err := contract.Validate(env); err != nil {
			t.Fatalf("%s: an envelope carrying the list is refused, so the negatives prove nothing: %v", effect, err)
		}
		for _, path := range got {
			env := satisfying(effect, row)
			clearPath(t, env, path)
			assertRefused(t, contract.Validate(env), contract.ErrMissingField, path)
		}
	}
	for _, number := range []int32{10, 99, -1} {
		if got := contract.EffectRequires(controlv1.EffectClass(number)); !slices.Equal(got, []string{"action.provider"}) {
			t.Errorf("EffectRequires(%d) = %v, want the material default alone", number, got)
		}
	}
}

// TestEffectRequiresOfTheZeroClassNamesTheEffect: the zero class is refused
// for its effect before anything else, so its list starts with the field
// Validate names, and a reader of the list that checks it in order refuses
// the same field.
func TestEffectRequiresOfTheZeroClassNamesTheEffect(t *testing.T) {
	unspecified := controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	got := contract.EffectRequires(unspecified)
	if want := []string{"action.effect", "action.provider"}; !slices.Equal(got, want) {
		t.Errorf("EffectRequires(%s) = %v, want %v", unspecified, got, want)
	}
	env := satisfying(unspecified, nil)
	assertRefused(t, contract.Validate(env), contract.ErrMissingField, got[0])
}

// TestEffectRequiresHandsOutACopy: for every declared class, the zero one
// included, a caller that edits the list it was given changes neither the
// next answer nor what Validate requires.
func TestEffectRequiresHandsOutACopy(t *testing.T) {
	for _, value := range declaredValues(t, controlv1.EffectClass(0).Descriptor().Values()) {
		effect := controlv1.EffectClass(value.Number())
		first := contract.EffectRequires(effect)
		if len(first) == 0 {
			t.Fatalf("EffectRequires(%s) is empty, so an edit of it proves nothing", effect)
		}
		want := slices.Clone(first)
		for i := range first {
			first[i] = "request_id"
		}
		if got := contract.EffectRequires(effect); !slices.Equal(got, want) {
			t.Errorf("%s: an edit of one answer reached the next: %v, want %v", effect, got, want)
		}
	}
	write := controlv1.EffectClass_EFFECT_CLASS_WRITE
	env := satisfying(write, effectsUnderTest()[write])
	env.Resource.Id = ""
	assertRefused(t, contract.Validate(env), contract.ErrMissingField, "resource.id")
}
