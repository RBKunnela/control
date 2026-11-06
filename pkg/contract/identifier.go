package contract

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// CheckIdentifier refuses a string no identifier in this contract may hold.
// The rule is ADR-0011's, at Unicode 17.0.0: invalid UTF-8, White_Space at
// either end, and anywhere a space separator other than U+0020, a code point
// in Cc, Cf, Zl or Zp, or a Default_Ignorable_Code_Point. Each is a way for
// two spellings of one value to look like one, for a value to look like
// nothing, or for a record to read differently from the bytes it holds.
//
// Validate holds every string of an envelope to this rule, map keys and values
// included, except the two free-text fields. It is exported so that anything
// else that records an identifier, the evidence builder first, holds it to
// this rule rather than to a second one.
//
// It checks what a value holds, not whether there is one: "" passes, and a
// caller that requires a value checks for it first, as Validate does.
//
// The refusal is a *ValidationError with no Field, wrapping ErrInvalidValue.
// It names the class and the code point by number and never repeats the
// string, which is the caller's.
func CheckIdentifier(s string) error {
	if err := identifierProblem(s); err != nil {
		return &ValidationError{Err: err}
	}
	return nil
}

// CheckID refuses a string that cannot be a required identifier: empty, as
// ErrMissingField; longer than MaxStringBytes, as ErrTooLarge; or refused by
// CheckIdentifier. It is the one rule for an identifier that must be present
// outside an envelope, a policy's id, a configured tenant, a request id read
// back, so that no caller keeps a copy of the bound beside the rule.
//
// The refusal is a *ValidationError with no Field and never repeats the
// string.
func CheckID(s string) error {
	switch {
	case s == "":
		return &ValidationError{Err: ErrMissingField}
	case len(s) > MaxStringBytes:
		return &ValidationError{Err: fmt.Errorf("%w: %d bytes, past the %d an identifier takes", ErrTooLarge, len(s), MaxStringBytes)}
	}
	return CheckIdentifier(s)
}

// identifierProblem is CheckIdentifier's rule without the wrapper, so the walk
// can attach the field it found the string in.
func identifierProblem(s string) error {
	if err := utf8Problem(s); err != nil || s == "" {
		return err
	}
	if first, _ := utf8.DecodeRuneInString(s); unicode.Is(unicode.White_Space, first) {
		return fmt.Errorf("%w: white space U+%04X at the start", ErrInvalidValue, first)
	}
	if last, _ := utf8.DecodeLastRuneInString(s); unicode.Is(unicode.White_Space, last) {
		return fmt.Errorf("%w: white space U+%04X at the end", ErrInvalidValue, last)
	}
	for i, r := range s {
		if class := refusedClass(r); class != "" {
			return fmt.Errorf("%w: %s U+%04X at byte %d", ErrInvalidValue, class, r, i)
		}
	}
	return nil
}

// freeTextProblem is the rule for arguments.redacted_preview and
// delegation[].reason, the two strings a person reads rather than a policy
// keys on. They may hold padding and format characters, and of the control
// characters only tab, line feed and carriage return; every other is refused.
// JSON escapes those three, so free text cannot break a record's line. It can
// still send a terminal back to the start of a line, or reorder a displayed
// line with a bidirectional control: whatever shows the raw text neutralises
// both itself.
//
// Invalid UTF-8 is refused here too, though ADR-0011 lists these fields as
// exempt from everything but controls. It is Protobuf's own rule for a string
// field: both decoders refuse it, and a message Validate passed in memory while
// holding it could not be encoded afterwards.
func freeTextProblem(s string) error {
	if err := utf8Problem(s); err != nil {
		return err
	}
	for i, r := range s {
		if r != '\t' && r != '\n' && r != '\r' && unicode.Is(unicode.Cc, r) {
			return fmt.Errorf("%w: a control character U+%04X at byte %d", ErrInvalidValue, r, i)
		}
	}
	return nil
}

func utf8Problem(s string) error {
	if utf8.ValidString(s) {
		return nil
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("%w: not valid UTF-8 at byte %d", ErrInvalidValue, i)
		}
		i += size
	}
	return fmt.Errorf("%w: not valid UTF-8", ErrInvalidValue)
}

// refusedClass names the class a code point is refused for anywhere in an
// identifier, or returns "" when it may appear inside one.
//
// Default_Ignorable_Code_Point is derived in DerivedCoreProperties.txt from
// Other_Default_Ignorable_Code_Point, Cf and Variation_Selector, less
// White_Space and some format characters. Go ships the three inputs and not
// the derived table. What the derivation takes out of Cf is refused as Cf
// anyway, and no White_Space code point is in the other two inputs, which a
// test pins, so the lookups below refuse exactly Cf and
// Default_Ignorable_Code_Point together.
func refusedClass(r rune) string {
	switch {
	case r < utf8.RuneSelf:
		if r < 0x20 || r == 0x7f {
			return "a control character"
		}
		return ""
	case unicode.Is(unicode.Cc, r):
		return "a control character"
	case unicode.Is(unicode.Cf, r):
		return "a format character"
	case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
		return "a line or paragraph separator"
	case unicode.Is(unicode.Zs, r):
		// U+0020 took the ASCII branch. A reader cannot tell the other space
		// separators from it, so two identifiers that look alike would be two.
		return "a space other than U+0020"
	case unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r), unicode.Is(unicode.Variation_Selector, r):
		return "a default-ignorable code point"
	}
	return ""
}
