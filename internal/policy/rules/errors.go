package rules

import (
	"strconv"
	"strings"
)

// sentinel is the type of the refusals Parse classifies, matched with
// errors.Is. They are constants, so no other code in the binary can reassign
// one and change what a refusal is classified as.
type sentinel string

// Error returns the refusal's text.
func (s sentinel) Error() string { return string(s) }

// Every refusal is an *Error wrapping exactly one of these, so a caller tells
// a bound from a broken rule without reading text.
const (
	// ErrTooLarge is a document over 1 MiB, more than 4096 rules, 64 values in
	// a list, 32 keys in a map, 8 obligations on a rule or 1024 bytes in a
	// string, or a staleness budget no time.Duration can hold.
	ErrTooLarge sentinel = "rules: over a bound"
	// ErrNotStrictJSON is a document the canonical form refuses: among others a
	// duplicate key, two keys that fold together, an integer outside the
	// JSON-safe range, invalid UTF-8 and nesting past its limit; and a number
	// written with a fraction or an exponent, which this format refuses though
	// the canonical form may not. It wraps the canonical form's own sentinel
	// where there is one.
	ErrNotStrictJSON sentinel = "rules: not strict JSON"
	ErrWrongType     sentinel = "rules: wrong JSON type"
	ErrUnknownKey    sentinel = "rules: a key this document format does not have"
	ErrMissingKey    sentinel = "rules: a required key is missing"
	ErrEmpty         sentinel = "rules: empty"
	// ErrIdentifier is a string the envelope could not carry where the rule
	// names it: one the identifier rule refuses, or a destination host with a
	// spelling other than the one a host has.
	ErrIdentifier          sentinel = "rules: breaks the identifier rule"
	ErrReservedKey         sentinel = "rules: a key in the reserved namespace"
	ErrAPIVersion          sentinel = "rules: an apiVersion this build does not read"
	ErrNotPositive         sentinel = "rules: not above zero"
	ErrEnum                sentinel = "rules: not a name this document spells a value with"
	ErrFloor               sentinel = "rules: a floor nothing can be compared against"
	ErrDuplicateRuleID     sentinel = "rules: a rule id used twice"
	ErrObligationsOnEffect sentinel = "rules: obligations on a rule whose effect carries none"
	ErrObligationType      sentinel = "rules: an obligation type outside the catalogue"
	ErrReason              sentinel = "rules: a reason this rule's effect may not name"
	// ErrObligationParam is a parameter the obligation's type does not
	// declare, a required one absent, or none of a set of which one is
	// required. Only CheckObligations returns it, never Parse.
	ErrObligationParam sentinel = "rules: a parameter the obligation's type does not declare or requires"
	// ErrObligationValue is a parameter value outside its grammar. Only
	// CheckObligations returns it, never Parse.
	ErrObligationValue sentinel = "rules: a parameter value the obligation's type cannot apply"
	// ErrExternal is an external constraint in a form other than a denial.
	ErrExternal sentinel = "rules: external holds only when the decision point denies"
	// ErrExternalEffect is an external constraint on a rule whose effect is
	// not DENY: the decision point may veto a grant and never make one.
	ErrExternalEffect sentinel = "rules: external on a rule whose effect is not DENY"
)

// Error is a refusal of a policy document. It says where, and never repeats
// what it found there: a refusal is written to logs, and the refused value can
// be anything up to the size of the document.
type Error struct {
	// Rule is the id of the rule the refusal is about, once that id has been
	// read and accepted. It is empty for the document and its bundle, and for a
	// rule whose own id is at fault.
	Rule string
	// Field is the path of the refused value, "rules[2].when.action.name[0]".
	// An entry of a map is named by its position in sorted key order, never by
	// its key, and a problem with the key itself adds ".key". Empty for the
	// document as a whole.
	Field string
	// Err wraps one of the sentinels above.
	Err error
}

// Error renders the rule, the field and the reason, each as a quoted Go
// string, so no part can start a second line in a log.
func (e *Error) Error() string {
	if e == nil {
		// A typed nil in an error interface is a caller bug; it still reads as a
		// refusal, which is the safe direction, so it prints rather than panics.
		return strconv.Quote("rules: invalid: nil *Error")
	}
	reason := "rules: invalid"
	if e.Err != nil {
		reason = e.Err.Error()
	}
	var b strings.Builder
	if e.Rule != "" {
		b.WriteString("rule ")
		b.WriteString(strconv.Quote(e.Rule))
		b.WriteString(" ")
	}
	if e.Field != "" {
		b.WriteString(strconv.Quote(e.Field))
		b.WriteString(": ")
	}
	b.WriteString(strconv.Quote(reason))
	return b.String()
}

// Unwrap exposes the sentinel to errors.Is. Nil-safe for the reason Error is.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// at is where a refusal is: the rule it is about, once that rule's id has been
// read and accepted, and the path of the field.
type at struct {
	rule string
	path string
}

func (a at) key(name string) at {
	if a.path == "" {
		return at{rule: a.rule, path: name}
	}
	return at{rule: a.rule, path: a.path + "." + name}
}

func (a at) index(i int) at {
	return at{rule: a.rule, path: a.path + "[" + strconv.Itoa(i) + "]"}
}

func (a at) refuse(err error) error {
	return &Error{Rule: a.rule, Field: a.path, Err: err}
}
