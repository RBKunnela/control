package rules

import (
	"errors"
	"strings"
	"testing"
)

// The builders splice one fragment into an otherwise fixed document that
// parses, so a refusal and its accepting twin differ only in the fragment a
// case writes out. They build input only; every expectation is written out in
// the case that uses them.
const (
	headerJSON   = `"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"payments","version":"1","serial":1,"maxStaleSeconds":300}`
	denyRuleJSON = `{"id":"r","effect":"DENY","when":{"action":{"name":["refund"]}}}`
)

func docWithBundle(bundle string) string {
	return `{"apiVersion":"agent-policy/v1alpha1","bundle":` + bundle + `,"rules":[` + denyRuleJSON + `]}`
}

func docWithRules(rules ...string) string {
	return `{` + headerJSON + `,"rules":[` + strings.Join(rules, ",") + `]}`
}

// docWithWhen puts when into a DENY rule whose id is "r".
func docWithWhen(when string) string {
	return docWithRules(`{"id":"r","effect":"DENY","when":` + when + `}`)
}

// sentinels is every refusal class Parse and CheckObligations have, written
// out, so a test can check that a refusal carries exactly one of them.
var sentinels = []error{
	ErrTooLarge, ErrNotStrictJSON, ErrWrongType, ErrUnknownKey, ErrMissingKey,
	ErrEmpty, ErrIdentifier, ErrReservedKey, ErrAPIVersion, ErrNotPositive,
	ErrEnum, ErrFloor, ErrDuplicateRuleID, ErrObligationsOnEffect,
	ErrObligationType, ErrReason, ErrExternal, ErrExternalEffect,
	ErrObligationParam, ErrObligationValue,
}

// Characters the identifier rule refuses, built from code points so that no
// invisible character sits in the source.
var (
	zeroWidthSpace = string(rune(0x200B))
	noBreakSpace   = string(rune(0x00A0))
	lineSeparator  = string(rune(0x2028))
	// longS folds to s under simple case folding and takes two bytes.
	longS = string(rune(0x017F))
)

// refusal is the refusal a case expects.
type refusal struct {
	err   error
	field string
	rule  string
}

// expectRefusal checks a refusal whole: no model and no bytes beside it, an
// *Error, the field and the rule the case names, and exactly one sentinel.
func expectRefusal(t *testing.T, doc string, want refusal) {
	t.Helper()
	model, canonical, err := Parse([]byte(doc))
	if model != nil || canonical != nil {
		t.Errorf("Parse returned a model or bytes beside its refusal")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v (%T), want an *Error wrapping %v", err, err, want.err)
	}
	matched := 0
	for _, s := range sentinels {
		if errors.Is(err, s) {
			matched++
		}
	}
	if !errors.Is(err, want.err) || matched != 1 || e.Field != want.field || e.Rule != want.rule {
		t.Fatalf("refusal {Rule %q, Field %q, Err %v} (%d sentinels), want {Rule %q, Field %q, Err %v}",
			e.Rule, e.Field, e.Err, matched, want.rule, want.field, want.err)
	}
}

// expectAccepted is the accepting twin of a refusal. Without it a refusal test
// passes against a parser that refuses everything, the stub included.
func expectAccepted(t *testing.T, doc string) *Document {
	t.Helper()
	model, canonical, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse refused an accepting twin: %v", err)
	}
	if model == nil || len(canonical) == 0 {
		t.Fatalf("Parse accepted, returning model %v and %d bytes", model, len(canonical))
	}
	return model
}
