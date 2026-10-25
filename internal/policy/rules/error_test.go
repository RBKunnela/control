package rules

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/guardana/control/internal/canon"
)

func TestErrorRendersOneQuotedLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  *Error
		want string
	}{
		{
			"rule, field and a reason holding a newline",
			&Error{Rule: `a"b`, Field: "rules[0].when", Err: fmt.Errorf("%w: line\nbreak", ErrEmpty)},
			`rule "a\"b" "rules[0].when": "rules: empty: line\nbreak"`,
		},
		{"no rule", &Error{Field: "bundle.serial", Err: ErrNotPositive}, `"bundle.serial": "rules: not above zero"`},
		{"the document", &Error{Err: ErrTooLarge}, `"rules: over a bound"`},
		{"no cause", &Error{}, `"rules: invalid"`},
		{"nil", nil, `"rules: invalid: nil *Error"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %s, want %s", got, tc.want)
			}
		})
	}
	if (*Error)(nil).Unwrap() != nil {
		t.Fatal("Unwrap of a nil *Error is not nil")
	}
}

// TestRefusalNeverRepeatsTheValue plants a marker in the refused value at each
// kind of position. The refusal says where, and the marker never reaches it.
func TestRefusalNeverRepeatsTheValue(t *testing.T) {
	t.Parallel()
	long := `"MARKER` + strings.Repeat("x", 1020) + `"`
	cases := []struct {
		name string
		doc  string
		rule string
	}{
		{"unknown key", docWithRules(`{"id":"r","effect":"DENY","MARKER":1,"when":{"action":{"name":["refund"]}}}`), "r"},
		{"apiVersion", `{"apiVersion":"MARKER","bundle":{"id":"p","version":"1","serial":1,"maxStaleSeconds":1},"rules":[` + denyRuleJSON + `]}`, ""},
		{"rule effect", docWithRules(`{"id":"r","effect":"MARKER","when":{"action":{"name":["refund"]}}}`), "r"},
		{"reason", docWithRules(`{"id":"r","effect":"DENY","reason":"MARKER","when":{"action":{"name":["refund"]}}}`), "r"},
		{"obligation type", docWithRules(`{"id":"r","effect":"REQUIRE_APPROVAL","obligations":[{"type":"MARKER"}],"when":{"action":{"name":["refund"]}}}`), "r"},
		{"effect class", docWithWhen(`{"action":{"effect":["MARKER"]}}`), "r"},
		{"trust zone", docWithWhen(`{"destination":{"trustZone":["MARKER"]}}`), "r"},
		{"floor", docWithWhen(`{"data":{"sensitivityAtLeast":"MARKER"}}`), "r"},
		{"identifier rule", docWithWhen(`{"action":{"name":["MARKER` + zeroWidthSpace + `"]}}`), "r"},
		{"string bound", docWithWhen(`{"action":{"name":[` + long + `]}}`), "r"},
		{"reserved key", docWithWhen(`{"resource":{"labels":{"reserved.MARKER":["x"]}}}`), "r"},
		{"map key identifier rule", docWithWhen(`{"principal":{"attributes":{"MARKER` + zeroWidthSpace + `":["x"]}}}`), "r"},
		{"params value", docWithRules(`{"id":"r","effect":"REQUIRE_APPROVAL","obligations":[{"type":"cap_amount","params":{"max":"MARKER\tx"}}],"when":{"action":{"name":["refund"]}}}`), "r"},
		{"duplicate rule id", docWithRules(
			`{"id":"MARKER","effect":"DENY","when":{"action":{"name":["a"]}}}`,
			`{"id":"MARKER","effect":"DENY","when":{"action":{"name":["b"]}}}`), ""},
		{"serial of the wrong type", docWithBundle(`{"id":"p","version":"1","serial":"MARKER","maxStaleSeconds":1}`), ""},
		{"a float under a label key", docWithWhen(`{"resource":{"labels":{"MARKER":[1.5]}}}`), ""},
		{"nesting under a label key", docWithWhen(`{"resource":{"labels":{"MARKER":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}}}`), ""},
		{"keys that fold together under a label key", docWithWhen(`{"resource":{"labels":{"MARKER":{"a":1,"A":2}}}}`), ""},
		{"a float under a params key", docWithRules(`{"id":"r","effect":"REQUIRE_APPROVAL","obligations":[{"type":"cap_amount","params":{"MARKER":1.5}}],"when":{"action":{"name":["refund"]}}}`), ""},
		{"a syntax error after a key", `{"MARKER": MARKER}`, ""},
		{"a syntax error in a string", `{"MARKER": "MARKER`, ""},
		{"trailing data", `{"MARKER": 1} MARKER`, ""},
		{"invalid UTF-8", "{\"MARKER\": \"\xff\"}", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := Parse([]byte(tc.doc))
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("err = %v, want an *Error", err)
			}
			if strings.Contains(err.Error(), "MARKER") {
				t.Fatalf("refusal %s repeats the refused value", err)
			}
			if e.Rule != tc.rule {
				t.Fatalf("refusal names rule %q, want %q", e.Rule, tc.rule)
			}
		})
	}
}

// TestNotStrictJSONKeepsTheCanonicalFormsSentinel: a refusal of what the
// canonical form refuses drops the canonical form's text, which names the
// author's map keys, and keeps its sentinel for errors.Is.
func TestNotStrictJSONKeepsTheCanonicalFormsSentinel(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("[", 40) + strings.Repeat("]", 40)
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"a float", docWithWhen(`{"resource":{"labels":{"k":[1.5]}}}`), canon.ErrUnsupportedValue},
		{"keys that fold together", docWithWhen(`{"resource":{"labels":{"k":{"a":1,"A":2}}}}`), canon.ErrUnsupportedValue},
		{"an integer outside the safe range", docWithBundle(`{"id":"p","version":"1","serial":9007199254740992,"maxStaleSeconds":1}`), canon.ErrUnsupportedValue},
		{"nesting past the limit", docWithWhen(`{"resource":{"labels":{"k":` + deep + `}}}`), canon.ErrTooDeep},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := Parse([]byte(tc.doc))
			if !errors.Is(err, ErrNotStrictJSON) || !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %v, want ErrNotStrictJSON wrapping %v", err, tc.want)
			}
			if msg := err.Error(); strings.Contains(msg, " at ") || strings.Contains(msg, "/rules/") {
				t.Fatalf("refusal %s carries the canonical form's pointer", msg)
			}
		})
	}
	_, _, err := Parse([]byte(`{"a": tru}`))
	if !errors.Is(err, ErrNotStrictJSON) || errors.Is(err, canon.ErrUnsupportedValue) || errors.Is(err, canon.ErrTooDeep) {
		t.Fatalf("a syntax error = %v, want ErrNotStrictJSON and neither of the canonical form's sentinels", err)
	}
}

// Every sentinel is a constant: a variable here would not build, and a
// variable could be set to nil from any test in the binary.
const (
	_ sentinel = ErrTooLarge
	_ sentinel = ErrNotStrictJSON
	_ sentinel = ErrWrongType
	_ sentinel = ErrUnknownKey
	_ sentinel = ErrMissingKey
	_ sentinel = ErrEmpty
	_ sentinel = ErrIdentifier
	_ sentinel = ErrReservedKey
	_ sentinel = ErrAPIVersion
	_ sentinel = ErrNotPositive
	_ sentinel = ErrEnum
	_ sentinel = ErrFloor
	_ sentinel = ErrDuplicateRuleID
	_ sentinel = ErrObligationsOnEffect
	_ sentinel = ErrObligationType
	_ sentinel = ErrReason
	_ sentinel = ErrObligationParam
	_ sentinel = ErrObligationValue
)

// TestSentinelsAreDistinct: the refusals are constants of one string type, so
// two with the same text would be one value, and errors.Is could not tell
// their checks apart.
func TestSentinelsAreDistinct(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, s := range sentinels {
		if seen[s.Error()] {
			t.Errorf("two refusals read %q", s)
		}
		seen[s.Error()] = true
	}
	if len(seen) != 20 {
		t.Fatalf("%d sentinels, want 20", len(seen))
	}
}
