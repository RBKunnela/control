package contract_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/pkg/contract"
)

type checkIDCase struct {
	name, value string
	want        error
}

// checkIDCases are CheckID's vectors with the sentinel each is refused for,
// as literals.
func checkIDCases() []checkIDCase {
	return []checkIDCase{
		{"empty", "", contract.ErrMissingField},
		{"one byte", "a", nil},
		{"exactly 1024 bytes", strings.Repeat("a", 1024), nil},
		{"1024 bytes of three-byte runes and one", strings.Repeat("\u6771", 341) + "a", nil},
		{"1025 bytes", strings.Repeat("a", 1025), contract.ErrTooLarge},
		{"342 runes of 1026 bytes", strings.Repeat("\u6771", 342), contract.ErrTooLarge},
		{"1025 bytes led by a space", " " + strings.Repeat("a", 1024), contract.ErrTooLarge},
		{"a space inside", "req 1", nil},
		{"a leading space", " req-1", contract.ErrInvalidValue},
		{"a trailing space", "req-1 ", contract.ErrInvalidValue},
		{"a leading no-break space", "\u00a0req-1", contract.ErrInvalidValue},
		{"a trailing no-break space", "req-1\u00a0", contract.ErrInvalidValue},
		{"a leading ideographic space", "\u3000req-1", contract.ErrInvalidValue},
		{"a trailing ideographic space", "req-1\u3000", contract.ErrInvalidValue},
		{"a bidi override", "req\u202e1", contract.ErrInvalidValue},
		{"a NUL", "req\x001", contract.ErrInvalidValue},
		{"invalid UTF-8", "req-\xff\xfe", contract.ErrInvalidValue},
	}
}

// TestCheckIDHoldsPresenceTheBoundAndTheRule: the bound is in bytes, not
// runes, and CheckIdentifier's empty string is refused as missing.
func TestCheckIDHoldsPresenceTheBoundAndTheRule(t *testing.T) {
	for _, c := range checkIDCases() {
		t.Run(c.name, func(t *testing.T) {
			err := contract.CheckID(c.value)
			if c.want == nil {
				if err != nil {
					t.Fatalf("CheckID = %v, want nil", err)
				}
				return
			}
			assertRefused(t, err, c.want, "")
			for _, other := range []error{contract.ErrMissingField, contract.ErrTooLarge, contract.ErrInvalidValue} {
				if !errors.Is(c.want, other) && errors.Is(err, other) {
					t.Errorf("CheckID = %v, which matches %v too", err, other)
				}
			}
		})
	}
}

// TestCheckIDIsValidateOnARequiredIdentifier: request_id is required and held
// to the identifier rule and the string bound, so Validate refuses each vector
// as a request_id exactly when CheckID does, for the same sentinel.
func TestCheckIDIsValidateOnARequiredIdentifier(t *testing.T) {
	for _, c := range checkIDCases() {
		t.Run(c.name, func(t *testing.T) {
			e := valid()
			e.RequestId = c.value
			err := contract.Validate(e)
			if c.want == nil {
				if err != nil {
					t.Fatalf("Validate = %v, and CheckID accepts the request id", err)
				}
				return
			}
			assertRefused(t, err, c.want, "request_id")
		})
	}
}

// TestCheckIDRefusalCarriesNoCallerText: an identifier refused for its length
// is as much the caller's as one refused for what it holds.
func TestCheckIDRefusalCarriesNoCallerText(t *testing.T) {
	const marker = "sk_live_HUNTER2"
	for _, s := range []string{
		" " + marker, marker + "\u3000", marker + "\u202e", marker + "\xff",
		strings.Repeat(marker, contract.MaxStringBytes/len(marker)+1),
	} {
		err := contract.CheckID(s)
		if err == nil {
			t.Fatalf("CheckID(%+q) = nil, so this case proves nothing", s)
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("the refusal repeats the caller's string: %v", err)
		}
	}
}
