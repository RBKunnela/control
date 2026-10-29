package adapterkit_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

// singleChain reports whether err reaches its end through single wraps only.
func singleChain(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if _, joined := err.(interface{ Unwrap() []error }); joined {
			return false
		}
	}
	return true
}

func TestUnclassifiedNeverJoinsTheTwoCauses(t *testing.T) {
	why := fmt.Errorf("%w: no entry names it", gateway.ErrUnclassified)
	lacks := &contract.ValidationError{Field: "action.effect", Err: contract.ErrMissingField}
	hash := &contract.ValidationError{Field: "arguments.canonical_hash", Err: fmt.Errorf("%w: too deep", contract.ErrInvalidValue)}
	tooLarge := &contract.ValidationError{Field: "action.name", Err: contract.ErrTooLarge}
	for _, tc := range []struct {
		name          string
		validated     error
		why           error
		want          error
		wantUnclassed bool
	}{
		{"validation passed", nil, why, why, true},
		{"only the effect is missing", lacks, why, why, true},
		{"the arguments did not hash", hash, why, hash, false},
		{"a field is past its bound", tooLarge, why, tooLarge, false},
		{"another field is missing", &contract.ValidationError{Field: "action.name", Err: contract.ErrMissingField}, why, nil, false},
		{"the effect is invalid, not missing", &contract.ValidationError{Field: "action.effect", Err: contract.ErrInvalidEnum}, why, nil, false},
		{"the missing effect beside another refusal", errors.Join(lacks, contract.ErrTooLarge), why, nil, false},
		{"the missing effect wrapped", fmt.Errorf("adapter: %w", lacks), why, nil, false},
	} {
		got := adapterkit.Unclassified(tc.validated, tc.why)
		if tc.want != nil && got != tc.want { //nolint:errorlint // identity: the very value handed in
			t.Errorf("%s: Unclassified = %v, want %v itself", tc.name, got, tc.want)
		}
		if tc.want == nil && got != tc.validated { //nolint:errorlint // identity: the very value handed in
			t.Errorf("%s: Unclassified = %v, want the validation refusal itself", tc.name, got)
		}
		if is := errors.Is(got, gateway.ErrUnclassified); is != tc.wantUnclassed {
			t.Errorf("%s: carries ErrUnclassified = %v, want %v", tc.name, is, tc.wantUnclassed)
		}
		if !singleChain(got) && tc.validated == nil {
			t.Errorf("%s: Unclassified joined causes: %v", tc.name, got)
		}
	}
}

// TestUnclassifiedRefusesAWhyThatLacksTheSentinel: a cause that does not say
// nothing classifies the call is returned as it is, and the pipeline refuses
// the call for it; only no cause at all is the bare sentinel.
func TestUnclassifiedRefusesAWhyThatLacksTheSentinel(t *testing.T) {
	for _, why := range []error{errors.New("two upstreams list it"), errors.Join(errors.New("a"), errors.New("b")), contract.ErrTooLarge} {
		got := adapterkit.Unclassified(nil, why)
		if got != why { //nolint:errorlint // identity: the very value handed in
			t.Errorf("Unclassified(nil, %v) = %v, want the cause itself", why, got)
		}
		if errors.Is(got, gateway.ErrUnclassified) {
			t.Errorf("Unclassified(nil, %v) = %v, which claims nothing classifies the call", why, got)
		}
	}
	if got := adapterkit.Unclassified(nil, nil); got != gateway.ErrUnclassified { //nolint:errorlint // identity: the sentinel itself
		t.Errorf("Unclassified(nil, nil) = %v, want ErrUnclassified", got)
	}
}
