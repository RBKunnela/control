package gateway

import (
	"errors"
	"fmt"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// wrapped is an error type of an adapter's own that wraps one cause.
type wrapped struct{ err error }

func (w wrapped) Error() string { return "adapter: " + w.err.Error() }
func (w wrapped) Unwrap() error { return w.err }

// claims says it is every target and wraps nothing.
type claims struct{}

func (claims) Error() string { return "claims" }
func (claims) Is(error) bool { return true }

// joinedOf wraps several causes the way errors.Join does, under a type of
// its own.
type joinedOf []error

func (j joinedOf) Error() string   { return "joined" }
func (j joinedOf) Unwrap() []error { return j }

func TestUnclassifiedOnlyIsOneCauseAlone(t *testing.T) {
	unclassified := fmt.Errorf("%w: no entry names it", ErrUnclassified)
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"the sentinel", ErrUnclassified, true},
		{"the sentinel wrapped", unclassified, true},
		{"wrapped twice", fmt.Errorf("outer: %w", unclassified), true},
		{"wrapped by an adapter type", wrapped{unclassified}, true},
		{"inside a validation error", &contract.ValidationError{Field: "action.effect", Err: unclassified}, true},
		{"another sentinel of the plane", ErrObligation, false},
		{"a contract sentinel", contract.ErrInvalidValue, false},
		{"its text without the sentinel", errors.New(string(ErrUnclassified)), false},
		{"a join with a bound", errors.Join(contract.ErrTooLarge, ErrUnclassified), false},
		{"a join of it alone", errors.Join(ErrUnclassified), false},
		{"a join of it twice", errors.Join(ErrUnclassified, unclassified), false},
		{"two wraps in one", fmt.Errorf("%w: %w", ErrUnclassified, contract.ErrInvalidValue), false},
		{"two wraps in one, reversed", fmt.Errorf("%w: %w", contract.ErrInvalidValue, ErrUnclassified), false},
		{"a join under a single wrap", wrapped{errors.Join(unclassified, contract.ErrMissingField)}, false},
		{"a join type of an adapter's own", joinedOf{unclassified}, false},
		{"a single wrap under a join", errors.Join(wrapped{unclassified}), false},
		{"an error that claims to be every target", claims{}, false},
		{"a claim wrapped", fmt.Errorf("x: %w", claims{}), false},
	} {
		if got := unclassifiedOnly(tc.err); got != tc.want {
			t.Errorf("%s: unclassifiedOnly(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestTranslationOfNamesTheRefusedStateZero(t *testing.T) {
	var zero translation
	if zero != translationRefused {
		t.Fatalf("the zero translation is %d, want refused", zero)
	}
	env := &controlv1.ActionEnvelope{}
	for _, tc := range []struct {
		name string
		in   Admission
		want translation
	}{
		{"whole", Admission{Envelope: env}, translationComplete},
		{"no envelope and no refusal", Admission{}, translationRefused},
		{"no envelope, unclassified", Admission{Refusal: ErrUnclassified}, translationRefused},
		{"unclassified", Admission{Envelope: env, Refusal: ErrUnclassified}, translationUnclassified},
		{"joined", Admission{Envelope: env, Refusal: errors.Join(ErrUnclassified, contract.ErrTooLarge)}, translationRefused},
		{"a contract refusal", Admission{Envelope: env, Refusal: contract.ErrMissingField}, translationRefused},
	} {
		if got := translationOf(tc.in); got != tc.want {
			t.Errorf("%s: translationOf = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// leafOf is the error a fuzz input starts from, and whether it is the
// sentinel alone.
func leafOf(op byte) (bool, error) {
	switch op % 3 {
	case 0:
		return true, ErrUnclassified
	case 1:
		return false, contract.ErrTooLarge
	}
	return false, claims{}
}

// wrapOnce wraps err the way op names, and says whether the result is still
// the sentinel alone: a single wrap keeps that, a join of any kind ends it.
func wrapOnce(alone bool, err error, op byte) (bool, error) {
	switch op % 6 {
	case 0:
		return alone, fmt.Errorf("w: %w", err)
	case 1:
		return alone, wrapped{err}
	case 2:
		return false, errors.Join(err, contract.ErrInvalidValue)
	case 3:
		return false, fmt.Errorf("%w: %w", contract.ErrMissingField, err)
	case 4:
		return false, joinedOf{err}
	}
	return alone, &contract.ValidationError{Field: "f", Err: err}
}

// FuzzUnclassifiedOnly builds an error from ops, one wrap per byte around a
// leaf the first byte names, and keeps its own account of whether the result
// is the sentinel on a chain of single wraps.
func FuzzUnclassifiedOnly(f *testing.F) {
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) == 0 || len(ops) > 64 {
			return
		}
		alone, err := leafOf(ops[0])
		for _, op := range ops[1:] {
			alone, err = wrapOnce(alone, err, op)
		}
		if got := unclassifiedOnly(err); got != alone {
			t.Fatalf("ops %v: unclassifiedOnly(%v) = %v, want %v", ops, err, got, alone)
		}
		if alone && !errors.Is(err, ErrUnclassified) {
			t.Fatalf("ops %v: a chain of single wraps around the sentinel does not reach it", ops)
		}
	})
}
