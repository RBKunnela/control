package mcp

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/rules"
)

// The obligation type the adapter applies, with its conformance tests. The
// pipeline applies the ones that read only the envelope or rewrite the
// arguments; the kernel refuses an obligation outside the union of the two
// sets as OBLIGATION_NOT_UNDERSTOOD.
const (
	obligationShortenTimeout = "shorten_timeout"

	paramMS = "ms"
)

// applies is each type the adapter applies, in the order it declares them.
// The parameters each reads are the catalogue's.
var applies = []string{obligationShortenTimeout}

// AppliedObligations returns the obligation types the adapter applies to a
// call it sends, which it declares to the kernel as applicable.
func AppliedObligations() []string {
	return slices.Clone(applies)
}

// applied is what the obligations of a decision demand of the send.
type applied struct {
	timeout time.Duration
}

// applyObligations reads every obligation and returns what the send has to
// honour, or the obligation the call fails: a non-advisory one the adapter
// cannot satisfy stops it. An advisory obligation that fails is skipped and
// the call proceeds.
func applyObligations(obligations []*controlv1.Obligation) (applied, error) {
	var out applied
	for _, o := range obligations {
		err := applyOne(o, &out)
		if err != nil && !o.GetAdvisory() {
			return applied{}, fmt.Errorf("%s: %w", o.GetType(), err)
		}
	}
	return out, nil
}

func applyOne(o *controlv1.Obligation, out *applied) error {
	if err := onlyParams(o); err != nil {
		return err
	}
	switch o.GetType() {
	case obligationShortenTimeout:
		return shorten(o.GetParams(), out)
	default:
		return errors.New("not applied by this adapter")
	}
}

// onlyParams refuses a parameter outside the ones the catalogue declares for
// the obligation's type: a parameter nobody read would be an instruction
// nobody followed. A bundle signed without the catalogue's check can still
// carry one.
func onlyParams(o *controlv1.Obligation) error {
	if !slices.Contains(applies, o.GetType()) {
		return errors.New("not applied by this adapter")
	}
	known, ok := rules.ParamNames(o.GetType())
	if !ok {
		return errors.New("not an obligation type of the catalogue")
	}
	for key := range o.GetParams() {
		if !slices.Contains(known, key) {
			return fmt.Errorf("parameter %q is not one this adapter applies", key)
		}
	}
	return nil
}

// shorten reads ms as a positive integer and keeps the shortest timeout. A
// value past what a duration holds is refused: multiplied, it would wrap to
// no bound or to one nobody wrote.
func shorten(params map[string]string, out *applied) error {
	ms, err := strconv.ParseInt(params[paramMS], 10, 64)
	if err != nil || ms <= 0 {
		return fmt.Errorf("%s is not a positive integer", paramMS)
	}
	if ms > int64(math.MaxInt64/time.Millisecond) {
		return fmt.Errorf("%s is longer than a duration holds", paramMS)
	}
	d := time.Duration(ms) * time.Millisecond
	if out.timeout == 0 || d < out.timeout {
		out.timeout = d
	}
	return nil
}
