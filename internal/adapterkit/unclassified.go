package adapterkit

import (
	"errors"

	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

// Unclassified is the refusal of an envelope nothing classifies, from what
// the adapter's own validation of it returned: why when validation refused
// nothing but the effect class nothing gave, and validation's refusal
// otherwise. It never joins the two, since the pipeline reads a join as a
// call refused for the other cause. A why that does not carry
// gateway.ErrUnclassified is returned as it is, and the call is refused for
// it; no why at all is the bare sentinel. The pipeline holds the claim to
// the rules Validate did not reach.
func Unclassified(validated, why error) error {
	if validated != nil && !LacksEffect(validated) {
		return validated
	}
	if why == nil {
		return gateway.ErrUnclassified
	}
	return why
}

// LacksEffect reports whether err is contract.Validate's refusal of an
// envelope with no effect class, which it reaches once the bounds, the schema
// version and the fields every envelope needs have passed, and before the
// values it checks after the effect, which this refusal says nothing about.
// The refusal is err itself: one found inside a wrap or a join could stand
// beside another.
func LacksEffect(err error) bool {
	var ve *contract.ValidationError
	if !errors.As(err, &ve) || error(ve) != err { //nolint:errorlint // identity: the refusal must be err itself, not one inside it
		return false
	}
	return ve.Field == "action.effect" && errors.Is(ve.Err, contract.ErrMissingField)
}
