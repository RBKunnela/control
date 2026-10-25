package supervise

import "fmt"

// Error is a refusal by this package, matched with errors.Is.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// The refusals. None quotes the input except a refused source's ids, each
// quoted.
const (
	// ErrProcedure is a procedure document this version does not accept.
	ErrProcedure Error = "supervise: procedure refused"
	// ErrRunID is a run id that is not an opened run's: "run-" and 32
	// lowercase hex digits. A plane's local run is never supervised.
	ErrRunID Error = "supervise: not an opened run's id"
	// ErrInput is an input Evaluate cannot judge a run from.
	ErrInput Error = "supervise: input refused"
)

func (e Error) with(why string) error { return fmt.Errorf("%w: %s", e, why) }
