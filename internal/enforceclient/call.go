package enforceclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// Result is what the tool reports of one run. A Status that is UNSPECIFIED,
// or a number the contract does not declare, is completed as UNKNOWN; a
// zero StartedAt or EndedAt is taken from the client's clock.
type Result struct {
	Status                 enforcev1alpha1.CompletionStatus
	StartedAt              time.Time
	EndedAt                time.Time
	ResultHash             string
	SideEffectConfirmation string
}

// Exec runs the tool with exactly the authorized bytes. It returns
// ErrNotSent, possibly wrapped, only when it knows the bytes never left; any
// other error means it cannot tell.
type Exec func(ctx context.Context, authorized []byte) (Result, error)

// Answer is what one Call learned.
type Answer struct {
	// Outcome is the admit outcome as this client read it: anything but
	// EXECUTE or PENDING reads as BLOCK.
	Outcome  enforcev1alpha1.Outcome
	Decision *controlv1.Decision
	// Pending is set with OUTCOME_PENDING.
	Pending *enforcev1alpha1.Pending
	// Ran says the tool was run, so an effect may have happened.
	Ran    bool
	Result Result
	// Ending is how the receiver said the execution ended, from a complete
	// or abort answer or from a HANDLE_SPENT refusal.
	Ending enforcev1alpha1.Ending
}

// Call admits tool with args and, only on an EXECUTE answer it can read in
// full, runs exec with exactly the authorized bytes and reports the run with
// one complete. It aborts instead when the execution carries an obligation,
// carries no bytes for a call that proposed some, or ctx ended before exec
// started. It never sends an admit, a complete or an abort twice.
//
// The error is nil only when exec ran, returned no error and the receiver
// answered ENDING_RECORDED. Answer.Ran says whether an effect may have
// happened whatever the error.
func (c *Client) Call(ctx context.Context, tool string, args []byte, exec Exec) (Answer, error) {
	ans, adm, cause, err := c.Admit(ctx, tool, args, "", CarryAuthorized)
	if cause != enforcev1alpha1.AbortCause_ABORT_CAUSE_UNSPECIFIED {
		return c.abort(ctx, ans, adm.Handle, cause)
	}
	if err != nil {
		return ans, err
	}
	return c.run(ctx, ans, adm.Handle, adm.Authorized, exec)
}

// run hands exec its own copy of the authorized bytes, so nothing exec does
// to them changes what complete reports as sent.
func (c *Client) run(ctx context.Context, ans Answer, handle string, authorized []byte, exec Exec) (Answer, error) {
	started := c.now()
	res, err := exec(ctx, slices.Clone(authorized))
	ended := c.now()
	if errors.Is(err, ErrNotSent) {
		return c.abort(ctx, ans, handle, enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT)
	}
	if res.StartedAt.IsZero() {
		res.StartedAt = started
	}
	if res.EndedAt.IsZero() {
		res.EndedAt = ended
	}
	ans.Ran, ans.Result = true, res
	ending, cerr := c.Complete(ctx, handle, authorized, res, err)
	ans.Ending = ending
	if cerr != nil {
		return ans, errors.Join(err, cerr)
	}
	return ans, err
}

func (c *Client) abort(ctx context.Context, ans Answer, handle string, cause enforcev1alpha1.AbortCause) (Answer, error) {
	ending, err := c.Abort(ctx, handle, cause)
	ans.Ending = ending
	if err != nil {
		return ans, errors.Join(fmt.Errorf("%w: %s", ErrAborted, cause), err)
	}
	return ans, fmt.Errorf("%w: %s", ErrAborted, cause)
}
