package enforceclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	ans := Answer{Outcome: enforcev1alpha1.Outcome_OUTCOME_BLOCK}
	if err := ctx.Err(); err != nil {
		return ans, err
	}
	resp := &enforcev1alpha1.AdmitResponse{}
	if err := c.post(ctx, PathAdmit, &enforcev1alpha1.AdmitRequest{Tool: tool, Arguments: args}, resp); err != nil {
		return ans, err
	}
	ans.Decision = resp.GetDecision()
	switch resp.GetOutcome() {
	case enforcev1alpha1.Outcome_OUTCOME_EXECUTE:
	case enforcev1alpha1.Outcome_OUTCOME_PENDING:
		ans.Outcome, ans.Pending = enforcev1alpha1.Outcome_OUTCOME_PENDING, resp.GetPending()
		return ans, ErrPending
	default:
		return ans, ErrBlocked
	}
	ex := resp.GetExecution()
	if ex.GetHandle() == "" {
		return ans, fmt.Errorf("%w: an EXECUTE answer with no handle", ErrMalformedAnswer)
	}
	ans.Outcome = enforcev1alpha1.Outcome_OUTCOME_EXECUTE
	authorized := ex.GetAuthorizedArguments()
	switch {
	case len(ex.GetObligations()) > 0:
		return c.abort(ctx, ans, ex.GetHandle(), enforcev1alpha1.AbortCause_ABORT_CAUSE_OBLIGATION)
	case len(authorized) == 0 && len(args) > 0:
		return c.abort(ctx, ans, ex.GetHandle(), enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER)
	case ctx.Err() != nil:
		return c.abort(ctx, ans, ex.GetHandle(), enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT)
	}
	return c.run(ctx, ans, ex.GetHandle(), authorized, exec)
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
	req := &enforcev1alpha1.CompleteRequest{
		Handle:                 handle,
		SentArguments:          authorized,
		Status:                 completionStatus(res.Status, err),
		StartedAt:              timestamppb.New(res.StartedAt),
		EndedAt:                timestamppb.New(res.EndedAt),
		ResultHash:             res.ResultHash,
		SideEffectConfirmation: res.SideEffectConfirmation,
	}
	resp := &enforcev1alpha1.CompleteResponse{}
	if cerr := c.post(ctx, PathComplete, req, resp); cerr != nil {
		if r, ok := refusal(cerr); ok {
			ans.Ending = r.Ending
		}
		return ans, errors.Join(err, cerr)
	}
	ans.Ending = resp.GetEnding()
	if ans.Ending != enforcev1alpha1.Ending_ENDING_RECORDED {
		return ans, errors.Join(err, fmt.Errorf("%w: %s", ErrNotRecorded, ans.Ending))
	}
	return ans, err
}

// completionStatus is what a complete reports. An exec that returned an
// error could not tell whether the effect happened, so only TIMEOUT or
// UNKNOWN goes with one; a status this contract does not declare is UNKNOWN.
func completionStatus(s enforcev1alpha1.CompletionStatus, err error) enforcev1alpha1.CompletionStatus {
	if err != nil {
		if s == enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_TIMEOUT {
			return s
		}
		return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNKNOWN
	}
	switch s {
	case enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS,
		enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_FAILURE,
		enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_TIMEOUT,
		enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_CANCELLED,
		enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNKNOWN:
		return s
	}
	return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNKNOWN
}

func (c *Client) abort(ctx context.Context, ans Answer, handle string, cause enforcev1alpha1.AbortCause) (Answer, error) {
	resp := &enforcev1alpha1.AbortResponse{}
	if err := c.post(ctx, PathAbort, &enforcev1alpha1.AbortRequest{Handle: handle, Cause: cause}, resp); err != nil {
		if r, ok := refusal(err); ok {
			ans.Ending = r.Ending
		}
		return ans, errors.Join(fmt.Errorf("%w: %s", ErrAborted, cause), err)
	}
	ans.Ending = resp.GetEnding()
	return ans, fmt.Errorf("%w: %s", ErrAborted, cause)
}
