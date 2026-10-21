package enforceclient

import (
	"bytes"
	"context"
	"fmt"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Carry is what a caller can send in place of the bytes it proposed.
type Carry int

const (
	// CarryExactOnly can send only the proposed bytes: an EXECUTE whose
	// authorized bytes differ from them is owed an abort with
	// ABORT_CAUSE_ARGUMENTS_DIFFER. Any value but CarryAuthorized reads as
	// this one.
	CarryExactOnly Carry = iota
	// CarryAuthorized sends whatever bytes the EXECUTE authorized.
	CarryAuthorized
)

// Admission is an execution the receiver opened. Authorized is set only
// when Admit returned no error; with ErrAbortOwed only Handle and ExpiresAt
// are.
type Admission struct {
	Handle     string
	Authorized []byte
	// ExpiresAt is zero when the answer carried no expiry.
	ExpiresAt time.Time
}

// Admit sends one admit for tool with args, and key as its request key when
// key is not empty. It never sends a complete or an abort.
//
// The error is nil only when the caller may run the tool with exactly
// adm.Authorized and must then report the run with one Complete on
// adm.Handle. An error wrapping ErrAbortOwed comes with the cause the caller
// must send in one Abort on adm.Handle; with any other error the client acts
// on no execution, the receiver's sweep closes one it opened, and the cause
// is UNSPECIFIED.
func (c *Client) Admit(ctx context.Context, tool string, args []byte, key string, carry Carry) (Answer, Admission, enforcev1alpha1.AbortCause, error) {
	const none = enforcev1alpha1.AbortCause_ABORT_CAUSE_UNSPECIFIED
	ans := Answer{Outcome: enforcev1alpha1.Outcome_OUTCOME_BLOCK}
	if err := ctx.Err(); err != nil {
		return ans, Admission{}, none, err
	}
	resp := &enforcev1alpha1.AdmitResponse{}
	if err := c.post(ctx, PathAdmit, &enforcev1alpha1.AdmitRequest{Tool: tool, Arguments: args, RequestKey: key}, resp); err != nil {
		return ans, Admission{}, none, err
	}
	ans.Decision = resp.GetDecision()
	switch resp.GetOutcome() {
	case enforcev1alpha1.Outcome_OUTCOME_EXECUTE:
	case enforcev1alpha1.Outcome_OUTCOME_PENDING:
		ans.Outcome, ans.Pending = enforcev1alpha1.Outcome_OUTCOME_PENDING, resp.GetPending()
		return ans, Admission{}, none, ErrPending
	default:
		return ans, Admission{}, none, ErrBlocked
	}
	ex := resp.GetExecution()
	if ex.GetHandle() == "" {
		return ans, Admission{}, none, fmt.Errorf("%w: an EXECUTE answer with no handle", ErrMalformedAnswer)
	}
	ans.Outcome = enforcev1alpha1.Outcome_OUTCOME_EXECUTE
	adm := Admission{Handle: ex.GetHandle()}
	if ts := ex.GetExpiresAt(); ts != nil {
		adm.ExpiresAt = ts.AsTime()
	}
	if cause := owed(ctx, ex, args, carry); cause != none {
		return ans, adm, cause, fmt.Errorf("%w: %s", ErrAbortOwed, cause)
	}
	adm.Authorized = ex.GetAuthorizedArguments()
	return ans, adm, none, nil
}

// owed is the cause of the abort an execution needs instead of a run, or
// UNSPECIFIED when the tool may run.
func owed(ctx context.Context, ex *enforcev1alpha1.Execution, args []byte, carry Carry) enforcev1alpha1.AbortCause {
	authorized := ex.GetAuthorizedArguments()
	switch {
	case len(ex.GetObligations()) > 0:
		return enforcev1alpha1.AbortCause_ABORT_CAUSE_OBLIGATION
	case len(authorized) == 0 && len(args) > 0,
		carry != CarryAuthorized && !bytes.Equal(authorized, args):
		return enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER
	case ctx.Err() != nil:
		return enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT
	}
	return enforcev1alpha1.AbortCause_ABORT_CAUSE_UNSPECIFIED
}

// Complete sends one complete for handle, reporting sent as the bytes that
// left and r's status as completionStatus reads it with toolErr. A zero
// StartedAt or EndedAt is taken from the client's clock.
//
// The error is nil only when the receiver answered ENDING_RECORDED; it never
// includes toolErr.
func (c *Client) Complete(ctx context.Context, handle string, sent []byte, r Result, toolErr error) (enforcev1alpha1.Ending, error) {
	if r.StartedAt.IsZero() {
		r.StartedAt = c.now()
	}
	if r.EndedAt.IsZero() {
		r.EndedAt = c.now()
	}
	req := &enforcev1alpha1.CompleteRequest{
		Handle:                 handle,
		SentArguments:          sent,
		Status:                 completionStatus(r.Status, toolErr),
		StartedAt:              timestamppb.New(r.StartedAt),
		EndedAt:                timestamppb.New(r.EndedAt),
		ResultHash:             r.ResultHash,
		SideEffectConfirmation: r.SideEffectConfirmation,
	}
	resp := &enforcev1alpha1.CompleteResponse{}
	if err := c.post(ctx, PathComplete, req, resp); err != nil {
		return refusedEnding(err), err
	}
	if resp.GetEnding() != enforcev1alpha1.Ending_ENDING_RECORDED {
		return resp.GetEnding(), fmt.Errorf("%w: %s", ErrNotRecorded, resp.GetEnding())
	}
	return resp.GetEnding(), nil
}

// Abort sends one abort for handle with cause, and returns the ending the
// receiver answered or its refusal carried.
func (c *Client) Abort(ctx context.Context, handle string, cause enforcev1alpha1.AbortCause) (enforcev1alpha1.Ending, error) {
	resp := &enforcev1alpha1.AbortResponse{}
	if err := c.post(ctx, PathAbort, &enforcev1alpha1.AbortRequest{Handle: handle, Cause: cause}, resp); err != nil {
		return refusedEnding(err), err
	}
	return resp.GetEnding(), nil
}

func refusedEnding(err error) enforcev1alpha1.Ending {
	if r, ok := refusal(err); ok {
		return r.Ending
	}
	return enforcev1alpha1.Ending_ENDING_UNSPECIFIED
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
