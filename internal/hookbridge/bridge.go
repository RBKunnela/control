package hookbridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
)

// Client is the part of the enforcement client the bridge speaks through;
// *enforceclient.Client is one.
type Client interface {
	Admit(ctx context.Context, tool string, args []byte, key string, carry enforceclient.Carry) (enforceclient.Answer, enforceclient.Admission, enforcev1alpha1.AbortCause, error)
	Complete(ctx context.Context, handle string, sent []byte, r enforceclient.Result, toolErr error) (enforcev1alpha1.Ending, error)
	Abort(ctx context.Context, handle string, cause enforcev1alpha1.AbortCause) (enforcev1alpha1.Ending, error)
}

// PreOutcome is what an admit event's reply must say. Its zero value denies.
type PreOutcome struct {
	// Allow lets the runtime run the call as it proposed it; the reply is
	// silence, never a reply that allows, asks, defers or changes the input.
	Allow bool
	// Reason is one line for the runtime to show with a deny. It never
	// holds any part of the tool's input.
	Reason string
	// Err is what went wrong, for the caller's own diagnostics.
	Err error
}

// PostResult is what a completion event came to.
type PostResult int

const (
	// PostFailed is a completion the bridge could not act on: no usable
	// profile, client or store, a wrong phase, or an entry it could not take.
	// It is the zero value.
	PostFailed PostResult = iota
	// PostRecorded is one complete the receiver answered ENDING_RECORDED.
	PostRecorded
	// PostNotRecorded is one complete sent whose answer was not
	// ENDING_RECORDED or was lost. It is never sent again.
	PostNotRecorded
	// PostUnmatched is a completion with no entry: no admit published one,
	// or another completion of the same call took it. Nothing was sent.
	PostUnmatched
	// PostNoInput is a completion that carries no tool input. Nothing was
	// sent; the receiver's sweep closes the handle as abandoned.
	PostNoInput
)

// PostOutcome is what a completion event came to.
type PostOutcome struct {
	Result PostResult
	// Status is the completion status sent, when one was.
	Status enforcev1alpha1.CompletionStatus
	// Ending is how the receiver said the execution ended, when it did.
	Ending enforcev1alpha1.Ending
	Err    error
}

// Pre admits the call an admit event proposes, with the event's tool input
// as the exact bytes and a request key derived from its session and call
// id. Only a full EXECUTE of exactly those bytes allows it, and only once
// the store holds its handle for the completion; anything else denies, and
// an execution the receiver opened that cannot run is aborted.
func Pre(ctx context.Context, p *Profile, ev Event, c Client, s *Store, token string) PreOutcome {
	switch {
	case p == nil || c == nil || s == nil || token == "":
		return PreOutcome{Reason: "the bridge is not configured", Err: ErrNotConfigured}
	case ev.Phase != PhaseAdmit || ev.Input == nil:
		return PreOutcome{Reason: "the event is not an admit with a tool input", Err: ErrNoInput}
	}
	ans, adm, cause, err := c.Admit(ctx, ev.Tool, ev.Input, RequestKey(ev.SessionID, ev.CallID), enforceclient.CarryExactOnly)
	if err != nil {
		out := PreOutcome{Reason: denyReason(ans, cause, err), Err: err}
		if errors.Is(err, enforceclient.ErrAbortOwed) {
			out.Err = errors.Join(err, abort(ctx, c, adm.Handle, cause))
		}
		return out
	}
	if err := s.Publish(token, ev.SessionID, ev.CallID, Entry{Handle: adm.Handle, ExpiresAt: adm.ExpiresAt}); err != nil {
		notSent := enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT
		return PreOutcome{
			Reason: "the call's handle could not be kept for its completion",
			Err:    errors.Join(err, abort(ctx, c, adm.Handle, notSent)),
		}
	}
	return PreOutcome{Allow: true}
}

// Post reports the call a completion event closes: it takes the call's entry
// from the store, sends one complete with the event's tool input as the
// bytes that were sent, and removes the entry. It never aborts: the call ran.
func Post(ctx context.Context, p *Profile, ev Event, c Client, s *Store, token string) PostOutcome {
	switch {
	case p == nil || c == nil || s == nil || token == "":
		return PostOutcome{Err: ErrNotConfigured}
	case ev.Phase != PhaseComplete && ev.Phase != PhaseCompleteFailure:
		return PostOutcome{Err: fmt.Errorf("%w: not a completion", ErrUnknownEvent)}
	}
	claimed, err := s.Claim(token, ev.SessionID, ev.CallID)
	if errors.Is(err, ErrNoEntry) {
		return PostOutcome{Result: PostUnmatched}
	}
	if err != nil {
		return PostOutcome{Err: err}
	}
	if ev.Input == nil {
		return PostOutcome{Result: PostNoInput, Err: s.Remove(claimed)}
	}
	status := completionStatus(ev)
	ending, err := c.Complete(ctx, claimed.Handle, ev.Input, enforceclient.Result{Status: status}, nil)
	out := PostOutcome{Result: PostRecorded, Status: status, Ending: ending, Err: errors.Join(err, s.Remove(claimed))}
	if err != nil {
		out.Result = PostNotRecorded
	}
	return out
}

// completionStatus is what a completion reports. A success is unknown when
// the event says the tool was interrupted; a failure is unknown unless the
// event says it was not, since an interrupted tool may have had its effect.
func completionStatus(ev Event) enforcev1alpha1.CompletionStatus {
	switch {
	case ev.Phase == PhaseComplete && ev.Interrupt != InterruptYes:
		return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS
	case ev.Phase == PhaseCompleteFailure && ev.Interrupt == InterruptNo:
		return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_FAILURE
	}
	return enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNKNOWN
}

func abort(ctx context.Context, c Client, handle string, cause enforcev1alpha1.AbortCause) error {
	if _, err := c.Abort(ctx, handle, cause); err != nil {
		return fmt.Errorf("the abort was not answered: %w", err)
	}
	return nil
}

// denyReason says in one line why an admit did not allow the call. It holds
// only the receiver's reason codes and approval id, each reduced to the
// characters they are minted from.
func denyReason(ans enforceclient.Answer, cause enforcev1alpha1.AbortCause, err error) string {
	switch {
	case errors.Is(err, enforceclient.ErrPending):
		held := "held for approval"
		if id := token(ans.Pending.GetApprovalId(), 128); id != "" {
			held += " " + id
		}
		wait := (ans.Pending.GetRetryAfter().AsDuration() + time.Second - 1) / time.Second
		return fmt.Sprintf("%s; once it is approved, ask again after %ds", held, wait)
	case errors.Is(err, enforceclient.ErrBlocked):
		return "blocked by policy" + codes(ans.Decision.GetReasonCodes())
	case cause == enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER:
		return "the policy allows this call only with a changed input, which this runtime cannot carry"
	case cause == enforcev1alpha1.AbortCause_ABORT_CAUSE_OBLIGATION:
		return "the policy attaches an obligation this bridge cannot honour"
	case errors.Is(err, enforceclient.ErrAbortOwed):
		return "the call was given up before it could run"
	case errors.Is(err, enforceclient.ErrRefused):
		return "the receiver refused the request"
	case errors.Is(err, enforceclient.ErrTransport):
		return "the receiver did not answer"
	case errors.Is(err, enforceclient.ErrMalformedAnswer):
		return "the receiver's answer could not be read"
	}
	return "the call could not be admitted"
}

func codes(cs []string) string {
	const most = 4
	var out []string
	for _, c := range cs {
		if t := token(c, 64); t != "" && len(out) < most {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return " (" + strings.Join(out, ", ") + ")"
}

// token keeps s when it is at most limit characters of [A-Za-z0-9._-], and
// is empty otherwise, so nothing the receiver sends can break the line.
func token(s string, limit int) string {
	if len(s) > limit {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return ""
		}
	}
	return s
}
