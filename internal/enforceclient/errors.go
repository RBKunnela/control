package enforceclient

import (
	"fmt"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
)

// Error is a refusal or an outcome of this package, matched with errors.Is.
// They are constants, so no other code can reassign one and turn a refusal
// into a pass.
type Error string

// Error returns the text.
func (e Error) Error() string { return string(e) }

// New's refusals.
const (
	// ErrNoSocket is a configuration without the receiver's socket path.
	ErrNoSocket Error = "enforceclient: no socket path"
	// ErrNoToken is a configuration without a run token.
	ErrNoToken Error = "enforceclient: no run token"
	// ErrNoTimeout is a request timeout that is not positive: a request with
	// no bound could wait forever for a receiver that never answers.
	ErrNoTimeout Error = "enforceclient: the request timeout must be positive"
)

// The outcomes of Call and of Admit, Complete and Abort other than a
// recorded execution.
const (
	// ErrBlocked is an admit answered BLOCK, UNSPECIFIED or an outcome this
	// client does not know; the tool was not run.
	ErrBlocked Error = "enforceclient: the call was blocked"
	// ErrPending is an admit answered PENDING; the tool was not run. The
	// caller resumes with a new Call after Answer.Pending's retry_after.
	ErrPending Error = "enforceclient: the call is held for approval"
	// ErrRefused is a receiver's Error body; errors.As with *RefusalError
	// reads its code.
	ErrRefused Error = "enforceclient: the receiver refused the request"
	// ErrMalformedAnswer is an answer this client cannot read strictly, or
	// one past its bound; nothing is run on it.
	ErrMalformedAnswer Error = "enforceclient: the receiver's answer is malformed"
	// ErrAborted is an execution the client aborted; the tool was not run.
	ErrAborted Error = "enforceclient: the execution was aborted"
	// ErrAbortOwed is an admission the tool must not run on: Admit sent no
	// abort, so the caller sends one with the cause Admit returned.
	ErrAbortOwed Error = "enforceclient: the execution is owed an abort"
	// ErrNotRecorded is a completion the receiver did not answer with
	// ENDING_RECORDED: the tool ran, but no closing record is known to have
	// landed.
	ErrNotRecorded Error = "enforceclient: the closing record did not land"
	// ErrTransport is a request that got no answer.
	ErrTransport Error = "enforceclient: no answer from the receiver"
	// ErrNotSent is what an Exec returns when it knows the bytes never left,
	// so the client aborts instead of completing. An Exec that cannot tell
	// returns any other error, and the client completes UNKNOWN.
	ErrNotSent Error = "enforceclient: the tool was not reached"
)

// RefusalError is a receiver's Error body, answered with a status other
// than 200.
type RefusalError struct {
	Status  int
	Code    enforcev1alpha1.ErrorCode
	Message string
	Ending  enforcev1alpha1.Ending
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("%s: %d %s: %q", ErrRefused, e.Status, e.Code, e.Message)
}

// Is matches ErrRefused.
func (e *RefusalError) Is(target error) bool { return target == ErrRefused }
