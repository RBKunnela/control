package gateway

// Error is a refusal by this package, matched with errors.Is. They are
// constants, so no other code in the binary can reassign one and turn a
// refusal into a pass.
type Error string

// Error returns the refusal's text.
func (e Error) Error() string { return string(e) }

// New's refusals, one per check.
const (
	// ErrMode is the zero mode or a number this build does not declare.
	ErrMode Error = "gateway: no such enforcement mode"
	// ErrModePlanned is a declared mode this build does not enforce yet.
	ErrModePlanned Error = "gateway: this enforcement mode is planned"
	// ErrNoAdapter is a nil adapter.
	ErrNoAdapter Error = "gateway: no adapter"
	// ErrCapability is a mode that needs a capability the adapter does not
	// declare: the plane refuses to start rather than observe while the
	// operator believes it enforces.
	ErrCapability Error = "gateway: the adapter lacks a capability the mode needs"
	// ErrObligation is a declared obligation type outside the catalogue.
	ErrObligation Error = "gateway: a declared obligation type is not in the catalogue"
	// ErrUnauthenticatedBinding is an adapter that binds an end user on a
	// listener that authenticates nobody: there is no user to bind, only a
	// claim.
	ErrUnauthenticatedBinding Error = "gateway: the listener authenticates nobody, so no end user can be bound"
	// ErrRunsMismatch is a runs directory without an adapter that presents
	// runs, or an adapter that presents runs without a runs directory.
	ErrRunsMismatch Error = "gateway: the runs directory and the adapter's runs disagree"
	// ErrNoPolicy is a nil policy source.
	ErrNoPolicy Error = "gateway: no policy source"
	// ErrNoPause is a nil pause source: a plane with no pause file is handed
	// PauseDisabled, so a source nobody set never reads as nothing paused.
	ErrNoPause Error = "gateway: no pause source; a plane without a pause file takes PauseDisabled"
	// ErrNoStops is a nil stop source: a plane with no route is handed
	// StopsDisabled, so a source nobody set never reads as nothing stopped.
	ErrNoStops Error = "gateway: no stop source; a plane without a route takes StopsDisabled"
	// ErrStopsWithoutRuns is a stop source other than StopsDisabled on a
	// plane that serves no opened run: a stop names an opened run, and every
	// call there runs under a run no stop can name.
	ErrStopsWithoutRuns Error = "gateway: a stop source is configured and no runs directory serves opened runs"
	// ErrNoSink is a nil evidence sink: a plane with nowhere to write refuses
	// to start rather than decide unrecorded.
	ErrNoSink Error = "gateway: no evidence sink"
	// ErrNoApprovals is a nil approval store.
	ErrNoApprovals Error = "gateway: no approval store"
	// ErrNoClock is a nil clock.
	ErrNoClock Error = "gateway: no clock"
	// ErrNoIDSource is a nil id source.
	ErrNoIDSource Error = "gateway: no id source"
	// ErrIDSource is an id source that returned an empty id, or the same id
	// twice, when New asked it for two: events, decisions and executions are
	// told apart by those ids.
	ErrIDSource Error = "gateway: the id source returned an empty or a repeated id"
	// ErrMaxHeld is a zero or negative bound on held requests: every held
	// request is kept in memory until it is resumed or expires.
	ErrMaxHeld Error = "gateway: the bound on held requests has to be positive"
	// ErrMaxHeldPerRun is a negative bound on the requests one run holds.
	ErrMaxHeldPerRun Error = "gateway: the bound on one run's held requests cannot be negative"
	// ErrMaxOpen is a zero or negative bound on open executions: every
	// execution handed out is kept in memory until it is closed or aborted.
	ErrMaxOpen Error = "gateway: the bound on open executions has to be positive"
	// ErrMaxRuns is a zero or negative bound on runs: every run's flow state
	// is kept in memory until the plane stops.
	ErrMaxRuns Error = "gateway: the bound on runs has to be positive"
	// ErrApprovalTTL is a zero or negative approval lifetime: an approval
	// with no expiry is expired.
	ErrApprovalTTL Error = "gateway: the approval lifetime has to be positive"
	// ErrReconcileMax is a negative bound on the entries a reconciliation
	// reads.
	ErrReconcileMax Error = "gateway: the bound on a reconciliation cannot be negative"
	// ErrRetryAfter is a zero or negative retry interval.
	ErrRetryAfter Error = "gateway: the retry interval has to be positive"
	// ErrNoDecisionPoint is a policy that reads the external decision
	// point's answer with no decision point configured: every call its veto
	// covers would be blocked as unanswered.
	ErrNoDecisionPoint Error = "gateway: the policy reads an external decision point and none is configured"
	// ErrDecisionPointUnused is a decision point no rule of the policy
	// consults: the operator would believe it vetoes what it never sees.
	ErrDecisionPointUnused Error = "gateway: a decision point is configured and no rule consults it"
	// ErrDecisionPointID is a decision point with no identifier, or an
	// identifier with no decision point.
	ErrDecisionPointID Error = "gateway: a decision point and its identifier are configured together"
	// ErrDecisionTimeout is a decision point with a zero or negative
	// deadline, or a deadline with no decision point.
	ErrDecisionTimeout Error = "gateway: a decision point's deadline has to be positive, and set only with one"
)

// Refusals of the approval store.
const (
	// ErrNoApproval is a binding nothing approves: nothing held, or held and
	// not yet decided.
	ErrNoApproval Error = "gateway: no approval for this binding"
	// ErrApprovalConsumed is an approval an earlier execution already used.
	ErrApprovalConsumed Error = "gateway: the approval was consumed"
	// ErrApprovalExpired is an approval past its expiry at the clock it was
	// checked against.
	ErrApprovalExpired Error = "gateway: the approval has expired"
	// ErrApprovalRejected is an approval an approver refused.
	ErrApprovalRejected Error = "gateway: the approval was rejected"
	// ErrMultiUse is an approval record marked multi-use, which this plane
	// does not honour: it consumes an approval once.
	ErrMultiUse Error = "gateway: a multi-use approval is not honoured"
	// ErrZeroTime is a clock reading of zero, which would pass every expiry.
	ErrZeroTime Error = "gateway: the clock reads zero"
	// ErrInvalidHold is a held request with no approval, no request id, no
	// binding, no envelope or no decision, which nothing could resume.
	ErrInvalidHold Error = "gateway: a held request needs an approval, a request id, a binding, an envelope and a decision"
	// ErrAlreadyHeld is a second hold of one request id under one binding.
	ErrAlreadyHeld Error = "gateway: this request is already held under this binding"
	// ErrApprovalAnswered is an answer to an approval that was answered, or
	// consumed, already.
	ErrApprovalAnswered Error = "gateway: the approval was answered already"
	// ErrApprovalAnswer is an answer that is neither APPROVED with an
	// approver nor REJECTED.
	ErrApprovalAnswer Error = "gateway: an answer is APPROVED with an approver, or REJECTED"
	// ErrResolution is a resolution a store may not be told to write: only
	// Consume marks a record spent, and a record is never unresolved again.
	ErrResolution Error = "gateway: a store resolves a record as not resumed and nothing else"
)

// Refusals of the hold journal.
const (
	// ErrHoldEntry is an entry that could not be recorded as a hold: one
	// missing a field the close of its trail needs, or in any state but held,
	// which is the only state a hold is recorded in.
	ErrHoldEntry Error = "gateway: a journal entry is recorded as held, with its ids, its position, its binding, its approval and its expiry"
	// ErrHoldRecorded is a second entry under one request id.
	ErrHoldRecorded Error = "gateway: this request has an entry in the journal already"
	// ErrNoHoldEntry is a request the journal holds no entry for.
	ErrNoHoldEntry Error = "gateway: the journal holds no entry for this request"
	// ErrHoldFlip is a flip a journal refuses: out of a state that is not
	// held, or into one that is not resuming or closing. An entry leaves held
	// once, and what it leaves it for is what the plane is about to write.
	ErrHoldFlip Error = "gateway: an entry leaves held once, for resuming or for closing"
	// ErrHoldMaybeRecorded is a record that failed after its entry may have
	// been filed: the caller treats the entry as filed.
	ErrHoldMaybeRecorded Error = "gateway: the record failed, and the entry may be filed"
)

// ErrUnclassified is a translation that could build every part of an
// envelope but the effect class, because nothing classifies the operation the
// call names. An adapter wraps it in Admission.Refusal beside that envelope,
// and the plane blocks the call with ACTION_UNCLASSIFIED in every mode but
// OBSERVE.
const ErrUnclassified Error = "gateway: nothing classifies the operation this call names"

// Close's and Abort's refusals.
const (
	// ErrNotMinted is a Disposition this pipeline did not hand out for an
	// execution, or one it closed already. Only what Admit minted names a
	// trail and an authorized digest the plane vouches for.
	ErrNotMinted Error = "gateway: this pipeline minted no open execution for the disposition"
	// ErrExecutedArgsMismatch is a closing whose sent bytes digest differently
	// from the authorized arguments. The closing record says so, and the
	// plane, or after CloseReported through a cooperative adapter the
	// execution's opened run, takes no further material call.
	ErrExecutedArgsMismatch Error = "gateway: the executed arguments differ from the authorized ones"
	// ErrNothingSent is a Close with nil sent bytes. A call the adapter did not
	// send is aborted, never closed: a closing record says what ran.
	ErrNothingSent Error = "gateway: Close takes the bytes that were sent; a call that was not sent is aborted"
	// ErrAbortCause is an AbortCause this build does not declare.
	ErrAbortCause Error = "gateway: no such abort cause"
	// ErrNotRecorded wraps the sink's refusal of a closing, an aborting or an
	// abandoning record, so a caller tells a record that did not land from one
	// that did and says the arguments differed.
	ErrNotRecorded Error = "gateway: the sink refused the record"
)

// ErrUnbuilt is an operation this build does not perform yet. It fails closed:
// a caller blocks the call or, after an effect, delivers the result and stops
// taking material calls.
const ErrUnbuilt Error = "gateway: not built in this version"
