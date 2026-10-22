package enforce

import (
	"context"
	"errors"
	"net/http"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

const codeMalformed = enforcev1alpha1.ErrorCode_ERROR_CODE_MALFORMED

// admit decides one admit. A slot of the run and the request key are
// reserved before the pipeline is asked and stay reserved while the
// execution they were taken for is open; an admit refused either is refused
// before anything is written.
func (a *Adapter) admit(ctx context.Context, w http.ResponseWriter, r *http.Request, p Pipeline, run gateway.OpenedRun) {
	req, ok := readRequest(a, w, r, decodeAdmit)
	if !ok {
		return
	}
	key := req.GetRequestKey()
	switch code := a.handles.reserve(run.ID, key); code {
	case enforcev1alpha1.ErrorCode_ERROR_CODE_DUPLICATE_REQUEST:
		a.refuse(w, code, "an execution with this request key is open in this run", 0)
		return
	case enforcev1alpha1.ErrorCode_ERROR_CODE_UNAVAILABLE:
		a.refuse(w, code, "this run holds as many open executions as the receiver allows", 0)
		return
	}
	adm, tool := a.translate(req, run)
	a.answer(ctx, w, p, run, key, adm, tool, p.Admit(ctx, adm))
}

// answer writes the admit answer for d: EXECUTE under a fresh handle, or
// PENDING, or BLOCK, after aborting what may not be handed out.
func (a *Adapter) answer(ctx context.Context, w http.ResponseWriter, p Pipeline, run gateway.OpenedRun, key string,
	adm gateway.Admission, tool Tool, d gateway.Disposition,
) {
	resp := &enforcev1alpha1.AdmitResponse{Outcome: enforcev1alpha1.Outcome_OUTCOME_BLOCK, Decision: d.Decision}
	runs := d.Action == core.Execute || d.Action == core.ExecuteWithObligations
	switch {
	case runs && untranslated(adm):
		// What could not be translated cannot be authorized, whatever the
		// mode let through.
		a.abortAs(ctx, p, d, gateway.AbortUntranslatable)
		resp.Decision = abortedDecision(d.Decision, gateway.AbortUntranslatable)
	case runs && moved(adm, tool, d):
		a.abortAs(ctx, p, d, gateway.AbortObligation)
		resp.Decision = abortedDecision(d.Decision, gateway.AbortObligation)
	case runs:
		a.execute(ctx, w, p, run, key, d, resp)
		return
	case d.Action == core.AwaitApproval && d.Pending != nil:
		a.counts.pending.Add(1)
		resp.Outcome = enforcev1alpha1.Outcome_OUTCOME_PENDING
		resp.Pending = &enforcev1alpha1.Pending{
			ApprovalId: d.Pending.ApprovalID, ActionDigest: d.Pending.ActionDigest,
			ExpiresAt: timestamppb.New(d.Pending.ExpiresAt), RetryAfter: durationpb.New(d.Pending.RetryAfter),
		}
	default:
		a.counts.blocked.Add(1)
	}
	a.handles.release(run.ID, key)
	write(w, http.StatusOK, resp)
}

// execute hands out d under a fresh handle. The execution stays minting
// while its EXECUTE is written, so nothing abandons it before its client is
// told; a shutdown that began meanwhile leaves it to this admit, which
// abandons it once the answer is out.
func (a *Adapter) execute(ctx context.Context, w http.ResponseWriter, p Pipeline, run gateway.OpenedRun, key string, d gateway.Disposition, resp *enforcev1alpha1.AdmitResponse) {
	now := a.cfg.Clock()
	e := &entry{run: run.ID, d: d, expires: now.Add(a.cfg.ExecutionLifetime), key: key}
	id, ok := a.handles.mint(e)
	if !ok {
		a.release(ctx, p, d)
		a.handles.release(run.ID, key)
		a.refuse(w, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAVAILABLE, "the receiver is shutting down", 0)
		return
	}
	a.counts.executed.Add(1)
	resp.Outcome = enforcev1alpha1.Outcome_OUTCOME_EXECUTE
	resp.Execution = &enforcev1alpha1.Execution{
		Handle: id, ExpiresAt: timestamppb.New(e.expires), AuthorizedArguments: d.AuthorizedArgs, Obligations: toHonour(d.Obligations),
	}
	write(w, http.StatusOK, resp)
	if a.handles.settle(e) {
		a.abandon(ctx, p, []taken{{id, e}})
	}
}

// moved reports whether the authorized bytes name another resource than the
// one the call was decided on, which a rewriting obligation can do: the
// client would act on a resource no decision covered.
func moved(adm gateway.Admission, tool Tool, d gateway.Disposition) bool {
	return tool.ResourceFrom != "" &&
		!adapterkit.SameResource(adm.Arguments, d.AuthorizedArgs, tool.ResourceFrom, adm.Envelope.GetResource().GetId())
}

// abortAs records that an execution was not handed out, under the cause the
// MCP adapter records the same case under, and counts it as a block.
func (a *Adapter) abortAs(ctx context.Context, p Pipeline, d gateway.Disposition, cause gateway.AbortCause) {
	if err := p.Abort(ctx, d, cause); err != nil {
		a.counts.recordsFailed.Add(1)
	}
	a.counts.aborted.Add(1)
	a.counts.blocked.Add(1)
}

// untranslated reports whether the envelope of adm was refused for anything
// but a tool the table does not name, which is the mode's to decide.
func untranslated(adm gateway.Admission) bool {
	return adm.Refusal != nil && !errors.Is(adm.Refusal, gateway.ErrUnclassified)
}

// abortedDecision is d with the code its execution was aborted under after
// its own, so a BLOCK answer never carries the kernel's allow alone.
func abortedDecision(d *controlv1.Decision, cause gateway.AbortCause) *controlv1.Decision {
	out := proto.CloneOf(d)
	if code, ok := cause.Code(); ok && out != nil {
		out.ReasonCodes = append(out.ReasonCodes, code)
	}
	return out
}

// release abandons an execution the adapter will hand to nobody, counting a
// record the pipeline did not confirm.
func (a *Adapter) release(ctx context.Context, p Pipeline, d gateway.Disposition) {
	if err := p.Abandon(ctx, d); err != nil {
		a.counts.recordsFailed.Add(1)
	}
	a.counts.abandoned.Add(1)
}

// toHonour is the obligations a client has to apply: advisory ones stay on
// the recorded decision and out of the answer, since the client aborts on
// any obligation it is handed.
func toHonour(obligations []*controlv1.Obligation) []*controlv1.Obligation {
	var out []*controlv1.Obligation
	for _, ob := range obligations {
		if !ob.GetAdvisory() {
			out = append(out, ob)
		}
	}
	return out
}

// complete closes one execution with what the client reports it sent and
// how it ended. retryable and result_schema_valid are never the client's to
// set, and stay false.
func (a *Adapter) complete(ctx context.Context, w http.ResponseWriter, r *http.Request, p Pipeline, run gateway.OpenedRun) {
	req, ok := readRequest(a, w, r, decodeComplete)
	if !ok {
		return
	}
	e, ok := a.take(w, req.GetHandle(), run)
	if !ok {
		return
	}
	result := &controlv1.ActionResult{
		SchemaVersion: schemaVersion, Status: resultStatus(req.GetStatus()),
		StartedAt: req.GetStartedAt(), EndedAt: req.GetEndedAt(),
		ResultHash: req.GetResultHash(), SideEffectConfirmation: req.GetSideEffectConfirmation(),
	}
	ending := endingOf(e.d, p.CloseReported(ctx, e.d, req.GetSentArguments(), result))
	a.handles.spend(req.GetHandle(), e, ending)
	a.counts.completed.Add(1)
	write(w, http.StatusOK, &enforcev1alpha1.CompleteResponse{Ending: ending})
}

// abort records that the client sent nothing, under the pipeline's cause for
// the client's. The pipeline counts a refused record of it as a failure before
// any effect, so the adapter counts it among its failed records too.
func (a *Adapter) abort(ctx context.Context, w http.ResponseWriter, r *http.Request, p Pipeline, run gateway.OpenedRun) {
	req, ok := readRequest(a, w, r, decodeAbort)
	if !ok {
		return
	}
	e, ok := a.take(w, req.GetHandle(), run)
	if !ok {
		return
	}
	err := p.Abort(ctx, e.d, abortCause(req.GetCause()))
	if errors.Is(err, gateway.ErrNotRecorded) {
		a.counts.recordsFailed.Add(1)
	}
	ending := endingOf(e.d, err)
	a.handles.spend(req.GetHandle(), e, ending)
	a.counts.aborted.Add(1)
	write(w, http.StatusOK, &enforcev1alpha1.AbortResponse{Ending: ending})
}

// readRequest reads and decodes one request body, or answers it malformed
// and reports false.
func readRequest[T any](a *Adapter, w http.ResponseWriter, r *http.Request, decode func([]byte) (T, error)) (T, bool) {
	data, err := readBody(r.Body, a.maxBody)
	var req T
	if err == nil {
		req, err = decode(data)
	}
	if err != nil {
		a.refuse(w, codeMalformed, err.Error(), 0)
		var zero T
		return zero, false
	}
	return req, true
}

// take hands over the open execution handle names in run, or answers why
// not: one answer for a handle unknown, expired, of another run or never
// minted, and how a spent one ended.
func (a *Adapter) take(w http.ResponseWriter, handle string, run gateway.OpenedRun) (*entry, bool) {
	e, code, ending := a.handles.take(handle, run.ID, a.cfg.Clock())
	switch code {
	case enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_UNKNOWN:
		a.refuse(w, code, "no open execution of this run has this handle", 0)
		return nil, false
	case enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_SPENT:
		a.refuse(w, code, "the execution has ended", ending)
		return nil, false
	}
	return e, true
}

// endingOf is how the execution d ended, as the client is told, from what
// closing it returned. The record landed when the pipeline returned nothing,
// or the mismatch it records without ErrNotRecorded; an execution the plane
// handed out unrecorded landed nowhere and is UNRECORDED.
func endingOf(d gateway.Disposition, err error) enforcev1alpha1.Ending {
	landed := err == nil || (errors.Is(err, gateway.ErrExecutedArgsMismatch) && !errors.Is(err, gateway.ErrNotRecorded))
	switch {
	case !landed:
		return enforcev1alpha1.Ending_ENDING_RECORD_FAILED
	case d.Unrecorded:
		return enforcev1alpha1.Ending_ENDING_UNRECORDED
	}
	return enforcev1alpha1.Ending_ENDING_RECORDED
}

// resultStatus is the v1 status a completion status is recorded as; the
// statuses name the same outcomes.
func resultStatus(s enforcev1alpha1.CompletionStatus) controlv1.ResultStatus {
	switch s {
	case enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_SUCCESS:
		return controlv1.ResultStatus_RESULT_STATUS_SUCCESS
	case enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_FAILURE:
		return controlv1.ResultStatus_RESULT_STATUS_FAILURE
	case enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_TIMEOUT:
		return controlv1.ResultStatus_RESULT_STATUS_TIMEOUT
	case enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_CANCELLED:
		return controlv1.ResultStatus_RESULT_STATUS_CANCELLED
	}
	return controlv1.ResultStatus_RESULT_STATUS_UNKNOWN
}

// abortCause is the pipeline's cause for the client's: bytes that differ,
// an obligation it cannot apply, and anything that kept the bytes from
// leaving, which the pipeline records as a call given up before it was sent.
func abortCause(c enforcev1alpha1.AbortCause) gateway.AbortCause {
	switch c {
	case enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER:
		return gateway.AbortArgsMismatch
	case enforcev1alpha1.AbortCause_ABORT_CAUSE_OBLIGATION:
		return gateway.AbortObligation
	}
	return gateway.AbortCancelled
}
