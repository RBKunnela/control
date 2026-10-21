package gateway

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
)

// Close records what execution did: it computes the canonical action digest
// of the authorized envelope with the bytes that were sent, compares it with
// the recorded decision's, and writes the closing record, ACTION_COMPLETED for
// a successful result and ACTION_FAILED for any other, with the trail's
// request id and the execution id the pipeline minted. Nil sent bytes are
// refused with ErrNothingSent, and the execution is aborted rather than left
// open: Admit hands out no nil authorized bytes, so a closing with none is a
// call nothing was sent for, and its record says the comparison did not run. A
// disposition this pipeline did not mint, or closed already, is refused with
// ErrNotMinted. A mismatch is recorded as ACTION_FAILED naming
// EXECUTED_ARGS_MISMATCH, returned as ErrExecutedArgsMismatch, and halts
// material calls until restart; a sink error is returned wrapped in
// ErrNotRecorded and halts them until an append succeeds. The caller delivers
// the result either way. The journal entry of a hold the execution resumed is
// forgotten only once the closing record lands: a trail a refused append left
// open keeps its entry, for a later plane to report as an interrupted close.
func (p *Pipeline) Close(ctx context.Context, d Disposition, sent []byte, result *controlv1.ActionResult) error {
	return p.close(ctx, d, sent, result, false)
}

// CloseReported is Close for bytes a caller reports it sent rather than bytes
// the adapter sent itself (ADR-0051). Through a cooperative adapter it differs
// in what a mismatch halts: the material calls of the execution's opened run,
// until restart, since a plane-wide halt would let any caller stop every run.
// A mismatch of an execution no opened run names, of a run past MaxRuns halted
// runs, or reported through an adapter that is not cooperative, which has no
// caller to report for it, halts the plane as Close does.
func (p *Pipeline) CloseReported(ctx context.Context, d Disposition, sent []byte, result *controlv1.ActionResult) error {
	return p.close(ctx, d, sent, result, true)
}

func (p *Pipeline) close(ctx context.Context, d Disposition, sent []byte, result *controlv1.ActionResult, reported bool) error {
	if p == nil || p.kernel == nil {
		return ErrUnbuilt
	}
	// The call was handed out, so its trail is closed whatever the agent does:
	// a request cancelled since must not leave the trail open, its reservation
	// unspent and material calls halted.
	ctx = context.WithoutCancel(ctx)
	if sent == nil {
		return p.closeUnsent(ctx, d)
	}
	ex := p.take(d.handle)
	if ex == nil {
		return ErrNotMinted
	}
	executed, err := canon.DigestV1(ex.envelope, sent)
	matched := err == nil && executed == ex.digest
	var mismatch error
	if !matched {
		p.counts.mismatched(p.haltScope(ex, reported), p.cfg.MaxRuns)
		mismatch = ErrExecutedArgsMismatch
		if err != nil {
			mismatch = fmt.Errorf("%w: %w", ErrExecutedArgsMismatch, err)
		}
	}
	if ex.unrecorded {
		return mismatch
	}
	gen := p.counts.generation()
	if err := p.sinkAppend(ctx, ex.closing(result, executed, matched)); err != nil {
		p.counts.sinkFailed(true)
		if mismatch != nil {
			return fmt.Errorf("%w: %w: %w", mismatch, ErrNotRecorded, err)
		}
		return fmt.Errorf("%w: %w", ErrNotRecorded, err)
	}
	p.counts.appended(gen)
	p.journalForget(ctx, ex.requestID)
	return mismatch
}

// haltScope is the opened run a mismatch of ex halts, or empty for the plane.
func (p *Pipeline) haltScope(ex *execution, reported bool) string {
	if !reported || p.cfg.Adapter.Capabilities().Enforcement != EnforcementCooperative {
		return ""
	}
	return ex.runID
}

// closeUnsent ends an execution the adapter closed with no bytes: the record
// says nothing was sent, as an abort does, and the refusal is still
// ErrNothingSent, so nothing is left open for a caller that cannot say what
// ran.
func (p *Pipeline) closeUnsent(ctx context.Context, d Disposition) error {
	err := p.abort(ctx, d, codeInvalidFieldValue)
	switch {
	case errors.Is(err, ErrNotMinted):
		return err
	case err != nil:
		return fmt.Errorf("%w: %w", ErrNothingSent, err)
	}
	return ErrNothingSent
}

// closing is the event that closes ex: ACTION_COMPLETED for a successful
// result sent with the authorized bytes, ACTION_FAILED otherwise, carrying
// the executed digest and, on a mismatch, its code in the one status field
// the result has for the protocol's word about what ran.
func (ex *execution) closing(result *controlv1.ActionResult, executed string, matched bool) *controlv1.Event {
	closing := ex.stamp(result)
	closing.ExecutedActionDigest = executed
	if !matched {
		closing.ToolProtocolStatus = statusExecutedArgsMismatch
		return ex.trail.Failed(closing)
	}
	if result.GetStatus() == resultSuccess {
		return ex.trail.Completed(closing)
	}
	return ex.trail.Failed(closing)
}

// AbortCause is why an adapter did not send a call the plane handed to
// execution. The set is closed; each cause is recorded as its registry code.
type AbortCause uint8

const (
	// AbortArgsMismatch is the adapter's digest of the bytes it was about to
	// send differing from the authorized one; nothing was sent.
	AbortArgsMismatch AbortCause = iota + 1
	// AbortObligation is an obligation the adapter applies refusing the call
	// or failing to apply; nothing was sent.
	AbortObligation
	// AbortUnroutable is a call no upstream of the adapter serves, so nothing
	// says where it would have gone and no effect class covers it; nothing
	// was sent.
	AbortUnroutable
	// AbortUntranslatable is a call the adapter cannot express in its
	// protocol from the authorized bytes, because a field it needs is not
	// one the protocol carries; nothing was sent.
	AbortUntranslatable
	// AbortCancelled is a call its agent gave up on before the adapter sent
	// it; nothing was sent. No registry code names a cancel, so it is
	// recorded as the plane's own failure to proceed.
	AbortCancelled
)

// Code is the registry code a cause is recorded as.
func (c AbortCause) Code() (string, bool) {
	switch c {
	case AbortArgsMismatch:
		return codeExecutedArgsMismatch, true
	case AbortObligation:
		return codeObligationNotApplied, true
	case AbortUnroutable:
		return codeActionUnclassified, true
	case AbortUntranslatable:
		return codeInvalidFieldValue, true
	case AbortCancelled:
		return codeEvidenceUnavailable, true
	}
	return "", false
}

// Abort records that the adapter did not send an execution it was handed:
// ACTION_FAILED whose result is BLOCKED, carries the cause's code in
// tool_protocol_status and no executed digest, because no comparison ran. It
// consumes the execution and never halts the plane. It refuses a cause this
// build does not declare with ErrAbortCause, leaving the execution open, and a
// disposition it did not mint, or closed already, with ErrNotMinted; a sink
// error is returned wrapped in ErrNotRecorded, and the journal entry of a hold
// the execution resumed stays, as it does at Close.
func (p *Pipeline) Abort(ctx context.Context, d Disposition, cause AbortCause) error {
	if p == nil || p.kernel == nil {
		return ErrUnbuilt
	}
	code, ok := cause.Code()
	if !ok {
		return fmt.Errorf("%w: %d", ErrAbortCause, cause)
	}
	return p.abort(ctx, d, code)
}

// abort consumes the execution d names and records that nothing was sent:
// ACTION_FAILED whose result is BLOCKED, carries code and no executed digest.
func (p *Pipeline) abort(ctx context.Context, d Disposition, code string) error {
	ctx = context.WithoutCancel(ctx)
	ex := p.take(d.handle)
	if ex == nil {
		return ErrNotMinted
	}
	if ex.unrecorded {
		return nil
	}
	aborted := ex.stamp(nil)
	aborted.Status = resultBlocked
	aborted.ToolProtocolStatus = code
	aborted.EndedAt = timestampOf(p.cfg.Clock())
	gen := p.counts.generation()
	if err := p.sinkAppend(ctx, ex.trail.Failed(aborted)); err != nil {
		p.counts.sinkFailed(false)
		return fmt.Errorf("%w: %w", ErrNotRecorded, err)
	}
	p.counts.appended(gen)
	p.journalForget(ctx, ex.requestID)
	return nil
}

// stamp is result as the closing record carries it, with the trail's request
// id and the minted execution id in place of whatever the adapter put there.
func (ex *execution) stamp(result *controlv1.ActionResult) *controlv1.ActionResult {
	out := &controlv1.ActionResult{SchemaVersion: resultSchemaVersion}
	if result != nil {
		out = proto.CloneOf(result)
	}
	out.RequestId = ex.requestID
	out.ExecutionId = ex.executionID
	return out
}

// Abandon closes an execution that was neither closed nor aborted by its
// expiry: ACTION_FAILED whose result is UNKNOWN, not retryable, carrying
// EXECUTION_ABANDONED in tool_protocol_status and no executed digest, because
// nobody knows whether the call ran and no comparison did (ADR-0051). It
// consumes the execution and never halts the plane, a sink refusal included,
// which is returned wrapped in ErrNotRecorded and leaves the journal entry of
// a hold the execution resumed, as Abort does. A disposition this pipeline did not mint,
// or closed already, is refused with ErrNotMinted.
func (p *Pipeline) Abandon(ctx context.Context, d Disposition) error {
	if p == nil || p.kernel == nil {
		return ErrUnbuilt
	}
	ctx = context.WithoutCancel(ctx)
	ex := p.take(d.handle)
	if ex == nil {
		return ErrNotMinted
	}
	p.counts.add(func(s *Stats) *uint64 { return &s.Abandoned })
	if ex.unrecorded {
		return nil
	}
	abandoned := ex.stamp(nil)
	abandoned.Status = resultUnknown
	abandoned.ToolProtocolStatus = codeExecutionAbandoned
	abandoned.EndedAt = timestampOf(p.cfg.Clock())
	gen := p.counts.generation()
	if err := p.sinkAppend(ctx, ex.trail.Failed(abandoned)); err != nil {
		p.counts.sinkFailedAbandoning()
		return fmt.Errorf("%w: %w", ErrNotRecorded, err)
	}
	p.counts.appended(gen)
	p.journalForget(ctx, ex.requestID)
	return nil
}
