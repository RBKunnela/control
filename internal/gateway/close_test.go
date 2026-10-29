package gateway_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// TestCloseRecordsTheResultsStatus: a failed result closes with
// ACTION_FAILED, and the record carries the executed digest.
func TestCloseRecordsTheResultsStatus(t *testing.T) {
	for status, kind := range map[controlv1.ResultStatus]controlv1.EventKind{
		controlv1.ResultStatus_RESULT_STATUS_SUCCESS:     kindCompleted,
		controlv1.ResultStatus_RESULT_STATUS_FAILURE:     kindFailed,
		controlv1.ResultStatus_RESULT_STATUS_UNKNOWN:     kindFailed,
		controlv1.ResultStatus_RESULT_STATUS_UNSPECIFIED: kindFailed,
	} {
		h := build(t, modeEnforce, snapshot(t, allowWrites))
		d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
		if err := h.p.Close(context.Background(), d, []byte(`{"k":1}`), result(status)); err != nil {
			t.Errorf("%s: Close = %v", status, err)
		}
		events := h.events()
		decided := events[1].GetDecision().GetActionDigest()
		if got := events[len(events)-1]; got.GetKind() != kind || decided == "" || got.GetResult().GetExecutedActionDigest() != decided {
			t.Errorf("%s: the closing record is %s with digest %q; want %s with the digest POLICY_DECIDED recorded, %q", status, got.GetKind(), got.GetResult().GetExecutedActionDigest(), kind, decided)
		}
		if err := evidence.ValidateChain(events); err != nil {
			t.Errorf("%s: ValidateChain: %v", status, err)
		}
	}
}

// TestCloseRecordsAMismatchAndHaltsMaterialCalls: bytes that digest
// differently from the authorized ones close with ACTION_FAILED naming
// EXECUTED_ARGS_MISMATCH, are returned as ErrExecutedArgsMismatch, counted,
// and every later material call is blocked while a read still runs.
func TestCloseRecordsAMismatchAndHaltsMaterialCalls(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites))
	d := h.admit(writeEnvelope(), []byte(`{"amount":1}`))
	sent := []byte(`{"amount":1000000}`)
	err := h.p.Close(context.Background(), d, sent, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS))
	if !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("Close with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
	events := h.events()
	expectMismatchRecord(t, writeEnvelope(), events[len(events)-1], sent, d.Decision.GetActionDigest())
	if err := evidence.ValidateChain(events); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	s := h.p.Stats()
	if s.Mismatches != 1 || !s.Halted {
		t.Errorf("Stats = %+v; want one mismatch and Halted", s)
	}
	blocked := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, blocked, verdictDeny, codeExecutedArgsMismatch, gateway.PDPType)
	if read := h.admit(readEnvelope(), []byte(`{}`)); read.Action != core.Execute {
		t.Errorf("a read on a plane halted by a mismatch: Action = %d, want Execute", read.Action)
	}
	// Bytes that cannot be digested at all are a mismatch too.
	h = build(t, modeEnforce, snapshot(t, allowWrites))
	d = h.admit(writeEnvelope(), []byte(`{}`))
	if err := h.p.Close(context.Background(), d, []byte(`{"a": 1e400}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Errorf("Close with bytes canon refuses = %v, want ErrExecutedArgsMismatch", err)
	}
}

// expectMismatchRecord asserts closing is ACTION_FAILED naming the mismatch,
// with the action digest of decidedOn with sent, which is not decided, and
// the upstream's own status.
func expectMismatchRecord(t *testing.T, decidedOn *controlv1.ActionEnvelope, closing *controlv1.Event, sent []byte, decided string) {
	t.Helper()
	executed, err := canon.DigestV1(decidedOn, sent)
	if err != nil {
		t.Fatalf("DigestV1: %v", err)
	}
	if closing.GetKind() != kindFailed || closing.GetResult().GetToolProtocolStatus() != codeExecutedArgsMismatch ||
		closing.GetResult().GetExecutedActionDigest() != executed || executed == decided {
		t.Errorf("the closing record = %s %+v; want ACTION_FAILED naming the mismatch and the action digest of the sent bytes, %q", closing.GetKind(), closing.GetResult(), executed)
	}
	if closing.GetResult().GetStatus() != controlv1.ResultStatus_RESULT_STATUS_SUCCESS {
		t.Errorf("the upstream's status was rewritten to %s", closing.GetResult().GetStatus())
	}
}

// TestCloseRefusesWhatItDidNotMint: a Disposition built in this package with
// a matching digest, a blocked one, a pending one and one closed already are
// all refused, and no record is written for them.
func TestCloseRefusesWhatItDidNotMint(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites, approveRefunds))
	sent := []byte(`{"k":1}`)
	forged := gateway.Disposition{Action: core.Execute, AuthorizedArgs: sent, AuthorizedDigest: argumentsHash(t, sent)}
	if err := h.p.Close(context.Background(), forged, sent, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("Close of a forged disposition = %v, want ErrNotMinted", err)
	}
	if err := h.p.Close(context.Background(), gateway.Disposition{}, sent, nil); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("Close of the zero disposition = %v, want ErrNotMinted", err)
	}
	pending := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	if pending.Action != core.AwaitApproval {
		t.Fatalf("the refund: Action = %d", pending.Action)
	}
	if err := h.p.Close(context.Background(), pending, refundArgs(), nil); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("Close of a pending disposition = %v, want ErrNotMinted", err)
	}
	before := len(h.events())
	write := writeEnvelope()
	write.RequestId = "req-write"
	d := h.admit(write, sent)
	if d.Action != core.Execute {
		t.Fatalf("the write: Action = %d, decision %+v", d.Action, d.Decision)
	}
	if err := h.p.Close(context.Background(), d, sent, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.p.Close(context.Background(), d, sent, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("a second Close = %v, want ErrNotMinted", err)
	}
	if got := len(h.events()) - before; got != 4 {
		t.Errorf("the refused closings wrote %d record(s)", got-4)
	}
	if s := h.p.Stats(); s.Halted || s.Mismatches != 0 {
		t.Errorf("a refused closing changed the plane: %+v", s)
	}
}

// expectHalts asserts which of the plane's halts stand, and that Halted is
// either of them.
func expectHalts(t *testing.T, h *harness, mismatch, sink bool) {
	t.Helper()
	if s := h.p.Stats(); s.MismatchHalted != mismatch || s.SinkHalted != sink || s.Halted != (mismatch || sink) {
		t.Errorf("Stats = %+v; want MismatchHalted %v and SinkHalted %v", s, mismatch, sink)
	}
}

// TestASinkThatRefusesTheClosingRecordHaltsUntilAnAppendSucceeds: the sink
// error is returned as is, the plane counts it and takes no material call,
// a read runs only under the risk setting; once the sink takes records again
// the next material call is still blocked by the halt, its own records are
// the append that lifts it, and the call after that runs.
func TestASinkThatRefusesTheClosingRecordHaltsUntilAnAppendSucceeds(t *testing.T) {
	for _, unrecorded := range []bool{false, true} {
		h := build(t, modeEnforce, snapshot(t, allowWrites, allowReads), func(c *gateway.Config) { c.AllowReadsUnrecorded = unrecorded })
		d := h.admit(writeEnvelope(), []byte(`{}`))
		h.sink.fail(true)
		if err := h.p.Close(context.Background(), d, []byte(`{}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, errSink) {
			t.Fatalf("Close under a failing sink = %v, want the sink's error", err)
		}
		if s := h.p.Stats(); !s.Halted || s.SinkFailuresAfterEffect != 1 {
			t.Errorf("Stats = %+v; want Halted and one failure after the effect", s)
		}
		expectHalts(t, h, false, true)
		expectBlock(t, h.admit(requestNamed(writeEnvelope(), "req-2"), []byte(`{}`)), verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		read := h.admit(requestNamed(readEnvelope(), "req-3"), []byte(`{}`))
		if unrecorded && read.Action != core.Execute {
			t.Errorf("under the risk setting a read on a halted plane: Action = %d, want Execute", read.Action)
		}
		if !unrecorded {
			expectBlock(t, read, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		}
		if !h.p.Stats().Halted {
			t.Errorf("unrecorded=%v: a refused append lifted the halt", unrecorded)
		}
		h.sink.fail(false)
		first := h.admit(requestNamed(writeEnvelope(), "req-4"), []byte(`{}`))
		expectBlock(t, first, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
		trail := h.trailOf("req-4")
		expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
		if err := evidence.ValidateChain(trail); err != nil {
			t.Errorf("unrecorded=%v: ValidateChain over the halted call: %v", unrecorded, err)
		}
		if h.p.Stats().Halted {
			t.Errorf("unrecorded=%v: the halted call's own records left the plane halted", unrecorded)
		}
		expectHalts(t, h, false, false)
		if d := h.admit(requestNamed(writeEnvelope(), "req-5"), []byte(`{}`)); d.Action != core.Execute {
			t.Errorf("unrecorded=%v: after an append succeeded a write: Action = %d, want Execute", unrecorded, d.Action)
		}
	}
}

// requestNamed is env under another request id.
func requestNamed(env *controlv1.ActionEnvelope, requestID string) *controlv1.ActionEnvelope {
	env.RequestId = requestID
	return env
}

// TestAMismatchOnAReadHaltsMaterialCallsToo: the halt stands whichever
// call's bytes were not the authorized ones.
func TestAMismatchOnAReadHaltsMaterialCallsToo(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites))
	d := h.admit(readEnvelope(), []byte(`{"q":1}`))
	if err := h.p.Close(context.Background(), d, []byte(`{"q":2}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("Close with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
	expectBlock(t, h.admit(requestNamed(writeEnvelope(), "req-2"), []byte(`{}`)), verdictDeny, codeExecutedArgsMismatch, gateway.PDPType)
	if !h.p.Stats().Halted {
		t.Errorf("a mismatch on a read left the plane taking material calls")
	}
}

// TestAnAppendInFlightDoesNotLiftAHaltRaisedWhileItRan: one closing record is
// in the sink when another one fails; the first returning does not lift the
// halt that failure raised, and the next append that starts after it does.
func TestAnAppendInFlightDoesNotLiftAHaltRaisedWhileItRan(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	first := h.admit(readEnvelope(), []byte(`{}`))
	second := h.admit(requestNamed(readEnvelope(), "req-2"), []byte(`{}`))
	if first.Action != core.Execute || second.Action != core.Execute {
		t.Fatalf("the two reads: %d and %d", first.Action, second.Action)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.sink.hook(kindCompleted, func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	})
	done := make(chan error, 1)
	go func() {
		done <- h.p.Close(context.Background(), first, []byte(`{}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS))
	}()
	<-entered
	h.sink.refuseKind(kindFailed)
	if err := h.p.Close(context.Background(), second, []byte(`{}`), result(controlv1.ResultStatus_RESULT_STATUS_FAILURE)); !errors.Is(err, errSink) {
		t.Fatalf("the second closing under a refusing sink = %v, want the sink's error", err)
	}
	if !h.p.Stats().Halted {
		t.Fatalf("a refused closing record left the plane taking material calls")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the first closing: %v", err)
	}
	if !h.p.Stats().Halted {
		t.Errorf("an append that started before the failure lifted the halt it raised")
	}
	// An append that starts after the failure does lift it.
	if d := h.admit(requestNamed(readEnvelope(), "req-3"), []byte(`{}`)); d.Action != core.Execute {
		t.Fatalf("a read on a plane halted for material calls: Action = %d", d.Action)
	}
	if h.p.Stats().Halted {
		t.Errorf("an append after the failure did not lift the halt")
	}
}

// TestAnEndTheSinkRefusesKeepsTheResumedEntry: an approved call whose closing,
// aborting or abandoning record the sink refuses leaves its trail open, so the
// journal keeps its entry at resuming for a later plane to report; one whose
// record lands leaves the journal empty.
func TestAnEndTheSinkRefusesKeepsTheResumedEntry(t *testing.T) {
	ends := map[string]struct {
		kind controlv1.EventKind
		end  func(*harness, gateway.Disposition) error
	}{
		"close": {kindCompleted, func(h *harness, d gateway.Disposition) error {
			return h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS))
		}},
		"abort": {kindFailed, func(h *harness, d gateway.Disposition) error {
			return h.p.Abort(context.Background(), d, gateway.AbortObligation)
		}},
		"abandon": {kindFailed, func(h *harness, d gateway.Disposition) error {
			return h.p.Abandon(context.Background(), d)
		}},
	}
	for name, e := range ends {
		for _, refused := range []bool{true, false} {
			j := &journalDouble{}
			h := build(t, modeEnforce, snapshot(t, approveRefunds), func(cfg *gateway.Config) { cfg.Journal = j })
			if err := h.store.Answer(hold(t, h).Pending.ApprovalID, approved, "alice", "", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			run := h.admit(retry(t, "req-2"), refundArgs())
			if run.Action != core.Execute {
				t.Fatalf("%s: the approved retry: Action = %d, want Execute", name, run.Action)
			}
			if refused {
				h.sink.refuseKind(e.kind)
			}
			err := e.end(h, run)
			if refused != errors.Is(err, errSink) {
				t.Errorf("%s, refused %v: the end = %v", name, refused, err)
			}
			if refused {
				expectEntry(t, j, gateway.HoldResuming)
			} else {
				expectNoEntry(t, j)
			}
		}
	}
}
