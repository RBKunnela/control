package gateway_test

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

const codeExecutionAbandoned = "EXECUTION_ABANDONED"

// TestAbandonClosesAnOpenExecutionAsUnknown: an execution nobody completed or
// aborted closes with ACTION_FAILED whose status is UNKNOWN, never success or
// blocked, naming EXECUTION_ABANDONED with no executed digest, since nothing
// was compared; it is consumed, counted, and the plane goes on taking
// material calls.
func TestAbandonClosesAnOpenExecutionAsUnknown(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites))
	d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.p.Abandon(ctx, d); err != nil {
		t.Fatalf("Abandon: %v", err)
	}
	expectAbandoned(t, h.events(), d)
	if s := h.p.Stats(); s.Open != 0 || s.Halted || s.Abandoned != 1 || s.Mismatches != 0 {
		t.Errorf("Stats = %+v; want nothing open, one abandoned and no halt", s)
	}
	if err := h.p.Abandon(context.Background(), d); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("a second Abandon = %v, want ErrNotMinted", err)
	}
	if err := h.p.Close(context.Background(), d, []byte(`{"k":1}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("Close after Abandon = %v, want ErrNotMinted", err)
	}
	if next := h.admit(requestNamed(writeEnvelope(), "req-2"), []byte(`{}`)); next.Action != core.Execute {
		t.Errorf("a write after an abandon: %s %v, want Execute", next.Decision.GetVerdict(), next.Decision.GetReasonCodes())
	}
}

// expectAbandoned asserts the trail ends in the abandoned record of d.
func expectAbandoned(t *testing.T, events []*controlv1.Event, d gateway.Disposition) {
	t.Helper()
	expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindFailed})
	if err := evidence.ValidateChain(events); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	closing := events[len(events)-1].GetResult()
	if closing.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_UNKNOWN || closing.GetToolProtocolStatus() != codeExecutionAbandoned ||
		closing.GetExecutedActionDigest() != "" || closing.GetRetryable() {
		t.Errorf("the abandoned record = %+v; want UNKNOWN naming %s, not retryable, with no executed digest", closing, codeExecutionAbandoned)
	}
	if closing.GetRequestId() != "req-1" || closing.GetExecutionId() != d.ExecutionID || d.ExecutionID == "" ||
		closing.GetSchemaVersion() != "1.0" || closing.GetEndedAt() == nil {
		t.Errorf("the abandoned record = %+v; want the trail's request id, the minted execution id and an end", closing)
	}
}

// TestAbandonRefusesWhatIsNotOpen: a forged disposition, the zero one, a
// pending one, one another pipeline minted, and one closed, aborted or
// abandoned already are refused with ErrNotMinted, write nothing and leave
// the execution that is open alone.
func TestAbandonRefusesWhatIsNotOpen(t *testing.T) {
	ctx := context.Background()
	h := build(t, modeEnforce, snapshot(t, allowWrites, approveRefunds))
	var n atomic.Int64
	other := build(t, modeEnforce, snapshot(t, allowWrites), func(c *gateway.Config) {
		c.NewID = func() string { return "other-" + strconv.FormatInt(n.Add(1), 10) }
	})
	sent := []byte(`{"k":1}`)
	foreign := other.admit(writeEnvelope(), sent)
	if foreign.ExecutionID == "" {
		t.Fatalf("the other plane's write was not handed out: %v", foreign.Decision.GetReasonCodes())
	}
	pending := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	if pending.Action != core.AwaitApproval {
		t.Fatalf("the refund: Action = %d", pending.Action)
	}
	closed, aborted, abandoned := spentThreeWays(t, h, sent)
	open := h.admit(requestNamed(writeEnvelope(), "req-open"), sent)
	before := len(h.events())
	for name, d := range map[string]gateway.Disposition{
		"forged":    {Action: core.Execute, AuthorizedArgs: sent, AuthorizedDigest: argumentsHash(t, sent), ExecutionID: closed.ExecutionID},
		"zero":      {},
		"pending":   pending,
		"foreign":   foreign,
		"closed":    closed,
		"aborted":   aborted,
		"abandoned": abandoned,
	} {
		if err := h.p.Abandon(ctx, d); !errors.Is(err, gateway.ErrNotMinted) {
			t.Errorf("Abandon of the %s disposition = %v, want ErrNotMinted", name, err)
		}
	}
	if got := len(h.events()) - before; got != 0 {
		t.Errorf("the refused abandons wrote %d record(s)", got)
	}
	if h.p.Stats().Open != 1 || other.p.Stats().Open != 1 {
		t.Errorf("open executions: %d here and %d on the other plane; want each still open", h.p.Stats().Open, other.p.Stats().Open)
	}
	if err := h.p.Abandon(ctx, open); err != nil {
		t.Errorf("Abandon of the open execution after the refusals: %v", err)
	}
	if err := (*gateway.Pipeline)(nil).Abandon(ctx, foreign); !errors.Is(err, gateway.ErrUnbuilt) {
		t.Errorf("Abandon on a nil pipeline = %v, want ErrUnbuilt", err)
	}
}

// TestAnAbandonTheSinkRefusesDoesNotHalt: the sink's error is returned
// wrapped in ErrNotRecorded and counted, the execution is consumed all the same, and the plane still takes
// material calls once the sink takes records again, where a refused closing
// of a call that ran halts it.
func TestAnAbandonTheSinkRefusesDoesNotHalt(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites))
	d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
	h.sink.fail(true)
	if err := h.p.Abandon(context.Background(), d); !errors.Is(err, errSink) || !errors.Is(err, gateway.ErrNotRecorded) {
		t.Fatalf("Abandon under a failing sink = %v, want the sink's error wrapped in ErrNotRecorded", err)
	}
	h.sink.fail(false)
	if s := h.p.Stats(); s.Halted || s.Open != 0 || s.SinkFailuresAbandoned != 1 || s.SinkFailuresAfterEffect != 0 || s.Abandoned != 1 {
		t.Errorf("Stats = %+v; want one refused abandon counted as such, nothing open and no halt", s)
	}
	if err := h.p.Abandon(context.Background(), d); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("a second Abandon = %v, want ErrNotMinted", err)
	}
	if next := h.admit(requestNamed(writeEnvelope(), "req-2"), []byte(`{}`)); next.Action != core.Execute {
		t.Errorf("a write after a refused abandon: %s %v, want Execute", next.Decision.GetVerdict(), next.Decision.GetReasonCodes())
	}
}

// TestAnUnrecordedReadIsAbandonedUnrecorded: under the risk setting a read
// whose trail the sink refused writes no abandoning record either, and is
// consumed and counted all the same.
func TestAnUnrecordedReadIsAbandonedUnrecorded(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads), func(c *gateway.Config) { c.AllowReadsUnrecorded = true })
	h.sink.fail(true)
	d := h.admit(readEnvelope(), []byte(`{}`))
	if d.Action != core.Execute {
		t.Fatalf("Action = %d", d.Action)
	}
	h.sink.fail(false)
	asked := len(h.sink.askedFor())
	if err := h.p.Abandon(context.Background(), d); err != nil {
		t.Errorf("Abandon of an unrecorded read = %v", err)
	}
	if n := len(h.sink.askedFor()) - asked; n != 0 {
		t.Errorf("Abandon asked the sink for %d append(s) on a trail it refused", n)
	}
	if s := h.p.Stats(); s.Open != 0 || s.Abandoned != 1 || s.Halted {
		t.Errorf("Stats = %+v; want nothing open, one abandoned and no halt", s)
	}
	if err := h.p.Abandon(context.Background(), d); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("a second Abandon = %v, want ErrNotMinted", err)
	}
}

// spentThreeWays hands out three writes of sent and closes, aborts and
// abandons them, in that order.
func spentThreeWays(t *testing.T, h *harness, sent []byte) (closed, aborted, abandoned gateway.Disposition) {
	t.Helper()
	ctx := context.Background()
	closed = h.admit(requestNamed(writeEnvelope(), "req-closed"), sent)
	aborted = h.admit(requestNamed(writeEnvelope(), "req-aborted"), sent)
	abandoned = h.admit(requestNamed(writeEnvelope(), "req-abandoned"), sent)
	if err := h.p.Close(ctx, closed, sent, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.p.Abort(ctx, aborted, gateway.AbortObligation); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := h.p.Abandon(ctx, abandoned); err != nil {
		t.Fatalf("Abandon: %v", err)
	}
	return closed, aborted, abandoned
}
