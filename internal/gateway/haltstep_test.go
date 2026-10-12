package gateway_test

import (
	"context"
	"errors"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// haltRaiser raises one halt from an execution the test admitted earlier.
type haltRaiser struct {
	name    string
	raise   func(t *testing.T, h *harness, earlier gateway.Disposition)
	verdict controlv1.Verdict
	code    string
}

var successResult = result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)

// planeHalts raise a halt of the whole plane: a mismatch Close reports, and a
// closing record the sink refuses.
var planeHalts = []haltRaiser{
	{"the plane's mismatch halt", func(t *testing.T, h *harness, earlier gateway.Disposition) {
		t.Helper()
		if err := h.p.Close(context.Background(), earlier, []byte(`{"amount":2}`), successResult); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
			t.Fatalf("Close with other bytes = %v, want ErrExecutedArgsMismatch", err)
		}
	}, verdictDeny, codeExecutedArgsMismatch},
	{"the plane's sink halt", func(t *testing.T, h *harness, earlier gateway.Disposition) {
		t.Helper()
		h.sink.refuseKind(kindCompleted)
		if err := h.p.Close(context.Background(), earlier, earlier.AuthorizedArgs, successResult); !errors.Is(err, errSink) {
			t.Fatalf("Close under a refused closing record = %v, want the sink's error", err)
		}
	}, verdictIndeterminate, codeEvidenceUnavailable},
}

// runHalt raises the halt of the earlier execution's own opened run.
var runHalt = haltRaiser{"the run's own halt", func(t *testing.T, h *harness, earlier gateway.Disposition) {
	t.Helper()
	if err := h.p.CloseReported(context.Background(), earlier, []byte(`{"amount":2}`), successResult); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("CloseReported with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
}, verdictDeny, codeExecutedArgsMismatch}

// executed admits a and fails the test unless it was handed out.
func executed(t *testing.T, h *harness, a gateway.Admission) gateway.Disposition {
	t.Helper()
	d := h.admitA(a)
	if d.ExecutionID == "" {
		t.Fatalf("setup: %s was not handed out: %s %v", a.Envelope.GetRequestId(), d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	return d
}

// quietWrite is a write of id under root whose trusted, public result raises
// nothing.
func quietWrite(requestID, id, root string) gateway.Admission {
	a := writeIn(requestID, id, root, []byte(`{"amount":1}`))
	a.ResultTrust, a.ResultSensitivity = controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL, sensPublic
	return a
}

// raisingWrite is a write of run-a under root-1 whose untrusted, confidential
// result raises the root.
func raisingWrite(requestID string) gateway.Admission {
	a := writeIn(requestID, "run-a", "root-1", []byte(`{}`))
	a.ResultTrust, a.ResultSensitivity = 0, sensConfidential
	return a
}

// TestAHaltRaisedDuringTheRaiseBlocksTheCall: a halt that covers a material
// call, raised while the raise of its run's root waits on the lock, blocks the
// call before it is recorded as started, as a pause does.
func TestAHaltRaisedDuringTheRaiseBlocksTheCall(t *testing.T) {
	for _, halt := range append([]haltRaiser{runHalt}, planeHalts...) {
		t.Run(halt.name, func(t *testing.T) {
			runs := newRuns("root-1")
			h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(runs), cooperative)
			earlier := executed(t, h, quietWrite("w-1", "run-a", "root-1"))
			runs.onRaise = func() { halt.raise(t, h, earlier) }
			d := h.admitA(raisingWrite("w-2"))
			expectPlaneBlock(t, h, d, halt.verdict, halt.code)
			if s := h.p.Stats(); s.Executed != 1 || s.Open != 0 || runs.raises != 1 {
				t.Errorf("Stats: %d executed, %d open, %d raise(s); want only the earlier write run and the root raised once", s.Executed, s.Open, runs.raises)
			}
		})
	}
}

// TestAnotherRunsHaltRaisedDuringTheRaiseBlocksNothing: the halt of one run
// raised during the raise of another run's call leaves that call running.
func TestAnotherRunsHaltRaisedDuringTheRaiseBlocksNothing(t *testing.T) {
	runs := newRuns("root-1", "root-b")
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(runs), cooperative)
	earlier := executed(t, h, quietWrite("b-1", "run-b", "root-b"))
	runs.onRaise = func() { runHalt.raise(t, h, earlier) }
	if d := h.admitA(raisingWrite("w-2")); d.Action != core.Execute {
		t.Errorf("run-a's write under run-b's halt: %s %v, want Execute", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	if s := h.p.Stats(); s.RunsHalted != 1 || s.Halted {
		t.Errorf("Stats = %+v; want run-b halted alone", s)
	}
}

// TestAHaltRaisedDuringTheLastAppendBlocksTheStart: a halt raised while a
// material call's POLICY_DECIDED is appended blocks it before an execution
// is handed out.
func TestAHaltRaisedDuringTheLastAppendBlocksTheStart(t *testing.T) {
	for _, halt := range planeHalts {
		t.Run(halt.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites))
			earlier := executed(t, h, admission(requestNamed(writeEnvelope(), "w-1"), []byte(`{"amount":1}`)))
			h.sink.hook(kindDecided, func() {
				h.sink.hook(kindDecided, nil)
				halt.raise(t, h, earlier)
			})
			d := h.admit(requestNamed(writeEnvelope(), "w-2"), []byte(`{}`))
			expectPlaneBlock(t, h, d, halt.verdict, halt.code)
			if s := h.p.Stats(); s.Executed != 1 || s.Open != 0 {
				t.Errorf("Stats: %d executed, %d open; want only the earlier write run", s.Executed, s.Open)
			}
		})
	}
}

// TestAHaltRaisedDuringTheApprovalLookupBlocksTheResume: a halt raised while
// the store looks an approved hold up blocks the retry before its approval is
// consumed, and the hold stands.
func TestAHaltRaisedDuringTheApprovalLookupBlocksTheResume(t *testing.T) {
	for _, halt := range planeHalts {
		t.Run(halt.name, func(t *testing.T) {
			var store *stepStore
			h := build(t, modeEnforce, snapshot(t, allowWrites, approveRefunds), withStepStore(&store))
			earlier := executed(t, h, admission(requestNamed(writeEnvelope(), "w-1"), []byte(`{"amount":1}`)))
			first := hold(t, h)
			if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			store.onFind = func() { halt.raise(t, h, earlier) }
			d := h.admit(retry(t, "req-2"), refundArgs())
			expectPlaneBlock(t, h, d, halt.verdict, halt.code)
			if n := store.consumed.Load(); n != 0 {
				t.Errorf("the blocked retry consumed %d approval(s)", n)
			}
			if s := h.p.Stats(); s.Executed != 1 || s.Held != 1 {
				t.Errorf("Stats: %d executed, %d held; want only the earlier write run and the hold standing", s.Executed, s.Held)
			}
		})
	}
}
