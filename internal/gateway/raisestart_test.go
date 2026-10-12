package gateway_test

import (
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// raisedCall is a read of run-a under root-1 whose untrusted, confidential
// result raises the root.
func raisedCall() gateway.Admission {
	return under(returning(readOf("r-1", "user-1"), 0, sensConfidential), opened("run-a", "root-1"))
}

// expectRaisedNotStarted: the call is blocked with nothing open and no
// ACTION_STARTED, and the root keeps what the raise wrote into it.
func expectRaisedNotStarted(t *testing.T, h *harness, runs *memRuns) {
	t.Helper()
	if s := h.p.Stats(); s.Open != 0 || s.Executed != 0 {
		t.Errorf("Stats: %d open, %d executed; want none", s.Open, s.Executed)
	}
	if got := runs.state("root-1"); runs.raises != 1 || got.Trusted || got.MaxRead != sensConfidential {
		t.Errorf("root-1 after %d raise(s) = %+v; want it raised once to untrusted CONFIDENTIAL", runs.raises, got)
	}
}

// TestAPausePublishedDuringTheRaiseBlocksTheCall: the raise of an opened run's
// root can wait on a lock, and a pause published meanwhile covers the call
// before it is recorded as started.
func TestAPausePublishedDuringTheRaiseBlocksTheCall(t *testing.T) {
	runs := newRuns("root-1")
	h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(runs))
	h.pause.set(paused(t))
	runs.onRaise = func() { h.pause.set(paused(t, pauseGlobal)) }
	d := h.admitA(raisedCall())
	expectPlaneBlock(t, h, d, verdictDeny, codePaused)
	expectRaisedNotStarted(t, h, runs)
}

// TestAStopPublishedDuringTheRaiseBlocksTheCall: the same with a stop of the
// call's own opened run.
func TestAStopPublishedDuringTheRaiseBlocksTheCall(t *testing.T) {
	runs := newRuns("root-1")
	src := newStopSource(stopped(t))
	h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(runs), withStops(src))
	runs.onRaise = func() { src.set(stopped(t, "run-a")) }
	d := h.admitA(raisedCall())
	expectPlaneBlock(t, h, d, verdictDeny, codeRunStopped)
	expectRaisedNotStarted(t, h, runs)
}

// TestOnlyARaiseThatWroteReadsThePauseAgain: a call whose result the root's
// state covers writes nothing and takes the pause state twice, at admission
// and before it starts; a call whose raise wrote takes it once more after the
// raise.
func TestOnlyARaiseThatWroteReadsThePauseAgain(t *testing.T) {
	cases := []struct {
		name   string
		result controlv1.Sensitivity
		raises int
		reads  int64
	}{
		{"a result the state covers", sensPublic, 0, 2},
		{"a result that raises the state", sensConfidential, 1, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runs := newRuns("root-1")
			runs.states["root-1"] = gateway.RunState{MaxRead: sensPublic}
			h := build(t, modeEnforce, snapshot(t, allowReads), withRuns(runs))
			before := h.pause.calls.Load()
			d := h.admitA(under(returning(readOf("r-1", "user-1"), 0, tc.result), opened("run-a", "root-1")))
			if d.ExecutionID == "" {
				t.Fatalf("the call was not handed out: %s %v", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
			}
			if got := h.pause.calls.Load() - before; runs.raises != tc.raises || got != tc.reads {
				t.Errorf("%d raise(s) and %d pause read(s); want %d and %d", runs.raises, got, tc.raises, tc.reads)
			}
		})
	}
}
