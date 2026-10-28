package gateway_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// writeIn is a write named requestID under the opened run id of root.
func writeIn(requestID, id, root string, args []byte) gateway.Admission {
	return under(admission(requestNamed(writeEnvelope(), requestID), args), opened(id, root))
}

// cooperative serves calls through an adapter that hands each decision to a
// caller, the one adapter whose callers report what they sent.
func cooperative(c *gateway.Config) {
	caps := c.Adapter.Capabilities()
	caps.Enforcement = gateway.EnforcementCooperative
	c.Adapter = fakeAdapter{name: "fake", caps: caps}
}

// readIn is a read named requestID under the opened run id of root.
func readIn(requestID, id, root string) gateway.Admission {
	return under(admission(requestNamed(readEnvelope(), requestID), []byte(`{}`)), opened(id, root))
}

// reportMismatch admits a write of run id under root and reports other bytes
// for it, which has to be refused as a mismatch.
func reportMismatch(t *testing.T, h *harness, requestID, id, root string) {
	t.Helper()
	d := h.admitA(writeIn(requestID, id, root, []byte(`{"amount":1}`)))
	if d.ExecutionID == "" {
		t.Fatalf("the write of %s was not handed out: %s %v", id, d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	sent := []byte(`{"amount":1000000}`)
	if err := h.p.CloseReported(context.Background(), d, sent, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("CloseReported with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
	trail := h.trailOf(requestID)
	expectMismatchRecord(t, trail[len(trail)-1], sent, d.Decision.GetActionDigest())
	if err := evidence.ValidateChain(trail); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

// TestAReportedMismatchHaltsOnlyItsOwnRun: bytes a client reports that were
// not the authorized ones are recorded as the mismatch Close records, and
// block that run's next material call until restart, while that run's reads,
// another run, and a run opened under the same root go on.
func TestAReportedMismatchHaltsOnlyItsOwnRun(t *testing.T) {
	runs := newRuns("root-a", "root-b")
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(runs), cooperative)
	reportMismatch(t, h, "a-1", "run-a", "root-a")
	if s := h.p.Stats(); s.Mismatches != 1 || s.Halted || s.MismatchHalted || s.SinkHalted || s.RunsHalted != 1 {
		t.Errorf("Stats = %+v; want one mismatch, one run halted and the plane not halted", s)
	}
	expectBlock(t, h.admitA(writeIn("a-2", "run-a", "root-a", []byte(`{}`))), verdictDeny, codeExecutedArgsMismatch, gateway.PDPType)
	for _, a := range []gateway.Admission{
		readIn("a-3", "run-a", "root-a"),
		writeIn("b-1", "run-b", "root-b", []byte(`{}`)),
		writeIn("c-1", "run-c", "root-a", []byte(`{}`)),
	} {
		if d := h.admitA(a); d.Action != core.Execute {
			t.Errorf("%s of %s: %s %v, want Execute", a.Envelope.GetRequestId(), a.Run.ID, d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
		}
	}
}

// shiftingAdapter answers Capabilities with what it holds at the moment it
// is asked, which an adapter is not allowed to change after New.
type shiftingAdapter struct {
	mu   sync.Mutex
	caps gateway.Capabilities
}

func (a *shiftingAdapter) Name() string { return "shifting" }

func (a *shiftingAdapter) Capabilities() gateway.Capabilities {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.caps
}

func (a *shiftingAdapter) enforce(e gateway.Enforcement) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.caps.Enforcement = e
}

// TestTheScopeAMismatchHaltsIsTheAdaptersAtNew: an adapter whose answer
// changes after New does not change what a reported mismatch halts. Checked
// cooperative, it halts the run alone though it later says inline; checked
// inline, it halts the plane though it later says cooperative.
func TestTheScopeAMismatchHaltsIsTheAdaptersAtNew(t *testing.T) {
	for _, c := range []struct {
		name         string
		atNew, after gateway.Enforcement
		planeHalted  bool
		runsHalted   int
	}{
		{"cooperative at New", gateway.EnforcementCooperative, gateway.EnforcementInline, false, 1},
		{"inline at New", gateway.EnforcementInline, gateway.EnforcementCooperative, true, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			adapter := &shiftingAdapter{}
			h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(newRuns("root-a")), func(cfg *gateway.Config) {
				adapter.caps = cfg.Adapter.Capabilities()
				adapter.caps.Enforcement = c.atNew
				cfg.Adapter = adapter
			})
			adapter.enforce(c.after)
			reportMismatch(t, h, "a-1", "run-a", "root-a")
			if s := h.p.Stats(); s.Halted != c.planeHalted || s.RunsHalted != c.runsHalted || s.Mismatches != 1 {
				t.Errorf("Stats = %+v; want the plane halted %v and %d run(s) halted on their own", s, c.planeHalted, c.runsHalted)
			}
		})
	}
}

// firstAnswerAdapter answers Capabilities with first once and with later on
// every call after, so a pipeline that asks again keeps a value never checked.
type firstAnswerAdapter struct {
	first, later gateway.Capabilities
	asked        int
}

func (a *firstAnswerAdapter) Name() string { return "first-answer" }

func (a *firstAnswerAdapter) Capabilities() gateway.Capabilities {
	a.asked++
	if a.asked == 1 {
		return a.first
	}
	return a.later
}

// TestNewKeepsTheCapabilitiesItChecked: New asks the adapter once and keeps
// that answer, so an adapter checked cooperative halts the run alone on a
// reported mismatch though every later answer says inline.
func TestNewKeepsTheCapabilitiesItChecked(t *testing.T) {
	adapter := &firstAnswerAdapter{}
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(newRuns("root-a")), func(cfg *gateway.Config) {
		adapter.first = cfg.Adapter.Capabilities()
		adapter.first.Enforcement = gateway.EnforcementCooperative
		adapter.later = adapter.first
		adapter.later.Enforcement = gateway.EnforcementInline
		cfg.Adapter = adapter
	})
	if adapter.asked != 1 {
		t.Errorf("New asked the adapter for its capabilities %d times, want once", adapter.asked)
	}
	reportMismatch(t, h, "a-1", "run-a", "root-a")
	if s := h.p.Stats(); s.Halted || s.RunsHalted != 1 {
		t.Errorf("Stats = %+v; want the run halted alone, as the answer New checked says", s)
	}
}

// TestCloseOfAnOpenedRunStillHaltsThePlane: the same mismatch handed to
// Close, by an adapter that sent the bytes itself, halts every run.
func TestCloseOfAnOpenedRunStillHaltsThePlane(t *testing.T) {
	runs := newRuns("root-a", "root-b")
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(runs), cooperative)
	d := h.admitA(writeIn("a-1", "run-a", "root-a", []byte(`{"amount":1}`)))
	if err := h.p.Close(context.Background(), d, []byte(`{"amount":2}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("Close with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
	if s := h.p.Stats(); !s.Halted || !s.MismatchHalted || s.SinkHalted || s.RunsHalted != 0 {
		t.Errorf("Stats = %+v; want the plane halted on the mismatch and no run halted on its own", s)
	}
	expectBlock(t, h.admitA(writeIn("b-1", "run-b", "root-b", []byte(`{}`))), verdictDeny, codeExecutedArgsMismatch, gateway.PDPType)
}

// TestAReportedMismatchFromAnInlineAdapterHaltsThePlane: an adapter that
// sends the bytes itself has no caller to report them, so a report through it
// is held to what Close holds it to, and a mismatch halts every run.
func TestAReportedMismatchFromAnInlineAdapterHaltsThePlane(t *testing.T) {
	runs := newRuns("root-a", "root-b")
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(runs))
	reportMismatch(t, h, "a-1", "run-a", "root-a")
	if s := h.p.Stats(); !s.Halted || s.RunsHalted != 0 || s.Mismatches != 1 {
		t.Errorf("Stats = %+v; want the plane halted and no run halted on its own", s)
	}
	expectBlock(t, h.admitA(writeIn("b-1", "run-b", "root-b", []byte(`{}`))), verdictDeny, codeExecutedArgsMismatch, gateway.PDPType)
}

// TestAReportedMismatchWithNoOpenedRunHaltsThePlane: a call no opened run
// names has no run to halt, so the plane takes no material call.
func TestAReportedMismatchWithNoOpenedRunHaltsThePlane(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites))
	d := h.admit(writeEnvelope(), []byte(`{"amount":1}`))
	if err := h.p.CloseReported(context.Background(), d, []byte(`{"amount":2}`), result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("CloseReported with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
	if s := h.p.Stats(); !s.Halted || s.RunsHalted != 0 || s.Mismatches != 1 {
		t.Errorf("Stats = %+v; want the plane halted", s)
	}
	expectBlock(t, h.admit(requestNamed(writeEnvelope(), "req-2"), []byte(`{}`)), verdictDeny, codeExecutedArgsMismatch, gateway.PDPType)
}

// TestAReportedMatchClosesAsCloseDoes: the authorized bytes reported back
// close the execution as completed and halt nothing.
func TestAReportedMatchClosesAsCloseDoes(t *testing.T) {
	runs := newRuns("root-a")
	h := build(t, modeEnforce, snapshot(t, allowWrites), withRuns(runs), cooperative)
	d := h.admitA(writeIn("a-1", "run-a", "root-a", []byte(`{"amount":1}`)))
	if err := h.p.CloseReported(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("CloseReported with the authorized bytes: %v", err)
	}
	expectKinds(t, kindsOf(h.trailOf("a-1")), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindCompleted})
	if s := h.p.Stats(); s.Halted || s.RunsHalted != 0 || s.Mismatches != 0 || s.Open != 0 {
		t.Errorf("Stats = %+v; want nothing halted or open", s)
	}
	if err := h.p.CloseReported(context.Background(), d, d.AuthorizedArgs, nil); !errors.Is(err, gateway.ErrNotMinted) {
		t.Errorf("a replayed CloseReported = %v, want ErrNotMinted", err)
	}
	if next := h.admitA(writeIn("a-2", "run-a", "root-a", []byte(`{}`))); next.Action != core.Execute {
		t.Errorf("the run's next write: %s %v, want Execute", next.Decision.GetVerdict(), next.Decision.GetReasonCodes())
	}
}

// TestRunHaltsPastMaxRunsHaltThePlane: the runs a plane keeps halted are
// bounded by MaxRuns; a mismatch reported by a run past the bound halts the
// plane rather than go unenforced.
func TestRunHaltsPastMaxRunsHaltThePlane(t *testing.T) {
	runs := newRuns("root-a", "root-b", "root-c")
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites), withRuns(runs), cooperative, func(c *gateway.Config) { c.MaxRuns = 1 })
	reportMismatch(t, h, "a-1", "run-a", "root-a")
	if s := h.p.Stats(); s.Halted || s.RunsHalted != 1 {
		t.Fatalf("after the first run's mismatch: %+v; want one run halted and the plane not", s)
	}
	if d := h.admitA(writeIn("c-1", "run-c", "root-c", []byte(`{}`))); d.Action != core.Execute {
		t.Fatalf("a third run's write before the bound bites: %s %v", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	// A halted run takes reads, and a mismatch on one of them halts the run
	// it halted already, not the plane.
	read := h.admitA(readIn("a-2", "run-a", "root-a"))
	if err := h.p.CloseReported(context.Background(), read, []byte(`{"x":1}`), nil); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("CloseReported of the halted run's read with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
	if s := h.p.Stats(); s.Halted || s.RunsHalted != 1 || s.Mismatches != 2 {
		t.Fatalf("after a second mismatch of the halted run: %+v; want the plane not halted", s)
	}
	reportMismatch(t, h, "b-1", "run-b", "root-b")
	if s := h.p.Stats(); !s.Halted || s.RunsHalted != 1 || s.Mismatches != 3 {
		t.Errorf("after the second run's mismatch: %+v; want the plane halted", s)
	}
	expectBlock(t, h.admitA(writeIn("c-2", "run-c", "root-c", []byte(`{}`))), verdictDeny, codeExecutedArgsMismatch, gateway.PDPType)
}
