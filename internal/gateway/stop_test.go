package gateway_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/reaction"
)

func TestNewRefusesAMissingOrRunlessStopSource(t *testing.T) {
	cfg := validConfig(t)
	cfg.Stops = nil
	if _, err := gateway.New(cfg); !errors.Is(err, gateway.ErrNoStops) {
		t.Errorf("New with no stop source = %v, want ErrNoStops", err)
	}
	cfg.Stops = gateway.StopsDisabled()
	if _, err := gateway.New(cfg); err != nil {
		t.Errorf("New with the disabled source and no runs: %v", err)
	}
	cfg.Stops = newStopSource(stopped(t))
	if _, err := gateway.New(cfg); !errors.Is(err, gateway.ErrStopsWithoutRuns) {
		t.Errorf("New with a stop source and no runs = %v, want ErrStopsWithoutRuns", err)
	}
	withRuns(newRuns("root-1"))(&cfg)
	if _, err := gateway.New(cfg); err != nil {
		t.Errorf("New with a stop source and runs: %v", err)
	}
}

// TestAStoppedRunIsBlockedInEveryMode: a read and a write of the stopped run
// are blocked RUN_STOPPED in every mode, OBSERVE included, while the same
// plane runs a read of another run.
func TestAStoppedRunIsBlockedInEveryMode(t *testing.T) {
	for _, mode := range allModes {
		t.Run(mode.String(), func(t *testing.T) {
			h := stopPlane(t, mode, []string{allowReads, allowWrites}, newStopSource(stopped(t, "run-a")))
			expectPlaneBlock(t, h, h.admit(requestNamed(tool(readEnvelope()), "read"), []byte(`{}`)), verdictDeny, codeRunStopped)
			write := []string{codeRunStopped}
			if mode == modeLockdown {
				write = append(write, codeLockdown)
			}
			expectPlaneBlock(t, h, h.admit(requestNamed(tool(writeEnvelope()), "write"), []byte(`{}`)), verdictDeny, write...)
			for _, e := range h.trailOf("read") {
				if e.GetRunId() != "run-a" {
					t.Errorf("%s carries run %q, want run-a", e.GetKind(), e.GetRunId())
				}
			}
			h.run = opened("run-b", "root-2")
			if d := h.admit(requestNamed(tool(readEnvelope()), "other"), []byte(`{}`)); d.Action != core.Execute {
				t.Errorf("another run's read: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
			}
		})
	}
}

// TestAStopNamesOnlyTheRunThePlaneVouchedFor: a stop of run-a of tenant-1
// lets through another run, a child of run-a, a run whose agent claims run-a
// in its context, and a run of another tenant that is also named run-a.
func TestAStopNamesOnlyTheRunThePlaneVouchedFor(t *testing.T) {
	claiming := readEnvelope()
	claiming.Context.RunId = "run-a"
	otherTenant := readEnvelope()
	otherTenant.TenantId, otherTenant.Principal.TenantId, otherTenant.Resource.TenantId = "tenant-2", "tenant-2", "tenant-2"
	ofTenant2 := opened("run-a", "root-2")
	ofTenant2.Who.TenantID = "tenant-2"
	for _, c := range []struct {
		name string
		env  *controlv1.ActionEnvelope
		run  *gateway.OpenedRun
	}{
		{"another run", readEnvelope(), opened("run-b", "root-2")},
		{"a child of the stopped run", readEnvelope(), opened("run-a-child", "root-1")},
		{"a run that claims the stopped id", claiming, opened("run-b", "root-2")},
		{"the same id in another tenant", otherTenant, ofTenant2},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := stopPlane(t, modeEnforce, []string{allowReads}, newStopSource(stopped(t, "run-a")))
			h.run = c.run
			if d := h.admit(tool(c.env), []byte(`{}`)); d.Action != core.Execute {
				t.Errorf("Action = %d, codes %v; want it run", d.Action, d.Decision.GetReasonCodes())
			}
			h.run = opened("run-a", "root-1")
			expectPlaneBlock(t, h, h.admit(requestNamed(tool(readEnvelope()), "stopped"), []byte(`{}`)), verdictDeny, codeRunStopped)
		})
	}
}

// TestALocalRunIsNeverStopped: on a plane that mints local runs, a list
// naming the minted run's id and the agent's claimed run id, both of the
// call's tenant, stops neither.
func TestALocalRunIsNeverStopped(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	if d := h.admit(requestNamed(tool(readEnvelope()), "first"), []byte(`{}`)); d.Action != core.Execute {
		t.Fatalf("the first read: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
	}
	local := h.trailOf("first")[0].GetRunId()
	if local == "" {
		t.Fatal("the first read names no local run")
	}
	snap := stopped(t, local, "run-1")
	for _, id := range []string{local, "run-1"} {
		if !snap.Active(id, "tenant-1", base(), time.Time{}) {
			t.Fatalf("the list does not stop %s, so this test examines nothing", id)
		}
	}
	gateway.SetStops(h.p, newStopSource(snap))
	if d := h.admit(requestNamed(tool(readEnvelope()), "second"), []byte(`{}`)); d.Action != core.Execute {
		t.Errorf("the local run's next read: Action = %d, codes %v; want it run", d.Action, d.Decision.GetReasonCodes())
	}
	if got := h.trailOf("second")[0].GetRunId(); got != local {
		t.Errorf("the second read ran under %q, want the local run %q", got, local)
	}
}

// TestAStopEndsAtItsExpiryByTheCallsClock: a stop that expired before the
// read stops nothing at the call's clock.
func TestAStopEndsAtItsExpiryByTheCallsClock(t *testing.T) {
	l := newStopList(t)
	l.stopFrom("run-a", base().Truncate(time.Second).Add(-2*time.Hour))
	h := stopPlane(t, modeEnforce, []string{allowReads}, newStopSource(l.readAt(base())))
	if d := h.admit(tool(readEnvelope()), []byte(`{}`)); d.Action != core.Execute {
		t.Errorf("a read after its run's stop expired: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
	}
}

// TestAnUnknownStopStateBlocksEveryCall: every snapshot the plane cannot
// vouch for blocks a read of a run no stop names, INDETERMINATE with code 46
// and never RUN_STOPPED. A clear snapshot three intervals old still lets it
// run, so each block is the state's.
func TestAnUnknownStopStateBlocksEveryCall(t *testing.T) {
	cases := map[string]func(t *testing.T) reaction.Snapshot{
		"never read": func(*testing.T) reaction.Snapshot { return reaction.Snapshot{} },
		"refused by the judge": func(t *testing.T) reaction.Snapshot {
			return reaction.Snapshot{}.Next(stopRoute(t), []byte("{\n"), base(), stopInterval)
		},
		"stale": func(t *testing.T) reaction.Snapshot {
			return newStopList(t).readAt(base().Add(-3*stopInterval - time.Nanosecond))
		},
		"read ahead": func(t *testing.T) reaction.Snapshot {
			return newStopList(t).readAt(base().Add(time.Nanosecond))
		},
		"disabled, from a source that is not": func(*testing.T) reaction.Snapshot { return reaction.DisabledSnapshot() },
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			h := stopPlane(t, modeEnforce, []string{allowReads}, newStopSource(snap(t)))
			h.run = opened("run-b", "root-2")
			expectPlaneBlock(t, h, h.admit(tool(readEnvelope()), []byte(`{}`)), verdictIndeterminate, codeStopStateUnavailable)
		})
	}
	for _, mode := range allModes {
		h := stopPlane(t, mode, []string{allowReads}, newStopSource(reaction.Snapshot{}))
		expectPlaneBlock(t, h, h.admit(tool(readEnvelope()), []byte(`{}`)), verdictIndeterminate, codeStopStateUnavailable)
	}
	h := stopPlane(t, modeEnforce, []string{allowReads}, newStopSource(newStopList(t).readAt(base().Add(-3*stopInterval))))
	if d := h.admit(tool(readEnvelope()), []byte(`{}`)); d.Action != core.Execute {
		t.Errorf("a clear snapshot three intervals old: %v", d.Decision.GetReasonCodes())
	}
	// A stale list that stops run-a says nothing the plane can vouch for,
	// so run-a's call reads the fault and not the stop.
	l := newStopList(t)
	l.stopFrom("run-a", base().Truncate(time.Second).Add(-10*time.Minute))
	h = stopPlane(t, modeEnforce, []string{allowReads}, newStopSource(l.readAt(base().Add(-3*stopInterval-time.Nanosecond))))
	expectPlaneBlock(t, h, h.admit(requestNamed(tool(readEnvelope()), "stale-stop"), []byte(`{}`)), verdictIndeterminate, codeStopStateUnavailable)
}

// TestTheListingUnderAStopIsTheListingUnderNone: Preview reads no stop
// state, so a stopped run and a state nobody can read preview as a clear
// list does, and as a plane without stops does.
func TestTheListingUnderAStopIsTheListingUnderNone(t *testing.T) {
	type preview struct {
		verdict controlv1.Verdict
		codes   []string
		listing gateway.Listing
	}
	of := func(h *harness, env *controlv1.ActionEnvelope) preview {
		a := admission(env, nil)
		a.Run = h.run
		p := h.p.Preview(context.Background(), a)
		return preview{p.Decision.GetVerdict(), p.Decision.GetReasonCodes(), p.Listing}
	}
	rules := []string{allowReads, denyWrites}
	none := build(t, modeLockdown, snapshot(t, rules...))
	for name, snap := range map[string]reaction.Snapshot{
		"clear": stopped(t), "stopped": stopped(t, "run-a"), "unknown": {},
	} {
		h := stopPlane(t, modeLockdown, rules, newStopSource(snap))
		for _, env := range []func() *controlv1.ActionEnvelope{readEnvelope, writeEnvelope} {
			got, want := of(h, tool(env())), of(none, tool(env()))
			if got.verdict != want.verdict || !slices.Equal(got.codes, want.codes) || got.listing != want.listing {
				t.Errorf("%s: %s previews as %v, want %v", name, env().GetAction().GetName(), got, want)
			}
		}
		expectUntouched(t, name, h)
	}
}

// TestAStoppedHoldIsNeverHeld: a call that would be held for an approval on a
// stopped run is blocked on its own trail, with nothing held or consumed.
func TestAStoppedHoldIsNeverHeld(t *testing.T) {
	var store *stepStore
	h := stopPlane(t, modeEnforce, []string{approveRefunds}, newStopSource(stopped(t, "run-a")), withStepStore(&store))
	d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	expectPlaneBlock(t, h, d, verdictDeny, codeRunStopped)
	if s := h.p.Stats(); s.Held != 0 || s.Pending != 0 || store.consumed.Load() != 0 {
		t.Errorf("Held = %d, Pending = %d, consumed = %d; want nothing held or spent", s.Held, s.Pending, store.consumed.Load())
	}
}

// heldUnderRunA holds a refund of run-a under a clear list and approves it.
func heldUnderRunA(t *testing.T, mut ...func(*gateway.Config)) (*harness, *stopSource) {
	t.Helper()
	src := newStopSource(stopped(t))
	h := stopPlane(t, modeEnforce, []string{approveRefunds}, src, mut...)
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	return h, src
}

// TestAStoppedRetryConsumesNothingAndResumesAfterTheLift: an approved retry
// of a stopped run is blocked on a trail of its own, the approval unspent and
// the hold standing; after a lift the next retry resumes the hold once.
func TestAStoppedRetryConsumesNothingAndResumesAfterTheLift(t *testing.T) {
	var store *stepStore
	h, src := heldUnderRunA(t, withStepStore(&store))
	src.set(stopped(t, "run-a"))
	expectPlaneBlock(t, h, h.admit(retry(t, "req-2"), refundArgs()), verdictDeny, codeRunStopped)
	if store.consumed.Load() != 0 {
		t.Errorf("a stopped retry consumed %d approval(s)", store.consumed.Load())
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested})
	if h.p.Stats().Held != 1 {
		t.Errorf("Stats.Held = %d after a stopped retry, want the hold standing", h.p.Stats().Held)
	}

	src.set(liftedAt(t, "run-a", base()))
	run := h.admit(retry(t, "req-3"), refundArgs())
	if run.Action != core.Execute {
		t.Fatalf("the retry after the lift: Action = %d, codes %v", run.Action, run.Decision.GetReasonCodes())
	}
	capped := []byte(`{"amount":1000,"currency":"EUR","ssn":"x"}`)
	if err := h.p.Close(context.Background(), run, capped, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted, kindCompleted})
	again := h.admit(retry(t, "req-4"), refundArgs())
	expectBlock(t, again, verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)
	if s := h.p.Stats(); s.Executed != 1 || store.consumed.Load() != 1 {
		t.Errorf("Executed = %d, consumed = %d; want the held request run once", s.Executed, store.consumed.Load())
	}
}

// TestAStopReadAfterTheConsumeClosesTheHeldTrail: a stop written while the
// approval is consumed is read before the execution starts, so the held
// trail closes RUN_STOPPED with the approval spent, and a retry after the
// lift finds it used.
func TestAStopReadAfterTheConsumeClosesTheHeldTrail(t *testing.T) {
	var store *stepStore
	h, src := heldUnderRunA(t, withStepStore(&store))
	store.onConsume = func() { src.set(stopped(t, "run-a")) }
	d := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, d, verdictDeny, codeRunStopped, gateway.PDPType)
	if d.ExecutionID != "" {
		t.Errorf("a stopped resume was handed execution %q", d.ExecutionID)
	}
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindBlocked})
	if len(h.trailOf("req-2")) != 0 {
		t.Errorf("the resume wrote a trail of its own: %v", kindsOf(h.trailOf("req-2")))
	}
	if s := h.p.Stats(); s.Executed != 0 || s.Open != 0 || s.Held != 0 || s.Blocks[codeRunStopped] != 1 || store.consumed.Load() != 1 {
		t.Errorf("Stats = %+v, consumed = %d; want nothing run, the approval spent and the block counted as RUN_STOPPED", s, store.consumed.Load())
	}
	src.set(liftedAt(t, "run-a", base()))
	expectBlock(t, h.admit(retry(t, "req-3"), refundArgs()), verdictDeny, codeApprovalAlreadyUsed, gateway.PDPType)
}

// TestAStopDuringTheApprovalLookupBlocksTheResume: a stop written while the
// store looks the hold up blocks the retry before anything is consumed.
func TestAStopDuringTheApprovalLookupBlocksTheResume(t *testing.T) {
	var store *stepStore
	h, src := heldUnderRunA(t, withStepStore(&store))
	store.onFind = func() { src.set(stopped(t, "run-a")) }
	expectPlaneBlock(t, h, h.admit(retry(t, "req-2"), refundArgs()), verdictDeny, codeRunStopped)
	if store.consumed.Load() != 0 {
		t.Errorf("the blocked retry consumed %d approval(s)", store.consumed.Load())
	}
	if h.p.Stats().Held != 1 {
		t.Errorf("Stats.Held = %d, want the hold standing", h.p.Stats().Held)
	}
}

// TestAStopDuringTheLookupOfANewRequestBlocksItsHold: a stop written while
// the store looks up a request nothing holds yet blocks it on its own trail
// instead of holding it.
func TestAStopDuringTheLookupOfANewRequestBlocksItsHold(t *testing.T) {
	var store *stepStore
	src := newStopSource(stopped(t))
	h := stopPlane(t, modeEnforce, []string{approveRefunds}, src, withStepStore(&store))
	store.onFind = func() { src.set(stopped(t, "run-a")) }
	d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	expectPlaneBlock(t, h, d, verdictDeny, codeRunStopped)
	if s := h.p.Stats(); s.Held != 0 || s.Pending != 0 {
		t.Errorf("Held = %d, Pending = %d; want nothing held", s.Held, s.Pending)
	}
}

// TestAStopDuringTheLookupOfARetryHeldAnewBlocksIt: a retry whose hold was
// decided otherwise, here because its run read restricted data in between,
// is held anew; a stop written while the store looked it up blocks it
// instead, and nothing more is held.
func TestAStopDuringTheLookupOfARetryHeldAnewBlocksIt(t *testing.T) {
	for _, stopDuringFind := range []bool{false, true} {
		var store *stepStore
		src := newStopSource(stopped(t))
		h := stopPlane(t, modeEnforce, []string{approveRefunds, taintedRefunds, allowReads}, src, withStepStore(&store))
		first := hold(t, h)
		if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
			t.Fatalf("Answer: %v", err)
		}
		read := returning(readOf("read-1", "user-1"), 0, sensRestricted)
		read.Run = h.run
		if between := h.admitA(read); between.Action != core.Execute {
			t.Fatalf("the read in between: Action = %d", between.Action)
		}
		if stopDuringFind {
			store.onFind = func() { src.set(stopped(t, "run-a")) }
		}
		d := h.admit(retry(t, "req-2"), refundArgs())
		switch {
		case !stopDuringFind && (d.Pending == nil || h.p.Stats().Held != 2):
			t.Fatalf("the tainted retry: Action = %d, pending %+v, held %d; want it held anew", d.Action, d.Pending, h.p.Stats().Held)
		case stopDuringFind:
			expectPlaneBlock(t, h, d, verdictDeny, codeRunStopped)
			if held := h.p.Stats().Held; held != 1 {
				t.Errorf("Stats.Held = %d after a stopped retry held anew, want the first hold alone", held)
			}
		}
	}
}

// TestAStopWrittenDuringTheAskBitesThatCall: the stop read after the ask
// decides the call; with nothing written during the ask the write runs.
func TestAStopWrittenDuringTheAskBitesThatCall(t *testing.T) {
	for _, c := range []struct {
		name   string
		during func(t *testing.T, h *harness, src *stopSource)
		want   []string
	}{
		{"nothing changes", func(*testing.T, *harness, *stopSource) {}, nil},
		{"a stop of the run", func(t *testing.T, _ *harness, src *stopSource) { src.set(stopped(t, "run-a")) }, []string{codeRunStopped}},
		{"a state nobody read", func(_ *testing.T, _ *harness, src *stopSource) { src.set(reaction.Snapshot{}) }, []string{codeStopStateUnavailable}},
		{"one tick past three intervals", func(_ *testing.T, h *harness, _ *stopSource) {
			h.clock.set(base().Add(3*stopInterval + time.Nanosecond))
		}, []string{codeStopStateUnavailable}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
			src := newStopSource(stopped(t))
			h := stopPlane(t, modeEnforce, []string{allowReads, allowWrites, vetoWrites}, src, withDecisionPoint(dp))
			dp.during = func() { c.during(t, h, src) }
			d := h.admit(tool(writeEnvelope()), []byte(`{"k":1}`))
			if len(dp.questions()) != 1 {
				t.Fatalf("the decision point was asked %d time(s), want once", len(dp.questions()))
			}
			if c.want == nil {
				if d.Action != core.Execute {
					t.Fatalf("with nothing changed during the ask: Action = %d, codes %v", d.Action, d.Decision.GetReasonCodes())
				}
				return
			}
			verdict := verdictDeny
			if c.want[0] == codeStopStateUnavailable {
				verdict = verdictIndeterminate
			}
			expectPlaneBlock(t, h, d, verdict, c.want...)
		})
	}
}

// TestTheStopSourceIsReadWithThePauseSource: on the rewrite path with an ask,
// the call reads the stop state before the ask, after it, right before it
// starts and, since its result raises its root, after the raise; a stop
// served by any of the four reads blocks it.
func TestTheStopSourceIsReadWithThePauseSource(t *testing.T) {
	clearState, stop := stopped(t), stopped(t, "run-a")
	for _, c := range []struct {
		name        string
		snaps       []reaction.Snapshot
		reads, asks int
		blocked     bool
	}{
		{"stopped before the ask", []reaction.Snapshot{stop}, 1, 0, true},
		{"stopped during the ask", []reaction.Snapshot{clearState, stop}, 2, 1, true},
		{"clear throughout", []reaction.Snapshot{clearState, clearState, clearState, clearState}, 4, 1, false},
		{"stopped before the start", []reaction.Snapshot{clearState, clearState, stop}, 3, 1, true},
		{"stopped during the raise", []reaction.Snapshot{clearState, clearState, clearState, stop}, 4, 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := newStopSource(c.snaps...)
			pauses := &sequence{snaps: []pause.Snapshot{paused(t)}}
			dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
			h := stopPlane(t, modeEnforce, []string{cappedRefunds, vetoRefunds}, src, withDecisionPoint(dp),
				func(cfg *gateway.Config) { cfg.Pause = pauses })
			d := h.admit(tool(refundEnvelope(t, refundArgs())), refundArgs())
			if got, want := src.reads.Load(), int64(c.reads); got != want || pauses.reads.Load() != want {
				t.Errorf("the call read the stop source %d and the pause source %d time(s), want %d each", got, pauses.reads.Load(), want)
			}
			if got := len(dp.questions()); got != c.asks {
				t.Errorf("the decision point was asked %d time(s), want %d", got, c.asks)
			}
			switch {
			case c.blocked:
				expectPlaneBlock(t, h, d, verdictDeny, codeRunStopped)
			case d.Action != core.ExecuteWithObligations:
				t.Errorf("under clear reads: Action = %d, codes %v; want the capped refund run", d.Action, d.Decision.GetReasonCodes())
			}
		})
	}
}

// TestAStopDuringTheLastAppendDoesNotCutTheCall: a stop written while
// POLICY_DECIDED is appended blocks the call before it starts; one written
// while ACTION_STARTED is appended leaves the execution handed out, and bites
// on the run's next call.
func TestAStopDuringTheLastAppendDoesNotCutTheCall(t *testing.T) {
	src := newStopSource(stopped(t))
	h := stopPlane(t, modeEnforce, []string{allowReads}, src)
	h.sink.hook(kindDecided, func() { src.set(stopped(t, "run-a")) })
	d := h.admit(requestNamed(tool(readEnvelope()), "before"), []byte(`{}`))
	expectPlaneBlock(t, h, d, verdictDeny, codeRunStopped)
	if d.ExecutionID != "" {
		t.Errorf("a call stopped before its start was handed execution %q", d.ExecutionID)
	}

	src.set(stopped(t))
	h.sink.hook(kindDecided, nil)
	h.sink.hook(kindStarted, func() { src.set(stopped(t, "run-a")) })
	during := h.admit(requestNamed(tool(readEnvelope()), "during"), []byte(`{}`))
	if during.Action != core.Execute || during.ExecutionID == "" {
		t.Fatalf("a call stopped during its last append: Action = %d, codes %v; want it handed out", during.Action, during.Decision.GetReasonCodes())
	}
	h.sink.hook(kindStarted, nil)
	expectPlaneBlock(t, h, h.admit(requestNamed(tool(readEnvelope()), "next"), []byte(`{}`)), verdictDeny, codeRunStopped)
}
