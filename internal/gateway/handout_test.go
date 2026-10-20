package gateway_test

import (
	"context"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/pkg/contract"
)

// The hand-out recheck of ADR-0055: a call is handed out only while the
// bundle its decision stood on is still the installed one and still fresh.
// The harness budget is ten minutes, from the bundle's 600 seconds and the
// operator's ten minutes, and snapshot confirms the bundle at base().

const handOutBudget = 10 * time.Minute

// expectWithheld asserts the plane's block for a policy no longer current:
// INDETERMINATE, POLICY_STALE alone, freshness STALE.
func expectWithheld(t *testing.T, d gateway.Disposition) {
	t.Helper()
	expectBlock(t, d, verdictIndeterminate, codePolicyStale, gateway.PDPType)
	if codes := d.Decision.GetReasonCodes(); len(codes) != 1 {
		t.Errorf("ReasonCodes = %v, want POLICY_STALE alone", codes)
	}
	if got := d.Decision.GetPolicyFreshness(); got != controlv1.PolicyFreshness_POLICY_FRESHNESS_STALE {
		t.Errorf("PolicyFreshness = %s, want STALE", got)
	}
}

func expectRuns(t *testing.T, d gateway.Disposition) {
	t.Helper()
	if d.Action != core.Execute || d.ExecutionID == "" {
		t.Fatalf("Action = %d, codes %v; want it handed out", d.Action, d.Decision.GetReasonCodes())
	}
}

// TestACallWhosePolicyGoesStaleBeforeTheHandOutRunsNothing: a read decided
// fresh, whose bundle passes its budget while POLICY_DECIDED is appended, is
// withheld before ACTION_STARTED. At the budget's last instant it runs.
func TestACallWhosePolicyGoesStaleBeforeTheHandOutRunsNothing(t *testing.T) {
	for _, c := range []struct {
		name string
		at   time.Time
		runs bool
	}{
		{"past the budget", base().Add(handOutBudget + time.Second), false},
		{"at the budget", base().Add(handOutBudget), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads))
			h.sink.hook(kindDecided, func() { h.clock.set(c.at) })
			d := h.admit(readEnvelope(), nil)
			if c.runs {
				expectRuns(t, d)
				return
			}
			expectWithheld(t, d)
			expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
			if s := h.p.Stats(); s.Executed != 0 || s.Blocks[codePolicyStale] != 1 {
				t.Errorf("Executed %d, Blocks %v; want nothing run and POLICY_STALE once", s.Executed, s.Blocks)
			}
		})
	}
}

// TestACallWhosePolicyGoesStaleWhileItStartsIsTakenBack: a plain ENFORCE
// call, held by no approval and in no opened run, whose bundle passes its
// budget while ACTION_STARTED is appended is aborted: ACTION_FAILED closes the
// trail and nothing is handed out.
func TestACallWhosePolicyGoesStaleWhileItStartsIsTakenBack(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	h.sink.hook(kindStarted, func() { h.clock.set(base().Add(handOutBudget + time.Second)) })
	d := h.admit(readEnvelope(), nil)
	expectWithheld(t, d)
	if d.ExecutionID != "" {
		t.Errorf("ExecutionID = %q, want none handed out", d.ExecutionID)
	}
	trail := h.trailOf("req-1")
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindFailed})
	result := trail[len(trail)-1].GetResult()
	if result.GetStatus() != controlv1.ResultStatus_RESULT_STATUS_BLOCKED || result.GetToolProtocolStatus() != codePolicyStale ||
		result.GetExecutedActionDigest() != "" {
		t.Errorf("ACTION_FAILED result %v; want BLOCKED with POLICY_STALE and no executed digest", result)
	}
}

// TestABundleReplacedWhileItStartsIsTakenBack: the policy is taken again
// after ACTION_STARTED, so another bundle installed while that record is
// appended aborts the call although the clock is well inside the budget.
func TestABundleReplacedWhileItStartsIsTakenBack(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	h.sink.hook(kindStarted, func() {
		h.clock.set(base().Add(time.Minute))
		h.policy.set(snapshot(t, allowReads, denyWrites))
	})
	expectWithheld(t, h.admit(readEnvelope(), nil))
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindStarted, kindFailed})
}

// TestABundleReplacedBeforeTheHandOutRunsNothing: another bundle installed
// while POLICY_DECIDED is appended withholds the call; a renewal of the same
// bundle, or the same snapshot installed again, does not.
func TestABundleReplacedBeforeTheHandOutRunsNothing(t *testing.T) {
	for _, c := range []struct {
		name    string
		install func(t *testing.T, h *harness)
		runs    bool
	}{
		{"another bundle", func(t *testing.T, h *harness) { h.policy.set(snapshot(t, allowReads, denyWrites)) }, false},
		{"a renewal of the same bundle", func(t *testing.T, h *harness) {
			h.policy.set(snapshotAt(t, base().Add(time.Minute), allowReads))
		}, true},
		{"the same snapshot again", func(_ *testing.T, h *harness) { h.policy.set(h.policy.Current()) }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads))
			h.sink.hook(kindDecided, func() {
				h.clock.set(base().Add(time.Minute))
				c.install(t, h)
			})
			d := h.admit(readEnvelope(), nil)
			if c.runs {
				expectRuns(t, d)
				return
			}
			expectWithheld(t, d)
		})
	}
}

// TestAReadingTheCallCannotRelyOnHandsOutNothing: a reading behind the
// decision's, or behind the time the plane verified for the installed
// bundle, proves the bundle fresh at no instant and withholds the call,
// although its age is inside the budget.
func TestAReadingTheCallCannotRelyOnHandsOutNothing(t *testing.T) {
	t.Run("behind the decision", func(t *testing.T) {
		h := build(t, modeEnforce, snapshot(t, allowReads))
		h.clock.set(base().Add(time.Minute))
		h.sink.hook(kindDecided, func() { h.clock.set(base().Add(time.Minute - time.Nanosecond)) })
		expectWithheld(t, h.admit(readEnvelope(), nil))
	})
	t.Run("behind the installed bundle's verified time", func(t *testing.T) {
		h := build(t, modeEnforce, snapshot(t, allowReads))
		h.sink.hook(kindDecided, func() {
			h.policy.set(snapshotAt(t, base().Add(5*time.Minute), allowReads))
			h.clock.set(base().Add(4 * time.Minute))
		})
		expectWithheld(t, h.admit(readEnvelope(), nil))
	})
}

// failOpen is a harness whose operator opened reads under FailOpenRead.
func failOpen(cfg *gateway.Config) { cfg.KernelOptions.FailOpenRead = true }

// TestAReadTheTableOpenedStaysInItsRow: a read the fail-closed table let run
// under a stale bundle, or with none, still runs while the bundle is the same
// one, or still none, and its record carries the setting. A read decided
// fresh that is stale at hand-out is withheld, since its record does not; so
// is an opened read whose bundle is replaced, and a read under LOCKDOWN.
func TestAReadTheTableOpenedStaysInItsRow(t *testing.T) {
	stale := base().Add(handOutBudget + time.Second)
	bundle := func(t *testing.T) *policy.Snapshot { return snapshot(t, allowReads) }
	none := func(*testing.T) *policy.Snapshot { return nil }
	for _, c := range []struct {
		name  string
		mode  controlv1.EnforcementMode
		snap  func(t *testing.T) *policy.Snapshot
		start time.Time
		then  func(t *testing.T, h *harness)
		runs  bool
	}{
		{"decided stale and still stale", modeEnforce, bundle, stale, func(*testing.T, *harness) {}, true},
		{"decided with no bundle and still none", modeEnforce, none, base(), func(*testing.T, *harness) {}, true},
		{"decided fresh and stale at hand-out", modeEnforce, bundle, base(), func(_ *testing.T, h *harness) { h.clock.set(stale) }, false},
		{"decided stale and replaced", modeEnforce, bundle, stale, func(t *testing.T, h *harness) {
			h.policy.set(snapshot(t, allowReads, denyWrites))
		}, false},
		{"decided with no bundle and given one", modeEnforce, none, base(), func(t *testing.T, h *harness) {
			h.policy.set(snapshot(t, allowReads))
		}, false},
		{"under LOCKDOWN, decided fresh and stale at hand-out", modeLockdown, bundle, base(), func(_ *testing.T, h *harness) { h.clock.set(stale) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, c.mode, c.snap(t), failOpen)
			h.clock.set(c.start)
			h.sink.hook(kindDecided, func() { c.then(t, h) })
			d := h.admit(readEnvelope(), nil)
			if !c.runs {
				expectWithheld(t, d)
				return
			}
			expectRuns(t, d)
			if !containsCode(d.Decision.GetReasonCodes(), codeFailOpenRead) {
				t.Errorf("codes %v; want the run recorded under FAIL_OPEN_READ_CONFIGURED", d.Decision.GetReasonCodes())
			}
		})
	}
}

// adviseReads allows every read with an advisory obligation, so its verdict
// is ALLOW_WITH_OBLIGATIONS and nothing rewrites the arguments.
const adviseReads = `{"id":"advise-reads","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_rate","params":{"per_minute":"60"},"advisory":true}],"when":{"action":{"effect":["READ"]}}}`

// TestObserveCountsOnlyWhatEnforceWouldHandOut: of the calls whose bundle
// goes stale before the hand-out, OBSERVE counts only those the kernel let
// run, a read the fail-closed table opened among them.
func TestObserveCountsOnlyWhatEnforceWouldHandOut(t *testing.T) {
	for name, c := range map[string]struct {
		rule    string
		refusal error
		counted uint64
	}{
		"held when decided":                  {approveReads, nil, 0},
		"undecided when decided":             {allowReads, contract.ErrMissingField, 0},
		"allowed with an obligation":         {adviseReads, nil, 1},
		"allowed, as the control of the set": {allowReads, nil, 1},
	} {
		t.Run(name+", stale at the hand-out", func(t *testing.T) {
			h := build(t, modeObserve, snapshot(t, c.rule))
			h.sink.hook(kindDecided, func() { h.clock.set(base().Add(handOutBudget + time.Second)) })
			a := admission(readEnvelope(), nil)
			a.Refusal = c.refusal
			expectRuns(t, h.p.Admit(context.Background(), a))
			if s := h.p.Stats(); s.StaleHandedOut != c.counted {
				t.Errorf("StaleHandedOut %d, want %d: only a call ENFORCE would have handed out counts", s.StaleHandedOut, c.counted)
			}
		})
	}
	t.Run("a read the table opened, its bundle replaced at the hand-out", func(t *testing.T) {
		h := build(t, modeObserve, snapshot(t, allowReads), failOpen)
		h.clock.set(base().Add(handOutBudget + time.Second))
		h.sink.hook(kindDecided, func() { h.policy.set(snapshot(t, allowReads, denyWrites)) })
		d := h.admit(readEnvelope(), nil)
		expectRuns(t, d)
		if !containsCode(d.Decision.GetReasonCodes(), codeFailOpenRead) {
			t.Fatalf("codes %v; want a read the fail-closed table opened", d.Decision.GetReasonCodes())
		}
		if s := h.p.Stats(); s.StaleHandedOut != 1 {
			t.Errorf("StaleHandedOut %d; want the read ENFORCE would hand out and then withhold counted", s.StaleHandedOut)
		}
	})
}

// TestObserveHandsOutWhatEnforceWouldWithhold: OBSERVE enforces no policy,
// so a call whose bundle goes stale before the hand-out runs and is counted
// once; a pause taken in the same window still blocks it.
func TestObserveHandsOutWhatEnforceWouldWithhold(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		h := build(t, modeObserve, snapshot(t, allowReads))
		h.sink.hook(kindDecided, func() { h.clock.set(base().Add(handOutBudget + time.Second)) })
		expectRuns(t, h.admit(readEnvelope(), nil))
		if s := h.p.Stats(); s.StaleHandedOut != 1 || s.Blocks[codePolicyStale] != 0 {
			t.Errorf("StaleHandedOut %d, Blocks %v; want one counted and none blocked", s.StaleHandedOut, s.Blocks)
		}
	})
	t.Run("denied when decided, stale at the hand-out", func(t *testing.T) {
		h := build(t, modeObserve, snapshot(t, denyReads))
		h.sink.hook(kindDecided, func() { h.clock.set(base().Add(handOutBudget + time.Second)) })
		expectRuns(t, h.admit(readEnvelope(), nil))
		if s := h.p.Stats(); s.StaleHandedOut != 0 {
			t.Errorf("StaleHandedOut %d; want a call its policy denied, which ENFORCE never hands out, not counted", s.StaleHandedOut)
		}
	})
	t.Run("stale when decided, or decided with no bundle", func(t *testing.T) {
		for _, snap := range []*policy.Snapshot{snapshot(t, allowReads), nil} {
			h := build(t, modeObserve, snap)
			h.clock.set(base().Add(handOutBudget + time.Second))
			expectRuns(t, h.admit(readEnvelope(), nil))
			if s := h.p.Stats(); s.StaleHandedOut != 0 {
				t.Errorf("StaleHandedOut %d; want a call its policy never let run counted at decision, not at hand-out", s.StaleHandedOut)
			}
		}
	})
	t.Run("stale, and the agent gone before the hand-out", func(t *testing.T) {
		h := build(t, modeObserve, snapshot(t, allowReads))
		ctx, cancel := context.WithCancel(context.Background())
		h.sink.hook(kindDecided, func() {
			h.clock.set(base().Add(handOutBudget + time.Second))
			cancel()
		})
		d := h.p.Admit(ctx, admission(readEnvelope(), nil))
		if d.Action != core.Block {
			t.Fatalf("Action = %d, want the call blocked for the agent that left", d.Action)
		}
		if s := h.p.Stats(); s.StaleHandedOut != 0 || s.Executed != 0 {
			t.Errorf("StaleHandedOut %d, Executed %d; want a call nobody was handed counted as neither", s.StaleHandedOut, s.Executed)
		}
	})
	t.Run("stale and paused", func(t *testing.T) {
		h := build(t, modeObserve, snapshot(t, allowReads))
		at := base().Add(handOutBudget + time.Second)
		h.sink.hook(kindDecided, func() {
			h.clock.set(at)
			h.pause.set(pause.Read(pauseFile(t, pauseGlobal), at, pauseInterval))
		})
		expectBlock(t, h.admit(readEnvelope(), nil), controlv1.Verdict_VERDICT_DENY, codePaused, gateway.PDPType)
	})
}

// findHook runs before the store is asked for the holds under a binding,
// which a retry does before it consumes anything.
type findHook struct {
	*spendingStore
	before func()
}

func (s *findHook) Find(ctx context.Context, b approval.Binding, now time.Time) ([]gateway.Held, error) {
	if s.before != nil {
		s.before()
	}
	return s.spendingStore.Find(ctx, b, now)
}

// TestAHoldWhosePolicyIsStaleBeforeTheConsumeSpendsNothing: a retry decided
// fresh whose bundle is stale when it is about to consume the approval is
// withheld on its own trail and consumes nothing; once the bundle is
// confirmed again, exactly one retry runs.
func TestAHoldWhosePolicyIsStaleBeforeTheConsumeSpendsNothing(t *testing.T) {
	var hook *findHook
	r := lapsingUnder(t, snapshot(t, approveRefunds), func(cfg *gateway.Config) {
		hook = &findHook{spendingStore: cfg.Approvals.(*spendingStore)}
		cfg.Approvals = hook
	})
	hook.before = func() { r.policy.set(snapshotAt(t, base().Add(-handOutBudget-time.Minute), approveRefunds)) }
	expectWithheld(t, r.admit(retry(t, "req-2"), refundArgs()))
	if n := r.store.consumed.Load(); n != 0 {
		t.Fatalf("the withheld retry consumed %d approval(s), want none", n)
	}
	hook.before = nil
	r.policy.set(snapshotAt(t, base().Add(2*time.Minute), approveRefunds))
	expectRuns(t, r.admit(retry(t, "req-3"), refundArgs()))
	if n := r.store.consumed.Load(); n != 1 {
		t.Errorf("Consume was asked %d time(s), want once, by the retry that ran", n)
	}
	if d := r.admit(retry(t, "req-4"), refundArgs()); d.Action != core.Block {
		t.Errorf("a third retry: Action = %d, want the spent approval refused", d.Action)
	}
}

// TestAHoldWhoseBundleIsReplacedAfterTheConsumeRunsNothing: a bundle replaced
// while the resume records its approval withholds the call on the held
// trail, after APPROVAL_DECIDED; the approval is spent, and the next retry,
// decided under the new bundle, is held anew rather than refused as used.
func TestAHoldWhoseBundleIsReplacedAfterTheConsumeRunsNothing(t *testing.T) {
	r := lapsing(t)
	r.journal.onResuming = func() { r.policy.set(snapshot(t, approveRefunds, allowReads)) }
	expectWithheld(t, r.admit(retry(t, "req-2"), refundArgs()))
	expectKinds(t, kindsOf(r.trailOf(r.first.Decision.GetRequestId())),
		[]controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindBlocked})
	r.journal.onResuming = nil
	next := r.admit(retry(t, "req-3"), refundArgs())
	if next.Action != core.AwaitApproval || next.Pending == nil || next.Pending.ApprovalID == r.first.Pending.ApprovalID {
		t.Fatalf("the retry under the new bundle: Action = %d, pending %+v; want held anew", next.Action, next.Pending)
	}
}

func containsCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
