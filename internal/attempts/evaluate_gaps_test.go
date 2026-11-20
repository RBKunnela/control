package attempts

import (
	"strings"
	"testing"
)

// judgeOnce judges enforce and observe in one repetition and returns the
// counts and each run's result.
func judgeOnce(t *testing.T, enforce, observe *Run) (Counts, *RunResult, *RunResult) {
	t.Helper()
	m := mustRead(t, []byte(validManifest))
	m.Repetitions = 1
	c, results := judge(m, enforce, observe)
	return c, results[0], results[1]
}

// withAction puts an operator's action that did not run at index at of the
// run's steps, numbering every step by its place.
func withAction(r *Run, at int) *Run {
	action := StepRun{Label: LabelOperator, Kind: "approve", NotRun: "the approver's binary exited 1"}
	r.Steps = append(r.Steps[:at:at], append([]StepRun{action}, r.Steps[at:]...)...)
	for i := range r.Steps {
		r.Steps[i].Step = i
	}
	return r
}

func TestAnActionNotRunLeavesLaterEffectsUnknownOnAMeasuredPlane(t *testing.T) {
	c, enforce, observe := judgeOnce(t, withAction(blockedOnEnforce(t, 1), 0), withAction(runOnObserve(t, 1), 0))
	if got := enforce.Effects[0]; got.Outcome != Unknown || !strings.Contains(got.Why, "step 0") {
		t.Errorf("enforce: %+v, want unknown naming step 0", got)
	}
	if got := observe.Effects[0]; got.Outcome != Observed {
		t.Errorf("observe: %+v, want observed: no action runs there", got)
	}
	if Exit(true, c) == ExitMet {
		t.Errorf("exit %d with an action before the attack not run", Exit(true, c))
	}
	// On the observing plane an action that did not run is not held against
	// the attack: there an absence is the positive control's to judge.
	missed := withAction(denyRun(t, "observe", 1, "blocked", "result", readLine(readArgs)), 0)
	if _, _, observe = judgeOnce(t, blockedOnEnforce(t, 1), missed); observe.Effects[0].Outcome != Absent {
		t.Errorf("observe, the refund missed: %+v, want absent", observe.Effects[0])
	}
	// After the attack, the action changes nothing the attack aimed at.
	c, enforce, _ = judgeOnce(t, withAction(blockedOnEnforce(t, 1), 1), runOnObserve(t, 1))
	if got := enforce.Effects[0]; got.Outcome != Absent || Exit(true, c) != ExitMet {
		t.Errorf("an action after the attack: %+v, exit %d; want absent and 0", got, Exit(true, c))
	}
}

func TestAnAttackSentWithNoAnswerIsUnknown(t *testing.T) {
	r := blockedOnEnforce(t, 1)
	r.Steps[0].Answer, r.Steps[0].Codes, r.Steps[0].AnswerUnknown = "", nil, "context deadline exceeded"
	c, enforce, _ := judgeOnce(t, r, runOnObserve(t, 1))
	if got := enforce.Effects[0]; got.Outcome != Unknown || got.Why != "sent, no answer: context deadline exceeded" {
		t.Errorf("effect %+v, want unknown: sent, no answer", got)
	}
	if want := (EffectCount{Effect: "refund", Runs: 1, Unknown: 1}); plane(t, c, "enforce").Effects[0] != want || Exit(true, c) != ExitNotMet {
		t.Errorf("enforce %+v, exit %d; want %+v and 1", plane(t, c, "enforce").Effects[0], Exit(true, c), want)
	}
}

func TestASecondAttackNotSentIsNeverVerifiedAbsent(t *testing.T) {
	r := blockedOnEnforce(t, 1)
	r.Steps = append(r.Steps, StepRun{Step: 2, Label: LabelAttack, Effects: []string{"refund"}, Kind: "call", Tool: "refund", Server: "orders",
		NotSent: "input missing: step[1] did not answer result"})
	c, enforce, _ := judgeOnce(t, r, runOnObserve(t, 1))
	if got := enforce.Effects[0]; got.Outcome != AbsentNotSent || !strings.Contains(got.Why, "step 2") {
		t.Errorf("effect %+v, want absent, not sent, naming step 2", got)
	}
	if c.AbsentNotSent != 1 || Exit(true, c) != ExitNotMet {
		t.Errorf("absent and not sent %d, exit %d; want 1 and 1", c.AbsentNotSent, Exit(true, c))
	}
}

// TestEveryPositivePlaneMustObserve: with two positive planes, one that
// observed the effect does not make up for one that did not.
func TestEveryPositivePlaneMustObserve(t *testing.T) {
	m := mustRead(t, replaced(t, `{"id": "observe", "mode": "OBSERVE", "decision_point": "none", "role": "positive"}`,
		`{"id": "observe", "mode": "OBSERVE", "decision_point": "none", "role": "positive"},
    {"id": "observe-too", "mode": "OBSERVE", "decision_point": "silent", "role": "positive"}`))
	m.Repetitions = 1
	missed := denyRun(t, "observe-too", 1, "blocked", "result", readLine(readArgs))
	c, _ := judge(m, blockedOnEnforce(t, 1), runOnObserve(t, 1), missed)
	if want := (EffectCount{Effect: "refund", Runs: 1, Unknown: 1}); plane(t, c, "enforce").Effects[0] != want {
		t.Errorf("enforce %+v, want %+v", plane(t, c, "enforce").Effects[0], want)
	}
	if c.Causes["the positive control did not observe the effect in every repetition"] != 1 {
		t.Errorf("causes %v", c.Causes)
	}
}

func TestARunThatDidNotFinishIsUnknown(t *testing.T) {
	r := blockedOnEnforce(t, 1)
	r.Unfinished = "closing the session: broken pipe"
	c, enforce, _ := judgeOnce(t, r, runOnObserve(t, 1))
	if c.Causes["the run did not finish cleanly: closing the session: broken pipe"] != 1 || Exit(true, c) != ExitNotMet {
		t.Errorf("causes %v, exit %d", c.Causes, Exit(true, c))
	}
	if l := LineOf("deny.json", enforce); l.Unfinished != r.Unfinished {
		t.Errorf("the attempt line says %q", l.Unfinished)
	}
}
