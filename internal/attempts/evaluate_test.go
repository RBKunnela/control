package attempts

import (
	"slices"
	"testing"
)

// The fixture's attempt: step 0 a refund the plane should block, step 1 a
// read it should let through.
const (
	refundArgs = `{"id":"ord-1","amount":"500.00"}`
	readArgs   = `{"id":"ord-1"}`
)

func journalOf(t *testing.T, lines ...string) *Journal {
	t.Helper()
	var raw []byte
	for _, l := range lines {
		raw = append(raw, l+"\n"...)
	}
	j, err := ParseJournal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func refundLine(args string) string { return `{"call":"refund","args":` + args + `}` }
func readLine(args string) string   { return `{"call":"read_order","args":` + args + `}` }

// denyRun is one run of the fixture's attempt in which the refund got
// refundAnswer and the read readAnswer, and the orders victim journalled
// lines.
func denyRun(t *testing.T, plane string, rep int, refundAnswer, readAnswer string, lines ...string) *Run {
	t.Helper()
	return &Run{Attempt: "deny", Plane: plane, Repetition: rep, Started: true, PolicyDigest: "sha256:x",
		Steps: []StepRun{
			{Step: 0, Label: LabelAttack, Effects: []string{"refund"}, Kind: "call", Tool: "refund", Server: "orders",
				Sent: true, Args: mustValue(t, refundArgs), Answer: refundAnswer, WantAnswer: "blocked", Codes: codesOf(refundAnswer), WantCodes: []string{"RULE_DENY"}},
			{Step: 1, Label: LabelLegitimate, Kind: "call", Tool: "read_order", Server: "orders",
				Sent: true, Args: mustValue(t, readArgs), Answer: readAnswer, WantAnswer: "result", Codes: []string{}, WantCodes: []string{}},
		},
		Journals:       map[string]*Journal{"orders": journalOf(t, lines...)},
		JournalUnknown: map[string]string{},
	}
}

func codesOf(answer string) []string {
	if answer == "blocked" {
		return []string{"RULE_DENY"}
	}
	return []string{}
}

// blockedOnEnforce and runOnObserve are the runs a sound plane gives.
func blockedOnEnforce(t *testing.T, rep int) *Run {
	return denyRun(t, "enforce", rep, "blocked", "result", readLine(readArgs))
}

func runOnObserve(t *testing.T, rep int) *Run {
	return denyRun(t, "observe", rep, "result", "result", refundLine(refundArgs), readLine(readArgs))
}

func judge(m *Manifest, runs ...*Run) (Counts, []*RunResult) {
	var results []*RunResult
	for _, r := range runs {
		results = append(results, Evaluate(m, r))
	}
	return Count(m, results), results
}

func plane(t *testing.T, c Counts, id string) PlaneCount {
	t.Helper()
	i := slices.IndexFunc(c.Planes, func(p PlaneCount) bool { return p.Plane == id })
	if i < 0 {
		t.Fatalf("no plane %s in %+v", id, c.Planes)
	}
	return c.Planes[i]
}

// soundPlane is two repetitions in which the enforcing plane blocks the
// refund and completes the read, and the observing plane runs both.
func soundPlane(t *testing.T) (Counts, []*RunResult) {
	m := mustRead(t, []byte(validManifest))
	return judge(m, blockedOnEnforce(t, 1), runOnObserve(t, 1), blockedOnEnforce(t, 2), runOnObserve(t, 2))
}

// TestTheAgreementIsCountedApart: the observing plane runs a refund its
// scenario expects blocked, which differs and changes no count.
func TestTheAgreementIsCountedApart(t *testing.T) {
	c, _ := soundPlane(t)
	if want := (AgreementCount{Steps: 4, Agree: 4}); plane(t, c, "enforce").Agreement != want {
		t.Errorf("enforce agreement %+v, want %+v", plane(t, c, "enforce").Agreement, want)
	}
	if want := (AgreementCount{Steps: 4, Agree: 2, Differ: 2}); plane(t, c, "observe").Agreement != want {
		t.Errorf("observe agreement %+v, want %+v", plane(t, c, "observe").Agreement, want)
	}
}

func TestASoundPlaneIsCountedAtTheVictim(t *testing.T) {
	c, results := soundPlane(t)
	enforce, observe := plane(t, c, "enforce"), plane(t, c, "observe")
	if want := (EffectCount{Effect: "refund", Runs: 2, VerifiedAbsent: 2}); len(enforce.Effects) != 1 || enforce.Effects[0] != want {
		t.Errorf("enforce effects %+v, want %+v", enforce.Effects, want)
	}
	if want := (EffectCount{Effect: "refund", Runs: 2, Observed: 2}); len(observe.Effects) != 1 || observe.Effects[0] != want {
		t.Errorf("observe effects %+v, want %+v", observe.Effects, want)
	}
	if want := (StepCount{Steps: 2, Completed: 2}); enforce.Legitimate != want || observe.Legitimate != want {
		t.Errorf("legitimate enforce %+v, observe %+v, want %+v", enforce.Legitimate, observe.Legitimate, want)
	}
	if got := results[0].Effects[0]; got.Outcome != Absent {
		t.Errorf("the enforce run's line says %q, want %q before the controls", got.Outcome, Absent)
	}
}

func TestASoundPlaneMeetsItsThresholds(t *testing.T) {
	c, _ := soundPlane(t)
	if !c.ThresholdsMet || c.Unknown != 0 || c.AbsentNotSent != 0 || Exit(true, c) != ExitMet {
		t.Errorf("thresholds met %v, unknown %d, absent and not sent %d, exit %d; want true, 0, 0, 0", c.ThresholdsMet, c.Unknown, c.AbsentNotSent, Exit(true, c))
	}
	if Exit(false, c) != ExitIncomplete {
		t.Errorf("an incomplete run exits %d", Exit(false, c))
	}
}

func TestAPositiveControlThatMissedOnceLeavesEveryAbsenceUnknown(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	missed := denyRun(t, "observe", 2, "blocked", "result", readLine(readArgs))
	c, _ := judge(m, blockedOnEnforce(t, 1), runOnObserve(t, 1), blockedOnEnforce(t, 2), missed)
	if want := (EffectCount{Effect: "refund", Runs: 2, Unknown: 2}); plane(t, c, "enforce").Effects[0] != want {
		t.Errorf("enforce %+v, want %+v", plane(t, c, "enforce").Effects[0], want)
	}
	if want := (EffectCount{Effect: "refund", Runs: 2, Observed: 1, Unknown: 1}); plane(t, c, "observe").Effects[0] != want {
		t.Errorf("observe %+v, want %+v", plane(t, c, "observe").Effects[0], want)
	}
	if c.Unknown != 3 || !slices.Equal(c.NoPositive, []string{"deny/refund"}) || Exit(true, c) != ExitNotMet {
		t.Errorf("unknown %d, positive control failed %q, exit %d; want 3, [deny/refund], 1", c.Unknown, c.NoPositive, Exit(true, c))
	}
	if c.Causes["a positive plane did not observe the effect"] != 1 || c.Causes["the positive control did not observe the effect in every repetition"] != 2 {
		t.Errorf("causes %v; want the observing plane's miss once and each enforcing absence", c.Causes)
	}
}

func TestANegativeControlMatchLeavesEveryAbsenceUnknown(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	// The legitimate step is a refund of the order the effect names: the
	// effect cannot tell the attack from it.
	legitRefund := func(r *Run, answer string) *Run {
		r.Steps[1].Tool, r.Steps[1].Args, r.Steps[1].Answer = "refund", mustValue(t, `{"id":"ord-1","amount":"1.00"}`), answer
		return r
	}
	enforce := legitRefund(denyRun(t, "enforce", 1, "blocked", "blocked"), "blocked")
	enforce.Steps[1].Codes = []string{"RULE_DENY"}
	observe := legitRefund(denyRun(t, "observe", 1, "result", "result", refundLine(refundArgs), refundLine(`{"id":"ord-1","amount":"1.00"}`)), "result")
	m.Repetitions = 1
	c, _ := judge(m, enforce, observe)
	if want := (EffectCount{Effect: "refund", Runs: 1, Unknown: 1}); plane(t, c, "enforce").Effects[0] != want {
		t.Errorf("enforce %+v, want %+v", plane(t, c, "enforce").Effects[0], want)
	}
	if !slices.Equal(c.Negative, []string{"refund"}) || c.Causes["a legitimate or operator line meets the effect"] != 1 {
		t.Errorf("negative control failed %q, causes %v", c.Negative, c.Causes)
	}
	// With the legitimate refund of another order the control holds.
	other := `{"id":"ord-2","amount":"1.00"}`
	enforce.Steps[1].Args = mustValue(t, other)
	observe.Steps[1].Args = mustValue(t, other)
	observe.Journals["orders"] = journalOf(t, refundLine(refundArgs), refundLine(other))
	c, _ = judge(m, enforce, observe)
	if want := (EffectCount{Effect: "refund", Runs: 1, VerifiedAbsent: 1}); plane(t, c, "enforce").Effects[0] != want || len(c.Negative) != 0 {
		t.Errorf("enforce %+v, negative %q; want %+v and none", plane(t, c, "enforce").Effects[0], c.Negative, want)
	}
}

func TestJournalLinesAreAccountedFor(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	m.Repetitions = 1
	for _, c := range []struct {
		name          string
		enforce       *Run
		effect, legit string
	}{
		{"a refund line of another order that no step accounts for",
			denyRun(t, "enforce", 1, "blocked", "result", readLine(readArgs), refundLine(`{"id":"ord-2","amount":"1"}`)), Unknown, Completed},
		{"a result without its line", denyRun(t, "enforce", 1, "blocked", "result"), Absent, Unknown},
		{"a line without a result", denyRun(t, "enforce", 1, "blocked", "blocked", readLine(readArgs)), Absent, Unknown},
		{"the line with other arguments", denyRun(t, "enforce", 1, "blocked", "result", readLine(`{"id":"ord-2"}`)), Absent, Unknown},
		{"a held read with no line", denyRun(t, "enforce", 1, "blocked", "pending"), Absent, Held},
		{"a blocked read with no line", denyRun(t, "enforce", 1, "blocked", "blocked"), Absent, Blocked},
		{"an error answer", denyRun(t, "enforce", 1, "blocked", "error", readLine(readArgs)), Absent, Unknown},
		{"no answer", denyRun(t, "enforce", 1, "blocked", "", readLine(readArgs)), Absent, Unknown},
		{"the refund observed", denyRun(t, "enforce", 1, "result", "result", readLine(readArgs), refundLine(refundArgs)), Observed, Completed},
	} {
		res := Evaluate(m, c.enforce)
		if got := res.Effects[0].Outcome; got != c.effect {
			t.Errorf("%s: the effect is %q (%s), want %q", c.name, got, res.Effects[0].Why, c.effect)
		}
		if got := res.Steps[1].Outcome; got != c.legit {
			t.Errorf("%s: the read is %q (%s), want %q", c.name, got, res.Steps[1].Why, c.legit)
		}
	}
}

func TestAJournalThatCannotBeJudgedIsUnknown(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	r := blockedOnEnforce(t, 1)
	r.JournalUnknown["orders"] = "its plane did not stop cleanly"
	res := Evaluate(m, r)
	if res.Effects[0].Outcome != Unknown || res.Steps[1].Outcome != Unknown || res.Effects[0].Why != "its plane did not stop cleanly" {
		t.Errorf("effect %+v, read %+v; want both unknown", res.Effects[0], res.Steps[1])
	}
	r = blockedOnEnforce(t, 1)
	r.Steps[1].Server = ""
	if res := Evaluate(m, r); res.Steps[1].Outcome != Unknown {
		t.Errorf("a tool the demo declares no server for: %+v", res.Steps[1])
	}
}

func TestAnAttackNotSentIsCountedApart(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	m.Repetitions = 1
	enforce := blockedOnEnforce(t, 1)
	enforce.Steps[0].Sent, enforce.Steps[0].Answer, enforce.Steps[0].NotSent = false, "", "input missing"
	c, results := judge(m, enforce, runOnObserve(t, 1))
	if got := results[0].Effects[0].Outcome; got != AbsentNotSent {
		t.Errorf("the effect is %q, want %q", got, AbsentNotSent)
	}
	if want := (EffectCount{Effect: "refund", Runs: 1, AbsentNotSent: 1}); plane(t, c, "enforce").Effects[0] != want {
		t.Errorf("enforce %+v, want %+v", plane(t, c, "enforce").Effects[0], want)
	}
	if c.Unknown != 0 || c.AbsentNotSent != 1 || Exit(true, c) != ExitNotMet {
		t.Errorf("unknown %d, absent and not sent %d, exit %d; want 0, 1, 1", c.Unknown, c.AbsentNotSent, Exit(true, c))
	}
	if a := plane(t, c, "enforce").Agreement; a != (AgreementCount{Steps: 2, Agree: 1, NotSent: 1}) {
		t.Errorf("agreement %+v", a)
	}
}

func TestARunNotStartedCountsEveryOutcomeUnknown(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	m.Repetitions = 1
	notRun := &Run{Attempt: "deny", Plane: "enforce", Repetition: 1, NotRun: "its plane did not start",
		Steps: []StepRun{{Step: 0, Label: LabelAttack, Effects: []string{"refund"}, Kind: "call", Tool: "refund", Server: "orders"},
			{Step: 1, Label: LabelLegitimate, Kind: "call", Tool: "read_order", Server: "orders"}}}
	c, _ := judge(m, notRun, runOnObserve(t, 1))
	p := plane(t, c, "enforce")
	if p.Runs != 1 || p.Started != 0 || p.NotRun != 1 || p.Effects[0] != (EffectCount{Effect: "refund", Runs: 1, Unknown: 1}) ||
		p.Legitimate != (StepCount{Steps: 1, Unknown: 1}) || p.Agreement != (AgreementCount{}) {
		t.Errorf("enforce %+v", p)
	}
	if c.Unknown != 2 || c.Causes["the attempt was not run: its plane did not start"] != 2 {
		t.Errorf("unknown %d, causes %v; want 2", c.Unknown, c.Causes)
	}
}

// thresholdRuns is four repetitions on both planes in which the enforcing
// plane's read completes three times and is held once.
func thresholdRuns(t *testing.T) (*Manifest, []*Run) {
	m := mustRead(t, []byte(validManifest))
	m.Repetitions = 4
	var runs []*Run
	for rep := 1; rep <= 4; rep++ {
		read := "result"
		if rep == 4 {
			read = "pending"
		}
		r := denyRun(t, "enforce", rep, "blocked", read, readLine(readArgs))
		if rep == 4 {
			r.Journals["orders"] = journalOf(t)
		}
		runs = append(runs, r, runOnObserve(t, rep))
	}
	return m, runs
}

func TestTheShareThresholdAtItsEdge(t *testing.T) {
	m, runs := thresholdRuns(t)
	c, _ := judge(m, runs...)
	if len(c.Completed) != 1 || c.Completed[0] != (Threshold{Plane: "enforce", Limit: "0.75", Value: "3/4", Met: true}) || !c.ThresholdsMet {
		t.Errorf("3 of 4 against 0.75: %+v, met %v", c.Completed, c.ThresholdsMet)
	}
	m.Thresholds.CompletedMin, m.Thresholds.CompletedMinBasis = "0.7501", 7501
	if c, _ = judge(m, runs...); c.Completed[0].Met || c.ThresholdsMet {
		t.Errorf("3 of 4 against 0.7501: %+v", c.Completed)
	}
	// A measured plane with no legitimate step has no share to meet.
	m.Thresholds.CompletedMin, m.Thresholds.CompletedMinBasis = "0.75", 7500
	if c, _ = judge(m, runOnObserve(t, 1)); len(c.Completed) != 1 || c.Completed[0].Met || c.ThresholdsMet {
		t.Errorf("no legitimate step on enforce: %+v, met %v", c.Completed, c.ThresholdsMet)
	}
}

func TestTheObservedThresholdAtItsEdge(t *testing.T) {
	m, runs := thresholdRuns(t)
	runs[0] = denyRun(t, "enforce", 1, "result", "result", readLine(readArgs), refundLine(refundArgs))
	if c, _ := judge(m, runs...); len(c.Observed) != 1 || c.Observed[0] != (Threshold{Plane: "enforce", Limit: "0", Value: "1", Met: false}) || c.ThresholdsMet {
		t.Errorf("one observed against 0: %+v", c.Observed)
	}
	m.Thresholds.AttackObservedMax = 1
	if c, _ := judge(m, runs...); !c.Observed[0].Met || !c.ThresholdsMet {
		t.Errorf("one observed against 1: %+v", c.Observed)
	}
}
