package supervise_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
)

const (
	ruleArgs     = "DENIED_ACTION_RETRIED_ARGUMENTS"
	ruleRes      = "DENIED_ACTION_RETRIED_RESOURCE"
	ruleAround   = "DENIED_ACTION_RETRIED_AROUND"
	transact     = controlv1.EffectClass_EFFECT_CLASS_TRANSACT
	read         = controlv1.EffectClass_EFFECT_CLASS_READ
	write        = controlv1.EffectClass_EFFECT_CLASS_WRITE
	unclassified = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
)

var retryRules = []string{ruleArgs, ruleRes, ruleAround}

// denial is d1, a refund of order 42 the policy denies at ten seconds.
func denial() act {
	return act{call: call{req: "d1", tool: "issue_refund", upstream: "pay", at: 10 * time.Second, outcome: "deny"},
		res: orderNo("42"), hash: hashOf('a'), effect: transact}
}

// again is r1, the denied refund at twenty seconds with other arguments.
func again() act {
	return act{call: call{req: "r1", tool: "issue_refund", upstream: "pay", at: 20 * time.Second},
		res: orderNo("42"), hash: hashOf('b'), effect: transact}
}

// manual is m1, the same order refunded by a tool outside the procedure.
func manual() act {
	return act{call: call{req: "m1", tool: "refund_manual", upstream: "pay", at: 20 * time.Second},
		res: orderNo("42"), hash: hashOf('a'), effect: transact}
}

// retrySupervise evaluates exports with the source given under the
// inherit fixture over family.
func retrySupervise(t *testing.T, src supervise.Source, exports ...supervise.Export) *supervise.Result {
	t.Helper()
	return treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family(), Exports: exports,
		Sources: []supervise.Source{src}})
}

// retries is the retry findings of res by rule, as run and verdict.
func retries(res *supervise.Result) map[string][]string {
	out := map[string][]string{}
	for _, rule := range retryRules {
		out[rule] = verdicts(res, rule)
	}
	return out
}

// TestEachRetryFormFiresOnItsOwnInputOnly: other arguments, another tool on
// the same resource and a source's report of the denied tool each raise
// their own rule and neither other, anchored on the denial and the run.
func TestEachRetryFormFiresOnItsOwnInputOnly(t *testing.T) {
	reported := source(ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second, stage: observev1.Stage_STAGE_STARTED})
	for name, c := range map[string]struct {
		x           supervise.Export
		src         supervise.Source
		rule, cites string
		verdict     string
	}{
		"other arguments":     {acts(denial(), again()), source(), ruleArgs, "d1-e2 r1-e1", "FINDING_VERDICT_SUSPECTED"},
		"another tool":        {acts(denial(), manual()), source(), ruleRes, "d1-e2 m1-e1", "FINDING_VERDICT_SUSPECTED"},
		"a report around one": {acts(denial()), reported, ruleAround, "d1-e2 obs-1", "FINDING_VERDICT_SUSPECTED"},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, c.src, c.x)
			for _, rule := range retryRules {
				want := 0
				if rule == c.rule {
					want = 1
				}
				if got := only(res, rule); len(got) != want {
					t.Fatalf("%d %s findings, want %d:\n%s", len(got), rule, want, dump(res.Findings))
				}
				if got := rules(res)[rule]; got != checked {
					t.Fatalf("%s is %s", rule, got)
				}
			}
			names(t, res, c.rule, runID, id02(c.rule, "d1", runID))
			f := only(res, c.rule)[0]
			if f.GetFinding().GetVerdict().String() != c.verdict || citedEvents(f) != c.cites {
				t.Fatalf("%s citing %q; want %s citing %q", f.GetFinding().GetVerdict(), citedEvents(f), c.verdict, c.cites)
			}
		})
	}
}

// interleaved is the denial and the retry with the retry proposed after the
// denial was proposed and before it was decided, listed after it all.
func interleaved() supervise.Export {
	r := again()
	r.at = 10*time.Second + 500*time.Millisecond
	return acts(denial(), r)
}

// TestWhatIsNoRetry: a block that is not the policy's denial, a retry an
// approval let run, the same arguments again, a variant proposed before the
// denial was decided and a read after a write's denial are no retries.
func TestWhatIsNoRetry(t *testing.T) {
	approved := again()
	approved.approval = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	sameArgs := again()
	sameArgs.hash = hashOf('a')
	earlier := again()
	earlier.at = 5 * time.Second
	reading := act{call: call{req: "g1", tool: "get_order", upstream: "shop", at: 20 * time.Second}, res: orderNo("42"), effect: read}
	for name, x := range map[string]supervise.Export{
		"an approved retry":         acts(denial(), approved),
		"a pause block":             acts(denial().ending("pause"), again(), manual()),
		"a stopped run":             acts(denial().ending("stopped"), again(), manual()),
		"a denial and a pause":      acts(denial().ending("denied and paused"), again(), manual()),
		"an approval that expired":  acts(denial().ending("expired"), again(), manual()),
		"the same arguments":        acts(denial(), sameArgs),
		"a variant proposed before": acts(earlier, denial()),
		"a variant before decision": interleaved(),
		"a read after a write":      acts(denial(), reading),
		"another resource":          acts(denial(), act{call: manual().call, res: orderNo("43"), effect: transact}),
		"no resource either side": acts(act{call: denial().call, effect: transact},
			act{call: manual().call, effect: transact}),
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(), x)
			for rule, got := range retries(res) {
				if len(got) != 0 {
					t.Fatalf("%s fires %q:\n%s", rule, got, dump(res.Findings))
				}
			}
		})
	}
}

// TestARetryHeldForApprovalIsIndeterminate: a retry still waiting on an
// approval may yet be approved; a later retry that ran keeps the finding
// suggested and is what it cites. One the plane blocked before it asked for
// the approval waits on nothing.
func TestARetryHeldForApprovalIsIndeterminate(t *testing.T) {
	held := again().ending("held")
	unasked := again().ending("unasked")
	ran := again()
	ran.req, ran.at, ran.hash = "r2", 30*time.Second, hashOf('c')
	for name, c := range map[string]struct {
		x           supervise.Export
		want, cites string
	}{
		"held alone":         {acts(denial(), held), "FINDING_VERDICT_INDETERMINATE", "d1-e2 r1-e1"},
		"held, then one ran": {acts(denial(), held, ran), "FINDING_VERDICT_SUSPECTED", "d1-e2 r2-e1"},
		"blocked unasked":    {acts(denial(), unasked), "FINDING_VERDICT_SUSPECTED", "d1-e2 r1-e1"},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(), c.x)
			got := only(res, ruleArgs)
			if len(got) != 1 || got[0].GetFinding().GetVerdict().String() != c.want || citedEvents(got[0]) != c.cites {
				t.Fatalf("want one %s citing %q:\n%s", c.want, c.cites, dump(res.Findings))
			}
		})
	}
}

// TestAfterIsThePlanesTimeWithinTheExportBothCameFrom: a later batch of an
// export may land before an earlier one, so its sequence orders nothing.
// The plane's times order the two: a retry listed before the denial but
// proposed after its decision is one, and one listed after it but proposed
// before is none; the same time or none is untold. Two planes may send to one
// collector and nothing in an event names its plane, so a later time only
// suggests, within one export or across, and a redundant export changes
// nothing.
func TestAfterIsThePlanesTimeWithinTheExportBothCameFrom(t *testing.T) {
	earlyTime := again()
	earlyTime.at = time.Second
	untimed := acts(again())
	for _, ev := range untimed.Events {
		ev.OccurredAt = nil
	}
	atDecision := again()
	atDecision.at = 11 * time.Second
	listedFirst := slices.Concat(again().events(), denial().events())
	untimedWithin := acts(denial(), again())
	for _, ev := range untimedWithin.Events[3:] {
		ev.OccurredAt = nil
	}
	for name, c := range map[string]struct {
		exports []supervise.Export
		want    []string
	}{
		"one export, listed after, proposed before": {[]supervise.Export{acts(denial(), earlyTime)}, nil},
		"one export, listed before, proposed after": {[]supervise.Export{{Whole: true, Events: listedFirst}}, []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"one export, the decision time":             {[]supervise.Export{acts(denial(), atDecision)}, []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"one export, no time":                       {[]supervise.Export{untimedWithin}, []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"two exports":                               {[]supervise.Export{acts(denial()), acts(again())}, []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"a redundant copy of the denial":            {[]supervise.Export{acts(denial()), acts(again()), acts(denial())}, []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"a redundant copy of the retry":             {[]supervise.Export{acts(denial()), acts(again()), acts(again())}, []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"an export holding both":                    {[]supervise.Export{acts(denial()), acts(again()), acts(denial(), again())}, []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"two exports, an earlier time":              {[]supervise.Export{acts(denial()), acts(earlyTime)}, nil},
		"two exports, the decision time":            {[]supervise.Export{acts(denial()), acts(atDecision)}, []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"two exports, no time":                      {[]supervise.Export{acts(denial()), untimed}, []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(), c.exports...)
			if got := verdicts(res, ruleArgs); !slices.Equal(got, c.want) {
				t.Fatalf("findings %q, want %q:\n%s", got, c.want, dump(res.Findings))
			}
			if len(c.want) > 0 {
				names(t, res, ruleArgs, runID, id02(ruleArgs, "d1", runID))
			}
		})
	}
}

// TestANewDenialGivesANewAnchor: a retry the policy denies is a new denial,
// and what follows it is a retry of each; further retries of one denial keep
// its finding's id.
func TestANewDenialGivesANewAnchor(t *testing.T) {
	deniedAgain := again().ending("deny")
	third := again()
	third.req, third.at, third.hash = "r2", 30*time.Second, hashOf('c')
	res := retrySupervise(t, source(), acts(denial(), deniedAgain, third))
	got := only(res, ruleArgs)
	want := []struct{ id, cites string }{
		{id02(ruleArgs, "d1", runID), "d1-e2 r1-e1 r2-e1"},
		{id02(ruleArgs, "r1", runID), "r1-e2 r2-e1"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d findings:\n%s", len(got), dump(res.Findings))
	}
	for i, w := range want {
		if got[i].GetFinding().GetFindingId() != w.id || citedEvents(got[i]) != w.cites {
			t.Errorf("finding %d is %s citing %q; want %s citing %q", i, got[i].GetFinding().GetFindingId(), citedEvents(got[i]), w.id, w.cites)
		}
	}
}

// TestARetryInAnotherRunNamesThatRun: under inherit a denial in one child
// and a retry in its sibling name the sibling, and a retry in each names
// each.
func TestARetryInAnotherRunNamesThatRun(t *testing.T) {
	other := manual()
	other.req, other.at = "r2", 30*time.Second
	for name, c := range map[string]struct {
		x    supervise.Export
		rule string
		want []string
	}{
		"other arguments":   {acts(denial().in(childRun), again().in(siblingRun)), ruleArgs, []string{siblingRun}},
		"another tool":      {acts(denial().in(childRun), manual().in(siblingRun)), ruleRes, []string{siblingRun}},
		"a retry from each": {acts(denial().in(childRun), manual().in(siblingRun), other.in(childRun)), ruleRes, []string{childRun, siblingRun}},
	} {
		t.Run(name, func(t *testing.T) {
			res := supervise02(t, siblings(), c.x)
			got := only(res, c.rule)
			if len(got) != len(c.want) {
				t.Fatalf("%d findings, want %d:\n%s", len(got), len(c.want), dump(res.Findings))
			}
			for i, run := range c.want {
				if f := got[i].GetFinding(); f.GetRunId() != run || f.GetFindingId() != id02(c.rule, "d1", run) {
					t.Errorf("finding %d names %s with id %s; want %s", i, f.GetRunId(), f.GetFindingId(), run)
				}
			}
		})
	}
}

// TestAReadCountsAfterTheDenialOfARead: on the same resource a read after the
// denial of anything but a read is no retry; an effect not told is no pass.
func TestAReadCountsAfterTheDenialOfARead(t *testing.T) {
	for _, c := range []struct {
		denied, retried controlv1.EffectClass
		want            string
	}{
		{transact, read, ""},
		{read, read, "FINDING_VERDICT_SUSPECTED"},
		{read, transact, "FINDING_VERDICT_SUSPECTED"},
		{transact, write, "FINDING_VERDICT_SUSPECTED"},
		{unclassified, write, "FINDING_VERDICT_SUSPECTED"},
		{read, unclassified, "FINDING_VERDICT_SUSPECTED"},
		{unclassified, read, "FINDING_VERDICT_INDETERMINATE"},
		{transact, unclassified, "FINDING_VERDICT_INDETERMINATE"},
		{transact, controlv1.EffectClass(99), "FINDING_VERDICT_INDETERMINATE"},
		{controlv1.EffectClass(99), read, "FINDING_VERDICT_INDETERMINATE"},
	} {
		t.Run(c.denied.String()+" then "+c.retried.String(), func(t *testing.T) {
			d, r := denial(), manual()
			d.effect, r.effect = c.denied, c.retried
			res := retrySupervise(t, source(), acts(d, r))
			want := []string{runID + " " + c.want}
			if c.want == "" {
				want = nil
			}
			if got := verdicts(res, ruleRes); !slices.Equal(got, want) {
				t.Fatalf("findings %q, want %q:\n%s", got, want, dump(res.Findings))
			}
		})
	}
}

// TestArgumentsNotHashedAreNoPass: with either hash missing a variant cannot
// be told from the call repeated.
func TestArgumentsNotHashedAreNoPass(t *testing.T) {
	unhashedDenial, unhashedRetry := denial(), again()
	unhashedDenial.hash, unhashedRetry.hash = "", ""
	for name, x := range map[string]supervise.Export{
		"the denial's": acts(unhashedDenial, again()),
		"the retry's":  acts(denial(), unhashedRetry),
		"either's":     acts(unhashedDenial, unhashedRetry),
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(), x)
			if got := verdicts(res, ruleArgs); !slices.Equal(got, []string{runID + " FINDING_VERDICT_INDETERMINATE"}) {
				t.Fatalf("findings %q:\n%s", got, dump(res.Findings))
			}
		})
	}
}

// TestTheRetryRulesSayWhatTheyChecked: with no plane event none is checked;
// with no source the report around a denial is not looked for.
func TestTheRetryRulesSayWhatTheyChecked(t *testing.T) {
	empty := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family()})
	for _, rule := range append([]string{ruleResource}, retryRules...) {
		if got := rules(empty)[rule]; got != "RULE_STATE_NOT_CHECKED:no plane event of the run" {
			t.Errorf("with no event %s is %s", rule, got)
		}
	}
	unsourced := supervise02(t, family(), acts(denial(), again()))
	if got := rules(unsourced)[ruleAround]; got != "RULE_STATE_NOT_CHECKED:no observation source was read" {
		t.Errorf("with no source %s is %s", ruleAround, got)
	}
	if got := strings.Join(verdicts(unsourced, ruleArgs), ","); got != runID+" FINDING_VERDICT_SUSPECTED" {
		t.Errorf("with no source %s fires %q", ruleArgs, got)
	}
	report := ob{id: "obs-1", name: "issue_refund", at: 30 * time.Second}
	neverHeard := source(report)
	neverHeard.Heard = false
	lapsed := source(report)
	lapsed.LastHeard = t0.Add(-time.Hour)
	quiet := source()
	quiet.SourceID, quiet.Heard = "s2", false
	for name, c := range map[string]struct {
		sources []supervise.Source
		notRead []string
		want    string
	}{
		"heard":               {[]supervise.Source{source(report)}, nil, "RULE_STATE_CHECKED:"},
		"never heard":         {[]supervise.Source{neverHeard}, nil, "RULE_STATE_NOT_CHECKED:a source is silent, never heard or not read"},
		"silent":              {[]supervise.Source{lapsed}, nil, "RULE_STATE_NOT_CHECKED:a source is silent, never heard or not read"},
		"another not read":    {[]supervise.Source{source(report)}, []string{"s9"}, "RULE_STATE_NOT_CHECKED:a source is silent, never heard or not read"},
		"another never heard": {[]supervise.Source{source(report), quiet}, nil, "RULE_STATE_NOT_CHECKED:a source is silent, never heard or not read"},
	} {
		res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family(),
			Exports: []supervise.Export{acts(denial())}, Sources: c.sources, SourcesNotRead: c.notRead})
		if got := rules(res)[ruleAround]; got != c.want {
			t.Errorf("a source %s: %s is %q, want %q", name, ruleAround, got, c.want)
		}
		if c.want != "RULE_STATE_CHECKED:" && len(only(res, ruleAround)) != 0 {
			t.Errorf("a source %s: %s not checked with findings:\n%s", name, ruleAround, dump(res.Findings))
		}
	}
}
