package supervise_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/supervise"
)

// TestARetryAnywhereInTheTreeSuggests: a retry by the denied run, one of its
// descendants, its parent or a sibling suggests, whichever form it takes;
// none confirms, since nothing in an event names the plane whose clock timed
// it.
func TestARetryAnywhereInTheTreeSuggests(t *testing.T) {
	otherOrder := act{call: call{req: "r9", tool: "issue_refund", upstream: "pay", at: 30 * time.Second},
		res: orderNo("77"), hash: hashOf('c'), effect: transact}
	for name, c := range map[string]struct {
		tree []supervise.Run
		x    supervise.Export
		rule string
		want string
	}{
		"the root's denial, its child's retry":       {family(), acts(denial(), again().in(childRun)), ruleArgs, childS},
		"the root's denial, its grandchild's retry":  {family(), acts(denial(), again().in(grandchildRun)), ruleArgs, grandchildRun + " FINDING_VERDICT_SUSPECTED"},
		"the child's denial, its own retry":          {family(), acts(denial().in(childRun), again().in(childRun)), ruleArgs, childS},
		"the child's denial, the root's other order": {siblings(), acts(denial().in(childRun), otherOrder), ruleArgs, rootS},
		"the child's denial, the root's retry":       {family(), acts(denial().in(childRun), manual()), ruleRes, rootS},
		"the grandchild's denial, its parent's retry": {family(), acts(denial().in(grandchildRun), again().in(childRun)), ruleArgs,
			childS},
		"a child's denial, its sibling's retry": {siblings(), acts(denial().in(childRun), again().in(siblingRun)), ruleArgs,
			siblingRun + " FINDING_VERDICT_SUSPECTED"},
	} {
		t.Run(name, func(t *testing.T) {
			res := supervise02(t, c.tree, c.x)
			if got := verdicts(res, c.rule); !slices.Equal(got, []string{c.want}) {
				t.Fatalf("%s findings %q, want %q:\n%s", c.rule, got, c.want, dump(res.Findings))
			}
		})
	}
}

// TestABindingConfirmsOnlyARunWhoseOwnCallsCarryTwoIds: 42 in the root and a
// denied probe of 43 in its child suspect both; 42 and 43 in the root
// confirm it, and its child's 42 beside them is suspected.
func TestABindingConfirmsOnlyARunWhoseOwnCallsCarryTwoIds(t *testing.T) {
	for name, c := range map[string]struct {
		x    supervise.Export
		want []string
	}{
		"one id in each run": {acts(lookupOf("l1", time.Second, orderNo("42")),
			lookupOf("l2", 5*time.Second, orderNo("43")).in(childRun).ending("deny")), []string{rootS, childS}},
		"two ids in the root": {acts(lookupOf("l1", time.Second, orderNo("42")), refundOf("l2", 5*time.Second, orderNo("43")),
			lookupOf("l3", 9*time.Second, orderNo("42")).in(childRun)), []string{rootC, childS}},
	} {
		t.Run(name, func(t *testing.T) {
			res := supervise02(t, siblings(), c.x)
			if got := verdicts(res, ruleResource); !slices.Equal(got, c.want) {
				t.Fatalf("findings %q, want %q:\n%s", got, c.want, dump(res.Findings))
			}
		})
	}
}

// TestAThresholdCrossedByAChildLeavesTheRootItsOwn: a closed child's three
// denials cross max_denials first; the root's fifty later ones confirm the
// root on its own, and the child on its own three.
func TestAThresholdCrossedByAChildLeavesTheRootItsOwn(t *testing.T) {
	var calls []call
	for i := range 3 {
		calls = append(calls, deny(fmt.Sprintf("c%d", i), childRun, time.Duration(i+1)*time.Second))
	}
	for i := range 50 {
		calls = append(calls, deny(fmt.Sprintf("r%02d", i), "", time.Duration(10+i)*time.Second))
	}
	tree := siblings()
	tree[1].Closed = true
	res := treeEvaluate(t, supervise.Input{Procedure: procAt3(t, inheritProc(t)), Tree: tree, Exports: []supervise.Export{export(calls...)}})
	if got := verdicts(res, supervise.RuleRepeatedDenial); !slices.Equal(got, []string{rootC, childC}) {
		t.Fatalf("findings %q:\n%s", got, dump(res.Findings))
	}
	for _, f := range only(res, supervise.RuleRepeatedDenial) {
		for _, r := range f.GetRefs() {
			if r.GetEvent().GetRunId() != f.GetFinding().GetRunId() {
				t.Errorf("the finding of %s cites %s of %s", f.GetFinding().GetRunId(), r.GetEvent().GetEventId(), r.GetEvent().GetRunId())
			}
		}
	}
}

// TestACrossingFromAnotherExportIsUntold: the root's three denials in one
// export confirm the root; the child's one, from another export whose clock
// puts it between them, cannot be placed at or after the third.
func TestACrossingFromAnotherExportIsUntold(t *testing.T) {
	var root []call
	for i := range 3 {
		root = append(root, deny(fmt.Sprintf("a%d", i), "", time.Duration(i+1)*time.Second))
	}
	child := deny("b0", childRun, 2500*time.Millisecond)
	res := treeEvaluate(t, supervise.Input{Procedure: procAt3(t, inheritProc(t)), Tree: siblings(),
		Exports: []supervise.Export{export(root...), export(child)}})
	if got := verdicts(res, supervise.RuleRepeatedDenial); !slices.Equal(got, []string{rootC, childI}) {
		t.Fatalf("findings %q:\n%s", got, dump(res.Findings))
	}
}

// TestADenialFromAnotherClockIsNeverLeftOut: two exports do not share a
// clock, so a child's denial timed before the root's in its own export may
// still be the one that crossed the bound; it is indeterminate, not dropped.
func TestADenialFromAnotherClockIsNeverLeftOut(t *testing.T) {
	root := []call{deny("a0", "", 10*time.Second), deny("a1", "", 20*time.Second)}
	child := deny("b0", childRun, 5*time.Second)
	res := treeEvaluate(t, supervise.Input{Procedure: procAt3(t, inheritProc(t)), Tree: siblings(),
		Exports: []supervise.Export{export(root...), export(child)}})
	if got := verdicts(res, supervise.RuleRepeatedDenial); !slices.Equal(got, []string{rootI, childI}) {
		t.Fatalf("findings %q:\n%s", got, dump(res.Findings))
	}
}

// TestAnUntimedDenialLeavesNoRunOut: in one export, a denial with no time
// could stand anywhere in the order, so no run's timed denials are known to
// come before the one that crossed the bound; a run's own three still
// confirm it.
func TestAnUntimedDenialLeavesNoRunOut(t *testing.T) {
	root2 := []call{deny("a0", "", 10*time.Second), deny("a1", "", 20*time.Second)}
	root3 := append(slices.Clone(root2), deny("a2", "", 30*time.Second))
	for name, c := range map[string]struct {
		x    supervise.Export
		want []string
	}{
		"the child's only denial": {untimedIn(export(append(slices.Clone(root2), deny("b0", childRun, 0))...), "b0"),
			[]string{rootI, childI}},
		"the child's second denial": {untimedIn(export(append(slices.Clone(root2), deny("b0", childRun, 30*time.Second),
			deny("b1", childRun, 0))...), "b1"), []string{rootI, childI}},
		"the root's own three": {untimedIn(export(append(slices.Clone(root3), deny("b0", childRun, 0))...), "b0"),
			[]string{rootC, childI}},
	} {
		t.Run(name, func(t *testing.T) {
			res := treeEvaluate(t, supervise.Input{Procedure: procAt3(t, inheritProc(t)), Tree: siblings(),
				Exports: []supervise.Export{c.x}})
			if got := verdicts(res, supervise.RuleRepeatedDenial); !slices.Equal(got, c.want) {
				t.Fatalf("findings %q, want %q:\n%s", got, c.want, dump(res.Findings))
			}
		})
	}
}

// untimedIn is x with no time on the events of request req.
func untimedIn(x supervise.Export, req string) supervise.Export {
	for _, ev := range x.Events {
		if ev.GetRequestId() == req {
			ev.OccurredAt = nil
		}
	}
	return x
}
