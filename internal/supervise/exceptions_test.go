package supervise_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
)

const (
	ruleOutside  = "STEP_OUTSIDE_PROCEDURE"
	ruleSkipped  = "REQUIRED_STEP_SKIPPED"
	ruleOrder    = "STEP_OUT_OF_ORDER"
	ruleContinue = "CONTINUED_AFTER_FAILURE"
	ruleTaken    = "EXCEPTION_TAKEN"
	approved     = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	rejected     = controlv1.ApprovalState_APPROVAL_STATE_REJECTED
)

// manualRefund is m1, the child's call of refund_manual on pay: a tool
// outside the procedure that the fixture's first exception names.
func manualRefund(approval controlv1.ApprovalState) act {
	return act{call: call{req: "m1", tool: "refund_manual", upstream: "pay", at: 20 * time.Second, run: childRun},
		approval: approval}
}

func lookupCall() act { return act{call: call{req: "r1", tool: "get_order", upstream: "shop"}} }

// TestAnApprovalTakesTheExceptionAndRaisesItsFinding: the child's approved
// call of refund_manual on pay is no STEP_OUTSIDE_PROCEDURE; EXCEPTION_TAKEN
// names the child with the procedure's severity and escalation, citing the
// call and its approval. The same call unapproved, or approved on another
// upstream, or another outside tool approved, is a finding.
func TestAnApprovalTakesTheExceptionAndRaisesItsFinding(t *testing.T) {
	res := supervise02(t, family(), acts(lookupCall(), manualRefund(approved)))
	if got := only(res, ruleOutside); len(got) != 0 {
		t.Fatalf("an approved exception left findings:\n%s", dump(got))
	}
	names(t, res, ruleTaken, childRun, id02(ruleTaken, "manual_refund_approved", childRun))
	taken := only(res, ruleTaken)[0]
	if f := taken.GetFinding(); f.GetVerdict() != confirmed || f.GetSeverity() != controlv1.FindingSeverity_FINDING_SEVERITY_INFO ||
		taken.GetEscalation() != findingv1alpha1.Escalation_ESCALATION_INFORM || citedEvents(taken) != "m1-e1 m1-e4" {
		t.Fatalf("EXCEPTION_TAKEN %s %s %s citing %q", f.GetVerdict(), f.GetSeverity(), taken.GetEscalation(), citedEvents(taken))
	}

	otherUpstream := manualRefund(approved)
	otherUpstream.upstream = "ops"
	otherTool := manualRefund(approved)
	otherTool.tool = "wipe_disk"
	for name, c := range map[string]struct {
		a      act
		anchor []string
	}{
		"unapproved":                {manualRefund(0), []string{"refund_manual", "pay"}},
		"approved on another place": {otherUpstream, []string{"refund_manual", "ops"}},
		"another tool approved":     {otherTool, []string{"wipe_disk", "pay"}},
	} {
		t.Run(name, func(t *testing.T) {
			res := supervise02(t, family(), acts(lookupCall(), c.a))
			names(t, res, ruleOutside, childRun, id02(ruleOutside, append(c.anchor, childRun)...))
			if v := only(res, ruleOutside)[0].GetFinding().GetVerdict(); v != confirmed || len(only(res, ruleTaken)) != 0 {
				t.Fatalf("%s with %d exceptions taken", v, len(only(res, ruleTaken)))
			}
		})
	}
}

// TestAHeldApprovalConfirmsNothingUntilRefusedOrExpired: a call held for an
// approval, or whose trail is in doubt, takes no waiver and leaves its
// finding indeterminate; once refused or expired the same finding is
// confirmed. A held call beside one the run made without approval does not
// weaken what that one confirms.
func TestAHeldApprovalConfirmsNothingUntilRefusedOrExpired(t *testing.T) {
	held := manualRefund(0)
	held.outcome = "held"
	expired := manualRefund(0)
	expired.outcome = "expired"
	unapproved := manualRefund(0)
	unapproved.req, unapproved.at = "m2", 40*time.Second
	inDoubt := acts(lookupCall(), manualRefund(approved))
	conflict := acts(manualRefund(approved))
	conflict.Events[3].OccurredAt = at(time.Hour)
	for name, c := range map[string]struct {
		exports []supervise.Export
		want    controlv1.FindingVerdict
		cites   string
	}{
		"held":                   {[]supervise.Export{acts(lookupCall(), held)}, indetermin, "m1-e1"},
		"then refused":           {[]supervise.Export{acts(lookupCall(), manualRefund(rejected))}, confirmed, "m1-e1"},
		"then expired":           {[]supervise.Export{acts(lookupCall(), expired)}, confirmed, "m1-e1"},
		"held beside unapproved": {[]supervise.Export{acts(lookupCall(), held, unapproved)}, confirmed, "m1-e1 m2-e1"},
		"approved in doubt":      {[]supervise.Export{inDoubt, conflict}, indetermin, "m1-e1"},
	} {
		t.Run(name, func(t *testing.T) {
			res := supervise02(t, family(), c.exports...)
			names(t, res, ruleOutside, childRun, id02(ruleOutside, "refund_manual", "pay", childRun))
			f := only(res, ruleOutside)[0]
			if f.GetFinding().GetVerdict() != c.want || citedEvents(f) != c.cites || len(only(res, ruleTaken)) != 0 {
				t.Fatalf("%s citing %q, %d exceptions taken; want %s citing %q and none taken",
					f.GetFinding().GetVerdict(), citedEvents(f), len(only(res, ruleTaken)), c.want, c.cites)
			}
		})
	}
}

// closedFamily is family with every run closed.
func closedFamily() []supervise.Run { return family(runID, childRun, grandchildRun) }

// stepFindings is each finding of the rules about steps and of
// EXCEPTION_TAKEN, as rule, verdict and what it cites, in order.
func stepFindings(res *supervise.Result) []string {
	var out []string
	for _, f := range res.Findings {
		switch rule := f.GetFinding().GetRuleId(); rule {
		case ruleSkipped, ruleOrder, ruleContinue, ruleTaken:
			out = append(out, rule+" "+strings.TrimPrefix(f.GetFinding().GetVerdict().String(), "FINDING_VERDICT_")+
				" "+citedEvents(f))
		}
	}
	return out
}

// TestAStepExceptionWaivesItsOwnRuleAndNoOther: a waiver takes away the
// finding of its one rule and raises EXCEPTION_TAKEN at that finding's
// verdict, citing it and the condition's evidence; the same input's
// findings of other rules stand. A condition not met waives nothing.
func TestAStepExceptionWaivesItsOwnRuleAndNoOther(t *testing.T) {
	failed := call{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"}
	denied := call{req: "r1", tool: "get_order", upstream: "shop", outcome: "deny"}
	mail := call{req: "n1", tool: "send_mail", upstream: "mail", at: 20 * time.Second}
	refund := call{req: "r2", tool: "issue_refund", upstream: "pay", at: 30 * time.Second}
	early := act{call: call{req: "n1", tool: "send_mail", upstream: "mail", at: 10 * time.Second}, approval: approved}
	silent := source()
	silent.Heard = false
	for name, c := range map[string]struct {
		x       supervise.Export
		sources []supervise.Source
		want    []string
	}{
		"a failed lookup excuses the refund, not the mail's order": {export(failed, mail), nil, []string{
			"STEP_OUT_OF_ORDER SUSPECTED n1-e1", "EXCEPTION_TAKEN SUSPECTED r1-e4"}},
		"a denied lookup is no failed step": {export(denied, mail), nil, []string{
			"REQUIRED_STEP_SKIPPED SUSPECTED ", "STEP_OUT_OF_ORDER SUSPECTED n1-e1"}},
		"the denial's reason waives continuing": {export(denied, refund), nil, []string{
			"EXCEPTION_TAKEN SUSPECTED r1-e3 r2-e1 r1-e2"}},
		"a failure of another reason does not": {export(failed, refund), nil, []string{
			"CONTINUED_AFTER_FAILURE SUSPECTED r1-e4 r2-e1"}},
		"an approved early mail": {acts(lookupCall(), early, act{call: refund}), nil, []string{
			"EXCEPTION_TAKEN SUSPECTED n1-e1 r2-e1 n1-e4"}},
		"an early mail not approved": {acts(lookupCall(), act{call: early.call}, act{call: refund}), nil, []string{
			"STEP_OUT_OF_ORDER SUSPECTED n1-e1 r2-e1"}},
		"no stronger than the finding it waives": {export(failed, mail), []supervise.Source{silent}, []string{
			"STEP_OUT_OF_ORDER INDETERMINATE n1-e1", "EXCEPTION_TAKEN INDETERMINATE r1-e4"}},
	} {
		t.Run(name, func(t *testing.T) {
			res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: closedFamily(),
				Exports: []supervise.Export{c.x}, Sources: c.sources})
			if got := stepFindings(res); !slices.Equal(got, c.want) {
				t.Fatalf("findings %q, want %q:\n%s", got, c.want, dump(res.Findings))
			}
		})
	}
}

// TestTheExceptionTakenIsAnchoredOnItsID: a waiver of a rule about the tree
// names the supervised run, and its id is the exception's.
func TestTheExceptionTakenIsAnchoredOnItsID(t *testing.T) {
	res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: closedFamily(), Exports: []supervise.Export{
		export(call{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"})}})
	names(t, res, ruleTaken, runID, id02(ruleTaken, "no_refund_after_failed_lookup"))
}

// TestAnUnknownConditionLeavesItsFindingIndeterminate: a failed step whose
// call has no end yet, and a reason read from a trail in doubt, take no
// waiver; the finding is raised indeterminate.
func TestAnUnknownConditionLeavesItsFindingIndeterminate(t *testing.T) {
	refund := call{req: "r2", tool: "issue_refund", upstream: "pay", at: 20 * time.Second}
	denied := export(call{req: "r1", tool: "get_order", upstream: "shop", outcome: "deny"}, refund)
	conflict := export(call{req: "r1", tool: "get_order", upstream: "shop", outcome: "deny"})
	conflict.Events[1].OccurredAt = at(time.Hour)
	for name, c := range map[string]struct {
		exports []supervise.Export
		rule    string
	}{
		"a lookup still held": {[]supervise.Export{export(call{req: "r1", tool: "get_order", upstream: "shop", outcome: "held"})}, ruleSkipped},
		"a reason in doubt":   {[]supervise.Export{denied, conflict}, ruleContinue},
	} {
		t.Run(name, func(t *testing.T) {
			res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: closedFamily(), Exports: c.exports})
			got := only(res, c.rule)
			if len(got) != 1 || got[0].GetFinding().GetVerdict() != indetermin || len(only(res, ruleTaken)) != 0 {
				t.Fatalf("%s: %d findings, %d taken:\n%s", c.rule, len(got), len(only(res, ruleTaken)), dump(res.Findings))
			}
		})
	}
}

// TestExceptionTakenIsCheckedWhenEveryRuleItWaivesIs: a waiver taken is
// written whatever else was judged, and the rule reads checked only when
// every rule an exception waives was; a procedure with no exception turns
// it off.
func TestExceptionTakenIsCheckedWhenEveryRuleItWaivesIs(t *testing.T) {
	x := acts(lookupCall(), manualRefund(approved))
	open := supervise02(t, family(), x)
	if got := rules(open)[ruleTaken]; got != "RULE_STATE_NOT_CHECKED:exceptions on REQUIRED_STEP_SKIPPED are not judged: the run is open" ||
		len(only(open, ruleTaken)) != 1 {
		t.Fatalf("open: %s is %q with findings:\n%s", ruleTaken, got, dump(open.Findings))
	}
	if got := rules(supervise02(t, closedFamily(), x))[ruleTaken]; got != checked {
		t.Fatalf("closed: %s is %q", ruleTaken, got)
	}
	p, err := supervise.ReadProcedure([]byte(withoutExceptions(t, v02Doc(t))))
	if err != nil {
		t.Fatal(err)
	}
	none := treeEvaluate(t, supervise.Input{Procedure: p, Tree: closedFamily(), Exports: []supervise.Export{x}})
	if got := rules(none)[ruleTaken]; got != "RULE_STATE_OFF:the procedure states no exception" || len(only(none, ruleOutside)) != 1 {
		t.Fatalf("no exception: %s is %q with findings:\n%s", ruleTaken, got, dump(none.Findings))
	}
}

// agentInduced is each condition the agent can bring about itself: a step
// it makes fail, and a reason code its own call draws.
var agentInduced = []string{`{"step_failed": "lookup"}`, `{"step_failed": "refund"}`, `{"reason": "RULE_DENY"}`,
	`{"reason": "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL"}`, `{"reason": "RULE_ALLOW"}`}

// TestNoRuleThatMayStopIsWaivedOnWhatTheAgentInduces: every rule that may
// stop a run, on every target, refuses each condition the agent can bring
// about.
func TestNoRuleThatMayStopIsWaivedOnWhatTheAgentInduces(t *testing.T) {
	var stopping []string
	for _, id := range supervise.RuleIDsOf("0.2") {
		if supervise.MayStop(id) {
			stopping = append(stopping, id)
		}
	}
	if want := []string{"REPEATED_DENIAL", "STEP_OUTSIDE_PROCEDURE", "RESOURCE_OUTSIDE_RUN"}; !slices.Equal(stopping, want) {
		t.Fatalf("the rules that may stop are %q, want %q", stopping, want)
	}
	for _, rule := range stopping {
		for _, target := range []string{onStep, onTool, `"step": "refund"`, `"tool": "wipe_disk", "upstream": "ops"`} {
			for _, cond := range agentInduced {
				doc := withException(t, exception(rule, target, cond))
				if p, err := supervise.ReadProcedure([]byte(doc)); !errors.Is(err, supervise.ErrProcedure) || p != nil {
					t.Errorf("%s on %s when %s: ReadProcedure = %v; want ErrProcedure", rule, target, cond, err)
				}
			}
		}
	}
}

// TestAReasonIsThePolicyDecisionsOwn: a reason is read from the call's
// policy decision, never from the block the plane wrote: a lookup the plane
// paused after the policy allowed it does not meet a condition on PAUSED,
// and one the policy denied meets RULE_DENY though the block carries more.
func TestAReasonIsThePolicyDecisionsOwn(t *testing.T) {
	refund := call{req: "r2", tool: "issue_refund", upstream: "pay", at: 30 * time.Second}
	onPause, err := supervise.ReadProcedure([]byte(v02With(t, `"condition": {"reason": "RULE_DENY"}`, `"condition": {"reason": "PAUSED"}`)))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		p      *supervise.Procedure
		lookup string
		want   []string
	}{
		"paused, waived on PAUSED": {onPause, "pause", []string{"CONTINUED_AFTER_FAILURE SUSPECTED r1-e3 r2-e1"}},
		"denied and paused, waived on RULE_DENY": {inheritProc(t), "denied and paused",
			[]string{"EXCEPTION_TAKEN SUSPECTED r1-e3 r2-e1 r1-e2"}},
	} {
		t.Run(name, func(t *testing.T) {
			res := treeEvaluate(t, supervise.Input{Procedure: c.p, Tree: closedFamily(), Exports: []supervise.Export{
				export(call{req: "r1", tool: "get_order", upstream: "shop", outcome: c.lookup}, refund)}})
			if got := stepFindings(res); !slices.Equal(got, c.want) {
				t.Fatalf("findings %q, want %q:\n%s", got, c.want, dump(res.Findings))
			}
		})
	}
}
