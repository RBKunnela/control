package supervise_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
)

// cutAfter is x with the events of req after its first n left out, as an
// export holds a trail whose later events are still in transit.
func cutAfter(x supervise.Export, req string, n int) supervise.Export {
	var out []*controlv1.Event
	seen := 0
	for _, ev := range x.Events {
		if ev.GetRequestId() == req {
			seen++
			if seen > n {
				continue
			}
		}
		out = append(out, ev)
	}
	x.Events = out
	return x
}

// TestADenialWhoseBlockHasNotArrivedIsNoPass: on a closed run, a request
// whose decision or block is still in transit may be a denial and a failure
// no rule has read, so the rules that count them are not checked; the same
// block read makes the count.
func TestADenialWhoseBlockHasNotArrivedIsNoPass(t *testing.T) {
	p := procWith(t)
	closed := supervise.Run{Closed: true}
	whole := evaluate(t, supervise.Input{Procedure: p, Run: closed, Exports: []supervise.Export{export(denials(4)...)}})
	if got := len(only(whole, "REPEATED_DENIAL")); got != 1 {
		t.Fatalf("four blocks read: %d REPEATED_DENIAL findings, want 1", got)
	}
	for _, n := range []int{1, 2} {
		cut := evaluate(t, supervise.Input{Procedure: p, Run: closed,
			Exports: []supervise.Export{cutAfter(export(denials(4)...), "d4", n)}})
		for _, rule := range []string{"REPEATED_DENIAL", "CONTINUED_AFTER_FAILURE"} {
			if got := rules(cut)[rule]; !strings.HasPrefix(got, "RULE_STATE_NOT_CHECKED:") || !strings.Contains(got, "d4") {
				t.Errorf("d4 cut after %d events: %s is %q, want not checked naming d4", n, rule, got)
			}
		}
		retry := retrySupervise(t, source(), cutAfter(acts(denial(), again()), "d1", n))
		for _, rule := range retryRules {
			if got := rules(retry)[rule]; !strings.HasPrefix(got, "RULE_STATE_NOT_CHECKED:") || !strings.Contains(got, `"d1"`) {
				t.Errorf("d1 cut after %d events: %s is %q, want not checked naming d1", n, rule, got)
			}
		}
	}
}

// TestACallWhoseEndHasNotArrivedIsNoPass: on a closed run, an allowed call
// whose failure is still in transit, followed by another step, may be a
// continuation after a failure no rule has read, so the rule is not checked;
// the same failure read makes the finding.
func TestACallWhoseEndHasNotArrivedIsNoPass(t *testing.T) {
	p := procWith(t)
	calls := []call{
		{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"},
		{req: "r3", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
		{req: "r4", tool: "send_mail", upstream: "mail", at: 20 * time.Second},
	}
	if got := len(only(closedRun(t, p, export(calls...)), "CONTINUED_AFTER_FAILURE")); got != 1 {
		t.Fatalf("the failure read: %d CONTINUED_AFTER_FAILURE findings, want 1", got)
	}
	cut := closedRun(t, p, cutAfter(export(calls...), "r1", 3))
	if got := rules(cut)["CONTINUED_AFTER_FAILURE"]; got != `RULE_STATE_NOT_CHECKED:request "r1" is in doubt: its end was not read` {
		t.Errorf("r1's failure in transit: CONTINUED_AFTER_FAILURE is %q", got)
	}
}

// approvedThenFailed is r1's whole trail: approval required and asked,
// approved, started and failed.
func approvedThenFailed() []*controlv1.Event {
	evs := call{req: "r1", tool: "get_order", upstream: "shop", outcome: "held"}.events()
	prev := evs[len(evs)-1].GetEventId()
	add := func(id string, kind controlv1.EventKind, sec int) {
		ev := &controlv1.Event{EventId: id, Kind: kind, RequestId: "r1", RunId: runID, ProjectId: proj, TenantId: tenant,
			OccurredAt: at(time.Duration(sec) * time.Second), SchemaVersion: "1.0",
			EnforcementMode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, PrevEventId: prev}
		if kind == controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED {
			ev.Payload = &controlv1.Event_Approval{Approval: &controlv1.Approval{SchemaVersion: "1.0", ApprovalId: "a1", RequestId: "r1",
				State: controlv1.ApprovalState_APPROVAL_STATE_APPROVED}}
		} else {
			ev.ExecutionId = "r1-x"
		}
		evs = append(evs, ev)
		prev = id
	}
	add("r1-e4", controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED, 3)
	add("r1-e5", controlv1.EventKind_EVENT_KIND_ACTION_STARTED, 4)
	add("r1-e6", controlv1.EventKind_EVENT_KIND_ACTION_FAILED, 5)
	return evs
}

// TestAClosedRunCutAfterAnApprovalAskIsNoPass: on a closed run nothing
// waits any more, so a call whose trail ends at its approval request, or at
// the decision that required one, may have been approved, run and failed in
// events no rule read: the rules that read how calls end are not checked.
// The whole trail makes the finding.
func TestAClosedRunCutAfterAnApprovalAskIsNoPass(t *testing.T) {
	p := procWith(t)
	rest := export(call{req: "r3", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
		call{req: "r4", tool: "send_mail", upstream: "mail", at: 20 * time.Second})
	trail := func(n int) supervise.Export {
		return supervise.Export{Whole: true, Events: append(approvedThenFailed()[:n], rest.Events...)}
	}
	if got := len(only(closedRun(t, p, trail(6)), "CONTINUED_AFTER_FAILURE")); got != 1 {
		t.Fatalf("the whole trail: %d CONTINUED_AFTER_FAILURE findings, want 1", got)
	}
	for _, n := range []int{2, 3} {
		cut := closedRun(t, p, trail(n))
		for _, rule := range []string{"REPEATED_DENIAL", "CONTINUED_AFTER_FAILURE"} {
			if got := rules(cut)[rule]; got != `RULE_STATE_NOT_CHECKED:request "r1" is in doubt: its end was not read` {
				t.Errorf("r1 cut after %d events: %s is %q", n, rule, got)
			}
		}
	}
}

// TestAnOpenRunWaitingOnAnApprovalIsNotInDoubt: on an open run a call
// waiting on its approval has not ended, and that puts nothing in doubt.
func TestAnOpenRunWaitingOnAnApprovalIsNotInDoubt(t *testing.T) {
	p := procWith(t)
	res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{{Whole: true, Events: approvedThenFailed()[:3]}}})
	if got := rules(res)["REPEATED_DENIAL"]; got != "RULE_STATE_CHECKED:" {
		t.Errorf("REPEATED_DENIAL beside a call waiting on its approval: %q", got)
	}
}

// TestARunsOwnCloseDecidesWhetherItsHeldCallIsInDoubt: under inherit a
// child's call left at its approval request is in doubt when the child is
// closed, whatever the root's state, and waits, putting nothing in doubt,
// when the child is open under a closed root. REPEATED_DENIAL is the rule
// read: the rules that need the whole tree closed are unchecked either way.
func TestARunsOwnCloseDecidesWhetherItsHeldCallIsInDoubt(t *testing.T) {
	x := export(call{req: "r1", tool: "get_order", upstream: "shop"},
		call{req: "c1", tool: "get_order", upstream: "shop", at: 10 * time.Second, outcome: "held", run: childRun})
	for _, c := range []struct {
		closed, want string
	}{
		{childRun, `RULE_STATE_NOT_CHECKED:request "c1" is in doubt: its end was not read`},
		{runID, "RULE_STATE_CHECKED:"},
	} {
		res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: family(c.closed), Exports: []supervise.Export{x}})
		if got := rules(res)["REPEATED_DENIAL"]; got != c.want {
			t.Errorf("%s closed alone: REPEATED_DENIAL is %q, want %q", c.closed, got, c.want)
		}
	}
}

// TestARetryDecidedForApprovalIsHeldBeforeItsRequest: the plane writes a
// decision that requires approval before it asks for one, so a trail that
// ends between the two may yet be approved, as one that ends after the ask.
func TestARetryDecidedForApprovalIsHeldBeforeItsRequest(t *testing.T) {
	held := again().ending("held")
	for name, x := range map[string]supervise.Export{
		"the approval asked":         acts(denial(), held),
		"the approval not yet asked": cutAfter(acts(denial(), held), "r1", 2),
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(), x)
			if got, want := verdicts(res, ruleArgs), []string{runID + " FINDING_VERDICT_INDETERMINATE"}; !slices.Equal(got, want) {
				t.Fatalf("%s findings %q, want %q:\n%s", ruleArgs, got, want, dump(res.Findings))
			}
		})
	}
}

// withPayloadVersion sets the version of every decision or approval of req
// in x.
func withPayloadVersion(x supervise.Export, req, version string) supervise.Export {
	for _, ev := range x.Events {
		if ev.GetRequestId() != req {
			continue
		}
		if d := ev.GetDecision(); d != nil {
			d.SchemaVersion = version
		}
		if a := ev.GetApproval(); a != nil {
			a.SchemaVersion = version
		}
	}
	return x
}

// TestAPayloadOfAnotherMajorIsNotRead: a decision or an approval carries a
// version of its own, and one of a major this build does not read is not
// read, whatever its event's version: its request is in doubt, so no rule
// reads as checked and nothing confirms from it. The same trail at 1.0
// confirms.
func TestAPayloadOfAnotherMajorIsNotRead(t *testing.T) {
	for _, version := range []string{"1.0", "1.7"} {
		res := retrySupervise(t, source(), withPayloadVersion(acts(denial(), again()), "d1", version))
		if got := rules(res)[ruleArgs]; got != checked {
			t.Fatalf("a decision of %s: %s is %q", version, ruleArgs, got)
		}
	}
	for _, version := range []string{"2.0", "", "1"} {
		res := retrySupervise(t, source(), withPayloadVersion(acts(denial(), again()), "d1", version))
		for _, f := range only(res, ruleArgs) {
			if v := f.GetFinding().GetVerdict(); v != indetermin {
				t.Fatalf("a decision of %q: %s is %s", version, ruleArgs, v)
			}
		}
		if got := rules(res)[ruleArgs]; !strings.Contains(got, `request "d1" is in doubt`) {
			t.Fatalf("a decision of %q: %s is %q", version, ruleArgs, got)
		}
	}
	taken := supervise02(t, family(), acts(lookupCall(), manualRefund(approved)))
	if len(only(taken, ruleTaken)) != 1 || len(only(taken, ruleOutside)) != 0 {
		t.Fatalf("an approval of 1.0 takes no exception:\n%s", dump(taken.Findings))
	}
	unread := supervise02(t, family(), withPayloadVersion(acts(lookupCall(), manualRefund(approved)), "m1", "2.0"))
	if got := only(unread, ruleTaken); len(got) != 0 {
		t.Fatalf("an approval of 2.0 takes an exception:\n%s", dump(got))
	}
	for _, f := range only(unread, ruleOutside) {
		if v := f.GetFinding().GetVerdict(); v != indetermin {
			t.Fatalf("an approval of 2.0: %s is %s", ruleOutside, v)
		}
	}
}

// TestAProposalOfAnotherProjectIsRefused: an event of the run whose proposal
// names another tenant or project is no account of the run's call, and is
// refused as an event of another project is.
func TestAProposalOfAnotherProjectIsRefused(t *testing.T) {
	foreign := func(project, tenant string) supervise.Export {
		x := export(call{req: "w1", tool: "wipe_disk", upstream: "ops"})
		env := x.Events[0].GetProposed()
		env.ProjectId, env.TenantId = project, tenant
		return x
	}
	if _, err := supervise.Evaluate(supervise.Input{Procedure: procWith(t), Run: supervise.Run{ID: runID, Tenant: tenant},
		Exports: []supervise.Export{foreign(proj, tenant)}}); err != nil {
		t.Fatalf("a proposal of the run's own project: %v", err)
	}
	for name, x := range map[string]supervise.Export{
		"another project": foreign("p2", tenant),
		"no project":      foreign("", tenant),
		"another tenant":  foreign(proj, "t2"),
	} {
		t.Run(name, func(t *testing.T) {
			res, err := supervise.Evaluate(supervise.Input{Procedure: procWith(t), Run: supervise.Run{ID: runID, Tenant: tenant},
				Exports: []supervise.Export{x}})
			if !errors.Is(err, supervise.ErrInput) {
				t.Fatalf("Evaluate = %v, %v; want ErrInput", res, err)
			}
		})
	}
}
