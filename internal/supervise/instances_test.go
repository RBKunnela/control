package supervise_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
)

// line is one instance as the tests compare it: request or observation,
// step, run, export, outcome, approval, mode, time state, resource and
// protocol.
func line(in supervise.Instance) string {
	who := in.Request
	if in.Observation != "" {
		who = "obs " + in.Observation + " from " + in.Source + " " + in.Trust.String()
	}
	clock := "untimed"
	switch {
	case in.Timed && in.Told:
		clock = "told " + in.At.Sub(t0).String()
	case in.Timed:
		clock = "untold " + in.At.Sub(t0).String()
	}
	s := fmt.Sprintf("%s %s@%s step=%q run=%s export=%d %s %s %s %s", who, in.Tool, in.Upstream, in.Step,
		in.Run[len(in.Run)-4:], in.Export, outcomeWord[in.Outcome], approvalWord[in.Approval], in.Mode.String(), clock)
	if in.Resource != (supervise.Resource{}) {
		s += " res=" + in.Resource.Type + "/" + in.Resource.ID + "/" + in.Resource.Tenant + "/" + in.Resource.Environment
	}
	if len(in.Reasons) > 0 {
		s += " reasons=" + strings.Join(in.Reasons, ",")
	}
	if in.Protocol != "" {
		s += " protocol=" + in.Protocol
	}
	if in.Doubt {
		s += " doubt"
	}
	if in.Excepted {
		s += " excepted"
	}
	return s
}

var outcomeWord = map[supervise.Outcome]string{
	supervise.OutcomeUnknown: "unknown", supervise.OutcomeOpen: "open", supervise.OutcomeCompleted: "completed",
	supervise.OutcomeFailed: "failed", supervise.OutcomeDenied: "denied", supervise.OutcomeBlocked: "blocked",
}

var approvalWord = map[supervise.Approval]string{
	supervise.ApprovalNone: "no-approval", supervise.ApprovalAsked: "asked", supervise.ApprovalGranted: "granted",
}

func lines(res *supervise.Result) []string {
	out := make([]string, len(res.Instances))
	for i, in := range res.Instances {
		out[i] = line(in)
	}
	return out
}

func sameLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestInstancesNameEachCallAsItsTrailEnded: every tool call of the run,
// step or not, in the order first read, with the outcome its trail ends in;
// a prompt is no call; a source's report no plane call joins comes after,
// with its source's trust, no export and no outcome of its own.
func TestInstancesNameEachCallAsItsTrailEnded(t *testing.T) {
	x := export(
		call{req: "r1", tool: "get_order", upstream: "shop"},
		call{req: "d1", tool: "issue_refund", upstream: "pay", at: 10 * time.Second, outcome: "deny"},
		call{req: "p1", tool: "issue_refund", upstream: "pay", at: 20 * time.Second, outcome: "pause"},
		call{req: "f1", tool: "search_docs", upstream: "docs", at: 30 * time.Second, outcome: "fail"},
		call{req: "h1", tool: "wipe_disk", upstream: "ops", at: 40 * time.Second, outcome: "held"},
		call{req: "s1", tool: "issue_refund", upstream: "pay", at: 50 * time.Second, outcome: "silent"},
		call{req: "q1", tool: "summary", upstream: "docs", kind: "prompt", at: 60 * time.Second},
	)
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Exports: []supervise.Export{x},
		Sources: []supervise.Source{source(ob{id: "obs-1", name: "send_mail", at: 70 * time.Second})}})
	sameLines(t, lines(res),
		`r1 get_order@shop step="lookup" run=cdef export=0 completed no-approval ENFORCEMENT_MODE_ENFORCE told 0s reasons=RULE_ALLOW`,
		`d1 issue_refund@pay step="refund" run=cdef export=0 denied no-approval ENFORCEMENT_MODE_ENFORCE told 10s reasons=RULE_DENY`,
		`p1 issue_refund@pay step="refund" run=cdef export=0 blocked no-approval ENFORCEMENT_MODE_ENFORCE told 20s reasons=PAUSED`,
		`f1 search_docs@docs step="" run=cdef export=0 failed no-approval ENFORCEMENT_MODE_ENFORCE told 30s reasons=RULE_ALLOW`,
		`h1 wipe_disk@ops step="" run=cdef export=0 open asked ENFORCEMENT_MODE_ENFORCE told 40s reasons=APPROVAL_REQUIRED`,
		`s1 issue_refund@pay step="refund" run=cdef export=0 blocked no-approval ENFORCEMENT_MODE_ENFORCE told 50s reasons=PDP_TIMEOUT`,
		`obs obs-1 from s1 TRUST_SELF_REPORTED send_mail@ step="notify" run=cdef export=-1 unknown no-approval ENFORCEMENT_MODE_UNSPECIFIED untold 1m10s`,
	)
}

// TestInstancesCarryTheApprovalTheResourceAndTheMode: an approval granted,
// one refused, the envelope's resource and protocol, and the mode the plane
// recorded with its decision, which an OBSERVE plane's export names; from
// two exports no time is told.
func TestInstancesCarryTheApprovalTheResourceAndTheMode(t *testing.T) {
	observed := acts(lookupOf("o1", 0, orderNo("42")))
	for _, ev := range observed.Events {
		ev.EnforcementMode = controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	}
	observed.Events[0].GetProposed().Action.Protocol = "enforce"
	res := supervise02(t, family(), observed,
		acts(manualRefund(approved), act{call: call{req: "m2", tool: "refund_manual", upstream: "pay", at: 30 * time.Second},
			approval: rejected}))
	sameLines(t, lines(res),
		`o1 get_order@shop step="lookup" run=cdef export=0 completed no-approval ENFORCEMENT_MODE_OBSERVE untold 0s res=shop_order/42/t1/prod reasons=RULE_ALLOW protocol=enforce`,
		`m1 refund_manual@pay step="" run=1111 export=1 completed granted ENFORCEMENT_MODE_ENFORCE untold 20s reasons=APPROVAL_REQUIRED excepted`,
		`m2 refund_manual@pay step="" run=cdef export=1 blocked asked ENFORCEMENT_MODE_ENFORCE untold 30s reasons=APPROVAL_REJECTED`,
	)
}

// TestAnInstanceIsToldOnlyWhenItsTimeOrdersIt: two calls of one instant are
// untold, in two exports or in one; one alone at its instant is told only
// when every call with a time comes from one export, since two exports'
// clocks are not one; a call with no time is neither timed nor told, and
// its export does not count.
func TestAnInstanceIsToldOnlyWhenItsTimeOrdersIt(t *testing.T) {
	untimed := export(call{req: "u1", tool: "send_mail", upstream: "mail", at: 90 * time.Second})
	for _, ev := range untimed.Events {
		ev.OccurredAt = nil
	}
	const u1 = `u1 send_mail@mail step="notify" run=cdef export=%d completed no-approval ENFORCEMENT_MODE_ENFORCE untimed reasons=RULE_ALLOW`
	for name, c := range map[string]struct {
		exports []supervise.Export
		want    []string
	}{
		"two exports": {[]supervise.Export{
			export(call{req: "r1", tool: "get_order", upstream: "shop"}, call{req: "a1", tool: "issue_refund", upstream: "pay", at: 10 * time.Second}),
			export(call{req: "a2", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
				call{req: "b1", tool: "send_mail", upstream: "mail", at: 30 * time.Second},
				call{req: "b2", tool: "send_mail", upstream: "mail", at: 30 * time.Second}),
			untimed,
		}, []string{
			`r1 get_order@shop step="lookup" run=cdef export=0 completed no-approval ENFORCEMENT_MODE_ENFORCE untold 0s reasons=RULE_ALLOW`,
			`a1 issue_refund@pay step="refund" run=cdef export=0 completed no-approval ENFORCEMENT_MODE_ENFORCE untold 10s reasons=RULE_ALLOW`,
			`a2 issue_refund@pay step="refund" run=cdef export=1 completed no-approval ENFORCEMENT_MODE_ENFORCE untold 10s reasons=RULE_ALLOW`,
			`b1 send_mail@mail step="notify" run=cdef export=1 completed no-approval ENFORCEMENT_MODE_ENFORCE untold 30s reasons=RULE_ALLOW`,
			`b2 send_mail@mail step="notify" run=cdef export=1 completed no-approval ENFORCEMENT_MODE_ENFORCE untold 30s reasons=RULE_ALLOW`,
			fmt.Sprintf(u1, 2),
		}},
		"one timed export": {[]supervise.Export{
			export(call{req: "r1", tool: "get_order", upstream: "shop"}, call{req: "a1", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
				call{req: "a2", tool: "issue_refund", upstream: "pay", at: 10 * time.Second}),
			untimed,
		}, []string{
			`r1 get_order@shop step="lookup" run=cdef export=0 completed no-approval ENFORCEMENT_MODE_ENFORCE told 0s reasons=RULE_ALLOW`,
			`a1 issue_refund@pay step="refund" run=cdef export=0 completed no-approval ENFORCEMENT_MODE_ENFORCE untold 10s reasons=RULE_ALLOW`,
			`a2 issue_refund@pay step="refund" run=cdef export=0 completed no-approval ENFORCEMENT_MODE_ENFORCE untold 10s reasons=RULE_ALLOW`,
			fmt.Sprintf(u1, 1),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			res := evaluate(t, supervise.Input{Procedure: procWith(t), Exports: c.exports})
			sameLines(t, lines(res), c.want...)
		})
	}
}

// TestAnInstanceInDoubtHasNoOutcome: a trail read with two contents under
// one event id tells no outcome, and an approval it holds is asked at most.
func TestAnInstanceInDoubtHasNoOutcome(t *testing.T) {
	x := acts(manualRefund(approved).in(runID))
	twin := acts(manualRefund(approved).in(runID))
	twin.Events[0].GetProposed().GetAction().Name = "refund_manual_x"
	twin.Events = twin.Events[:1]
	res := supervise02(t, family(), x, twin)
	sameLines(t, lines(res),
		`m1 refund_manual@pay step="" run=cdef export=0 unknown asked ENFORCEMENT_MODE_ENFORCE told 20s reasons=APPROVAL_REQUIRED doubt`,
	)
}

// TestEachFindingNamesTheInstancesItCites: a call outside the procedure is
// the instance its finding rests on; a skipped step rests on none.
func TestEachFindingNamesTheInstancesItCites(t *testing.T) {
	run := supervise.Run{ID: runID, Tenant: tenant, Closed: true}
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Run: run, Exports: []supervise.Export{export(
		call{req: "r1", tool: "get_order", upstream: "shop"},
		call{req: "w1", tool: "wipe_disk", upstream: "ops", at: 10 * time.Second},
		call{req: "w2", tool: "wipe_disk", upstream: "ops", at: 20 * time.Second},
	)}})
	if len(res.Rests) != len(res.Findings) {
		t.Fatalf("%d rests for %d findings", len(res.Rests), len(res.Findings))
	}
	got := map[string]string{}
	for i, f := range res.Findings {
		var reqs []string
		for _, n := range res.Rests[i] {
			reqs = append(reqs, res.Instances[n].Request)
		}
		got[f.GetFinding().GetRuleId()] = strings.Join(reqs, " ")
	}
	if want := map[string]string{ruleOutside: "w1 w2", ruleSkipped: ""}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("rests %v, want %v", got, want)
	}
}

// TestOnlyTheCallsAnExceptionWaivedAreExcepted: a waiver marks the call it
// waived, never the evidence that met its condition nor another call its
// finding cites: the failed lookup that excuses a skipped refund, and the
// refund an early mail or a denied lookup came before, are not excepted.
func TestOnlyTheCallsAnExceptionWaivedAreExcepted(t *testing.T) {
	failed := call{req: "r1", tool: "get_order", upstream: "shop", outcome: "fail"}
	denied := call{req: "r1", tool: "get_order", upstream: "shop", outcome: "deny"}
	refund := call{req: "r2", tool: "issue_refund", upstream: "pay", at: 30 * time.Second}
	early := act{call: call{req: "n1", tool: "send_mail", upstream: "mail", at: 10 * time.Second}, approval: approved}
	for name, c := range map[string]struct {
		x    supervise.Export
		want string
	}{
		"a refund skipped after a failed lookup": {export(failed), ""},
		"a denied lookup continued from":         {export(denied, refund), "r1"},
		"an approved early mail":                 {acts(lookupCall(), early, act{call: refund}), "n1"},
		"an approved call outside":               {acts(lookupCall(), manualRefund(approved)), "m1"},
	} {
		t.Run(name, func(t *testing.T) {
			res := treeEvaluate(t, supervise.Input{Procedure: inheritProc(t), Tree: closedFamily(),
				Exports: []supervise.Export{c.x}})
			if len(only(res, ruleTaken)) != 1 {
				t.Fatalf("%d exceptions taken:\n%s", len(only(res, ruleTaken)), dump(res.Findings))
			}
			var got []string
			for _, in := range res.Instances {
				if in.Excepted {
					got = append(got, in.Request)
				}
			}
			if strings.Join(got, " ") != c.want {
				t.Fatalf("excepted %q, want %q", got, c.want)
			}
		})
	}
}
