package supervise_test

import (
	"slices"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/supervise"
)

// TestAReportAroundADenialIsPlacedByTimeOnly: a source's report of the
// denied tool no plane call joins suggests a retry when the call it reports
// began after the denial was decided; with no time on either side, or the same time, it is
// untold; before the decision it is none, in doubt or not. A name the denied tool's entry
// does not list, or another entry's, is no report of it.
func TestAReportAroundADenialIsPlacedByTimeOnly(t *testing.T) {
	untimedReport := source(ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second})
	untimedReport.Observations[0].EventTime = nil
	untimedDenial := acts(denial())
	for _, ev := range untimedDenial.Events {
		ev.OccurredAt = nil
	}
	mail := act{call: call{req: "d1", tool: "send_mail", upstream: "mail", at: 10 * time.Second, outcome: "deny"}}
	for name, c := range map[string]struct {
		x    supervise.Export
		src  supervise.Source
		want []string
	}{
		"after the decision":          {acts(denial()), source(ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second, stage: observev1.Stage_STAGE_STARTED}), []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"proposed after the decision": {acts(denial()), source(ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second, stage: observev1.Stage_STAGE_PROPOSED}), []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"at the decision":             {acts(denial()), source(ob{id: "obs-1", name: "issue_refund", at: 11 * time.Second}), []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"before the decision":         {acts(denial()), source(ob{id: "obs-1", name: "issue_refund", at: 10 * time.Second}), nil},
		"a report with no time":       {acts(denial()), untimedReport, []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"a denial with no time":       {untimedDenial, source(ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second}), []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"another entry's name":        {acts(denial()), source(ob{id: "obs-1", name: "get_order", at: 20 * time.Second}), nil},
		"a name no entry lists":       {acts(mail), source(ob{id: "obs-1", name: "send_mail", at: 20 * time.Second}), nil},
		"one in doubt before the decision": {acts(denial()), source(ob{id: "obs-1", name: "issue_refund", at: 5 * time.Second},
			ob{id: "obs-1", name: "issue_refund", at: 6 * time.Second}), nil},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, c.src, c.x)
			if got := verdicts(res, ruleAround); !slices.Equal(got, c.want) {
				t.Fatalf("findings %q, want %q:\n%s", got, c.want, dump(res.Findings))
			}
		})
	}
}

// TestAReportAroundADenialInDoubtOfItsJoinIsIndeterminate: on a span chain
// the join walks to its end the report joins the denied call itself and is
// no retry; one span more and the walk is cut, so the report may be that
// call or another, the finding is indeterminate and the rule, with
// STEP_OUTSIDE_PROCEDURE, reads not checked.
func TestAReportAroundADenialInDoubtOfItsJoinIsIndeterminate(t *testing.T) {
	for _, n := range []int{supervise.MaxWalkSteps, supervise.MaxWalkSteps + 1} {
		src := chain(n, ob{id: "obs-top", name: "issue_refund", at: 20 * time.Second}, observev1.SubjectKind_SUBJECT_KIND_AGENT, "mcp_call")
		d := denial()
		d.span = spanAt(n - 1)
		res := retrySupervise(t, src, acts(d))
		want := []string{runID + " FINDING_VERDICT_INDETERMINATE"}
		if n == supervise.MaxWalkSteps {
			want = nil
		}
		if got := verdicts(res, ruleAround); !slices.Equal(got, want) {
			t.Fatalf("at %d spans: findings %q, want %q:\n%s", n, got, want, dump(res.Findings))
		}
		state := "RULE_STATE_CHECKED:"
		if n > supervise.MaxWalkSteps {
			state = "RULE_STATE_NOT_CHECKED:a span walk ran out of steps, so a source's report may be a plane call"
		}
		for _, id := range []string{ruleAround, supervise.RuleStepOutsideProcedure} {
			if got := rules(res)[id]; got != state {
				t.Errorf("at %d spans: %s is %q, want %q", n, id, got, state)
			}
		}
	}
}
