package supervise_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/supervise"
)

// reportRules are the rules that rest on what a source did not report.
var reportRules = []string{"STEP_OUTSIDE_PROCEDURE", ruleAround}

// TestASourceThatMayHaveMissedACallLeavesTheReportRulesNotChecked: a call
// around the plane that a sampled source dropped, that a silent source has
// not sent, or that sits in a write its log has not closed, is a call no rule
// saw; the rules that rest on a source's reports are then not checked, and
// a complete source heard after the run with every write closed leaves them
// checked.
func TestASourceThatMayHaveMissedACallLeavesTheReportRulesNotChecked(t *testing.T) {
	sampled := source()
	sampled.Sampling = observev1.Sampling_SAMPLING_PARTIAL
	unsaid := source()
	unsaid.Sampling = observev1.Sampling_SAMPLING_UNSPECIFIED
	lapsed := source()
	lapsed.LastHeard = t0.Add(-time.Hour)
	unclosed := source()
	unclosed.Unclosed = true
	for name, c := range map[string]struct {
		src  supervise.Source
		want string
	}{
		"complete and heard": {source(), ""},
		"sampled":            {sampled, `source "s1" is in doubt: its descriptor does not say it reports every call`},
		"sampling not said":  {unsaid, `source "s1" is in doubt: its descriptor does not say it reports every call`},
		"silent":             {lapsed, "a source is silent, never heard or not read"},
		"a write not closed": {unclosed, `source "s1" is in doubt: its log holds a write no import report closes`},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, c.src, acts(denial()))
			for _, rule := range reportRules {
				got := rules(res)[rule]
				switch {
				case c.want == "" && got != checked:
					t.Errorf("%s is %q, want checked", rule, got)
				case c.want != "" && (!strings.HasPrefix(got, "RULE_STATE_NOT_CHECKED:") || !strings.Contains(got, c.want)):
					t.Errorf("%s is %q, want not checked: %s", rule, got, c.want)
				}
			}
		})
	}
}

// TestAReportTimedAtItsEndSaysNotWhenItBegan: a report stamped when its
// call ended, after the denial, may be of a call begun before it, so it is
// untold; one stamped when its call started after the denial suggests a
// retry, and one that ended before the denial is none.
func TestAReportTimedAtItsEndSaysNotWhenItBegan(t *testing.T) {
	started := observev1.Stage_STAGE_STARTED
	for name, c := range map[string]struct {
		o    ob
		want []string
	}{
		"ended after the denial":   {ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second}, []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"failed after the denial":  {ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second, stage: observev1.Stage_STAGE_FAILED}, []string{runID + " FINDING_VERDICT_INDETERMINATE"}},
		"started after the denial": {ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second, stage: started}, []string{runID + " FINDING_VERDICT_SUSPECTED"}},
		"ended before the denial":  {ob{id: "obs-1", name: "issue_refund", at: 10 * time.Second}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(c.o), acts(denial()))
			if got := verdicts(res, ruleAround); !slices.Equal(got, c.want) {
				t.Fatalf("findings %q, want %q:\n%s", got, c.want, dump(res.Findings))
			}
		})
	}
}
