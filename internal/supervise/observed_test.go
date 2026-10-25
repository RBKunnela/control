package supervise_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/supervise"
)

func TestARunInTwoProjectsIsRefused(t *testing.T) {
	calls := append(conforming(), call{req: "r9", tool: "search_docs", upstream: "docs", at: 40 * time.Second, proj: "p2"})
	_, err := supervise.Evaluate(supervise.Input{Procedure: procWith(t), Run: supervise.Run{ID: runID, Tenant: tenant},
		Exports: []supervise.Export{export(calls...)}})
	if !errors.Is(err, supervise.ErrInput) {
		t.Fatalf("Evaluate = %v, want ErrInput", err)
	}
}

func TestATimeOrAnOrderWithNoTimeIsNotChecked(t *testing.T) {
	x := export(late()...)
	for _, ev := range x.Events {
		ev.OccurredAt = nil
	}
	res := closedRun(t, procWith(t, `"deadline_seconds":600`, `"deadline_seconds":1`), x)
	for _, rule := range []string{"DEADLINE_EXCEEDED", "STEP_OUT_OF_ORDER", "CONTINUED_AFTER_FAILURE"} {
		if got := rules(res)[rule]; got != "RULE_STATE_NOT_CHECKED:no event of the run has a time" {
			t.Errorf("%s %s", rule, got)
		}
	}
	if got := rules(res)["REQUIRED_STEP_SKIPPED"]; got != checked {
		t.Errorf("REQUIRED_STEP_SKIPPED %s", got)
	}
	sameFindings(t, res.Findings)
}

func TestAFailedObservationIsReportedAndNoContinuation(t *testing.T) {
	p := procWith(t)
	for name, failed := range map[string]ob{
		"a failed stage": {id: "obs-2", name: "get_order", span: "2222222222222222", at: 10 * time.Second,
			stage: observev1.Stage_STAGE_FAILED},
		"an error status": {id: "obs-2", name: "get_order", span: "2222222222222222", at: 10 * time.Second,
			status: observev1.Status_STATUS_ERROR},
	} {
		res := evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
			Exports: []supervise.Export{export(conforming()...)}, Sources: []supervise.Source{source(failed)}})
		t.Run(name, func(t *testing.T) {
			sameFindings(t, res.Findings)
			if got := res.Steps[0]; !reflect.DeepEqual(got, supervise.StepMatch{StepID: "lookup",
				RequestIDs: []string{"r1"}, ObservationIDs: []string{"obs-2"}}) {
				t.Fatalf("lookup %+v", got)
			}
		})
	}
}

func TestARepeatedObservationIsCountedAndAConflictingOneIsInDoubt(t *testing.T) {
	p := procWith(t)
	o := ob{id: "obs-9", name: "drop_table", span: "9999999999999999", at: 40 * time.Second}
	other := o
	other.at = 41 * time.Second
	for name, tc := range map[string]struct {
		second  ob
		why     string
		verdict string
	}{
		"a copy":     {o, "duplicate", "FINDING_VERDICT_SUSPECTED"},
		"a conflict": {other, "conflicting id", "FINDING_VERDICT_INDETERMINATE"},
	} {
		res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(conforming()...)},
			Sources: []supervise.Source{source(o, tc.second)}})
		if len(res.Findings) != 1 || res.Findings[0].GetFinding().GetVerdict().String() != tc.verdict ||
			len(res.Findings[0].GetRefs()) != 1 || res.Report.GetRead().GetObservationsLeftOut()[tc.why] != 1 {
			t.Errorf("%s: %s %v", name, dump(res.Findings), res.Report.GetRead())
		}
	}
}

func TestAFindingIsTheWeakestOfWhatItRestsOn(t *testing.T) {
	p := procWith(t)
	live := source(ob{id: "obs-1", name: "drop_table", span: "1000000000000001", at: 40 * time.Second})
	silent := supervise.Source{SourceID: "s2", Tenant: tenant, Project: proj, HeartbeatSeconds: 300, LastHeard: t0.Add(-time.Hour), Heard: true,
		Observations: []*observev1.Observation{
			ob{id: "obs-2", source: "s2", name: "drop_table", span: "1000000000000002", at: 41 * time.Second}.obs(),
		}}
	res := evaluate(t, supervise.Input{Procedure: p, Exports: []supervise.Export{export(conforming()...)},
		Sources: []supervise.Source{silent, live}})
	sameFindings(t, res.Findings, want(p, "STEP_OUTSIDE_PROCEDURE", medium, alert, indetermin,
		handID(tenant, proj, runID, "refund", "1", "STEP_OUTSIDE_PROCEDURE", "1", "drop_table"),
		obsRef("s2", "obs-2"), obsRef("s1", "obs-1")))
}
