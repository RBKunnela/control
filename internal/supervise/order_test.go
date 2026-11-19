package supervise_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/supervise"
)

// TestRequestsFollowThePlanesTimesNotTheirPlaceInTheExport: a plane ships
// several batches at once, so an export can hold a later request first. A
// step's requests, a finding's references and the references a long finding
// keeps follow the plane's times, the same for every arrival order.
func TestRequestsFollowThePlanesTimesNotTheirPlaceInTheExport(t *testing.T) {
	calls := manyDenials(supervise.MaxFindingRefs + 2)
	slices.Reverse(calls)
	res := evaluate(t, supervise.Input{Procedure: noDeadline(t), Exports: []supervise.Export{export(calls...)}})
	if len(res.Findings) != 1 {
		t.Fatalf("%d findings, want one REPEATED_DENIAL", len(res.Findings))
	}
	wantCited := []string{"d00000", "d00001", "d00002", "d00003", "d00004",
		"d00005", "d00006", "d00007", "d00008", "d00009"}
	if got := cited(res.Findings[0]); !slices.Equal(got, wantCited) {
		t.Errorf("the finding cites %q, want the ten earliest denials %q", got, wantCited)
	}
	if left := res.Findings[0].GetRefsLeftOut(); left != 2 {
		t.Errorf("%d references left out, want 2", left)
	}
	wantSteps := []supervise.StepMatch{
		{StepID: "lookup", RequestIDs: []string{"r1"}},
		{StepID: "refund", RequestIDs: append(slices.Clone(wantCited), "d00010", "d00011")},
		{StepID: "notify"},
	}
	if !reflect.DeepEqual(res.Steps, wantSteps) {
		t.Errorf("steps %+v, want %+v", res.Steps, wantSteps)
	}
}

// TestRequestsOfOneInstantFollowTheirIDs: two proposals the plane timed
// alike are listed by request id, whichever the export holds first.
func TestRequestsOfOneInstantFollowTheirIDs(t *testing.T) {
	for name, calls := range map[string][]call{
		"held in id order": {
			{req: "r1", tool: "get_order", upstream: "shop", at: 5 * time.Second},
			{req: "r2", tool: "get_order", upstream: "shop", at: 5 * time.Second},
		},
		"held against id order": {
			{req: "r2", tool: "get_order", upstream: "shop", at: 5 * time.Second},
			{req: "r1", tool: "get_order", upstream: "shop", at: 5 * time.Second},
		},
	} {
		t.Run(name, func(t *testing.T) {
			res := evaluate(t, supervise.Input{Procedure: procWith(t), Exports: []supervise.Export{export(calls...)}})
			if len(res.Steps) == 0 || !slices.Equal(res.Steps[0].RequestIDs, []string{"r1", "r2"}) {
				t.Errorf("steps %+v, want lookup's requests r1 then r2", res.Steps)
			}
		})
	}
}
