package supervise_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/supervise"
)

func TestAnUnjoinedObservationNeverSatisfiesAStep(t *testing.T) {
	p := procWith(t)
	refundOnly := export(call{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second})
	skippedLookup := want(p, "REQUIRED_STEP_SKIPPED", high, alert, suspected, id("REQUIRED_STEP_SKIPPED", "lookup"))
	outOfOrder := want(p, "STEP_OUT_OF_ORDER", medium, inform, suspected, id("STEP_OUT_OF_ORDER", "refund"),
		evRef("r3-e1", "r3"))
	sameFindings(t, closedRun(t, p, refundOnly).Findings, skippedLookup, outOfOrder)

	res := evaluate(t, supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{refundOnly},
		Sources: []supervise.Source{source(ob{id: "obs-1", name: "get_order", span: "1111111111111111"})}})
	sameFindings(t, res.Findings, skippedLookup, outOfOrder)
	wantSteps := []supervise.StepMatch{
		{StepID: "lookup", ObservationIDs: []string{"obs-1"}},
		{StepID: "refund", RequestIDs: []string{"r3"}},
		{StepID: "notify"},
	}
	if !reflect.DeepEqual(res.Steps, wantSteps) {
		t.Fatalf("steps %+v, want %+v", res.Steps, wantSteps)
	}
}

func TestASourceNamedButNotReadPutsAnAbsenceInDoubt(t *testing.T) {
	p := procWith(t)
	in := supervise.Input{Procedure: p, Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(skipped()...)}, Sources: []supervise.Source{source()}}
	sameFindings(t, evaluate(t, in).Findings,
		want(p, "REQUIRED_STEP_SKIPPED", high, alert, suspected, id("REQUIRED_STEP_SKIPPED", "refund")),
		want(p, "STEP_OUT_OF_ORDER", medium, inform, suspected, id("STEP_OUT_OF_ORDER", "notify"), evRef("r4-e1", "r4")))

	in.SourcesNotRead = []string{"sources/s2.json"}
	res := evaluate(t, in)
	sameFindings(t, res.Findings,
		want(p, "REQUIRED_STEP_SKIPPED", high, alert, indetermin, id("REQUIRED_STEP_SKIPPED", "refund")),
		want(p, "STEP_OUT_OF_ORDER", medium, inform, indetermin, id("STEP_OUT_OF_ORDER", "notify"), evRef("r4-e1", "r4")))
	if !reflect.DeepEqual(res.SourcesNotRead, []string{"sources/s2.json"}) {
		t.Fatalf("sources not read %q", res.SourcesNotRead)
	}
	if got := inDoubt(res); got != "0.2 SOURCE_STATE_NOT_READ::0" {
		t.Fatalf("the report names %q, want the source not read and no path", got)
	}

	in.Exports = []supervise.Export{export(denials(4)...)}
	sameFindings(t, evaluate(t, in).Findings, want(p, "REPEATED_DENIAL", high, alert, confirmed,
		id("REPEATED_DENIAL", "issue_refund", "pay"),
		evRef("d1-e3", "d1"), evRef("d2-e3", "d2"), evRef("d3-e3", "d3"), evRef("d4-e3", "d4")))
}

// TestASourceIsSilentOnlyPastItsHeartbeat: the run's last plane event is at
// 33 s; s1 and s2 have a heartbeat of 300 s. s1, heard at -267 s, is heard
// exactly at that event; s2, heard a nanosecond earlier, is silent; s3 and
// s0 were never heard, and the report keeps them in the order given; s4,
// heard after the event, was live as of it.
func TestASourceIsSilentOnlyPastItsHeartbeat(t *testing.T) {
	heard := func(id string, at time.Duration, ok bool) supervise.Source {
		return supervise.Source{SourceID: id, Kind: otelKind, Tenant: tenant, Project: proj, HeartbeatSeconds: 300, LastHeard: t0.Add(at), Heard: ok}
	}
	never := heard("s3", time.Hour, false)
	never.HeartbeatSeconds = 60
	res := evaluate(t, supervise.Input{Procedure: procWith(t), Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(conforming()...)},
		Sources: []supervise.Source{
			heard("s1", -267*time.Second, true), heard("s2", -267*time.Second-1, true), never, heard("s4", time.Hour, true),
			heard("s0", time.Hour, false),
		}})
	if !reflect.DeepEqual(res.Silent, []string{"s2"}) || !reflect.DeepEqual(res.NeverHeard, []string{"s3", "s0"}) {
		t.Fatalf("silent %q, never heard %q; want [s2] and [s3 s0]", res.Silent, res.NeverHeard)
	}
	if got := inDoubt(res); got != "0.2 SOURCE_STATE_NEVER_HEARD:s3:60 SOURCE_STATE_NEVER_HEARD:s0:300 SOURCE_STATE_SILENT:s2:300" {
		t.Fatalf("the report names %q, want s3 and s0 never heard in the order given, then s2 silent", got)
	}
	quiet := evaluate(t, supervise.Input{Procedure: procWith(t), Run: supervise.Run{Closed: true},
		Exports: []supervise.Export{export(conforming()...)}, Sources: []supervise.Source{heard("s1", -267*time.Second, true)}})
	if quiet.Silent != nil || quiet.NeverHeard != nil {
		t.Fatalf("silent %q, never heard %q; want none", quiet.Silent, quiet.NeverHeard)
	}
	if got := inDoubt(quiet); got != "0.1" {
		t.Fatalf("the report names %q, want no source and schema 0.1", got)
	}
}

// inDoubt is the report's schema, then each source it names as
// state:id:heartbeat.
func inDoubt(res *supervise.Result) string {
	out := []string{res.Report.GetSchemaVersion()}
	for _, s := range res.Report.GetSourcesInDoubt() {
		out = append(out, fmt.Sprintf("%s:%s:%d", s.GetState(), s.GetSourceId(), s.GetHeartbeatSeconds()))
	}
	return strings.Join(out, " ")
}

// TestASupervisionIsGivenAtMostMaxSources: MaxSources sources, read or not,
// are judged; one more is refused.
func TestASupervisionIsGivenAtMostMaxSources(t *testing.T) {
	in := supervise.Input{Procedure: procWith(t), Run: supervise.Run{ID: runID, Tenant: tenant, Closed: true},
		Exports: []supervise.Export{export(conforming()...)}}
	for i := range supervise.MaxSources - 1 {
		s := source()
		s.SourceID = fmt.Sprintf("s%02d", i)
		in.Sources = append(in.Sources, s)
	}
	in.SourcesNotRead = []string{"gone.json"}
	if _, err := supervise.Evaluate(in); err != nil {
		t.Fatalf("%d sources: %v", supervise.MaxSources, err)
	}
	in.SourcesNotRead = append(in.SourcesNotRead, "gone-too.json")
	if _, err := supervise.Evaluate(in); !errors.Is(err, supervise.ErrInput) {
		t.Fatalf("%d sources: %v, want ErrInput", supervise.MaxSources+1, err)
	}
}
