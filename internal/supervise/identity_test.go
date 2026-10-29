package supervise_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/guardana/control/internal/supervise"
)

// TestASourceOfAnotherIdentityIsRefused: a source is read under its
// descriptor's tenant and project, so one that is not the run's would lend
// the run its liveness and its doubt while none of its observations is taken.
// A run of one event names its project as surely as a run of many.
func TestASourceOfAnotherIdentityIsRefused(t *testing.T) {
	p := procWith(t)
	run := supervise.Run{ID: runID, Tenant: tenant}
	oneEvent := export(conforming()...)
	oneEvent.Events = oneEvent.Events[:1]
	for name, x := range map[string]supervise.Export{"the run": export(conforming()...), "a run of one event": oneEvent} {
		for what, tc := range map[string]struct {
			tenant, project string
			names           []string
		}{
			"another tenant":  {"t2", proj, []string{`"s1"`, `tenant "t2"`, `"t1"`}},
			"another project": {tenant, "p2", []string{`"s1"`, `project "p2"`, `"p1"`}},
		} {
			src := source()
			src.Tenant, src.Project = tc.tenant, tc.project
			_, err := supervise.Evaluate(supervise.Input{Procedure: p, Run: run,
				Exports: []supervise.Export{x}, Sources: []supervise.Source{source2(), src}})
			if !errors.Is(err, supervise.ErrInput) {
				t.Fatalf("%s, %s: Evaluate = %v, want ErrInput", name, what, err)
			}
			for _, want := range tc.names {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s, %s: %q names no %s", name, what, err, want)
				}
			}
		}
		if _, err := supervise.Evaluate(supervise.Input{Procedure: p, Run: run,
			Exports: []supervise.Export{x}, Sources: []supervise.Source{source2(), source()}}); err != nil {
			t.Fatalf("%s, the run's own sources: Evaluate = %v", name, err)
		}
	}
}

// TestWithNoEventReadOnlyTheTenantIsHeld: no event names the run's project,
// so no rule is checked and no project is there to hold a source to.
func TestWithNoEventReadOnlyTheTenantIsHeld(t *testing.T) {
	other := conforming()
	for i := range other {
		other[i].run = "run-ffffffffffffffffffffffffffffffff"
	}
	in := supervise.Input{Procedure: procWith(t), Run: supervise.Run{ID: runID, Tenant: tenant},
		Exports: []supervise.Export{export(other...)}}
	src := source()
	src.Project = "p2"
	in.Sources = []supervise.Source{src}
	res, err := supervise.Evaluate(in)
	if err != nil {
		t.Fatalf("a source of another project: Evaluate = %v", err)
	}
	if got := res.Report.GetRead().GetEventsTaken(); got != 0 {
		t.Fatalf("events taken %d, want 0", got)
	}
	src.Tenant = "t2"
	in.Sources = []supervise.Source{src}
	if _, err := supervise.Evaluate(in); !errors.Is(err, supervise.ErrInput) {
		t.Fatalf("a source of another tenant: Evaluate = %v, want ErrInput", err)
	}
}

// TestWithNoEventReadTheRecordHoldsTheSourcesProject: a record that names its
// project holds every source to it even when no event of the run was read.
func TestWithNoEventReadTheRecordHoldsTheSourcesProject(t *testing.T) {
	other := conforming()
	for i := range other {
		other[i].run = "run-ffffffffffffffffffffffffffffffff"
	}
	in := supervise.Input{Procedure: procWith(t), Run: supervise.Run{ID: runID, Tenant: tenant, Project: proj},
		Exports: []supervise.Export{export(other...)}}
	src := source()
	src.Project = "p2"
	in.Sources = []supervise.Source{src}
	if _, err := supervise.Evaluate(in); !errors.Is(err, supervise.ErrInput) || !strings.Contains(err.Error(), `record of project "`+proj+`"`) {
		t.Fatalf("a source of another project than the record: Evaluate = %v, want ErrInput naming the record's project", err)
	}
	in.Sources = []supervise.Source{source()}
	if _, err := supervise.Evaluate(in); err != nil {
		t.Fatalf("a source of the record's project: Evaluate = %v", err)
	}
}

// source2 is source under the id s2.
func source2() supervise.Source {
	s := source()
	s.SourceID = "s2"
	return s
}

// TestAnEventOfTheRunWithNoProjectIsRefused: an event naming no project is
// refused wherever it falls, so the order of the export cannot decide which
// project the run, and the sources held to it, are of.
func TestAnEventOfTheRunWithNoProjectIsRefused(t *testing.T) {
	p := procWith(t)
	run := supervise.Run{ID: runID, Tenant: tenant}
	for _, at := range []string{"first", "last"} {
		x := export(conforming()...)
		ev := x.Events[0]
		if at == "last" {
			ev = x.Events[len(x.Events)-1]
		}
		ev.ProjectId = ""
		_, err := supervise.Evaluate(supervise.Input{Procedure: p, Run: run, Exports: []supervise.Export{x}, Sources: []supervise.Source{source()}})
		if !errors.Is(err, supervise.ErrInput) || !strings.Contains(err.Error(), "names no project") {
			t.Errorf("the %s event with no project: Evaluate = %v, want ErrInput naming it", at, err)
		}
	}
}

// TestEventsOfAnotherProjectThanTheRecordAreRefused: the run's record names
// its project, so an export whose events of the run name another is refused
// as a source of another tenant is, and RunProject refuses it too. A run whose
// record names no project takes the events' project.
func TestEventsOfAnotherProjectThanTheRecordAreRefused(t *testing.T) {
	p := procWith(t)
	oneEvent := export(conforming()...)
	oneEvent.Events = oneEvent.Events[:1]
	for name, x := range map[string]supervise.Export{"the run": export(conforming()...), "a run of one event": oneEvent} {
		in := supervise.Input{Procedure: p, Run: supervise.Run{ID: runID, Tenant: tenant, Project: "p2"},
			Exports: []supervise.Export{x}}
		_, err := supervise.Evaluate(in)
		if !errors.Is(err, supervise.ErrInput) {
			t.Fatalf("%s: Evaluate = %v, want ErrInput", name, err)
		}
		for _, want := range []string{`project "p1"`, `record of project "p2"`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q names no %s", name, err, want)
			}
		}
		if got, err := supervise.RunProject(in); !errors.Is(err, supervise.ErrInput) || got != "" {
			t.Errorf("%s: RunProject = %q, %v; want ErrInput", name, got, err)
		}
		for _, project := range []string{proj, ""} {
			in.Run.Project = project
			res, err := supervise.Evaluate(in)
			if err != nil || res.Report.GetRead().GetEventsTaken() != uint64(len(x.Events)) {
				t.Fatalf("%s, a record of project %q: Evaluate = %v", name, project, err)
			}
			if got, err := supervise.RunProject(in); err != nil || got != "p1" {
				t.Fatalf("%s, a record of project %q: RunProject = %q, %v; want p1", name, project, got, err)
			}
		}
	}
}
