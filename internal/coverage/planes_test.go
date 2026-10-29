package coverage_test

import (
	"errors"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/coverage"
)

func TestPlaneStates(t *testing.T) {
	cases := []struct {
		name   string
		planes []coverage.Plane
		want   coverage.State
		basis  string
	}{
		{"ENFORCE enforces a write", []coverage.Plane{plane("a", modeEnforce, false, override(effectWrite))}, coverage.Enforced, "override pins fingerprint fp1; the live definition is not checked"},
		{"APPROVE enforces a write", []coverage.Plane{plane("a", modeApprove, false, override(effectWrite))}, coverage.Enforced, "APPROVE"},
		{"LOCKDOWN enforces a write", []coverage.Plane{plane("a", modeLockdown, false, override(effectWrite))}, coverage.Enforced, "LOCKDOWN"},
		{"OBSERVE decides a write", []coverage.Plane{plane("a", modeObserve, false, override(effectWrite))}, coverage.Decided, "OBSERVE"},
		{"OBSERVE decides a read", []coverage.Plane{plane("a", modeObserve, false, override(effectRead))}, coverage.Decided, "OBSERVE"},
		{"ENFORCE enforces a read with fail_open_read off", []coverage.Plane{plane("a", modeEnforce, false, override(effectRead))}, coverage.Enforced, "ENFORCE"},
		{"ENFORCE with fail_open_read decides a read", []coverage.Plane{plane("a", modeEnforce, true, override(effectRead))}, coverage.Decided, "a read runs undecided while the policy is unavailable"},
		{"APPROVE with fail_open_read decides a read", []coverage.Plane{plane("a", modeApprove, true, override(effectRead))}, coverage.Decided, "a read runs undecided while the policy is unavailable"},
		{"ENFORCE with fail_open_read enforces a write", []coverage.Plane{plane("a", modeEnforce, true, override(effectWrite))}, coverage.Enforced, "ENFORCE"},
		{"LOCKDOWN with fail_open_read enforces a read", []coverage.Plane{plane("a", modeLockdown, true, override(effectRead))}, coverage.Enforced, "LOCKDOWN"},
		{"SHADOW classifies nothing", []coverage.Plane{plane("a", modeShadow, false, override(effectWrite))}, coverage.NotCovered, "refused at start"},
		{"WARN classifies nothing", []coverage.Plane{plane("a", modeWarn, false, override(effectWrite))}, coverage.NotCovered, "refused at start"},
		{"an ENFORCE and an OBSERVE plane decide", []coverage.Plane{
			plane("a", modeEnforce, false, override(effectWrite)), plane("b", modeObserve, false, override(effectWrite))}, coverage.Decided, "OBSERVE"},
		{"an OBSERVE and an ENFORCE plane decide", []coverage.Plane{
			plane("b", modeObserve, false, override(effectWrite)), plane("a", modeEnforce, false, override(effectWrite))}, coverage.Decided, "OBSERVE"},
		{"a SHADOW plane beside an ENFORCE plane takes nothing away", []coverage.Plane{
			plane("a", modeEnforce, false, override(effectWrite)), plane("b", modeShadow, false, override(effectWrite))}, coverage.Enforced, "ENFORCE"},
		{"a read and a write definition under fail-open decide", []coverage.Plane{plane("a", modeEnforce, true,
			override(effectWrite), coverage.Override{Upstream: "github", Tool: "create_issue", Fingerprint: "fp2", Effect: effectRead})},
			coverage.Decided, "fp2"},
		{"another upstream's tool of the same name", []coverage.Plane{plane("a", modeEnforce, false,
			coverage.Override{Upstream: "gitlab", Tool: "create_issue", Fingerprint: "fp1", Effect: effectWrite})}, coverage.NotCovered, ""},
		{"another tool on the upstream", []coverage.Plane{plane("a", modeEnforce, false,
			coverage.Override{Upstream: "github", Tool: "create_issues", Fingerprint: "fp1", Effect: effectWrite})}, coverage.NotCovered, ""},
		{"no plane", nil, coverage.NotCovered, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: tc.planes}).Paths[0]
			if p.State != tc.want {
				t.Fatalf("state %v, want %v; planes %+v", p.State, tc.want, p.Planes)
			}
			var bases []string
			for _, l := range p.Planes {
				bases = append(bases, l.Basis)
			}
			if !strings.Contains(strings.Join(bases, "\n"), tc.basis) {
				t.Errorf("plane bases %q do not say %q", bases, tc.basis)
			}
		})
	}
}

// TestPlaneLinesNameEveryPlane: the path shows each plane's own state, so a
// reader sees which plane weakens it.
func TestPlaneLinesNameEveryPlane(t *testing.T) {
	p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{
		plane("a.yaml", modeEnforce, false, override(effectWrite)),
		plane("b.yaml", modeObserve, false, override(effectWrite)),
		plane("c.yaml", modeWarn, false, override(effectWrite)),
		plane("d.yaml", modeEnforce, false),
	}}).Paths[0]
	want := []coverage.PlaneLine{{Plane: "a.yaml", State: coverage.Enforced}, {Plane: "b.yaml", State: coverage.Decided},
		{Plane: "c.yaml", State: coverage.NotCovered}}
	if len(p.Planes) != len(want) {
		t.Fatalf("plane lines %+v, want %d", p.Planes, len(want))
	}
	for i, w := range want {
		if p.Planes[i].Plane != w.Plane || p.Planes[i].State != w.State {
			t.Errorf("plane line %d = %+v, want %+v", i, p.Planes[i], w)
		}
	}
}

func TestOnlyAnMCPToolIsClassified(t *testing.T) {
	inv := mustInventory(t, `{"schema_version":"0.1","paths":[{"id":"p","kind":"process","name":"create_issue"},`+
		`{"id":"e","kind":"egress","host":"github"}]}`)
	for _, p := range mustMap(t, coverage.Input{Inventory: inv, Planes: []coverage.Plane{
		plane("a", modeEnforce, false, override(effectWrite))}}).Paths {
		if p.State != coverage.NotCovered || len(p.Planes) != 0 {
			t.Errorf("%s: %v with %+v, want not covered by any plane", p.Path.ID, p.State, p.Planes)
		}
	}
}

func TestMapRefusesAnUndeclaredModeOrEffect(t *testing.T) {
	cases := map[string]coverage.Plane{
		"an unspecified mode":   plane("a", controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED, false, override(effectWrite)),
		"an undeclared mode":    plane("a", controlv1.EnforcementMode(99), false, override(effectWrite)),
		"an unspecified effect": plane("a", modeEnforce, false, override(controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED)),
		"an undeclared effect":  plane("a", modeEnforce, false, override(controlv1.EffectClass(99))),
		"a tool of an unspecified effect": {Name: "a", Mode: modeEnforce, Strength: channel.StrengthCooperative,
			Tools: []coverage.Tool{{Name: "refund", Effect: controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED}}},
		"a tool of an undeclared effect": {Name: "a", Mode: modeEnforce, Strength: channel.StrengthCooperative,
			Tools: []coverage.Tool{{Name: "refund", Effect: controlv1.EffectClass(99)}}},
	}
	for name, pl := range cases {
		r, err := coverage.Map(coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{pl}, Now: now})
		if !errors.Is(err, coverage.ErrInput) || r != nil {
			t.Errorf("%s: Map = %+v, %v; want ErrInput", name, r, err)
		}
	}
}

// TestAPlaneListingTheUpstreamCounts: a plane that lists the path's upstream
// and has no override for its tool still stands in front of the call. It
// blocks the unclassified call in every mode but OBSERVE, which lets it run.
func TestAPlaneListingTheUpstreamCounts(t *testing.T) {
	enforcing := plane("a", modeEnforce, false, override(effectWrite))
	cases := []struct {
		name   string
		second coverage.Plane
		want   coverage.State
		line   coverage.PlaneLine
	}{
		{"OBSERVE", listing(plane("b", modeObserve, false), "github"), coverage.Decided, coverage.PlaneLine{Plane: "b", State: coverage.Decided,
			Basis: "an unclassified call runs in OBSERVE; the plane lists the upstream and no override names the tool; the plane's environment is not read"}},
		{"ENFORCE", listing(plane("b", modeEnforce, false), "github"), coverage.Enforced, coverage.PlaneLine{Plane: "b", State: coverage.Enforced,
			Basis: "an unclassified call is blocked in ENFORCE; the plane lists the upstream and no override names the tool; the plane's environment is not read"}},
		{"APPROVE", listing(plane("b", modeApprove, false), "github"), coverage.Enforced, coverage.PlaneLine{Plane: "b", State: coverage.Enforced,
			Basis: "an unclassified call is blocked in APPROVE; the plane lists the upstream and no override names the tool; the plane's environment is not read"}},
		{"LOCKDOWN", listing(plane("b", modeLockdown, false), "github"), coverage.Enforced, coverage.PlaneLine{Plane: "b", State: coverage.Enforced,
			Basis: "an unclassified call is blocked in LOCKDOWN; the plane lists the upstream and no override names the tool; the plane's environment is not read"}},
		{"ENFORCE with fail_open_read", listing(plane("b", modeEnforce, true), "github"), coverage.Enforced, coverage.PlaneLine{Plane: "b", State: coverage.Enforced,
			Basis: "an unclassified call is blocked in ENFORCE; the plane lists the upstream and no override names the tool; the plane's environment is not read"}},
		{"SHADOW", listing(plane("b", modeShadow, false), "github"), coverage.Enforced, coverage.PlaneLine{Plane: "b", State: coverage.NotCovered,
			Basis: "SHADOW is refused at start by the plane, so it classifies nothing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{enforcing, tc.second}}).Paths[0]
			if p.State != tc.want || len(p.Planes) != 2 || p.Planes[1] != tc.line {
				t.Fatalf("%v with %+v; want %v and a second line %+v", p.State, p.Planes, tc.want, tc.line)
			}
		})
	}
}

// TestAPlaneThatDoesNotListTheUpstreamDoesNotCount: a plane in front of
// other upstreams never sees the call.
func TestAPlaneThatDoesNotListTheUpstreamDoesNotCount(t *testing.T) {
	p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{
		plane("a", modeEnforce, false, override(effectWrite)), listing(plane("b", modeObserve, false), "gitlab", "githubx")}}).Paths[0]
	if p.State != coverage.Enforced || p.Basis != "planes a" || len(p.Planes) != 1 {
		t.Fatalf("%v (%q) with %+v; want enforced by plane a alone", p.State, p.Basis, p.Planes)
	}
	p = mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{listing(plane("b", modeObserve, false), "gitlab")}}).Paths[0]
	if p.State != coverage.NotCovered || len(p.Planes) != 0 {
		t.Fatalf("%v with %+v; want not covered and no plane line", p.State, p.Planes)
	}
}

// TestAnObservePlaneWithoutAnOverrideIsShown is the map as printed: an
// ENFORCE plane classifies the tool, an OBSERVE plane in front of the same
// upstream lets it run unclassified.
func TestAnObservePlaneWithoutAnOverrideIsShown(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{
		plane("a.yaml", modeEnforce, false, override(effectWrite)), listing(plane("b.yaml", modeObserve, false), "github")},
		Sources: []coverage.Source{liveSource(selfReported, observedA.record())}})
	want := []string{
		"gh-create decided, not enforced: planes a.yaml, b.yaml",
		"  plane a.yaml: enforced: ENFORCE; override pins fingerprint fp1; the live definition is not checked; the plane's environment is not read",
		"  plane b.yaml: decided, not enforced: an unclassified call runs in OBSERVE; the plane lists the upstream and no override names the tool; the plane's environment is not read",
	}
	if got := r.Lines(); strings.Join(got[:3], "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
