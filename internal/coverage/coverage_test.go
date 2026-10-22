package coverage_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/coverage"
)

// The TestValidation tests walk ADR-0041's Validation list, one item each.

func TestValidationObserveNeverEnforces(t *testing.T) {
	for _, o := range []coverage.Override{override(effectWrite), override(effectRead)} {
		p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{plane("a", modeObserve, false, o)},
			Sources: []coverage.Source{liveSource(selfReported, observedA.record())}}).Paths[0]
		if p.State != coverage.Decided {
			t.Errorf("%v: %v, want decided", o.Effect, p.State)
		}
	}
}

func TestValidationFailOpenReadNeverEnforcesARead(t *testing.T) {
	for _, m := range []controlv1.EnforcementMode{modeEnforce, modeApprove} {
		p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{plane("a", m, true, override(effectRead))}}).Paths[0]
		if p.State != coverage.Decided || !strings.Contains(p.Planes[0].Basis, "a read runs undecided while the policy is unavailable") {
			t.Errorf("%v: %v (%q), want decided with the fail-open ruling", m, p.State, p.Planes[0].Basis)
		}
	}
}

func TestValidationAnUnjoinedObservationIsACallAroundThePlane(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t),
		Planes:  []coverage.Plane{withExport(plane("a", modeEnforce, false, override(effectWrite)), wholeExport(t))},
		Sources: []coverage.Source{liveSource(selfReported, observedA.record())}})
	if !contains(r.Lines(), "obs-a", "a call around the plane") {
		t.Errorf("no line names obs-a as a call around the plane:\n%s", strings.Join(r.Lines(), "\n"))
	}
}

func TestValidationSelfReportedOnly(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{liveSource(selfReported, observedA.record())}})
	if got := r.Lines()[0]; !strings.HasPrefix(got, "gh-create observed, self_reported") {
		t.Errorf("path line %q", got)
	}
}

func TestValidationPastItsHeartbeatIsUnknown(t *testing.T) {
	src := coverage.Source{Descriptor: descriptor("s1", selfReported), Records: []*observev1.Record{
		report("s1", at(-time.Hour), at(-time.Hour)), observedA.record()}}
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{src}})
	if got := r.Lines()[0]; r.Paths[0].State != coverage.Unknown || !strings.HasPrefix(got, "gh-create unknown") {
		t.Errorf("%v, path line %q", r.Paths[0].State, got)
	}
}

func TestValidationARemovedDescriptorIsNotCovered(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t)})
	if got := r.Lines()[0]; r.Paths[0].State != coverage.NotCovered || !strings.HasPrefix(got, "gh-create not covered") {
		t.Errorf("%v, path line %q", r.Paths[0].State, got)
	}
}

func TestValidationTheStandingRowIsAlwaysPrinted(t *testing.T) {
	for _, r := range []*coverage.Report{
		mustMap(t, coverage.Input{Inventory: toolInventory(t)}),
		mustMap(t, coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{liveSource(selfReported, observedA.record())}}),
		{},
	} {
		l := r.Lines()
		if len(l) == 0 || l[len(l)-1] != "undeclared paths: unknown" {
			t.Errorf("last line of %q", l)
		}
	}
}

func contains(lines []string, parts ...string) bool {
	for _, l := range lines {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(l, p)
		}
		if all {
			return true
		}
	}
	return false
}

func TestLines(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t),
		Planes: []coverage.Plane{withExport(plane("a.yaml", modeEnforce, false, override(effectWrite)),
			wholeExport(t, proposal{trace: traceA, span: spanA}.line()))},
		Sources: []coverage.Source{liveSource(platform, with(observedA, func(o *obs) { o.trust = platform }).record())}})
	got := r.Lines()
	want := []string{
		"gh-create enforced: planes a.yaml",
		"  plane a.yaml: enforced: ENFORCE; override pins fingerprint fp1; the live definition is not checked; the plane's environment is not read",
		"  source s1: observed, platform, sampled: last heard 2026-10-05T11:59:50Z, heartbeat 300 s",
		"  join: 1 joined",
		"undeclared paths: unknown",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestLinesQuoteWhatTheyDidNotWrite: a plane name or an observation id holding
// a control character is quoted, so a log cannot write into the terminal.
func TestLinesQuoteWhatTheyDidNotWrite(t *testing.T) {
	r := mustMap(t, coverage.Input{Inventory: toolInventory(t),
		Planes:  []coverage.Plane{withExport(plane("a\x1b[2J.yaml", modeEnforce, false, override(effectWrite)), wholeExport(t))},
		Sources: []coverage.Source{liveSource(selfReported, with(observedA, func(o *obs) { o.id = "obs-\x1b]0;x\x07" }).record())}})
	for _, l := range r.Lines() {
		if strings.ContainsAny(l, "\x1b\x07") {
			t.Errorf("line %q carries a control character", l)
		}
	}
}

func TestExitStatus(t *testing.T) {
	observed := liveSource(selfReported, observedA.record())
	enforced := []coverage.Plane{plane("a", modeEnforce, false, override(effectWrite))}
	cases := []struct {
		name string
		in   coverage.Input
		want int
	}{
		{"every path observed", coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{observed}}, 0},
		{"a path not covered", coverage.Input{Inventory: toolInventory(t)}, 1},
		{"a path unknown", coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{{Descriptor: descriptor("s1", selfReported)}}}, 1},
		{"enforced with no evidence", coverage.Input{Inventory: toolInventory(t), Planes: enforced, Sources: []coverage.Source{observed}}, 0},
		{"enforced and joined", coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{observed},
			Planes: []coverage.Plane{withExport(enforced[0], wholeExport(t, proposal{trace: traceA, span: spanA}.line()))}}, 0},
		{"a bypass on an enforced path", coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{observed},
			Planes: []coverage.Plane{withExport(enforced[0], wholeExport(t))}}, 1},
		{"a second plane's export not given", coverage.Input{Inventory: toolInventory(t), Sources: []coverage.Source{observed},
			Planes: []coverage.Plane{withExport(enforced[0], wholeExport(t)), plane("b", modeEnforce, false, override(effectWrite))}}, 0},
		{"one path of two not covered", coverage.Input{Inventory: mustInventory(t, `{"schema_version":"0.1","paths":[`+
			`{"id":"gh-create","kind":"mcp_tool","upstream":"github","tool":"create_issue","sources":[{"source_id":"s1","name":"create_issue"}]},`+
			`{"id":"out","kind":"egress","host":"example.com"}]}`), Sources: []coverage.Source{observed}}, 1},
	}
	for _, tc := range cases {
		if got := coverage.ExitStatus(mustMap(t, tc.in), nil); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
	if got := coverage.ExitStatus(mustMap(t, cases[0].in), errors.New("a log could not be read")); got != 2 {
		t.Errorf("with an error: exit %d, want 2", got)
	}
	if got := coverage.ExitStatus(nil, nil); got != 2 {
		t.Errorf("with no map: exit %d, want 2", got)
	}
}

// TestAPathWithNoSourceSaysWhyNothingIsJoined: beside a path a plane decides
// or enforces, a join line says no source is named for it; a path no plane
// decides has no join to make and prints none.
func TestAPathWithNoSourceSaysWhyNothingIsJoined(t *testing.T) {
	inv := mustInventory(t, `{"schema_version":"0.1","paths":[{"id":"gh-create","kind":"mcp_tool","upstream":"github","tool":"create_issue"}]}`)
	cases := []struct {
		name   string
		planes []coverage.Plane
		want   []string
	}{
		{"enforced", []coverage.Plane{plane("a", modeEnforce, false, override(effectWrite))}, []string{
			"gh-create enforced: planes a",
			"  plane a: enforced: ENFORCE; override pins fingerprint fp1; the live definition is not checked; the plane's environment is not read",
			"  join: none checked: no source is named for it",
			"undeclared paths: unknown",
		}},
		{"decided", []coverage.Plane{listing(plane("a", modeObserve, false), "github")}, []string{
			"gh-create decided, not enforced: planes a",
			"  plane a: decided, not enforced: an unclassified call runs in OBSERVE; the plane lists the upstream and no override names the tool; the plane's environment is not read",
			"  join: none checked: no source is named for it",
			"undeclared paths: unknown",
		}},
		{"no plane", nil, []string{
			"gh-create not covered: no plane classifies it and no live source observed it",
			"undeclared paths: unknown",
		}},
	}
	for _, tc := range cases {
		got := mustMap(t, coverage.Input{Inventory: inv, Planes: tc.planes}).Lines()
		if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("%s: lines:\n%s\nwant:\n%s", tc.name, strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
		}
	}
}
