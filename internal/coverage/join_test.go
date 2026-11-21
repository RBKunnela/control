package coverage_test

import (
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/coverage"
)

// joinOf maps the path github/create_issue, enforced by plane a whose export
// is x and seen by source s1 in the given records, and returns its one join.
func joinOf(t *testing.T, x *coverage.Export, records ...*observev1.Record) coverage.JoinCheck {
	t.Helper()
	p := mustMap(t, coverage.Input{
		Inventory: toolInventory(t),
		Planes:    []coverage.Plane{withExport(plane("a", modeEnforce, false, override(effectWrite)), x)},
		Sources:   []coverage.Source{liveSource(selfReported, records...)},
	}).Paths[0]
	if p.State != coverage.Enforced || len(p.Joins) != 1 {
		t.Fatalf("%v with joins %+v; want enforced with one join", p.State, p.Joins)
	}
	return p.Joins[0]
}

var observedA = obs{id: "obs-a", trace: traceA, span: spanA}

func TestAProposalJoinsItsObservation(t *testing.T) {
	j := joinOf(t, wholeExport(t, proposal{trace: traceA, span: spanA}.line()), observedA.record())
	if j.Join != coverage.Joined || j.ObservationID != "obs-a" {
		t.Fatalf("%+v, want obs-a joined", j)
	}
}

func TestNothingJoinsOnLessThanEverything(t *testing.T) {
	cases := map[string]struct {
		o obs
		p proposal
	}{
		"no proposal at all":                    {observedA, proposal{trace: traceB, span: spanB, tool: "other"}},
		"the trace alone":                       {observedA, proposal{trace: traceA, span: spanB}},
		"the span alone":                        {observedA, proposal{trace: traceB, span: spanA}},
		"empty span ids":                        {obs{trace: traceA}, proposal{trace: traceA}},
		"empty trace ids":                       {obs{span: spanA}, proposal{span: spanA}},
		"another tenant":                        {observedA, proposal{trace: traceA, span: spanA, tenant: "t2"}},
		"another project":                       {observedA, proposal{trace: traceA, span: spanA, project: "p2"}},
		"another tenant on the event alone":     {observedA, proposal{trace: traceA, span: spanA, eventTenant: "t2"}},
		"another tenant in the envelope alone":  {observedA, proposal{trace: traceA, span: spanA, envelopeTenant: "t2"}},
		"another project on the event alone":    {observedA, proposal{trace: traceA, span: spanA, eventProject: "p2"}},
		"another project in the envelope alone": {observedA, proposal{trace: traceA, span: spanA, envelopeProject: "p2"}},
		"another tool":                          {observedA, proposal{trace: traceA, span: spanA, tool: "delete_issue"}},
		"another upstream":                      {observedA, proposal{trace: traceA, span: spanA, upstream: "gitlab"}},
		"the enforcement API's proposal":        {observedA, proposal{trace: traceA, span: spanA, protocol: "enforce"}},
		"no protocol":                           {observedA, proposal{trace: traceA, span: spanA, protocol: "none"}},
		"an OBSERVE-mode proposal":              {observedA, proposal{trace: traceA, span: spanA, mode: "OBSERVE"}},
		"a SHADOW-mode proposal":                {observedA, proposal{trace: traceA, span: spanA, mode: "SHADOW"}},
		"an unspecified mode":                   {observedA, proposal{trace: traceA, span: spanA, mode: "UNSPECIFIED"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			j := joinOf(t, wholeExport(t, tc.p.line()), tc.o.record())
			if j.Join == coverage.Joined {
				t.Fatalf("%+v joined", j)
			}
		})
	}
}

// TestOnlyAToolCallJoins: a prompt or a resource read through the plane under
// the tool's name, upstream and ids is not the tool call the source saw.
func TestOnlyAToolCallJoins(t *testing.T) {
	hit := proposal{trace: traceA, span: spanA}
	cases := []struct {
		name string
		line string
		want coverage.Join
	}{
		{"a tool call", hit.line(), coverage.Joined},
		{"a prompt", withKind(hit, "prompt").line(), coverage.JoinAround},
		{"a resource", withKind(hit, "resource").line(), coverage.JoinAround},
		{"a kind spelled otherwise", withKind(hit, "Tool").line(), coverage.JoinAround},
		{"no kind", strings.Replace(hit.line(), `"kind":"tool",`, "", 1), coverage.JoinAround},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if j := joinOf(t, wholeExport(t, tc.line), observedA.record()); j.Join != tc.want {
				t.Fatalf("%+v, want %v", j, tc.want)
			}
		})
	}
}

func withKind(p proposal, kind string) proposal {
	p.kind = kind
	return p
}

// TestAnUnjoinedObservationIsACallAroundThePlane: whole evidence whose window
// holds the observation, and no proposal joining it.
func TestAnUnjoinedObservationIsACallAroundThePlane(t *testing.T) {
	j := joinOf(t, wholeExport(t, proposal{trace: traceA, span: spanB}.line()), observedA.record())
	if j.Join != coverage.JoinAround {
		t.Fatalf("%+v, want a call around the plane", j)
	}
}

func TestADescendantJoins(t *testing.T) {
	child := obs{id: "obs-child", kind: observev1.SubjectKind_SUBJECT_KIND_MODEL, name: "m", trace: traceA, span: spanB, parent: spanA}
	grandchild := obs{id: "obs-grand", kind: observev1.SubjectKind_SUBJECT_KIND_MODEL, name: "m", trace: traceA, span: spanC, parent: spanB}
	cases := []struct {
		name    string
		records []*observev1.Record
		span    string
		want    coverage.Join
	}{
		{"a child", []*observev1.Record{observedA.record(), child.record()}, spanB, coverage.Joined},
		{"a grandchild", []*observev1.Record{observedA.record(), child.record(), grandchild.record()}, spanC, coverage.Joined},
		{"a child of another source", []*observev1.Record{observedA.record(), with(child, func(o *obs) { o.source = "s2" }).record()}, spanB, coverage.JoinAround},
		{"a child with an empty span id", []*observev1.Record{observedA.record(), with(child, func(o *obs) { o.span = "" }).record()}, "", coverage.JoinAround},
		{"a child in another trace", []*observev1.Record{observedA.record(), with(child, func(o *obs) { o.trace = traceB }).record()}, spanB, coverage.JoinAround},
		{"a child of another tenant", []*observev1.Record{observedA.record(), with(child, func(o *obs) { o.tenant = "t2" }).record()}, spanB, coverage.JoinAround},
		{"a child of another project", []*observev1.Record{observedA.record(), with(child, func(o *obs) { o.project = "p2" }).record()}, spanB, coverage.JoinAround},
		{"a grandchild below a child of another tenant", []*observev1.Record{observedA.record(),
			with(child, func(o *obs) { o.tenant = "t2" }).record(), grandchild.record()}, spanC, coverage.JoinAround},
		{"a parent does not join for its child", []*observev1.Record{
			with(observedA, func(o *obs) { o.parent = spanB }).record(),
			{Record: &observev1.Record_Observation{Observation: &observev1.Observation{ObservationId: "obs-up",
				Source: &observev1.SourceRef{SourceId: "s1"}, Subject: &observev1.Subject{Kind: observev1.SubjectKind_SUBJECT_KIND_AGENT, Name: "a"},
				Correlation: &observev1.Correlation{TraceId: traceA, SpanId: spanB}}}}}, spanB, coverage.JoinAround},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := joinOf(t, wholeExport(t, proposal{trace: traceA, span: tc.span}.line()), tc.records...)
			if j.Join != tc.want || j.ObservationID != "obs-a" {
				t.Fatalf("%+v, want obs-a %v", j, tc.want)
			}
		})
	}
}

func with(o obs, change func(*obs)) obs {
	change(&o)
	return o
}

func TestAJoinNotCheckedSaysWhy(t *testing.T) {
	miss := proposal{trace: traceA, span: spanB}.line()
	notWhole := func(query string, end bool, extra ...string) *coverage.Export {
		l := append([]string{header(query), windowEvent(-time.Hour), windowEvent(0), miss}, extra...)
		return mustExport(t, lines(append(l, trailer(3, len(extra), 0, end))...))
	}
	cases := []struct {
		name string
		x    *coverage.Export
		o    obs
		why  string
	}{
		{"no export", nil, observedA, "no export of plane a"},
		{"no export and no ids", nil, obs{}, "no trace or span id"},
		{"a filtered export", notWhole(`{"limit":1000,"tenant":["t1"]}`, true), observedA, "the export of plane a is not whole: it is filtered"},
		{"an export after a cursor", notWhole(`{"after":"v1:x","limit":1000}`, true), observedA, "not whole"},
		{"an export stopped early", notWhole(plainQuery, false), observedA, "not whole"},
		{"a gapped export", notWhole(plainQuery, true, `{"type":"gap","offset":0,"cursor":"c","reason":"malformed"}`), observedA, "not whole"},
		{"a cut export", mustExport(t, lines(header(plainQuery), windowEvent(-time.Hour), windowEvent(0), miss)), observedA, "not whole"},
		{"no event time", wholeExport(t, miss), with(observedA, func(o *obs) { o.noTime = true }), "no event time"},
		{"before the window", mustExport(t, lines(header(plainQuery), windowEvent(-30*time.Second), miss, trailer(2, 0, 0, true))), observedA,
			"outside the window of the export of plane a"},
		{"after the window", mustExport(t, lines(header(plainQuery), windowEvent(-time.Hour),
			proposal{trace: traceA, span: spanB, occurred: -2 * time.Minute}.line(), trailer(2, 0, 0, true))), observedA, "outside"},
		{"an export with no event", mustExport(t, lines(header(plainQuery), trailer(0, 0, 0, true))), observedA, "outside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := joinOf(t, tc.x, tc.o.record())
			if j.Join != coverage.JoinNotChecked || !strings.Contains(j.Why, tc.why) {
				t.Fatalf("%+v, want not checked because %q", j, tc.why)
			}
		})
	}
}

// TestAMatchInANotWholeExportIsNotAJoin: a filtered or cut export is read
// for nothing.
func TestAMatchInANotWholeExportIsNotAJoin(t *testing.T) {
	cut := mustExport(t, lines(header(plainQuery), windowEvent(-time.Hour), proposal{trace: traceA, span: spanA}.line()))
	if j := joinOf(t, cut, observedA.record()); j.Join != coverage.JoinNotChecked {
		t.Fatalf("%+v, want not checked", j)
	}
}

func TestOnlyAPlaneDecidedPathIsJoined(t *testing.T) {
	p := mustMap(t, coverage.Input{
		Inventory: toolInventory(t),
		Sources:   []coverage.Source{liveSource(selfReported, observedA.record())},
	}).Paths[0]
	if p.State != coverage.Observed || len(p.Joins) != 0 {
		t.Fatalf("%v with joins %+v; want observed and no join", p.State, p.Joins)
	}
	p = mustMap(t, coverage.Input{
		Inventory: toolInventory(t),
		Planes: []coverage.Plane{withExport(plane("a", modeObserve, false, override(effectWrite)),
			wholeExport(t, proposal{trace: traceA, span: spanA, mode: "OBSERVE"}.line()))},
		Sources: []coverage.Source{liveSource(selfReported, observedA.record())},
	}).Paths[0]
	if p.State != coverage.Decided || len(p.Joins) != 1 || p.Joins[0].Join != coverage.Joined {
		t.Fatalf("%v with joins %+v; want decided, joined by the OBSERVE plane's own proposal", p.State, p.Joins)
	}
}

// withExport is plane p with export x.
func withExport(p coverage.Plane, x *coverage.Export) coverage.Plane {
	p.Export = x
	return p
}

// TestAnExportSpeaksOnlyForItsPlane: a call around the plane needs every
// plane in front of the path to have a whole export covering the
// observation, and a join may come from any of them.
func TestAnExportSpeaksOnlyForItsPlane(t *testing.T) {
	a := plane("a", modeEnforce, false, override(effectWrite))
	b := plane("b", modeEnforce, false, override(effectWrite))
	unrelated := listing(plane("c", modeEnforce, false), "gitlab")
	miss := proposal{trace: traceA, span: spanB}.line()
	hit := proposal{trace: traceA, span: spanA}.line()
	cut := mustExport(t, lines(header(plainQuery), windowEvent(-time.Hour), windowEvent(0), miss))
	cases := []struct {
		name   string
		planes []coverage.Plane
		want   coverage.Join
		why    string
	}{
		{"one plane of two with an export", []coverage.Plane{withExport(a, wholeExport(t, miss)), b},
			coverage.JoinNotChecked, "no export of plane b"},
		{"only an unrelated plane's export", []coverage.Plane{a, withExport(unrelated, wholeExport(t, miss))},
			coverage.JoinNotChecked, "no export of plane a"},
		{"the other plane's export not whole", []coverage.Plane{withExport(a, wholeExport(t, miss)), withExport(b, cut)},
			coverage.JoinNotChecked, "the export of plane b is not whole: it has no trailer: it was cut short"},
		{"the other plane's export outside the window", []coverage.Plane{withExport(a, wholeExport(t, miss)),
			withExport(b, mustExport(t, lines(header(plainQuery), windowEvent(-30*time.Second), trailer(1, 0, 0, true))))},
			coverage.JoinNotChecked, "outside the window of the export of plane b"},
		{"both planes' exports whole", []coverage.Plane{withExport(a, wholeExport(t, miss)), withExport(b, wholeExport(t, miss))},
			coverage.JoinAround, ""},
		{"a join in the second plane's export", []coverage.Plane{withExport(a, wholeExport(t, miss)), withExport(b, wholeExport(t, hit))},
			coverage.Joined, ""},
		{"a join in a plane's export beside one with none", []coverage.Plane{a, withExport(b, wholeExport(t, hit))},
			coverage.Joined, ""},
		{"a plane not in front of the path needs no export", []coverage.Plane{withExport(a, wholeExport(t, miss)), unrelated},
			coverage.JoinAround, ""},
		{"a join in an unrelated plane's export is no join", []coverage.Plane{withExport(a, wholeExport(t, miss)), withExport(unrelated, wholeExport(t, hit))},
			coverage.JoinAround, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: tc.planes,
				Sources: []coverage.Source{liveSource(selfReported, observedA.record())}}).Paths[0]
			if p.State != coverage.Enforced || len(p.Joins) != 1 {
				t.Fatalf("%v with joins %+v; want enforced with one join", p.State, p.Joins)
			}
			if j := p.Joins[0]; j.Join != tc.want || j.Why != tc.why {
				t.Fatalf("%+v, want %v (%q)", j, tc.want, tc.why)
			}
		})
	}
}

// TestAMatchJoinsWhateverTheTime: the event time and the export's window only
// bound calling an unjoined observation a call around the plane.
func TestAMatchJoinsWhateverTheTime(t *testing.T) {
	hit := proposal{trace: traceA, span: spanA}.line()
	cases := map[string]*coverage.Export{
		"no event time":      wholeExport(t, hit),
		"outside the window": mustExport(t, lines(header(plainQuery), windowEvent(-30*time.Second), hit, trailer(2, 0, 0, true))),
	}
	for name, x := range cases {
		t.Run(name, func(t *testing.T) {
			o := observedA
			o.noTime = name == "no event time"
			if j := joinOf(t, x, o.record()); j.Join != coverage.Joined {
				t.Fatalf("%+v, want joined", j)
			}
		})
	}
}

// TestEveryProposalUnderOneIDPairIsTried: proposals of other tenants, kinds
// and tools carrying the same ids, before and after the one that joins.
func TestEveryProposalUnderOneIDPairIsTried(t *testing.T) {
	ids := proposal{trace: traceA, span: spanA}
	others := []string{
		withProposal(ids, func(p *proposal) { p.tenant = "t2" }).line(),
		withProposal(ids, func(p *proposal) { p.kind = "prompt" }).line(),
		withProposal(ids, func(p *proposal) { p.tool = "delete_issue" }).line(),
	}
	for _, events := range [][]string{append(others, ids.line()), append([]string{ids.line()}, others...)} {
		if j := joinOf(t, wholeExport(t, events...), observedA.record()); j.Join != coverage.Joined {
			t.Fatalf("%+v, want joined", j)
		}
	}
}

func withProposal(p proposal, change func(*proposal)) proposal {
	change(&p)
	return p
}

// TestTheWindowHoldsItsEdges: the observation is a minute before now; an
// export whose first or last event is at that instant holds it, and one a
// nanosecond short of it on either side does not.
func TestTheWindowHoldsItsEdges(t *testing.T) {
	window := func(first, last time.Duration) *coverage.Export {
		miss := proposal{trace: traceA, span: spanB, occurred: first}.line()
		return mustExport(t, lines(header(plainQuery), windowEvent(first), miss, windowEvent(last), trailer(3, 0, 0, true)))
	}
	cases := []struct {
		name string
		x    *coverage.Export
		want coverage.Join
	}{
		{"at the earliest", window(-time.Minute, 0), coverage.JoinAround},
		{"at the latest", window(-time.Hour, -time.Minute), coverage.JoinAround},
		{"a nanosecond before the earliest", window(-time.Minute+time.Nanosecond, 0), coverage.JoinNotChecked},
		{"a nanosecond after the latest", window(-time.Hour, -time.Minute-time.Nanosecond), coverage.JoinNotChecked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if j := joinOf(t, tc.x, observedA.record()); j.Join != tc.want {
				t.Fatalf("%+v, want %v", j, tc.want)
			}
		})
	}
}
