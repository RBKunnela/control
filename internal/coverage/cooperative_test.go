package coverage_test

import (
	"errors"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/coverage"
)

// enforceInventory declares one enforce_tool path, the tool refund, seen by
// source s1 as refund.
func enforceInventory(t testing.TB) *coverage.Inventory {
	t.Helper()
	return mustInventory(t, `{"schema_version":"0.1","paths":[{"id":"refund","kind":"enforce_tool","tool":"refund",`+
		`"sources":[{"source_id":"s1","name":"refund"}]}]}`)
}

// cooperative is an enforcement API plane classifying tools by name, each a
// transaction.
func cooperative(name string, mode controlv1.EnforcementMode, failOpenRead bool, tools ...string) coverage.Plane {
	p := coverage.Plane{Name: name, Mode: mode, FailOpenRead: failOpenRead, Strength: channel.StrengthCooperative}
	for _, tool := range tools {
		p.Tools = append(p.Tools, coverage.Tool{Name: tool, Effect: controlv1.EffectClass_EFFECT_CLASS_TRANSACT})
	}
	return p
}

// reading is p with its tools classified as reads.
func reading(p coverage.Plane) coverage.Plane {
	for i := range p.Tools {
		p.Tools[i].Effect = controlv1.EffectClass_EFFECT_CLASS_READ
	}
	return p
}

const cooperativeBasis = "the tool table classifies it by name; a cooperating client enforces the decision, " +
	"which the plane cannot keep from the effect; no tool definition is checked; the plane's environment is not read"

func TestReadInventoryReadsAnEnforceTool(t *testing.T) {
	inv := enforceInventory(t)
	p := inv.Paths[0]
	if coverage.KindEnforceTool != "enforce_tool" || p.Kind != coverage.KindEnforceTool || p.Tool != "refund" || p.Upstream != "" ||
		len(p.Sources) != 1 || p.Sources[0].Name != "refund" {
		t.Fatalf("read %+v", p)
	}
}

func TestReadInventoryRefusesAnEnforceTool(t *testing.T) {
	doc := func(paths ...string) string {
		return `{"schema_version":"0.1","paths":[` + strings.Join(paths, ",") + `]}`
	}
	const tool = `{"id":"a","kind":"enforce_tool","tool":"refund"}`
	cases := map[string]string{
		"no tool":                       doc(`{"id":"a","kind":"enforce_tool"}`),
		"an empty tool":                 doc(`{"id":"a","kind":"enforce_tool","tool":""}`),
		"an upstream":                   doc(`{"id":"a","kind":"enforce_tool","tool":"refund","upstream":"u"}`),
		"the tool twice":                doc(tool, `{"id":"b","kind":"enforce_tool","tool":"refund"}`),
		"a name instead of a tool":      doc(`{"id":"a","kind":"enforce_tool","name":"refund"}`),
		"the kind spelled otherwise":    doc(`{"id":"a","kind":"Enforce_tool","tool":"refund"}`),
		"a host beside the tool":        doc(`{"id":"a","kind":"enforce_tool","tool":"refund","host":"h"}`),
		"a control character in a tool": doc(`{"id":"a","kind":"enforce_tool","tool":"re\u0007fund"}`),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			inv, err := coverage.ReadInventory([]byte(d))
			if !errors.Is(err, coverage.ErrInventory) || inv != nil {
				t.Fatalf("ReadInventory = %+v, %v; want ErrInventory", inv, err)
			}
		})
	}
	both := doc(tool, `{"id":"b","kind":"mcp_tool","upstream":"u","tool":"refund"}`)
	if _, err := coverage.ReadInventory([]byte(both)); err != nil {
		t.Errorf("an enforce_tool and an mcp_tool of one name are two paths; ReadInventory: %v", err)
	}
}

// TestACooperativePlaneNeverEnforces holds the amended coverage table: a
// plane that hands its decision to a cooperating client decides the tools it
// classifies, in every mode it runs in, and never enforces them.
func TestACooperativePlaneNeverEnforces(t *testing.T) {
	cases := []struct {
		name  string
		plane coverage.Plane
		want  coverage.State
		basis string
	}{
		{"ENFORCE", cooperative("api", modeEnforce, false, "refund"), coverage.Decided, "ENFORCE; " + cooperativeBasis},
		{"APPROVE", cooperative("api", modeApprove, false, "refund"), coverage.Decided, "APPROVE; " + cooperativeBasis},
		{"LOCKDOWN", cooperative("api", modeLockdown, false, "refund"), coverage.Decided, "LOCKDOWN; " + cooperativeBasis},
		{"OBSERVE", cooperative("api", modeObserve, false, "refund"), coverage.Decided, "OBSERVE; " + cooperativeBasis},
		{"ENFORCE with fail_open_read", cooperative("api", modeEnforce, true, "refund"), coverage.Decided, "ENFORCE; " + cooperativeBasis},
		{"a read under ENFORCE with fail_open_read", reading(cooperative("api", modeEnforce, true, "refund")), coverage.Decided,
			"ENFORCE with fail_open_read: a read runs undecided while the policy is unavailable; " + cooperativeBasis},
		{"a read under APPROVE with fail_open_read", reading(cooperative("api", modeApprove, true, "refund")), coverage.Decided,
			"APPROVE with fail_open_read: a read runs undecided while the policy is unavailable; " + cooperativeBasis},
		{"a read under ENFORCE", reading(cooperative("api", modeEnforce, false, "refund")), coverage.Decided, "ENFORCE; " + cooperativeBasis},
		{"a read under LOCKDOWN with fail_open_read", reading(cooperative("api", modeLockdown, true, "refund")), coverage.Decided, "LOCKDOWN; " + cooperativeBasis},
		{"a read under OBSERVE with fail_open_read", reading(cooperative("api", modeObserve, true, "refund")), coverage.Decided, "OBSERVE; " + cooperativeBasis},
		{"SHADOW", cooperative("api", modeShadow, false, "refund"), coverage.NotCovered, "SHADOW is refused at start by the plane, so it classifies nothing"},
		{"WARN", cooperative("api", modeWarn, false, "refund"), coverage.NotCovered, "WARN is refused at start by the plane, so it classifies nothing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustMap(t, coverage.Input{Inventory: enforceInventory(t), Planes: []coverage.Plane{tc.plane}}).Paths[0]
			if p.State != tc.want || len(p.Planes) != 1 || p.Planes[0].State != tc.want || p.Planes[0].Basis != tc.basis {
				t.Fatalf("%v with %+v; want %v with the basis %q", p.State, p.Planes, tc.want, tc.basis)
			}
		})
	}
}

// TestACooperativePlaneCapsWhatItsOverridesWouldEnforce: whatever a
// cooperative plane classifies, an MCP tool included, it never makes the
// path enforced, and it weakens a path an inline plane enforces.
func TestACooperativePlaneCapsWhatItsOverridesWouldEnforce(t *testing.T) {
	coop := plane("api", modeEnforce, false, override(effectWrite))
	coop.Strength = channel.StrengthCooperative
	p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{coop}}).Paths[0]
	if p.State != coverage.Decided || len(p.Planes) != 1 || !strings.Contains(p.Planes[0].Basis, "a cooperating client enforces the decision") {
		t.Fatalf("%v with %+v; want decided, not enforced, naming the cooperating client", p.State, p.Planes)
	}
	listed := listing(plane("api", modeLockdown, false), "github")
	listed.Strength = channel.StrengthCooperative
	p = mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{
		plane("inline", modeEnforce, false, override(effectWrite)), listed}}).Paths[0]
	if p.State != coverage.Decided || p.Basis != "planes inline, api" || p.Planes[0].State != coverage.Enforced || p.Planes[1].State != coverage.Decided {
		t.Fatalf("%v (%q) with %+v; want the inline plane enforced, the cooperative one decided, the path decided", p.State, p.Basis, p.Planes)
	}
}

// TestAPlaneOfNoStatedStrengthEnforcesNothing: a plane whose strength is the
// zero value, or a number no protocol has, decides what an inline plane in
// its mode would enforce, and says why.
func TestAPlaneOfNoStatedStrengthEnforcesNothing(t *testing.T) {
	for name, strength := range map[string]channel.Strength{"none": channel.StrengthNone, "undeclared": channel.Strength(9)} {
		pl := plane("bare", modeEnforce, false, override(effectWrite))
		pl.Strength = strength
		p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{pl}}).Paths[0]
		if p.State != coverage.Decided || len(p.Planes) != 1 || !strings.HasSuffix(p.Planes[0].Basis, "; no enforcement point holds the path") {
			t.Errorf("%s: %v with %+v; want decided, naming no enforcement point", name, p.State, p.Planes)
		}
	}
	if p := mustMap(t, coverage.Input{Inventory: toolInventory(t), Planes: []coverage.Plane{plane("inline", modeEnforce, false, override(effectWrite))}}).Paths[0]; p.State != coverage.Enforced {
		t.Errorf("an inline plane: %v, want enforced", p.State)
	}
}

// TestAPlaneCountsOnlyForAPathOfItsOwnKind: a cooperative plane classifies
// tools by name and an MCP plane by upstream, so neither stands in front of
// the other's path of the same tool name.
func TestAPlaneCountsOnlyForAPathOfItsOwnKind(t *testing.T) {
	inv := mustInventory(t, `{"schema_version":"0.1","paths":[`+
		`{"id":"mcp","kind":"mcp_tool","upstream":"github","tool":"create_issue"},`+
		`{"id":"api","kind":"enforce_tool","tool":"create_issue"},`+
		`{"id":"other","kind":"enforce_tool","tool":"refund"}]}`)
	r := mustMap(t, coverage.Input{Inventory: inv, Planes: []coverage.Plane{
		listing(plane("inline", modeEnforce, false, override(effectWrite)), "github"),
		cooperative("coop", modeEnforce, false, "create_issue"),
	}})
	want := map[string]struct {
		state coverage.State
		basis string
	}{
		"mcp":   {coverage.Enforced, "planes inline"},
		"api":   {coverage.Decided, "planes coop"},
		"other": {coverage.NotCovered, "no plane classifies it and no live source observed it"},
	}
	for _, p := range r.Paths {
		if w := want[p.Path.ID]; p.State != w.state || p.Basis != w.basis || len(p.Planes) > 1 {
			t.Errorf("%s: %v (%q) with %+v; want %v (%q) from one plane at most", p.Path.ID, p.State, p.Basis, p.Planes, w.state, w.basis)
		}
	}
}

// TestACooperativePlanePrintsWhatItRestsOn is the map as printed.
func TestACooperativePlanePrintsWhatItRestsOn(t *testing.T) {
	inv := mustInventory(t, `{"schema_version":"0.1","paths":[{"id":"refund","kind":"enforce_tool","tool":"refund"}]}`)
	r := mustMap(t, coverage.Input{Inventory: inv, Planes: []coverage.Plane{cooperative("api.yaml", modeEnforce, false, "refund")}})
	want := []string{
		"refund decided, not enforced: planes api.yaml",
		"  plane api.yaml: decided, not enforced: ENFORCE; " + cooperativeBasis,
		"  join: none checked: no source is named for it",
		coverage.UndeclaredRow,
	}
	if got := r.Lines(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestAnEnforceProposalJoinsAnEnforceToolPath: a proposal the enforcement
// API recorded for the tool joins the observation; a proposal of the same
// tool name from another protocol does not.
func TestAnEnforceProposalJoinsAnEnforceToolPath(t *testing.T) {
	cases := []struct {
		name string
		p    proposal
		want coverage.Join
	}{
		{"the enforcement API's proposal", proposal{trace: traceA, span: spanA, tool: "refund", upstream: "payments", protocol: channel.ProtocolEnforce}, coverage.Joined},
		{"an MCP proposal of the tool's name", proposal{trace: traceA, span: spanA, tool: "refund", upstream: "payments", protocol: "mcp"}, coverage.JoinAround},
		{"no protocol", proposal{trace: traceA, span: spanA, tool: "refund", upstream: "payments"}, coverage.JoinAround},
		{"another tool", proposal{trace: traceA, span: spanA, tool: "refunds", upstream: "payments", protocol: channel.ProtocolEnforce}, coverage.JoinAround},
		{"a prompt", proposal{trace: traceA, span: spanA, tool: "refund", kind: "prompt", protocol: channel.ProtocolEnforce}, coverage.JoinAround},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustMap(t, coverage.Input{
				Inventory: enforceInventory(t),
				Planes:    []coverage.Plane{withExport(cooperative("api", modeEnforce, false, "refund"), wholeExport(t, tc.p.line()))},
				Sources:   []coverage.Source{liveSource(selfReported, obs{id: "obs-a", name: "refund", trace: traceA, span: spanA}.record())},
			}).Paths[0]
			if p.State != coverage.Decided || len(p.Joins) != 1 || p.Joins[0].Join != tc.want {
				t.Fatalf("%v with joins %+v; want decided with one join %v", p.State, p.Joins, tc.want)
			}
		})
	}
}
