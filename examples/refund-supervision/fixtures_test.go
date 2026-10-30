package refundsupervision

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/ingest"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/supervise"
)

// The 0.2 procedure and the cases procedure test runs over it.
const (
	procedure02 = "refund-0.2.procedure.json"
	casesFile   = "refund-0.2.cases.json"
)

// TestTheExamplesFilesAgree: the procedure and the source descriptor are
// read by the readers supervise and observe import use, each step names a
// tool the plane classifies on the upstream it names, and the descriptor's
// tenant and project are the plane's, without which every observation would
// be left out of the run as another tenant's or project's.
func TestTheExamplesFilesAgree(t *testing.T) {
	t.Parallel()
	plane := readFile(t, "plane.yaml")
	raw := readFile(t, "refund.procedure.json")
	p, err := supervise.ReadProcedure([]byte(raw))
	if err != nil {
		t.Fatalf("the procedure is refused: %v", err)
	}
	if len(p.Steps()) != 2 {
		t.Fatalf("the procedure has %d steps, want 2", len(p.Steps()))
	}
	for _, s := range p.Steps() {
		classified := regexp.MustCompile(`(?m)^  - upstream: ` + regexp.QuoteMeta(s.Upstream) +
			`\n    tool: ` + regexp.QuoteMeta(s.Tool) + `\n`)
		if !classified.MatchString(plane) {
			t.Errorf("step %s names %s on %s, which plane.yaml does not classify", s.ID, s.Tool, s.Upstream)
		}
	}
	d, err := ingest.ReadDescriptor([]byte(readFile(t, "runtime.source.json")))
	if err != nil {
		t.Fatalf("the source descriptor is refused: %v", err)
	}
	for _, want := range []string{"tenant_id: " + d.GetTenantId() + "\n", "project_id: " + d.GetProjectId() + "\n"} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(want)).MatchString(plane) {
			t.Errorf("plane.yaml has no top-level %q, which the descriptor names", want)
		}
	}
	if d.GetRunAttribute() == "" {
		t.Error("the descriptor names no run attribute, so no observation could claim the run")
	}
}

// liftPlaceholder is the line of route.json the lift key's public line takes.
const liftPlaceholder = "LIFT_PUBLIC_KEY_FROM_KEYGEN"

// TestTheRouteAllowsOnlyTheRulesThatStop: route.json, its lift key filled
// in, is read by the reader route sign uses, names the plane's tenant, and
// allows two rules, each the one a confirmed finding of the example raises
// under the digest supervise gives its procedure: REPEATED_DENIAL of the 0.1
// procedure and DENIED_ACTION_RETRIED_RESOURCE of the 0.2 one. A route under
// any other digest stops nothing.
func TestTheRouteAllowsOnlyTheRulesThatStop(t *testing.T) {
	t.Parallel()
	doc := readFile(t, "route.json")
	if n := strings.Count(doc, liftPlaceholder); n != 1 {
		t.Fatalf("route.json holds %s %d times, want once", liftPlaceholder, n)
	}
	lift := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4c}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	r, err := reaction.ParseRoute([]byte(strings.Replace(doc, liftPlaceholder, base64.StdEncoding.EncodeToString(lift), 1)))
	if err != nil {
		t.Fatalf("the route is refused: %v", err)
	}
	var want []reaction.Rule
	for file, rule := range map[string]string{"refund.procedure.json": "REPEATED_DENIAL", procedure02: "DENIED_ACTION_RETRIED_RESOURCE"} {
		p, err := supervise.ReadProcedure([]byte(readFile(t, file)))
		if err != nil {
			t.Fatalf("%s is refused: %v", file, err)
		}
		version, ok := supervise.RuleVersionOf(rule)
		if !ok || !supervise.MayStop(rule) {
			t.Fatalf("%s is no rule that may stop a run", rule)
		}
		want = append(want, reaction.Rule{ProcedureID: p.ID(), ProcedureVersion: p.Version(), ProcedureDigest: p.Digest(),
			RuleID: rule, RuleVersion: version})
	}
	byVersion := func(a, b reaction.Rule) int { return strings.Compare(a.ProcedureVersion, b.ProcedureVersion) }
	slices.SortFunc(want, byVersion)
	got := r.Rules()
	slices.SortFunc(got, byVersion)
	if !slices.Equal(got, want) {
		t.Errorf("the route's rules are %+v, want only %+v", got, want)
	}
	if !regexp.MustCompile(`(?m)^tenant_id: ` + regexp.QuoteMeta(r.TenantID()) + "\n").MatchString(readFile(t, "plane.yaml")) {
		t.Errorf("plane.yaml has no top-level tenant_id %q, which the route names", r.TenantID())
	}
}

// TestTheProcedure02AgreesWithThePlane: every tool the 0.2 procedure names,
// as a step, an allowed tool or an exception's, is one plane.yaml classifies
// on that upstream, so none is blocked as unclassified; a tool that binds a
// resource gets the binding's resource type from the plane, without which
// RESOURCE_OUTSIDE_RUN would see no id. The cases document tests this
// procedure.
func TestTheProcedure02AgreesWithThePlane(t *testing.T) {
	t.Parallel()
	plane := readFile(t, "plane.yaml")
	raw := readFile(t, procedure02)
	p, err := supervise.ReadProcedure([]byte(raw))
	if err != nil {
		t.Fatalf("the procedure is refused: %v", err)
	}
	if p.Schema() != supervise.ProcedureSchema02 || len(p.Steps()) != 2 || len(p.Exceptions()) != 1 {
		t.Fatalf("the procedure is schema %s with %d steps and %d exceptions, want 0.2 with 2 and 1",
			p.Schema(), len(p.Steps()), len(p.Exceptions()))
	}
	types := map[string]string{}
	for _, b := range p.Bindings() {
		types[b.Name] = b.ResourceType
	}
	for _, tool := range namedTools(t, raw, p) {
		block := regexp.MustCompile(`(?m)^  - upstream: ` + regexp.QuoteMeta(tool[1]) + `\n    tool: ` + regexp.QuoteMeta(tool[0]) +
			`\n((?:    .*\n)*)`).FindStringSubmatch(plane)
		binding, binds := p.BindingOf(tool[0], tool[1])
		switch {
		case block == nil:
			t.Errorf("the procedure names %s on %s, which plane.yaml does not classify", tool[0], tool[1])
		case binds && !strings.Contains(block[1], "    resource_type: "+types[binding]+"\n"):
			t.Errorf("%s binds %s, of type %q, which plane.yaml does not give it:\n%s", tool[0], binding, types[binding], block[1])
		}
	}
	var cases struct {
		Procedure string `json:"procedure"`
	}
	if err := json.Unmarshal([]byte(readFile(t, casesFile)), &cases); err != nil || cases.Procedure != procedure02 {
		t.Errorf("%s tests %q, want %s: %v", casesFile, cases.Procedure, procedure02, err)
	}
}

// namedTools is each tool and upstream the 0.2 procedure names: its steps,
// its one allowed tool, read from the document, and its exceptions' tools.
func namedTools(t *testing.T, raw string, p *supervise.Procedure) [][2]string {
	t.Helper()
	var doc struct {
		Allow []struct{ Tool, Upstream string } `json:"allow"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil || len(doc.Allow) != 1 {
		t.Fatalf("the procedure's allow list is %+v, want one tool: %v", doc.Allow, err)
	}
	tools := [][2]string{{doc.Allow[0].Tool, doc.Allow[0].Upstream}}
	for _, s := range p.Steps() {
		tools = append(tools, [2]string{s.Tool, s.Upstream})
	}
	for _, x := range p.Exceptions() {
		tools = append(tools, [2]string{x.Tool, x.Upstream})
	}
	return tools
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name) //nolint:gosec // G304: this package's own file
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
