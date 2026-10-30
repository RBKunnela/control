package mcp_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// readOneFile allows a read of /allowed alone. A listing previews a tool with
// no arguments, so the rule's match is unknown there. denySlow denies the
// slow tool whatever its call carries.
const (
	readOneFile = `{"id":"read-one-file","effect":"ALLOW","when":{"action":{"effect":["READ"]},"resource":{"id":["/allowed"]}}}`
	denySlow    = `{"id":"deny-slow","effect":"DENY","when":{"action":{"name":["slow"]}}}`
)

// TestAToolOnlyItsCallCanDecideStaysListed: a read the policy allows for one
// resource id is listed and marked DECIDED_PER_CALL, not hidden as a DENY,
// while a tool a DENY rule matches beside the same unknown ALLOW is hidden.
// The call that names the allowed id runs, and one that names another is
// denied for no matching rule.
func TestAToolOnlyItsCallCanDecideStaysListed(t *testing.T) {
	rules := []string{readOneFile, denySlow, denyMail}
	hide := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, mode: modeEnforce, rules: rules})
	agent := hide.connect(t, "agent-a")
	names := toolNames(listTools(t, agent))
	if !slices.Contains(names, "read_file") || slices.Contains(names, "slow") || slices.Contains(names, "send_mail") {
		t.Errorf("hide: tools %s, want read_file and neither slow nor send_mail", strings.Join(names, ","))
	}

	expectMarks(t, newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeAnnotate, mode: modeEnforce, rules: rules}),
		map[string]string{"read_file": "DECIDED_PER_CALL", "slow": "VERDICT_DENY", "send_mail": "VERDICT_DENY"})

	if res, err := callTool(t, agent, "read_file", map[string]any{"path": "/allowed"}); err != nil || res.IsError {
		t.Fatalf("a read of /allowed: %v %+v", err, res)
	}
	res, err := callTool(t, agent, "read_file", map[string]any{"path": "/other"})
	if err != nil || !res.IsError || !slices.Equal(codesOf(t, res), []string{"NO_MATCHING_RULE"}) {
		t.Fatalf("a read of /other: %v %+v", err, res)
	}
	if n := hide.victim.count("read_file"); n != 1 {
		t.Errorf("the upstream ran read_file %d times, want once", n)
	}
}

// expectMarks lists the tools on r and holds each tool want names to its mark.
func expectMarks(t *testing.T, r *rig, want map[string]string) {
	t.Helper()
	for _, tool := range listTools(t, r.connect(t, "agent-a")).Tools {
		if w, ok := want[tool.Name]; ok && tool.Meta[metaVerdict] != w {
			t.Errorf("annotate: %s carries %v, want %s", tool.Name, tool.Meta[metaVerdict], w)
		}
	}
}

// TestTheListingIsThePipelinesWord: shaping reads the preview's listing, never
// its verdict. The zero listing shows every classified tool and marks it
// DECIDED_PER_CALL, even under a DENY; a denied listing hides the tool even
// under an ALLOW.
func TestTheListingIsThePipelinesWord(t *testing.T) {
	classified := "delete_file,read_file,send_mail,slow,transfer"
	for _, c := range []struct {
		name    string
		preview gateway.Previewed
		hidden  string
	}{
		{"the zero listing under a DENY", gateway.Previewed{Decision: decision(controlv1.Verdict_VERDICT_DENY, "NO_MATCHING_RULE")}, classified},
		{"a denied listing under an ALLOW", gateway.Previewed{Decision: decision(controlv1.Verdict_VERDICT_ALLOW), Listing: gateway.ListingDenied}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide})
			r.pipe.preview = func(gateway.Admission) gateway.Previewed { return c.preview }
			if got := strings.Join(toolNames(listTools(t, r.connect(t, "agent-a"))), ","); got != c.hidden {
				t.Errorf("hide: tools %q, want %q", got, c.hidden)
			}
		})
	}
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeAnnotate})
	r.pipe.preview = func(gateway.Admission) gateway.Previewed {
		return gateway.Previewed{Decision: decision(controlv1.Verdict_VERDICT_DENY, "NO_MATCHING_RULE")}
	}
	for _, tool := range listTools(t, r.connect(t, "agent-a")).Tools {
		want := "DECIDED_PER_CALL"
		if tool.Name == "unlisted" {
			want = "ACTION_UNCLASSIFIED"
		}
		if tool.Meta[metaVerdict] != want {
			t.Errorf("annotate: %s carries %v, want %s", tool.Name, tool.Meta[metaVerdict], want)
		}
	}
}

// readFileOnly confines a constraint to read_file, so the other tools of the
// rig are decided as no rule matching them.
func readFileOnly(when string) string {
	return `{"action":{"name":["read_file"]},` + when + `}`
}

// noResourceFrom is the rig's manifest with read_file classified without a
// pointer, so no call to it carries a resource id.
func noResourceFrom(v *victim, t *testing.T) []mcp.Override {
	o := v.overrides(t)
	for i := range o {
		if o[i].Tool == "read_file" {
			o[i].ResourceFrom = ""
		}
	}
	return o
}

// TestAListingKeepsOnlyWhatACallCouldBeAllowed: a tool whose preview is the
// DENY of no matching rule stays listed only when an ALLOW rule's every
// unknown input is one a call to it brings: the resource id its pointer reads,
// or its run's flow. An input the listener fixes, the principal's
// authentication strength or attributes, one no MCP call carries, labels, a
// host, a delegation or data labels, or a resource id with no pointer to read
// it from, leaves every call denied, and the tool out.
func TestAListingKeepsOnlyWhatACallCouldBeAllowed(t *testing.T) {
	const allowID = `"resource":{"id":["/allowed"]}`
	rule := func(id, when string) string {
		return `{"id":"` + id + `","effect":"ALLOW","when":` + readFileOnly(when) + `}`
	}
	for _, c := range []struct {
		name      string
		rules     []string
		overrides func(*victim, *testing.T) []mcp.Override
		shown     bool
	}{
		{"authnStrength", []string{rule("mfa", `"principal":{"authnStrength":["mfa"]}`)}, nil, false},
		{"principal attributes", []string{rule("ops", `"principal":{"attributes":{"team":["ops"]}}`)}, nil, false},
		{"resource labels", []string{rule("labelled", `"resource":{"labels":{"approved":["yes"]}}`)}, nil, false},
		{"destination host", []string{rule("host", `"destination":{"host":["api.example"]}`)}, nil, false},
		{"delegation scopes", []string{rule("scoped", `"delegation":{"scopes":["files.read"]}`)}, nil, false},
		{"data sensitivity", []string{rule("labelled-data", `"data":{"sensitivityAtLeast":"INTERNAL"}`)}, nil, false},
		{"resource id with a pointer", []string{rule("one-file", allowID)}, nil, true},
		{"resource id without a pointer", []string{rule("one-file", allowID)}, noResourceFrom, false},
		{"the run's flow", []string{rule("flowing", `"flow":{"toxicAtLeast":"CONFIDENTIAL"}`)}, nil, true},
		{"resource id and authnStrength in one rule",
			[]string{rule("both", allowID+`,"principal":{"authnStrength":["mfa"]}`)}, nil, false},
		{"beside it, a rule on the resource id alone",
			[]string{rule("both", allowID+`,"principal":{"authnStrength":["mfa"]}`), rule("one-file", allowID)}, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			hide := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, mode: modeEnforce, rules: c.rules, overrides: c.overrides})
			if got := slices.Contains(toolNames(listTools(t, hide.connect(t, "agent-a"))), "read_file"); got != c.shown {
				t.Errorf("hide lists read_file: %t, want %t", got, c.shown)
			}
			mark := "VERDICT_DENY"
			if c.shown {
				mark = "DECIDED_PER_CALL"
			}
			expectMarks(t, newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeAnnotate, mode: modeEnforce, rules: c.rules, overrides: c.overrides}),
				map[string]string{"read_file": mark})
		})
	}
}
