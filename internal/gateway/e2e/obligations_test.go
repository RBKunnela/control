package e2e_test

import (
	"testing"

	"github.com/guardana/control/adapters/mcp"
)

// obligedCalls is a rule over reads, deletes and mail that attaches the
// obligations, written as JSON.
func obligedCalls(obligations string) string {
	return `{"id":"obliged-calls","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[` + obligations + `],` +
		`"when":{"action":{"effect":["READ","DELETE","COMMUNICATE"]}}}`
}

// TestTheEnvelopeChecksRunInThePipeline: read_only, restrict_resources and
// deny_external_sink, which the MCP adapter no longer declares, are applied
// by the pipeline behind it: a call that holds reaches the upstream once, and
// one that fails is the plane's DENY recorded as PROPOSED, DECIDED, BLOCKED,
// with the upstream never asked.
func TestTheEnvelopeChecksRunInThePipeline(t *testing.T) {
	cases := []struct {
		name       string
		obligation string
		tool       string
		args       map[string]any
		runs       bool
	}{
		{"read_only on a read", `{"type":"read_only"}`, toolRead, map[string]any{"path": "/x"}, true},
		{"read_only on a delete", `{"type":"read_only"}`, toolDelete, map[string]any{"path": "/x"}, false},
		{"restrict_resources under the prefix", `{"type":"restrict_resources","params":{"prefix":"/srv/data/"}}`, toolRead, map[string]any{"path": "/srv/data/x"}, true},
		{"restrict_resources past the prefix", `{"type":"restrict_resources","params":{"prefix":"/srv/data/"}}`, toolRead, map[string]any{"path": "/srv/data/../etc/passwd"}, false},
		{"deny_external_sink on mail outside", `{"type":"deny_external_sink"}`, toolMail, map[string]any{"to": "x@example.com"}, false},
		{"deny_external_sink on an unstated zone", `{"type":"deny_external_sink"}`, toolRead, map[string]any{"path": "/x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPlane(t, options{kind: mcp.KindStatelessHTTP, mode: modeEnforce, rules: []string{obligedCalls(tc.obligation)}})
			agent := p.connect(t, "agent-a")
			res := call(t, agent, tc.tool, tc.args)
			trail := p.oneTrail(t)
			if tc.runs {
				if res.IsError || p.victim.ran() != 1 {
					t.Fatalf("a call the check holds for: %+v, the upstream ran %d times", res.StructuredContent, p.victim.ran())
				}
				expectTrail(t, trail, kindProposed, kindDecided, kindStarted, kindCompleted)
				return
			}
			blockedWith(t, res, codeObligationsUnmet)
			if n := p.victim.ran(); n != 0 {
				t.Fatalf("the upstream ran %d times for a call the check fails", n)
			}
			expectTrail(t, trail, kindProposed, kindDecided, kindBlocked)
			if pdp := eventOf(t, trail, kindBlocked).GetDecision().GetPdpType(); pdp != gatewayPDP {
				t.Errorf("the block is %q's, want the plane's", pdp)
			}
		})
	}
}
