//go:build unix

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

const checkedBundleID = "checked-fixture"

// checkedDocument signs one rule of each envelope check: reads must be reads
// of o-1 to a trusted destination, notes must be reads, and mail may not
// leave the trusted zones.
const checkedDocument = `{"apiVersion":"agent-policy/v1alpha1",
  "bundle":{"id":"checked-fixture","version":"2026-11-04.1","serial":1,"maxStaleSeconds":600},
  "rules":[
    {"id":"checked-reads","effect":"ALLOW_WITH_OBLIGATIONS","when":{"action":{"effect":["READ"]}},
     "obligations":[{"type":"read_only"},{"type":"restrict_resources","params":{"ids":"o-1"}},{"type":"deny_external_sink"}]},
    {"id":"read-only-notes","effect":"ALLOW_WITH_OBLIGATIONS","when":{"action":{"effect":["WRITE"]}},
     "obligations":[{"type":"read_only"}]},
    {"id":"no-mail-out","effect":"ALLOW_WITH_OBLIGATIONS","when":{"action":{"effect":["COMMUNICATE"]}},
     "obligations":[{"type":"deny_external_sink"}]}
  ]}`

// checkedTool is one tool both listeners classify alike: its effect, its
// trust zone, and whether the resource id is read from /id.
type checkedTool struct {
	name, effect, zone string
	resource           bool
}

var checkedTools = []checkedTool{
	{"read_order", "READ", "TRUSTED_INTERNAL", true},
	{"write_note", "WRITE", "TRUSTED_INTERNAL", true},
	{"send_mail", "COMMUNICATE", "UNTRUSTED_EXTERNAL", true},
	{"list_orders", "READ", "TRUSTED_INTERNAL", false},
}

func (c checkedTool) keys(indent string) string {
	s := fmt.Sprintf("%seffect: %s\n%sresource_type: record\n%strust_zone: %s\n", indent, c.effect, indent, indent, c.zone)
	if c.resource {
		s += indent + "resource_from: /id\n"
	}
	return s
}

// checkedCall is one call and whether the checks hold for it.
type checkedCall struct {
	tool, id string
	runs     bool
	why      string
}

var checkedCalls = []checkedCall{
	{"read_order", "o-1", true, "every check holds"},
	{"read_order", "o-2", false, "restrict_resources: another id"},
	{"write_note", "n-1", false, "read_only: a write"},
	{"send_mail", "m-1", false, "deny_external_sink: an untrusted destination"},
	{"list_orders", "o-1", false, "restrict_resources: no resource id"},
}

// checkedConfig is the shared part of both planes' configurations.
func checkedConfig(t *testing.T, dir, collector string) string {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, "spool"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeBundle(t, filepath.Join(dir, "policy.bundle"), checkedDocument)
	return fmt.Sprintf(`mode: ENFORCE
project_id: %s
tenant_id: %s
environment: dev
health:
  address: 127.0.0.1:0
policy:
  bundle_id: %s
  bundle_file: policy.bundle
  key_id: %s
  public_key: %s
%sevidence:
  dir: spool
export:
  endpoint: %s
  allow_plaintext: true
  in_flight: 1
  linger: 5ms
`, runsProject, runsTenant, checkedBundleID, fixtureKeyID, fixturePublicKey(), freshnessKeys(t, dir, checkedBundleID), collector)
}

// serveChecked runs serve over config in this process until the test ends,
// and returns the address on the line that starts with ready.
func serveChecked(t *testing.T, config, ready string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out, done := &syncBuffer{}, make(chan int, 1)
	go func() { done <- serve(ctx, config, "", out, out) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the plane did not stop")
		}
	})
	return afterPrefix(waitFor(t, out, ready), ready)
}

// mcpCheckedRuns serves the document over stateless MCP and returns, per
// call, whether the upstream ran it.
func mcpCheckedRuns(t *testing.T, collector *acceptingCollector) []bool {
	t.Helper()
	dir := t.TempDir()
	clearProductEnvironment(t)
	tools := make([]*sdk.Tool, len(checkedTools))
	for i, c := range checkedTools {
		tools[i] = chaosTool(c.name)
	}
	upstream := newHTTPUpstream(t, answerEvery, tools...)
	doc := checkedConfig(t, dir, collector.url) + fmt.Sprintf(`listener:
  kind: stateless_http
  address: 127.0.0.1:0
  principal:
    id: %s
  agent:
    id: %s
upstreams:
  - name: orders
    endpoint: %s
    tenant_id: %s
    environment: dev
overrides:
`, runsPrincipal, runsAgent, upstream.url, runsTenant)
	for i, c := range checkedTools {
		fp, err := adaptermcp.Fingerprint(tools[i])
		if err != nil {
			t.Fatal(err)
		}
		doc += fmt.Sprintf("  - upstream: orders\n    tool: %s\n    fingerprint: %s\n%s", c.name, fp, c.keys("    "))
	}
	config := filepath.Join(dir, "plane.yaml")
	if err := os.WriteFile(config, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	agent := connectAgent(t, serveChecked(t, config, "listening for agents on "))
	out := make([]bool, len(checkedCalls))
	for i, c := range checkedCalls {
		before := upstream.count(c.tool)
		res, err := chaosCall(t, agent, chaosTool(c.tool), c.id)
		if err != nil {
			t.Fatalf("MCP %s %s: %v", c.tool, c.id, err)
		}
		out[i] = !res.IsError && upstream.count(c.tool) == before+1
		if res.IsError && upstream.count(c.tool) != before {
			t.Errorf("MCP %s %s was refused and reached the upstream", c.tool, c.id)
		}
	}
	return out
}

// enforceCheckedRuns serves the document over the enforcement API and
// returns, per call, whether the plane answered EXECUTE; each execution is
// completed with the authorized bytes.
func enforceCheckedRuns(t *testing.T, collector *acceptingCollector) []bool {
	t.Helper()
	dir := t.TempDir()
	clearProductEnvironment(t)
	tr := newEnforceTree(t, "1m", collector.url)
	doc := checkedConfig(t, dir, collector.url) + fmt.Sprintf(`listener:
  kind: enforce_api
  socket: %s
  execution_lifetime: 1m
  principal:
    id: %s
  agent:
    id: %s
runs:
  dir: %s
tools:
`, tr.socket, runsPrincipal, runsAgent, tr.runs)
	for _, c := range checkedTools {
		doc += fmt.Sprintf("  - name: %s\n    provider: orders\n%s", c.name, c.keys("    "))
	}
	config := filepath.Join(dir, "plane.yaml")
	if err := os.WriteFile(config, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	token := tr.openRun(t)
	serveChecked(t, config, "listening for tools on ")
	client := newRawClient(t, tr.socket, token)
	out := make([]bool, len(checkedCalls))
	for i, c := range checkedCalls {
		args := []byte(`{"id":"` + c.id + `"}`)
		resp := client.admit(c.tool, args)
		switch resp.GetOutcome() {
		case enforcev1alpha1.Outcome_OUTCOME_EXECUTE:
			if obl := resp.GetExecution().GetObligations(); len(obl) != 0 {
				t.Errorf("enforce %s %s was handed obligations to apply: %v", c.tool, c.id, obl)
			}
			if ending := client.complete(resp.GetExecution().GetHandle(), resp.GetExecution().GetAuthorizedArguments()); ending != enforcev1alpha1.Ending_ENDING_RECORDED {
				t.Errorf("enforce %s %s completed as %v", c.tool, c.id, ending)
			}
			out[i] = true
		case enforcev1alpha1.Outcome_OUTCOME_BLOCK:
		default:
			t.Fatalf("enforce %s %s was answered %v", c.tool, c.id, resp.GetOutcome())
		}
	}
	return out
}

// checkedTrail is the shape of one recorded call: its kinds, and the codes
// and enforcement point of the decision that blocked it.
type checkedTrail struct {
	kinds []controlv1.EventKind
	codes []string
	pdp   string
}

func checkedTrails(t *testing.T, collector *acceptingCollector) []checkedTrail {
	t.Helper()
	collector.waitUntil(t, "every call's closed trail", allClosed(len(checkedCalls)))
	events := collector.events(t)
	validChains(t, events)
	out := make([]checkedTrail, len(checkedCalls))
	for i, c := range checkedCalls {
		id := c.id
		if c.tool == "list_orders" {
			id = ""
		}
		trail := trailOfTool(t, events, c.tool, id)
		for _, e := range trail {
			out[i].kinds = append(out[i].kinds, e.GetKind())
		}
		if last := trail[len(trail)-1]; last.GetKind() == kindBlocked {
			out[i].codes, out[i].pdp = last.GetDecision().GetReasonCodes(), last.GetDecision().GetPdpType()
		}
	}
	return out
}

// TestTheEnvelopeChecksDecideAlikeOnEveryListener: one signed rule of each
// of read_only, restrict_resources and deny_external_sink gives the same
// verdict and the same trail on stateless MCP and on the enforcement API. The
// enforcement API runs the call every check holds for, which it denied while
// only the MCP adapter applied these types, and blocks each one a check fails,
// a tool with no resource_from among them.
func TestTheEnvelopeChecksDecideAlikeOnEveryListener(t *testing.T) {
	mcpCollector, enforceCollector := newAcceptingCollector(t), newAcceptingCollector(t)
	mcpRuns := mcpCheckedRuns(t, mcpCollector)
	enforceRuns := enforceCheckedRuns(t, enforceCollector)
	mcpTrails, enforceTrails := checkedTrails(t, mcpCollector), checkedTrails(t, enforceCollector)
	ranTrail := []controlv1.EventKind{kProposed, kDecided, kindStarted, kindCompleted}
	blockedTrail := []controlv1.EventKind{kProposed, kDecided, kindBlocked}
	for i, c := range checkedCalls {
		if mcpRuns[i] != c.runs || enforceRuns[i] != c.runs {
			t.Errorf("%s %s (%s): MCP ran it %t, the enforcement API %t; want %t", c.tool, c.id, c.why, mcpRuns[i], enforceRuns[i], c.runs)
		}
		want := checkedTrail{kinds: ranTrail}
		if !c.runs {
			want = checkedTrail{kinds: blockedTrail, codes: []string{"OBLIGATION_NOT_UNDERSTOOD"}, pdp: "gateway"}
		}
		for name, got := range map[string]checkedTrail{"MCP": mcpTrails[i], "the enforcement API": enforceTrails[i]} {
			if !slices.Equal(got.kinds, want.kinds) || !slices.Equal(got.codes, want.codes) || got.pdp != want.pdp {
				t.Errorf("%s %s (%s) on %s: trail %v, block %v by %q; want %v, %v by %q",
					c.tool, c.id, c.why, name, got.kinds, got.codes, got.pdp, want.kinds, want.codes, want.pdp)
			}
		}
	}
}
