package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// supProcedure is the refund procedure: look the order up, refund it, then
// optionally mail the customer; searching the docs is allowed.
const supProcedure = `{"schema_version":"0.1","procedure_id":"refund","version":"1",` +
	`"steps":[` +
	`{"id":"lookup","tool":"get_order","upstream":"shop","observed_as":["get_order"],"required":true},` +
	`{"id":"refund","tool":"issue_refund","upstream":"pay","observed_as":["issue_refund"],"required":true},` +
	`{"id":"notify","tool":"send_mail","upstream":"mail","observed_as":["send_mail"],"required":false}],` +
	`"order":{"refund":["lookup"],"notify":["refund"]},` +
	`"allow":[{"tool":"search_docs","upstream":"docs","observed_as":["search_docs"]}],` +
	`"max_denials":4,"deadline_seconds":600,"rules":{` +
	`"REPEATED_DENIAL":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUTSIDE_PROCEDURE":{"severity":"medium","escalation":"alert"},` +
	`"DEADLINE_EXCEEDED":{"severity":"low","escalation":"inform"},` +
	`"REQUIRED_STEP_SKIPPED":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUT_OF_ORDER":{"severity":"medium","escalation":"inform"},` +
	`"CONTINUED_AFTER_FAILURE":{"severity":"critical","escalation":"alert"}}}`

// supProject is the project the plane recorded the run's events in.
const supProject = "orders"

// supTree is an owner-only directory with a runs directory, a procedure, a
// findings directory, and the run each test supervises, opened by runs open.
type supTree struct {
	dir, runs, procedure, findings, run string
}

func newSupTree(t *testing.T) supTree {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: an owner-only directory, which the owner must enter
		t.Fatal(err)
	}
	tr := supTree{dir: dir, runs: filepath.Join(dir, "runs"), procedure: filepath.Join(dir, "procedure.json"),
		findings: filepath.Join(dir, "findings")}
	for _, d := range []string{tr.runs, tr.findings} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, tr.procedure, supProcedure)
	tr.run = openRun(t, tr.runs, who, "1h").runID
	return tr
}

func (tr supTree) closeRun(t *testing.T, id string) {
	t.Helper()
	if code, _, stderr := invoke(t, "runs", "close", tr.runs, id); code != exitOK {
		t.Fatalf("runs close answered %d: %q", code, stderr)
	}
}

func (tr supTree) args(extra ...string) []string {
	return append([]string{"supervise", "--procedure", tr.procedure, "--runs", tr.runs, "--run", tr.run,
		"--findings", tr.findings}, extra...)
}

// supCall is one request's trail in the run: ok runs and completes it, deny
// is the policy's DENY. Its events are req-e1, req-e2, ... one second apart
// from at past base; broken links the last to an event never read.
type supCall struct {
	req, tool, upstream string
	at                  time.Duration
	deny, broken        bool
}

func (c supCall) events(run string, base time.Time) []*controlv1.Event {
	const (
		proposed  = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
		decided   = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
		started   = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
		completed = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
		blocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
	)
	kinds := []controlv1.EventKind{proposed, decided, started, completed}
	d := &controlv1.Decision{SchemaVersion: "1.0", DecisionId: c.req + "-k", RequestId: c.req,
		Verdict: controlv1.Verdict_VERDICT_ALLOW, ReasonCodes: []string{"RULE_ALLOW"}}
	if c.deny {
		kinds = []controlv1.EventKind{proposed, decided, blocked}
		d.Verdict, d.ReasonCodes = controlv1.Verdict_VERDICT_DENY, []string{"RULE_DENY"}
	}
	var out []*controlv1.Event
	prev := ""
	for i, kind := range kinds {
		ev := &controlv1.Event{
			EventId: fmt.Sprintf("%s-e%d", c.req, i+1), Kind: kind, RequestId: c.req, RunId: run,
			ProjectId: supProject, TenantId: who.TenantID, SchemaVersion: "1.0", PrevEventId: prev,
			OccurredAt:      timestamppb.New(base.Add(c.at + time.Duration(i)*time.Second)),
			EnforcementMode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		}
		switch kind {
		case proposed:
			ev.Payload = &controlv1.Event_Proposed{Proposed: &controlv1.ActionEnvelope{
				SchemaVersion: "1.0", RequestId: c.req, ProjectId: supProject, TenantId: who.TenantID,
				Action: &controlv1.Action{Name: c.tool, Provider: c.upstream, Kind: "tool"}}}
		case decided, blocked:
			ev.Payload = &controlv1.Event_Decision{Decision: d}
		case started, completed:
			ev.ExecutionId = c.req + "-x"
		}
		out = append(out, ev)
		prev = ev.EventId
	}
	if c.broken {
		out[len(out)-1].PrevEventId = c.req + "-e9"
	}
	return out
}

// supBase is when the fixture runs' events start: in the past, so a source
// heard at the same time was heard before its import report was received.
var supBase = time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)

// conformingCalls keep to the refund procedure.
func conformingCalls() []supCall {
	return []supCall{
		{req: "r1", tool: "get_order", upstream: "shop"},
		{req: "r2", tool: "issue_refund", upstream: "pay", at: 10 * time.Second},
		{req: "r3", tool: "send_mail", upstream: "mail", at: 20 * time.Second},
	}
}

// export writes a whole export of calls' events for run, at base, and
// returns its path.
func (tr supTree) export(t *testing.T, run string, base time.Time, calls ...supCall) string {
	t.Helper()
	return tr.exportRuns(t, base, runCalls{run: run, calls: calls})
}

// runCalls is calls made under one run.
type runCalls struct {
	run   string
	calls []supCall
}

// exportRuns writes a whole export of the events of each part's calls under
// its run, in order, at base, and returns its path.
func (tr supTree) exportRuns(t *testing.T, base time.Time, parts ...runCalls) string {
	t.Helper()
	lines := []string{fmt.Sprintf(`{"type":"header","format":%q,"version":"1.0","file":"gateway.trail",`+
		`"source":"57f7f9c13a3299681c3a7122a448585ec8e5984f4c854f0c3dd54b08c997e2a3","query":{"limit":1000}}`,
		brand.OTelNamespace+".evidence-export")}
	var events []*controlv1.Event
	for _, p := range parts {
		for _, c := range p.calls {
			events = append(events, c.events(p.run, base)...)
		}
	}
	for n, ev := range events {
		raw, err := protojson.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, fmt.Sprintf(`{"type":"event","offset":%d,"cursor":"c%d","event":%s}`, n, n, raw))
	}
	lines = append(lines, fmt.Sprintf(`{"type":"trailer","next_cursor":"c","end_reached":true,"tail_bytes":0,`+
		`"writer_held":false,"counts":{"event":%d,"gap":0,"duplicate":0},"scanned_bytes":0,"dedup_scope":"export"}`, len(events)))
	path := filepath.Join(tr.dir, "export.jsonl")
	writeFixture(t, path, strings.Join(lines, "\n")+"\n")
	return path
}

// supRefused runs the command and wants exit 2, nothing on stdout and one
// stderr line under the command's name holding each of names.
func supRefused(t *testing.T, args []string, names ...string) {
	t.Helper()
	code, stdout, stderr := invoke(t, args...)
	if code != 2 || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 2 and nothing printed", code, stdout, stderr)
	}
	line := oneStderrLine(t, stderr)
	for _, want := range append([]string{brand.CLI + ": supervise: "}, names...) {
		if !strings.Contains(line, want) {
			t.Errorf("stderr %q does not hold %q", line, want)
		}
	}
}

// supSpan is one OTLP/JSON line of the descriptor's service with one tool
// call named tool, claimed for run, ending at end.
const supSpan = `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"support-agent"}}]},` +
	`"scopeSpans":[{"scope":{"name":"agent-sdk","version":"1.0.0"},"schemaUrl":"https://opentelemetry.io/schemas/1.41.0","spans":[` +
	`{"traceId":"4bf92f3577b34da6a3ce929d0e0e4736","spanId":"00f067aa0ba90001","name":"span-1","kind":3,` +
	`"startTimeUnixNano":"%d","endTimeUnixNano":"%d","attributes":[` +
	`{"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},` +
	`{"key":"gen_ai.tool.name","value":{"stringValue":%q}},` +
	`{"key":"app.run_id","value":{"stringValue":%q}}],"status":{"code":1}}]}],` +
	`"schemaUrl":"https://opentelemetry.io/schemas/1.41.0"}]}` + "\n"

// source writes the test descriptor for the run's tenant and project, and an
// empty log directory, and returns both paths.
func (tr supTree) source(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/observe/descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.NewReplacer(`"tenant-a"`, fmt.Sprintf("%q", who.TenantID), `"project-a"`, fmt.Sprintf("%q", supProject)).Replace(string(raw))
	descriptor, log := filepath.Join(tr.dir, "source.json"), filepath.Join(tr.dir, "log")
	writeFixture(t, descriptor, body)
	if err := os.Mkdir(log, 0o700); err != nil {
		t.Fatal(err)
	}
	return descriptor, log
}

// observe imports one call of tool claimed for the run, ending at end.
func (tr supTree) observe(t *testing.T, descriptor, log, tool string, end time.Time) {
	t.Helper()
	input := filepath.Join(tr.dir, "spans.jsonl")
	writeFixture(t, input, fmt.Sprintf(supSpan, end.Add(-time.Second).UnixNano(), end.UnixNano(), tool, tr.run))
	if code, out, stderr := invoke(t, "observe", "import", "--source", descriptor, "--log", log, input); code != exitOK {
		t.Fatalf("import: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}
