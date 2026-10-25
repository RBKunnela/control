package runview_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	rootRun  = "run-0123456789abcdef0123456789abcdef"
	childRun = "run-11111111111111111111111111111111"
	tenant   = "t1"
	proj     = "p1"
)

var t0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

const rules01 = `"REPEATED_DENIAL":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUTSIDE_PROCEDURE":{"severity":"medium","escalation":"alert"},` +
	`"DEADLINE_EXCEEDED":{"severity":"low","escalation":"inform"},` +
	`"REQUIRED_STEP_SKIPPED":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUT_OF_ORDER":{"severity":"medium","escalation":"inform"},` +
	`"CONTINUED_AFTER_FAILURE":{"severity":"critical","escalation":"alert"}`

// refund01 is the refund procedure: look the order up, refund it, then
// optionally mail the customer; searching the docs is allowed.
const refund01 = `{"schema_version":"0.1","procedure_id":"refund","version":"1","steps":[` +
	`{"id":"lookup","tool":"get_order","upstream":"shop","observed_as":["get_order"],"required":true},` +
	`{"id":"refund","tool":"issue_refund","upstream":"pay","observed_as":["issue_refund"],"required":true},` +
	`{"id":"notify","tool":"send_mail","upstream":"mail","observed_as":["send_mail"],"required":false}],` +
	`"order":{"refund":["lookup"],"notify":["refund"]},` +
	`"allow":[{"tool":"search_docs","upstream":"docs","observed_as":["search_docs"]}],` +
	`"max_denials":4,"deadline_seconds":600,"rules":{` + rules01 + `}}`

// refund02 is refund under 0.2: the order and the customer are bound, an
// approved manual refund is an exception, and children are inherited.
const refund02 = `{"schema_version":"0.2","procedure_id":"refund","version":"2",` +
	`"bindings":{"order":"shop_order","customer":"crm_customer"},"steps":[` +
	`{"id":"lookup","tool":"get_order","upstream":"shop","observed_as":["get_order"],"required":true,"binds":["order"]},` +
	`{"id":"refund","tool":"issue_refund","upstream":"pay","observed_as":["issue_refund"],"required":true,"binds":["order"]},` +
	`{"id":"notify","tool":"send_mail","upstream":"mail","observed_as":[],"required":false,"binds":["customer"]}],` +
	`"order":{"refund":["lookup"],"notify":["refund"]},` +
	`"allow":[{"tool":"search_docs","upstream":"docs","observed_as":["search_docs"],"binds":[]}],` +
	`"exceptions":[{"id":"manual_refund_approved","waives":"STEP_OUTSIDE_PROCEDURE","tool":"refund_manual",` +
	`"upstream":"pay","condition":{"approval":"granted"}}],` +
	`"children":"inherit","max_denials":4,"deadline_seconds":600,"rules":{` + rules01 + `,` +
	`"RESOURCE_OUTSIDE_RUN":{"severity":"critical","escalation":"alert"},` +
	`"DENIED_ACTION_RETRIED_ARGUMENTS":{"severity":"medium","escalation":"inform"},` +
	`"DENIED_ACTION_RETRIED_RESOURCE":{"severity":"high","escalation":"alert"},` +
	`"DENIED_ACTION_RETRIED_AROUND":{"severity":"low","escalation":"inform"},` +
	`"EXCEPTION_TAKEN":{"severity":"info","escalation":"inform"}}}`

// call is one request's trail: its events are req-e1, req-e2, ... one
// second apart from at, in run, recorded by a plane in mode, its action of
// protocol.
type call struct {
	req, tool, upstream, run string
	protocol                 string
	at                       time.Duration
	// outcome is "" for completed, or deny, pause, fail or approved.
	outcome string
	res     *controlv1.Resource
	hash    string
	mode    controlv1.EnforcementMode
	untimed bool
}

func decision(id, req string, v controlv1.Verdict, codes ...string) *controlv1.Decision {
	return &controlv1.Decision{SchemaVersion: "1.0", DecisionId: id, RequestId: req, Verdict: v, ReasonCodes: codes}
}

const (
	proposed  = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	decided   = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	requested = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
	answered  = controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED
	started   = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	completed = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	failed    = controlv1.EventKind_EVENT_KIND_ACTION_FAILED
	blocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
)

// trail is the kinds of the call's outcome, the kernel's decision and the
// decision a block carries.
func (c call) trail() ([]controlv1.EventKind, *controlv1.Decision, *controlv1.Decision) {
	k := c.req + "-k"
	allow := decision(k, c.req, controlv1.Verdict_VERDICT_ALLOW, "RULE_ALLOW")
	switch c.outcome {
	case "deny":
		d := decision(k, c.req, controlv1.Verdict_VERDICT_DENY, "RULE_DENY")
		return []controlv1.EventKind{proposed, decided, blocked}, d, d
	case "pause":
		return []controlv1.EventKind{proposed, decided, blocked}, allow,
			decision(c.req+"-p", c.req, controlv1.Verdict_VERDICT_DENY, "PAUSED")
	case "fail":
		return []controlv1.EventKind{proposed, decided, started, failed}, allow, nil
	case "approved":
		return []controlv1.EventKind{proposed, decided, requested, answered, started, completed},
			decision(k, c.req, controlv1.Verdict_VERDICT_REQUIRE_APPROVAL, "APPROVAL_REQUIRED"), nil
	}
	return []controlv1.EventKind{proposed, decided, started, completed}, allow, nil
}

func (c call) events() []*controlv1.Event {
	kinds, kernel, block := c.trail()
	run, mode := c.run, c.mode
	if run == "" {
		run = rootRun
	}
	if mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
	}
	out := make([]*controlv1.Event, 0, len(kinds))
	prev := ""
	for i, kind := range kinds {
		id := fmt.Sprintf("%s-e%d", c.req, i+1)
		ev := &controlv1.Event{EventId: id, Kind: kind, RequestId: c.req, RunId: run, ProjectId: proj, TenantId: tenant,
			OccurredAt: timestamppb.New(t0.Add(c.at + time.Duration(i)*time.Second)), SchemaVersion: "1.0",
			EnforcementMode: mode, PrevEventId: prev}
		if c.untimed {
			ev.OccurredAt = nil
		}
		switch kind {
		case proposed:
			env := &controlv1.ActionEnvelope{SchemaVersion: "1.0", RequestId: c.req, ProjectId: proj, TenantId: tenant,
				Action: &controlv1.Action{Kind: "tool", Name: c.tool, Provider: c.upstream, Protocol: c.protocol}, Resource: c.res}
			if c.hash != "" {
				env.Arguments = &controlv1.Arguments{CanonicalHash: c.hash}
			}
			ev.Payload = &controlv1.Event_Proposed{Proposed: env}
		case decided:
			ev.Payload = &controlv1.Event_Decision{Decision: kernel}
		case blocked:
			ev.Payload = &controlv1.Event_Decision{Decision: block}
		case answered:
			ev.Payload = &controlv1.Event_Approval{Approval: &controlv1.Approval{SchemaVersion: "1.0",
				ApprovalId: c.req + "-a", RequestId: c.req, State: controlv1.ApprovalState_APPROVAL_STATE_APPROVED, ApproverId: "ops"}}
		case started, completed, failed:
			ev.ExecutionId = c.req + "-x"
		}
		out = append(out, ev)
		prev = id
	}
	return out
}

// export is one whole export of the calls' trails, in order.
func export(calls ...call) supervise.Export {
	x := supervise.Export{Whole: true}
	for _, c := range calls {
		x.Events = append(x.Events, c.events()...)
	}
	return x
}

// report is a source's report of a tool call by name, claimed for run.
func report(id, name, run string, at time.Duration) *observev1.Observation {
	return &observev1.Observation{
		SchemaVersion: "0.1", ObservationId: id, TenantId: tenant, ProjectId: proj,
		Source:    &observev1.SourceRef{SourceId: "s1", Trust: observev1.Trust_TRUST_SELF_REPORTED},
		EventTime: timestamppb.New(t0.Add(at)), Stage: observev1.Stage_STAGE_COMPLETED,
		Subject: &observev1.Subject{Kind: observev1.SubjectKind_SUBJECT_KIND_TOOL, Name: name},
		Correlation: &observev1.Correlation{Basis: observev1.Basis_BASIS_CLAIMED, RunId: run,
			TraceId: "0af7651916cd43dd8448eb211c80319c"},
	}
}

// heard is source s1, heard an hour after t0, holding obs.
func heard(obs ...*observev1.Observation) supervise.Source {
	return supervise.Source{SourceID: "s1", Tenant: tenant, Project: proj, HeartbeatSeconds: 300, LastHeard: t0.Add(time.Hour), Heard: true, Observations: obs}
}

func order(id string) *controlv1.Resource {
	return &controlv1.Resource{Type: "shop_order", Id: id, TenantId: tenant, Environment: "prod"}
}

func hashOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// judge evaluates the input with doc as its procedure, the tree's first run
// supervised, or the closed root alone when tree is empty.
func judge(t *testing.T, doc string, in supervise.Input) (*supervise.Procedure, *supervise.Result) {
	t.Helper()
	p, err := supervise.ReadProcedure([]byte(doc))
	if err != nil {
		t.Fatalf("ReadProcedure: %v", err)
	}
	in.Procedure = p
	if len(in.Tree) == 0 {
		in.Tree = []supervise.Run{{ID: rootRun, Tenant: tenant, Closed: true}}
	}
	in.Run = in.Tree[0]
	res, err := supervise.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return p, res
}

// closedTree is the closed root and its closed child.
func closedTree() []supervise.Run {
	return []supervise.Run{{ID: rootRun, Tenant: tenant, Closed: true},
		{ID: childRun, Tenant: tenant, Parent: rootRun, Closed: true}}
}

// refundRun is a 0.1 run: lookup, three docs searches decided by a plane
// that enforces nothing, a call outside the procedure the policy denies,
// the refund, two more searches, and a tool outside the procedure only the
// runtime reported. The optional mail is never sent.
func refundRun(t *testing.T) (*supervise.Procedure, *supervise.Result) {
	t.Helper()
	observe := controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	return judge(t, refund01, supervise.Input{
		Exports: []supervise.Export{
			export(call{req: "r1", tool: "get_order", upstream: "shop"},
				call{req: "d1", tool: "delete_customer", upstream: "crm", at: 30 * time.Second, outcome: "deny"},
				call{req: "r2", tool: "issue_refund", upstream: "pay", at: 40 * time.Second},
				call{req: "p1", tool: "issue_refund", upstream: "pay", at: 50 * time.Second, outcome: "pause"}),
			export(call{req: "s1", tool: "search_docs", upstream: "docs", at: 5 * time.Second, mode: observe},
				call{req: "s2", tool: "search_docs", upstream: "docs", at: 10 * time.Second, mode: observe},
				call{req: "s3", tool: "search_docs", upstream: "docs", at: 15 * time.Second, mode: observe},
				call{req: "s4", tool: "search_docs", upstream: "docs", at: 60 * time.Second, mode: observe},
				call{req: "s5", tool: "search_docs", upstream: "docs", at: 70 * time.Second, mode: observe}),
		},
		Sources: []supervise.Source{heard(report("obs-1", "export_csv", rootRun, 90*time.Second))},
	})
}

// exceptionRun is a 0.2 tree under inherit: the root looks the order up
// and refunds it; the child refunds by hand with an approval, which the
// procedure's exception takes.
func exceptionRun(t *testing.T) (*supervise.Procedure, *supervise.Result) {
	t.Helper()
	return judge(t, refund02, supervise.Input{Tree: closedTree(), Exports: []supervise.Export{export(
		call{req: "r1", tool: "get_order", upstream: "shop", res: order("42")},
		call{req: "r2", tool: "issue_refund", upstream: "pay", at: 10 * time.Second, res: order("42")},
		call{req: "m1", tool: "refund_manual", upstream: "pay", at: 20 * time.Second, run: childRun, outcome: "approved"},
	)}})
}

// strayRun is a 0.2 tree under inherit: the root looks order 42 up and the
// policy denies its refund; the child retries the refund with other
// arguments, then looks up order 77, outside the run's order.
func strayRun(t *testing.T) (*supervise.Procedure, *supervise.Result) {
	t.Helper()
	return judge(t, refund02, supervise.Input{Tree: closedTree(), Exports: []supervise.Export{export(
		call{req: "r1", tool: "get_order", upstream: "shop", res: order("42")},
		call{req: "d1", tool: "issue_refund", upstream: "pay", at: 10 * time.Second, outcome: "deny", res: order("42"), hash: hashOf('a')},
		call{req: "r3", tool: "issue_refund", upstream: "pay", at: 20 * time.Second, run: childRun, res: order("42"), hash: hashOf('b')},
		call{req: "l2", tool: "get_order", upstream: "shop", at: 30 * time.Second, run: childRun, res: order("77")},
	)}})
}
