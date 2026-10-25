package supervise_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	runID  = "run-0123456789abcdef0123456789abcdef"
	tenant = "t1"
	proj   = "p1"
	traceA = "0af7651916cd43dd8448eb211c80319c"
)

var t0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

func at(d time.Duration) *timestamppb.Timestamp { return timestamppb.New(t0.Add(d)) }

const rulesJSON = `{` +
	`"REPEATED_DENIAL":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUTSIDE_PROCEDURE":{"severity":"medium","escalation":"alert"},` +
	`"DEADLINE_EXCEEDED":{"severity":"low","escalation":"inform"},` +
	`"REQUIRED_STEP_SKIPPED":{"severity":"high","escalation":"alert"},` +
	`"STEP_OUT_OF_ORDER":{"severity":"medium","escalation":"inform"},` +
	`"CONTINUED_AFTER_FAILURE":{"severity":"critical","escalation":"alert"}}`

// procJSON is the refund procedure: look the order up, refund it, then
// optionally mail the customer; searching the docs is allowed.
const procJSON = `{"schema_version":"0.1","procedure_id":"refund","version":"1",` +
	`"steps":[` +
	`{"id":"lookup","tool":"get_order","upstream":"shop","observed_as":["get_order"],"required":true},` +
	`{"id":"refund","tool":"issue_refund","upstream":"pay","observed_as":["issue_refund"],"required":true},` +
	`{"id":"notify","tool":"send_mail","upstream":"mail","observed_as":["send_mail"],"required":false}],` +
	`"order":{"refund":["lookup"],"notify":["refund"]},` +
	`"allow":[{"tool":"search_docs","upstream":"docs","observed_as":["search_docs"]}],` +
	`"max_denials":4,"deadline_seconds":600,"rules":` + rulesJSON + `}`

// procWith is procJSON with each pair of old and new text replaced once.
func procWith(t *testing.T, pairs ...string) *supervise.Procedure {
	t.Helper()
	doc := procJSON
	for i := 0; i+1 < len(pairs); i += 2 {
		if !strings.Contains(doc, pairs[i]) {
			t.Fatalf("procedure fixture holds no %q", pairs[i])
		}
		doc = strings.Replace(doc, pairs[i], pairs[i+1], 1)
	}
	p, err := supervise.ReadProcedure([]byte(doc))
	if err != nil {
		t.Fatalf("ReadProcedure: %v", err)
	}
	return p
}

// call is one request's trail. Its events are req-e1, req-e2, ... one second
// apart from at; its kernel decision is req-k and a plane's own is req-p. Its
// action is a tool call unless kind names another.
type call struct {
	req, tool, upstream string
	kind                string
	at                  time.Duration
	outcome             string
	run, tenant, proj   string
	span                string
}

func pick(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func decision(id, req string, v controlv1.Verdict, codes ...string) *controlv1.Decision {
	return &controlv1.Decision{SchemaVersion: "1.0", DecisionId: id, RequestId: req, Verdict: v, ReasonCodes: codes}
}

// kinds is the trail of each outcome: its kinds, the kernel's decision and
// the decision the block carries, if any.
func (c call) kinds() ([]controlv1.EventKind, *controlv1.Decision, *controlv1.Decision) {
	k, p := c.req+"-k", c.req+"-p"
	const (
		proposed  = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
		decided   = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
		requested = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
		expired   = controlv1.EventKind_EVENT_KIND_APPROVAL_EXPIRED
		started   = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
		completed = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
		failed    = controlv1.EventKind_EVENT_KIND_ACTION_FAILED
		blocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
	)
	allow := decision(k, c.req, controlv1.Verdict_VERDICT_ALLOW, "RULE_ALLOW")
	approval := decision(k, c.req, controlv1.Verdict_VERDICT_REQUIRE_APPROVAL, "APPROVAL_REQUIRED")
	switch c.outcome {
	case "fail":
		return []controlv1.EventKind{proposed, decided, started, failed}, allow, nil
	case "deny":
		d := decision(k, c.req, controlv1.Verdict_VERDICT_DENY, "RULE_DENY")
		return []controlv1.EventKind{proposed, decided, blocked}, d, d
	case "pause":
		return []controlv1.EventKind{proposed, decided, blocked}, allow,
			decision(p, c.req, controlv1.Verdict_VERDICT_DENY, "PAUSED")
	case "stopped":
		return []controlv1.EventKind{proposed, decided, blocked},
			decision(k, c.req, controlv1.Verdict_VERDICT_DENY, "RULE_DENY"),
			decision(p, c.req, controlv1.Verdict_VERDICT_DENY, "RUN_STOPPED")
	case "denied and paused":
		return []controlv1.EventKind{proposed, decided, blocked},
			decision(k, c.req, controlv1.Verdict_VERDICT_DENY, "RULE_DENY"),
			decision(p, c.req, controlv1.Verdict_VERDICT_DENY, "RULE_DENY", "PAUSED")
	case "silent":
		d := decision(k, c.req, controlv1.Verdict_VERDICT_INDETERMINATE, "PDP_TIMEOUT")
		return []controlv1.EventKind{proposed, decided, blocked}, d, d
	case "expired":
		return []controlv1.EventKind{proposed, decided, requested, expired, blocked}, approval,
			decision(p, c.req, controlv1.Verdict_VERDICT_DENY, "APPROVAL_EXPIRED")
	case "held":
		return []controlv1.EventKind{proposed, decided, requested}, approval, nil
	}
	return []controlv1.EventKind{proposed, decided, started, completed}, allow, nil
}

func (c call) events() []*controlv1.Event {
	kinds, kernel, block := c.kinds()
	out := make([]*controlv1.Event, 0, len(kinds))
	prev := ""
	for i, kind := range kinds {
		id := c.req + "-e" + string(rune('1'+i))
		ev := &controlv1.Event{
			EventId: id, Kind: kind, RequestId: c.req, RunId: pick(c.run, runID),
			ProjectId: pick(c.proj, proj), TenantId: pick(c.tenant, tenant),
			OccurredAt: at(c.at + time.Duration(i)*time.Second), SchemaVersion: "1.0",
			EnforcementMode: controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, PrevEventId: prev,
		}
		c.payload(ev, kernel, block)
		out = append(out, ev)
		prev = id
	}
	return out
}

func (c call) payload(ev *controlv1.Event, kernel, block *controlv1.Decision) {
	switch ev.GetKind() {
	case controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED:
		ev.Payload = &controlv1.Event_Proposed{Proposed: &controlv1.ActionEnvelope{
			SchemaVersion: "1.0", RequestId: c.req, TraceId: traceA, SpanId: c.span,
			ProjectId: pick(c.proj, proj), TenantId: pick(c.tenant, tenant),
			Action: &controlv1.Action{Kind: pick(c.kind, "tool"), Name: c.tool, Provider: c.upstream},
		}}
	case controlv1.EventKind_EVENT_KIND_POLICY_DECIDED:
		ev.Payload = &controlv1.Event_Decision{Decision: kernel}
	case controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED:
		ev.Payload = &controlv1.Event_Decision{Decision: block}
	case controlv1.EventKind_EVENT_KIND_ACTION_STARTED, controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED,
		controlv1.EventKind_EVENT_KIND_ACTION_FAILED:
		ev.ExecutionId = c.req + "-x"
	}
}

// export is one whole export of calls' trails, in order.
func export(calls ...call) supervise.Export {
	var x supervise.Export
	for _, c := range calls {
		x.Events = append(x.Events, c.events()...)
	}
	x.Whole = true
	return x
}

// ob is one tool observation, claimed for runID in t1 and p1 by source s1.
type ob struct {
	id, source, name, tenant, proj, run string
	basis                               observev1.Basis
	kind                                observev1.SubjectKind
	stage                               observev1.Stage
	status                              observev1.Status
	span, parent                        string
	at                                  time.Duration
}

func (o ob) obs() *observev1.Observation {
	basis, kind, stage := o.basis, o.kind, o.stage
	if basis == observev1.Basis_BASIS_UNSPECIFIED {
		basis = observev1.Basis_BASIS_CLAIMED
	}
	if kind == observev1.SubjectKind_SUBJECT_KIND_UNSPECIFIED {
		kind = observev1.SubjectKind_SUBJECT_KIND_TOOL
	}
	if stage == observev1.Stage_STAGE_UNSPECIFIED {
		stage = observev1.Stage_STAGE_COMPLETED
	}
	out := &observev1.Observation{
		SchemaVersion: "0.1", ObservationId: o.id, TenantId: pick(o.tenant, tenant), ProjectId: pick(o.proj, proj),
		Source:    &observev1.SourceRef{SourceId: pick(o.source, "s1"), Trust: observev1.Trust_TRUST_SELF_REPORTED},
		EventTime: at(o.at), Stage: stage, Subject: &observev1.Subject{Kind: kind, Name: o.name},
		Correlation: &observev1.Correlation{Basis: basis, RunId: pick(o.run, runID), TraceId: traceA,
			SpanId: o.span, ParentSpanId: o.parent},
	}
	if o.status != observev1.Status_STATUS_UNSPECIFIED {
		out.Outcome = &observev1.Outcome{Status: o.status}
	}
	return out
}

// source is s1 of t1 and p1, heard an hour after t0 with a heartbeat of
// 300 s.
func source(obs ...ob) supervise.Source {
	s := supervise.Source{SourceID: "s1", Tenant: tenant, Project: proj, HeartbeatSeconds: 300, LastHeard: t0.Add(time.Hour), Heard: true}
	for _, o := range obs {
		s.Observations = append(s.Observations, o.obs())
	}
	return s
}

// handID is the finding id by its documented construction, computed here
// apart from the package: "fnd-" and the first 32 hex digits of SHA-256 over
// "finding-id:1" and fields, each after its length in eight big-endian bytes.
func handID(fields ...string) string {
	h := sha256.New()
	var n [8]byte
	for _, s := range append([]string{"finding-id:1"}, fields...) {
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	return "fnd-" + hex.EncodeToString(h.Sum(nil)[:16])
}

func evRef(event, req string) *findingv1alpha1.Reference {
	return &findingv1alpha1.Reference{Ref: &findingv1alpha1.Reference_Event{
		Event: &findingv1alpha1.EventRef{EventId: event, RequestId: req}}}
}

func obsRef(src, id string) *findingv1alpha1.Reference {
	return &findingv1alpha1.Reference{Ref: &findingv1alpha1.Reference_Observation{
		Observation: &findingv1alpha1.ObservationRef{SourceId: src, ObservationId: id}}}
}

// want is the finding record a rule of the refund procedure writes.
// ruleVersions is each rule's version, spelled here rather than read from the
// package's table.
var ruleVersions = map[string]string{
	"REPEATED_DENIAL": "2", "STEP_OUTSIDE_PROCEDURE": "1", "DEADLINE_EXCEEDED": "1",
	"REQUIRED_STEP_SKIPPED": "1", "STEP_OUT_OF_ORDER": "2", "CONTINUED_AFTER_FAILURE": "2",
	"RESOURCE_OUTSIDE_RUN": "1", "DENIED_ACTION_RETRIED_ARGUMENTS": "1", "DENIED_ACTION_RETRIED_RESOURCE": "1",
	"DENIED_ACTION_RETRIED_AROUND": "1", "EXCEPTION_TAKEN": "1",
}

func want(p *supervise.Procedure, rule string, sev controlv1.FindingSeverity, esc findingv1alpha1.Escalation,
	verdict controlv1.FindingVerdict, id string, refs ...*findingv1alpha1.Reference) *findingv1alpha1.FindingRecord {
	return &findingv1alpha1.FindingRecord{
		SchemaVersion: "0.1", TenantId: tenant, ProjectId: proj,
		Procedure:  &findingv1alpha1.ProcedureRef{ProcedureId: "refund", Version: "1", Digest: p.Digest()},
		Escalation: esc, Refs: refs,
		Finding: &controlv1.Finding{FindingId: id, RuleId: rule, RuleVersion: ruleVersions[rule], Severity: sev,
			Verdict: verdict, RunId: runID, Source: controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC},
	}
}

func evaluate(t *testing.T, in supervise.Input) *supervise.Result {
	t.Helper()
	if in.Run.ID == "" {
		in.Run.ID = runID
	}
	if in.Run.Tenant == "" {
		in.Run.Tenant = tenant
	}
	res, err := supervise.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for _, f := range res.Findings {
		if v := f.GetFinding().GetVerdict(); v == confirmed && !supervise.CanConfirm(f.GetFinding().GetRuleId()) {
			t.Fatalf("%s, a rule that cannot confirm, is %s:\n%s", f.GetFinding().GetRuleId(), v, dump(res.Findings))
		}
	}
	return res
}

func sameFindings(t *testing.T, got []*findingv1alpha1.FindingRecord, want ...*findingv1alpha1.FindingRecord) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d findings, want %d:\n%s", len(got), len(want), dump(got))
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			t.Fatalf("finding %d:\n got %s\nwant %s", i, protojson.Format(got[i]), protojson.Format(want[i]))
		}
	}
}

func dump(rs []*findingv1alpha1.FindingRecord) string {
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(protojson.Format(r))
		b.WriteString("\n")
	}
	return b.String()
}

// rules is each rule's state and why, by id.
func rules(res *supervise.Result) map[string]string {
	out := map[string]string{}
	for _, r := range res.Report.GetRules() {
		out[r.GetRuleId()] = r.GetState().String() + ":" + r.GetWhy()
	}
	return out
}
