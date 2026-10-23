package enforce_test

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
)

const allowMail = `{"id":"allow-mail","effect":"ALLOW","when":{"action":{"name":["send_mail"]}}}`

const (
	kindProposed = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	kindDecided  = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	kindStarted  = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	kindDone     = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	kindFailed   = controlv1.EventKind_EVENT_KIND_ACTION_FAILED
	kindBlocked  = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED

	outcomeExecute = enforcev1alpha1.Outcome_OUTCOME_EXECUTE
	outcomeBlock   = enforcev1alpha1.Outcome_OUTCOME_BLOCK
	outcomePending = enforcev1alpha1.Outcome_OUTCOME_PENDING
)

// admit posts an admit of tool with args, plus any members in extra, and
// decodes a 200 answer strictly.
func (r *rig) admit(t *testing.T, token, tool, args, extra string) *enforcev1alpha1.AdmitResponse {
	t.Helper()
	body := `{"tool":"` + tool + `","arguments":"` + b64(args) + `"` + extra + `}`
	status, answer := r.post(t, token, enforce.PathAdmit, body)
	return outcome(t, status, answer)
}

func (r *rig) proposed(t *testing.T) []*controlv1.ActionEnvelope {
	t.Helper()
	var out []*controlv1.ActionEnvelope
	for _, e := range r.sink.Events() {
		if e.GetKind() == kindProposed {
			out = append(out, e.GetProposed())
		}
	}
	return out
}

func TestTheEnvelopeIsBuiltFromTheRunAndTheTable(t *testing.T) {
	o := defaults()
	o.rules = append(o.rules, allowMail)
	r := newRig(t, o)
	args := `{"to":"ops@example.org","body":"hi"}`
	key := "order-mark.77"
	resp := r.admit(t, runA, "send_mail", args,
		`,"requestKey":"`+key+`","traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"`)
	if resp.GetOutcome() != outcomeExecute {
		t.Fatalf("outcome %s", resp.GetOutcome())
	}
	envs := r.proposed(t)
	if len(envs) != 1 {
		t.Fatalf("%d proposals", len(envs))
	}
	env := envs[0]
	hash, err := canon.ArgumentsHashV1([]byte(args))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		field     string
		got, want any
	}{
		{"schema_version", env.GetSchemaVersion(), "1.0"},
		{"project_id", env.GetProjectId(), "proj-1"},
		{"tenant_id", env.GetTenantId(), "tenant-1"},
		{"environment", env.GetEnvironment(), "prod"},
		{"occurred_at", env.GetOccurredAt().AsTime(), base()},
		{"principal.id", env.GetPrincipal().GetId(), "user-1"},
		{"principal.tenant_id", env.GetPrincipal().GetTenantId(), "tenant-1"},
		{"principal.type", env.GetPrincipal().GetType(), "user"},
		{"agent.id", env.GetAgent().GetId(), "agent-1"},
		{"action.kind", env.GetAction().GetKind(), "tool"},
		{"action.name", env.GetAction().GetName(), "send_mail"},
		{"action.protocol", env.GetAction().GetProtocol(), "enforce"},
		{"action.effect", env.GetAction().GetEffect(), effectComm},
		{"action.provider", env.GetAction().GetProvider(), "mail"},
		{"resource.type", env.GetResource().GetType(), "mailbox"},
		{"resource.id", env.GetResource().GetId(), "ops@example.org"},
		{"resource.tenant_id", env.GetResource().GetTenantId(), "tenant-1"},
		{"resource.environment", env.GetResource().GetEnvironment(), "prod"},
		{"destination.trust_zone", env.GetDestination().GetTrustZone(), zoneExternal},
		{"arguments.canonical_hash", env.GetArguments().GetCanonicalHash(), hash},
		{"trace_id", env.GetTraceId(), "4bf92f3577b34da6a3ce929d0e0e4736"},
		{"span_id", env.GetSpanId(), "00f067aa0ba902b7"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if env.GetRequestId() == "" || env.GetRequestId() == key {
		t.Errorf("request_id %q is not one the receiver minted", env.GetRequestId())
	}
	for _, e := range r.sink.Events() {
		if text, err := protojson.Marshal(e); err != nil || strings.Contains(string(text), key) {
			t.Fatalf("an event carries the request key, or will not marshal: %v", err)
		}
	}
}

// TestWhatAReadReturnsSetsNoDestination: a read with no destination of its
// own keeps none, whatever trust the table says its results hold: what a tool
// returns is never where a call sends data (ADR-0021).
func TestWhatAReadReturnsSetsNoDestination(t *testing.T) {
	values := controlv1.TrustZone(0).Descriptor().Values()
	for i := range values.Len() {
		trust := controlv1.TrustZone(values.Get(i).Number())
		o := defaults()
		if o.tools[1].Name != "read_file" || o.tools[1].TrustZone != 0 {
			t.Fatalf("the table's second tool is %+v, not the read with no destination this test is about", o.tools[1])
		}
		o.tools[1].ReturnsTrust = trust
		r := newRig(t, o)
		if resp := r.admit(t, runA, "read_file", `{"path":"a"}`, `,"requestKey":"k1"`); resp.GetOutcome() != outcomeExecute {
			t.Fatalf("returns %s: outcome %s", trust, resp.GetOutcome())
		}
		envs := r.proposed(t)
		if len(envs) != 1 {
			t.Fatalf("returns %s: %d proposals", trust, len(envs))
		}
		if d := envs[0].GetDestination(); d != nil {
			t.Errorf("returns %s: the envelope's destination is %v, want none", trust, d)
		}
	}
}

func TestATraceparentNotOfVersion00RecordsNoTrace(t *testing.T) {
	r := newRig(t, defaults())
	for _, tp := range []string{
		"garbage",
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
	} {
		r.admit(t, runA, "read_file", `{"path":"a"}`, `,"traceparent":"`+tp+`"`)
	}
	for _, env := range r.proposed(t) {
		if env.GetTraceId() != "" || env.GetSpanId() != "" {
			t.Fatalf("trace %q/%q recorded from an invalid traceparent", env.GetTraceId(), env.GetSpanId())
		}
	}
}

func TestAToolTheTableDoesNotNameIsUnclassified(t *testing.T) {
	r := newRig(t, defaults())
	resp := r.admit(t, runA, "drop_database", `{"name":"prod"}`, "")
	if resp.GetOutcome() != outcomeBlock || resp.GetExecution() != nil || resp.GetPending() != nil {
		t.Fatalf("answer %v", resp)
	}
	if !slices.Contains(resp.GetDecision().GetReasonCodes(), "ACTION_UNCLASSIFIED") {
		t.Fatalf("reason codes %v", resp.GetDecision().GetReasonCodes())
	}
	if got := r.kinds(); !slices.Equal(got, []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}) {
		t.Fatalf("trail %v", got)
	}
}

var handleShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// checkExecution holds an EXECUTE answer to a fresh-looking handle expiring a
// lifetime after the admit, the proposed bytes unchanged and no obligation.
func checkExecution(t *testing.T, resp *enforcev1alpha1.AdmitResponse, args string) {
	t.Helper()
	ex := resp.GetExecution()
	switch {
	case resp.GetOutcome() != outcomeExecute || resp.GetPending() != nil:
		t.Fatalf("answer %v", resp)
	case !handleShape.MatchString(ex.GetHandle()):
		t.Fatalf("handle %q", ex.GetHandle())
	case !ex.GetExpiresAt().AsTime().Equal(base().Add(time.Minute)):
		t.Fatalf("expires_at %v", ex.GetExpiresAt().AsTime())
	case string(ex.GetAuthorizedArguments()) != args:
		t.Fatalf("authorized %q, proposed %q", ex.GetAuthorizedArguments(), args)
	case len(ex.GetObligations()) != 0:
		t.Fatalf("obligations %v", ex.GetObligations())
	case resp.GetDecision().GetVerdict() != controlv1.Verdict_VERDICT_ALLOW:
		t.Fatalf("decision %v", resp.GetDecision())
	}
}

func TestAnExecuteCarriesAFreshHandleAndTheAuthorizedBytes(t *testing.T) {
	r := newRig(t, defaults())
	args := `{"path": "a",  "n": 1}`
	first := r.admit(t, runA, "read_file", args, "")
	second := r.admit(t, runA, "read_file", args, "")
	checkExecution(t, first, args)
	checkExecution(t, second, args)
	if first.GetExecution().GetHandle() == second.GetExecution().GetHandle() {
		t.Fatal("two executions share a handle")
	}
	if s := r.a.Stats(); s.Executed != 2 || s.Open != 2 {
		t.Fatalf("stats %+v", s)
	}
	if r.count(kindStarted) != 2 {
		t.Fatalf("trail %v", r.kinds())
	}
}

func TestAnAdmitWithoutArgumentsIsTheEmptyDocument(t *testing.T) {
	r := newRig(t, defaults())
	status, body := r.post(t, runA, enforce.PathAdmit, `{"tool":"read_file"}`)
	resp := outcome(t, status, body)
	if string(resp.GetExecution().GetAuthorizedArguments()) != "{}" {
		t.Fatalf("authorized %q", resp.GetExecution().GetAuthorizedArguments())
	}
}

func TestRewrittenBytesAreAuthorizedAndAdvisoryObligationsStayOut(t *testing.T) {
	o := defaults()
	o.rules = []string{cappedRefunds}
	r := newRig(t, o)
	resp := r.admit(t, runA, "refund", `{"account":"acc-1","amount":1250}`, "")
	if resp.GetOutcome() != outcomeExecute {
		t.Fatalf("outcome %s", resp.GetOutcome())
	}
	var got struct {
		Account string `json:"account"`
		Amount  int    `json:"amount"`
	}
	if err := json.Unmarshal(resp.GetExecution().GetAuthorizedArguments(), &got); err != nil || got.Amount != 1000 || got.Account != "acc-1" {
		t.Fatalf("authorized %s: %v", resp.GetExecution().GetAuthorizedArguments(), err)
	}
	if n := len(resp.GetExecution().GetObligations()); n != 0 {
		t.Fatalf("the answer carries %d obligations: %v", n, resp.GetExecution().GetObligations())
	}
	var advisory bool
	for _, ob := range resp.GetDecision().GetObligations() {
		advisory = advisory || (ob.GetType() == "cap_rate" && ob.GetAdvisory())
	}
	if !advisory {
		t.Fatalf("the decision lost its advisory obligation: %v", resp.GetDecision().GetObligations())
	}
}

func TestABlockCarriesTheDecisionAndNothingToSend(t *testing.T) {
	o := defaults()
	o.rules = []string{denyRefunds}
	r := newRig(t, o)
	resp := r.admit(t, runA, "refund", `{"account":"acc-1","amount":5}`, "")
	if resp.GetOutcome() != outcomeBlock || resp.GetExecution() != nil || resp.GetPending() != nil {
		t.Fatalf("answer %v", resp)
	}
	if resp.GetDecision().GetVerdict() != controlv1.Verdict_VERDICT_DENY {
		t.Fatalf("decision %v", resp.GetDecision())
	}
	if r.count(kindStarted) != 0 || r.a.Stats().Blocked != 1 {
		t.Fatalf("trail %v, stats %+v", r.kinds(), r.a.Stats())
	}
}

func TestAPendingAnswerCarriesTheHoldAndAResumeExecutes(t *testing.T) {
	o := defaults()
	o.mode, o.rules = modeApprove, []string{approveRefunds}
	r := newRig(t, o)
	args := `{"account":"acc-1","amount":5}`
	held := r.admit(t, runA, "refund", args, "")
	p := held.GetPending()
	switch {
	case held.GetOutcome() != outcomePending || held.GetExecution() != nil:
		t.Fatalf("answer %v", held)
	case p.GetApprovalId() == "" || p.GetActionDigest() != held.GetDecision().GetActionDigest():
		t.Fatalf("pending %v", p)
	case !p.GetExpiresAt().AsTime().Equal(base().Add(10*time.Minute)) || p.GetRetryAfter().AsDuration() != 5*time.Second:
		t.Fatalf("pending %v", p)
	}
	if err := r.store.Answer(p.GetApprovalId(), controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", r.clock.read()); err != nil {
		t.Fatal(err)
	}
	r.clock.advance(5 * time.Second)
	if resumed := r.admit(t, runA, "refund", args, ""); resumed.GetOutcome() != outcomeExecute {
		t.Fatalf("resume answered %v", resumed)
	}
	if again := r.admit(t, runA, "refund", args, ""); again.GetOutcome() == outcomeExecute {
		t.Fatal("one approval executed twice")
	}
}
