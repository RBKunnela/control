package gateway_test

import (
	"bytes"
	"context"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

// denyToxic blocks every call that carries data read under untrusted
// influence, at CONFIDENTIAL or above, to a destination nobody trusts.
const denyToxic = `{"id":"deny-toxic","effect":"DENY","reason":"TOXIC_FLOW_SENSITIVE_TO_EXTERNAL","when":{"flow":{"toxicAtLeast":"CONFIDENTIAL"}}}`

const (
	codeToxicFlow     = "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL"
	codeLimitExceeded = "LIMIT_EXCEEDED"

	sensPublic       = controlv1.Sensitivity_SENSITIVITY_PUBLIC
	sensInternal     = controlv1.Sensitivity_SENSITIVITY_INTERNAL
	sensConfidential = controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL
	sensRestricted   = controlv1.Sensitivity_SENSITIVITY_RESTRICTED
	sensSecret       = controlv1.Sensitivity_SENSITIVITY_SECRET

	zoneInternal = controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL
	zonePartner  = controlv1.TrustZone_TRUST_ZONE_PARTNER
)

// readOf is a read as requestID by principal, with no destination: a
// destination nobody described is one nobody trusts.
func readOf(requestID, principal string) *controlv1.ActionEnvelope {
	env := readEnvelope()
	env.RequestId = requestID
	env.Principal.Id = principal
	return env
}

// returning is an admission of env whose result the operator declared as
// trust and read.
func returning(env *controlv1.ActionEnvelope, trust controlv1.TrustZone, read controlv1.Sensitivity) gateway.Admission {
	a := admission(env, []byte(`{}`))
	a.ResultTrust, a.ResultSensitivity = trust, read
	return a
}

// cleanRun is env as the pipeline records the first call of a run: with the
// flow tags of a run that took in nothing.
func cleanRun(env *controlv1.ActionEnvelope) *controlv1.ActionEnvelope {
	out := proto.CloneOf(env)
	out.Context.Tags = append(out.Context.Tags, "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
	return out
}

func (h *harness) admitA(a gateway.Admission) gateway.Disposition {
	return h.p.Admit(context.Background(), h.onPlane(a))
}

// proposedTags are the run-context tags ACTION_PROPOSED of requestID recorded.
func (h *harness) proposedTags(t *testing.T, requestID string) []string {
	t.Helper()
	trail := h.trailOf(requestID)
	if len(trail) == 0 || trail[0].GetKind() != kindProposed {
		t.Fatalf("no ACTION_PROPOSED for %s: %v", requestID, kindsOf(trail))
	}
	return trail[0].GetProposed().GetContext().GetTags()
}

func expectTags(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("tags = %q, want %q", got, want)
	}
}

func expectVerdict(t *testing.T, d gateway.Disposition, verdict controlv1.Verdict) {
	t.Helper()
	if d.Decision.GetVerdict() != verdict {
		t.Errorf("verdict = %s %v, want %s", d.Decision.GetVerdict(), d.Decision.GetReasonCodes(), verdict)
	}
	if verdict != verdictAllow && d.Action != core.Block {
		t.Errorf("Action = %d, want Block", d.Action)
	}
}

// TestAFreshRunIsCleanAndSaysSo: the first call of a principal is decided in a
// run that took in nothing, so the flow rule does not match, and its proposal
// records that state.
func TestAFreshRunIsCleanAndSaysSo(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
	d := h.admitA(returning(readOf("r-1", "user-1"), 0, 0))
	if d.Action != core.Execute {
		t.Fatalf("the first read: Action = %d, decision %+v", d.Action, d.Decision)
	}
	expectTags(t, h.proposedTags(t, "r-1"), "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
}

// TestAnExecutionTaintsItsRunWhenItIsHandedOut: the first read's result is
// untrusted and confidential; the next call of the run is decided after the
// first was handed out, whatever the adapter or the sink did about its
// closing since.
func TestAnExecutionTaintsItsRunWhenItIsHandedOut(t *testing.T) {
	for name, after := range map[string]func(t *testing.T, h *harness, d gateway.Disposition){
		"still running": func(*testing.T, *harness, gateway.Disposition) {},
		"aborted": func(t *testing.T, h *harness, d gateway.Disposition) {
			if err := h.p.Abort(context.Background(), d, gateway.AbortObligation); err != nil {
				t.Fatalf("Abort: %v", err)
			}
		},
		"closing refused": func(t *testing.T, h *harness, d gateway.Disposition) {
			h.sink.refuseKind(kindCompleted)
			if err := h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err == nil {
				t.Fatalf("Close took a record the sink refused")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
			first := h.admitA(returning(readOf("r-1", "user-1"), 0, sensConfidential))
			if first.Action != core.Execute {
				t.Fatalf("the first read: Action = %d", first.Action)
			}
			after(t, h, first)
			d := h.admitA(returning(readOf("r-2", "user-1"), 0, 0))
			expectVerdict(t, d, verdictDeny)
			if !slices.Contains(d.Decision.GetReasonCodes(), codeToxicFlow) {
				t.Errorf("codes = %v, want %s", d.Decision.GetReasonCodes(), codeToxicFlow)
			}
			expectTags(t, h.proposedTags(t, "r-2"), "flow.v1.untrusted=true", "flow.v1.max_read=CONFIDENTIAL")
		})
	}
}

// TestAnUnrecordedReadTaintsItsRun: a read the sink refused runs unrecorded
// under the risk setting, and what it returns counts all the same.
func TestAnUnrecordedReadTaintsItsRun(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic), func(c *gateway.Config) { c.AllowReadsUnrecorded = true })
	h.sink.fail(true)
	if d := h.admitA(returning(readOf("r-1", "user-1"), 0, sensSecret)); d.Action != core.Execute {
		t.Fatalf("the unrecorded read: Action = %d, decision %+v", d.Action, d.Decision)
	}
	h.sink.fail(false)
	expectVerdict(t, h.admitA(returning(readOf("r-2", "user-1"), 0, 0)), verdictDeny)
}

// TestACallNotHandedOutTaintsNothing: a denied call and a held one each
// declare an untrusted, secret result, and neither ran, so the run is clean.
func TestACallNotHandedOutTaintsNothing(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic, approveRefunds))
	refund := admission(refundEnvelope(t, refundArgs()), refundArgs())
	refund.ResultSensitivity = sensSecret
	if d := h.admitA(refund); d.Action != core.AwaitApproval {
		t.Fatalf("the refund: Action = %d, %s %v", d.Action, d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	write := writeEnvelope()
	write.RequestId = "w-1"
	if d := h.admitA(returning(write, 0, sensSecret)); d.Action != core.Block {
		t.Fatalf("the write no rule allows: Action = %d", d.Action)
	}
	if d := h.admitA(returning(readOf("r-2", "user-1"), 0, 0)); d.Action != core.Execute {
		t.Errorf("a read after two calls that never ran: %s %v", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	expectTags(t, h.proposedTags(t, "r-2"), "flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC")
}

// TestAResultDeclaredTrustedDoesNotTaint: a partner's or an internal result
// leaves the run trusted, and its sensitivity is still what the run read.
func TestAResultDeclaredTrustedDoesNotTaint(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
	for i, zone := range []controlv1.TrustZone{zoneInternal, zonePartner} {
		if d := h.admitA(returning(readOf("r-"+strconv.Itoa(i), "user-1"), zone, sensSecret)); d.Action != core.Execute {
			t.Fatalf("a read after trusted results: %s %v", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
		}
	}
	d := h.admitA(returning(readOf("r-9", "user-1"), 0, 0))
	if d.Action != core.Execute {
		t.Errorf("a read after trusted results: %s %v", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	expectTags(t, h.proposedTags(t, "r-9"), "flow.v1.untrusted=false", "flow.v1.max_read=SECRET")
}

// TestAKeyPastTheBoundIsUncomputed: with room for one run, a second principal
// is decided with the state nobody computed: the flow rule is undetermined,
// never false, and nothing names a run on its trail. With room for two it
// gets a clean run of its own.
func TestAKeyPastTheBoundIsUncomputed(t *testing.T) {
	for _, tc := range []struct {
		runs    int
		verdict controlv1.Verdict
		tags    []string
	}{
		{1, verdictIndeterminate, []string{"flow.v1.state=uncomputed"}},
		{2, verdictAllow, []string{"flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC"}},
	} {
		t.Run(strconv.Itoa(tc.runs), func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic), func(c *gateway.Config) { c.MaxRuns = tc.runs })
			if d := h.admitA(returning(readOf("a-1", "user-a"), 0, 0)); d.Action != core.Execute {
				t.Fatalf("the first principal: Action = %d", d.Action)
			}
			d := h.admitA(returning(readOf("b-1", "user-b"), 0, 0))
			expectVerdict(t, d, tc.verdict)
			expectTags(t, h.proposedTags(t, "b-1"), tc.tags...)
			uncomputed := tc.verdict == verdictIndeterminate
			if got := h.trailOf("b-1")[0].GetRunId(); (got == "") != uncomputed {
				t.Errorf("the second principal's trail names run %q", got)
			}
			s := h.p.Stats()
			if want := uint64(0); uncomputed {
				want = 1
				if s.FlowUncomputed != want || s.Runs != 1 {
					t.Errorf("Stats: %d uncomputed, %d runs; want %d and 1", s.FlowUncomputed, s.Runs, want)
				}
			} else if s.FlowUncomputed != want || s.Runs != 2 {
				t.Errorf("Stats: %d uncomputed, %d runs; want 0 and 2", s.FlowUncomputed, s.Runs)
			}
		})
	}
}

// TestACallWithNoPrincipalIsUncomputed: a call the pipeline cannot key is
// decided and recorded with the state nobody computed, and is counted.
func TestACallWithNoPrincipalIsUncomputed(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
	env := readOf("n-1", "")
	h.admitA(returning(env, 0, 0))
	expectTags(t, h.proposedTags(t, "n-1"), "flow.v1.state=uncomputed")
	if got := h.trailOf("n-1")[0].GetRunId(); got != "" {
		t.Errorf("an unkeyed call names run %q", got)
	}
	if s := h.p.Stats(); s.FlowUncomputed != 1 || s.Runs != 0 {
		t.Errorf("Stats: %d uncomputed, %d runs; want 1 and 0", s.FlowUncomputed, s.Runs)
	}
}

// TestARunIsThePrincipalAndTheAgent: calls of one principal and agent share
// one minted run id whatever the producer says its session or run is; another
// principal or another agent is another run, and one run's taint stays in it.
func TestARunIsThePrincipalAndTheAgent(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
	h.admitA(returning(readOf("a-1", "user-a"), 0, sensConfidential))
	other := readOf("a-2", "user-a")
	other.Context = &controlv1.RunContext{RunId: "run-2", SessionId: "sess-2"}
	expectVerdict(t, h.admitA(returning(other, 0, 0)), verdictDeny)
	agent := readOf("c-1", "user-a")
	agent.Agent.Id = "agent-2"
	expectVerdict(t, h.admitA(returning(agent, 0, 0)), verdictAllow)
	expectVerdict(t, h.admitA(returning(readOf("b-1", "user-b"), 0, 0)), verdictAllow)

	runOf := func(id string) string { return h.trailOf(id)[0].GetRunId() }
	for _, e := range h.events() {
		if id := e.GetRunId(); id == "run-1" || id == "run-2" || id == "" {
			t.Errorf("%s of %s names run %q; a run id is the plane's own", e.GetKind(), e.GetRequestId(), id)
		}
	}
	if runOf("a-1") != runOf("a-2") {
		t.Errorf("one principal in two sessions: runs %q and %q", runOf("a-1"), runOf("a-2"))
	}
	if runOf("a-1") == runOf("c-1") || runOf("a-1") == runOf("b-1") || runOf("c-1") == runOf("b-1") {
		t.Errorf("three keys share a run: %q %q %q", runOf("a-1"), runOf("c-1"), runOf("b-1"))
	}
	if s := h.p.Stats(); s.Runs != 3 {
		t.Errorf("Stats().Runs = %d, want 3", s.Runs)
	}
}

// TestAProducersFlowTagIsRefused: a tag under the plane's prefix is refused
// in every mode, since its record would carry a state nobody computed.
func TestAProducersFlowTagIsRefused(t *testing.T) {
	for _, mode := range []controlv1.EnforcementMode{modeEnforce, modeObserve} {
		t.Run(mode.String(), func(t *testing.T) {
			h := build(t, mode, snapshot(t, allowReads))
			env := readOf("f-1", "user-1")
			env.Context.Tags = []string{"mcp.client=x/1", "flow.v1.untrusted=false"}
			d := h.admitA(returning(env, 0, 0))
			expectBlock(t, d, verdictIndeterminate, codeInvalidFieldValue, d.Decision.GetPdpType())
			if got := h.p.Preview(context.Background(), returning(env, 0, 0)).Decision; got.GetVerdict() != verdictIndeterminate {
				t.Errorf("Preview of a forged tag: %s %v", got.GetVerdict(), got.GetReasonCodes())
			}
		})
	}
}

// TestTheStampedTagsShareTheBoundOnTags: two tags more fit an envelope that
// holds thirty, and not one that holds thirty-one.
func TestTheStampedTagsShareTheBoundOnTags(t *testing.T) {
	for _, tc := range []struct {
		producer int
		allowed  bool
	}{{contract.MaxLabels - 2, true}, {contract.MaxLabels - 1, false}} {
		h := build(t, modeEnforce, snapshot(t, allowReads))
		env := readOf("t-1", "user-1")
		for i := range tc.producer {
			env.Context.Tags = append(env.Context.Tags, "tag-"+strconv.Itoa(i))
		}
		if err := contract.Validate(env); err != nil {
			t.Fatalf("the producer's envelope: %v", err)
		}
		d := h.admitA(returning(env, 0, 0))
		switch {
		case tc.allowed && d.Action != core.Execute:
			t.Errorf("%d tags: %s %v, want an execution", tc.producer, d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
		case !tc.allowed:
			expectBlock(t, d, verdictIndeterminate, codeLimitExceeded, d.Decision.GetPdpType())
		}
	}
}

// TestTheStampedTagsAreAValidRecord: a trail whose proposal carries the tags
// is one chain, round-trips the JSONL codec, and its envelope validates.
func TestTheStampedTagsAreAValidRecord(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
	d := h.admitA(returning(readOf("r-1", "user-1"), 0, 0))
	if err := h.p.Close(context.Background(), d, d.AuthorizedArgs, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h.admitA(returning(readOf("r-2", "user-1"), 0, 0))
	expectTags(t, h.proposedTags(t, "r-2"), "flow.v1.untrusted=true", "flow.v1.max_read=UNKNOWN")
	for _, id := range []string{"r-1", "r-2"} {
		trail := h.trailOf(id)
		if err := evidence.ValidateChain(trail); err != nil {
			t.Errorf("ValidateChain over %s: %v", id, err)
		}
		if err := contract.Validate(trail[0].GetProposed()); err != nil {
			t.Errorf("the recorded proposal of %s: %v", id, err)
		}
	}
	var buf bytes.Buffer
	events := h.events()
	if err := evidence.EncodeJSONL(&buf, events); err != nil {
		t.Fatalf("EncodeJSONL: %v", err)
	}
	back, err := evidence.DecodeJSONL(&buf, len(events))
	if err != nil {
		t.Fatalf("DecodeJSONL: %v", err)
	}
	if len(back) != len(events) {
		t.Fatalf("decoded %d events of %d", len(back), len(events))
	}
	for i := range events {
		if !proto.Equal(back[i], events[i]) {
			t.Errorf("event %d changed through the codec", i)
		}
	}
}

// TestPreviewNeverReadsARun: a listing is cached per principal and outlives any
// state, so Preview answers in a tainted run what it answers in a clean one,
// and that answer is the undetermined one.
func TestPreviewNeverReadsARun(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic))
	preview := func() *controlv1.Decision {
		return h.p.Preview(context.Background(), returning(readOf("p-1", "user-1"), 0, 0)).Decision
	}
	clean := preview()
	h.admitA(returning(readOf("r-1", "user-1"), 0, sensSecret))
	tainted := preview()
	if clean.GetVerdict() != verdictIndeterminate || tainted.GetVerdict() != clean.GetVerdict() ||
		!slices.Equal(tainted.GetReasonCodes(), clean.GetReasonCodes()) {
		t.Errorf("Preview: clean %s %v, tainted %s %v; want the same INDETERMINATE",
			clean.GetVerdict(), clean.GetReasonCodes(), tainted.GetVerdict(), tainted.GetReasonCodes())
	}
	if s := h.p.Stats(); s.FlowUncomputed != 0 {
		t.Errorf("Preview counted %d uncomputed calls; it decides no call", s.FlowUncomputed)
	}
}

// TestAResumeWeighsTheRunAsItStandsNow: a held refund, approved, is resumed by
// a retry after a call that changed what the run read without making the
// flow rule match; it is held anew once the run is tainted instead.
func TestAResumeWeighsTheRunAsItStandsNow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trust   controlv1.TrustZone
		read    controlv1.Sensitivity
		resumes bool
	}{
		{"a trusted internal read", zoneInternal, sensInternal, true},
		{"an untrusted restricted read", 0, sensRestricted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, approveRefunds, taintedRefunds, allowReads))
			first := hold(t, h)
			if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
				t.Fatalf("Answer: %v", err)
			}
			between := h.admitA(returning(readOf("read-1", "user-1"), tc.trust, tc.read))
			if between.Action != core.Execute {
				t.Fatalf("the read in between: Action = %d", between.Action)
			}
			d := h.admit(retry(t, "req-2"), refundArgs())
			if resumed := d.Action == core.Execute; resumed != tc.resumes {
				t.Fatalf("the retry: Action = %d, pending %+v; resumed %t, want %t", d.Action, d.Pending, resumed, tc.resumes)
			}
			if !tc.resumes && (d.Pending == nil || d.Pending.ApprovalID == first.Pending.ApprovalID) {
				t.Errorf("the tainted retry spent or reused the first approval: %+v", d.Pending)
			}
			if tc.resumes {
				expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
			}
		})
	}
}

// TestTheRunStateNeverAnswersNotToxicWhereTheTruthIs: over random runs of
// declared and undeclared results and every floor, a probe that carries a
// PUBLIC label to an untrusted destination is never allowed where what the
// run truly read reaches the floor, and is decided exactly as the three-valued
// model below says.
func TestTheRunStateNeverAnswersNotToxicWhereTheTruthIs(t *testing.T) {
	levels := []controlv1.Sensitivity{sensPublic, sensInternal, sensConfidential, sensRestricted, sensSecret}
	rng := rand.New(rand.NewPCG(21, 5)) //nolint:gosec // G404: a fixed seed keeps the property reproducible
	for _, floor := range levels {
		name := floor.String()[len("SENSITIVITY_"):]
		deny := `{"id":"deny-floor","effect":"DENY","when":{"flow":{"toxicAtLeast":"` + name + `"}}}`
		snap := snapshot(t, allowReads, deny)
		for trial := range 150 {
			n := rng.IntN(6)
			truth, known, undeclared := sensPublic, sensPublic, false
			h := build(t, modeEnforce, snap)
			for i := range n {
				level := levels[rng.IntN(len(levels))]
				truth = max(truth, level)
				declared := level
				if rng.IntN(3) == 0 {
					declared, undeclared = 0, true
				} else {
					known = max(known, level)
				}
				env := readOf("s-"+strconv.Itoa(i), "user-1")
				env.Destination = &controlv1.Destination{TrustZone: zoneInternal}
				if d := h.admitA(returning(env, 0, declared)); d.Action != core.Execute {
					t.Fatalf("floor %s, trial %d: a read to a trusted destination: %v", name, trial, d.Decision.GetReasonCodes())
				}
			}
			probe := readOf("probe", "user-1")
			probe.Data = &controlv1.DataLabels{Sensitivities: []controlv1.Sensitivity{sensPublic}}
			got := h.admitA(returning(probe, 0, 0)).Decision.GetVerdict()
			if n > 0 && truth >= floor && got == verdictAllow {
				t.Fatalf("floor %s, trial %d: the run truly read %s and the probe was allowed", name, trial, truth)
			}
			if want := modelVerdict(n > 0, undeclared, known, floor); got != want {
				t.Fatalf("floor %s, trial %d (known %s, undeclared %t): %s, want %s", name, trial, known, undeclared, got, want)
			}
		}
	}
}

// modelVerdict is the probe's verdict from what the run took in: nothing
// untrusted is clean and the PUBLIC label reaches a PUBLIC floor; past that,
// an undeclared read leaves the run's reading unknown for good, even beside a
// known one at the floor, and a run that read only declared results is toxic
// at or above the floor and clean below it.
func modelVerdict(untrusted, undeclared bool, known, floor controlv1.Sensitivity) controlv1.Verdict {
	switch {
	case !untrusted:
		return verdictAllow
	case floor == sensPublic:
		return verdictDeny
	case undeclared:
		return verdictIndeterminate
	case known >= floor:
		return verdictDeny
	}
	return verdictAllow
}

// TestARunTheIDSourceCannotNameIsUncomputed: a run needs an id its trails can
// carry, so an empty one mints no run and the call is decided uncomputed.
func TestARunTheIDSourceCannotNameIsUncomputed(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyToxic), func(c *gateway.Config) { c.NewID = idEmptyAt(3) })
	expectVerdict(t, h.admitA(returning(readOf("r-1", "user-1"), 0, 0)), verdictIndeterminate)
	expectTags(t, h.proposedTags(t, "r-1"), "flow.v1.state=uncomputed")
	if s := h.p.Stats(); s.FlowUncomputed != 1 || s.Runs != 0 {
		t.Errorf("Stats: %d uncomputed, %d runs; want 1 and 0", s.FlowUncomputed, s.Runs)
	}
}
