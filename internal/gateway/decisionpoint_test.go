package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

const (
	codePDPTimeout       = "PDP_TIMEOUT"
	codePDPUnavailable   = "PDP_UNAVAILABLE"
	codePDPAnswerRefused = "PDP_ANSWER_REFUSED"
	codePDPDeny          = "PDP_DENY"
	codePDPAllow         = "PDP_ALLOW"
	codeRuleUndetermined = "RULE_UNDETERMINED"

	decisionPointID = "pdp-1"
	askDeadline     = 50 * time.Millisecond
	// released bounds how long a blocking fake waits for its ctx before it
	// reports that nothing released it.
	released = 5 * time.Second

	vetoReads   = `{"id":"veto-reads","effect":"DENY","when":{"action":{"effect":["READ"]},"external":{"denies":true}}}`
	vetoWrites  = `{"id":"veto-writes","effect":"DENY","when":{"action":{"effect":["WRITE"]},"external":{"denies":true}}}`
	vetoRefunds = `{"id":"veto-refunds","effect":"DENY","when":{"action":{"name":["refund"]},"external":{"denies":true}}}`
)

// fakeDecisionPoint answers every ask with answer and records what it was
// asked about. A blocking one waits for its ctx and answers a timeout; during
// runs while an ask is in flight.
type fakeDecisionPoint struct {
	mu        sync.Mutex
	answer    core.External
	block     bool
	during    func()
	asked     []*controlv1.ActionEnvelope
	deadlines []time.Duration
	// undated counts the asks whose ctx carried no deadline at all.
	undated int
	stuck   int
	// scribble makes it write to the envelope it was handed.
	scribble bool
}

func (f *fakeDecisionPoint) Ask(ctx context.Context, env *controlv1.ActionEnvelope) core.External {
	f.mu.Lock()
	f.asked = append(f.asked, proto.CloneOf(env))
	if deadline, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, time.Until(deadline))
	} else {
		f.undated++
	}
	answer, block, during := f.answer, f.block, f.during
	if f.scribble {
		env.RequestId, env.Action.Name, env.Action.Effect = "req-scribbled", "orders.read", controlv1.EffectClass_EFFECT_CLASS_READ
	}
	f.mu.Unlock()
	if during != nil {
		during()
	}
	if !block {
		return answer
	}
	select {
	case <-ctx.Done():
		return core.ExternalTimeout()
	case <-time.After(released):
		f.mu.Lock()
		f.stuck++
		f.mu.Unlock()
		return core.ExternalTimeout()
	}
}

func (f *fakeDecisionPoint) set(answer core.External) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

func (f *fakeDecisionPoint) questions() []*controlv1.ActionEnvelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

// expectAsks asserts n asks, each with a deadline no later than the
// configured one, none left waiting past it. A deadline that passed before
// the fake ran is still one: under load the ask can start late.
func (f *fakeDecisionPoint) expectAsks(t *testing.T, n int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.asked) != n {
		t.Errorf("the decision point was asked %d time(s), want %d", len(f.asked), n)
	}
	if f.undated != 0 {
		t.Errorf("%d ask(s) carried no deadline, want one within %v", f.undated, askDeadline)
	}
	for i, d := range f.deadlines {
		if d > askDeadline {
			t.Errorf("ask %d had %v left before its deadline, want a deadline within %v", i, d, askDeadline)
		}
	}
	if f.stuck != 0 {
		t.Errorf("%d ask(s) waited past the deadline without their ctx releasing them", f.stuck)
	}
}

func withDecisionPoint(dp gateway.DecisionPoint) func(*gateway.Config) {
	return func(c *gateway.Config) {
		c.DecisionPoint, c.DecisionPointID, c.DecisionTimeout = dp, decisionPointID, askDeadline
	}
}

// recorded is the decision the trail of requestID recorded.
func (h *harness) recorded(t *testing.T, requestID string) *controlv1.Decision {
	t.Helper()
	for _, e := range h.trailOf(requestID) {
		if e.GetKind() == kindDecided {
			return e.GetDecision()
		}
	}
	t.Fatalf("the trail of %s holds no POLICY_DECIDED", requestID)
	return nil
}

// expectConsulted asserts decision carries verdict, the one PDP code and the
// decision point's identifier.
func expectConsulted(t *testing.T, decision *controlv1.Decision, verdict controlv1.Verdict, code string) {
	t.Helper()
	if decision.GetVerdict() != verdict {
		t.Errorf("Verdict = %s, want %s", decision.GetVerdict(), verdict)
	}
	var pdp []string
	for _, c := range decision.GetReasonCodes() {
		if len(c) > 4 && c[:4] == "PDP_" || c == codeObligationNotUnderstood {
			pdp = append(pdp, c)
		}
	}
	if !slices.Equal(pdp, []string{code}) {
		t.Errorf("ReasonCodes = %v, want exactly %s among the decision point's", decision.GetReasonCodes(), code)
	}
	if decision.GetPdpInstance() != decisionPointID || decision.GetPdpType() != "builtin" {
		t.Errorf("pdp = %q/%q, want builtin/%s", decision.GetPdpType(), decision.GetPdpInstance(), decisionPointID)
	}
}

// TestACallTheAnswerCannotChangeIsNotAskedAbout: a read no veto covers runs
// on the first decision, and the decision point hears nothing of it.
func TestACallTheAnswerCannotChangeIsNotAskedAbout(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalDenied()}
	h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites, vetoWrites), withDecisionPoint(dp))
	d := h.admit(readEnvelope(), []byte(`{}`))
	if d.Action != core.Execute || d.Decision.GetVerdict() != verdictAllow {
		t.Fatalf("a read no veto covers: Action = %d, decision %+v", d.Action, d.Decision)
	}
	dp.expectAsks(t, 0)
	if got := h.recorded(t, "req-1"); got.GetPdpInstance() != "" || slices.Contains(got.GetReasonCodes(), codePDPDeny) {
		t.Errorf("a decision that consulted no answer names the decision point: %+v", got)
	}
	if s := h.p.Stats(); s.Asks != (gateway.Asks{}) {
		t.Errorf("Stats.Asks = %+v, want nothing asked", s.Asks)
	}
}

// TestACallThatNeedsTheAnswerIsAskedOnce: a write a veto covers is asked
// about once, about the proposed envelope, and the decision recorded and
// answered is the one with the answer, which the first decision without it
// could not have been.
func TestACallThatNeedsTheAnswerIsAskedOnce(t *testing.T) {
	cases := []struct {
		answer  core.External
		action  core.EnforcementAction
		verdict controlv1.Verdict
		code    string
		counted gateway.Asks
	}{
		{core.ExternalAllowed(), core.Execute, verdictAllow, codePDPAllow, gateway.Asks{Made: 1, Allowed: 1}},
		{core.ExternalDenied(), core.Block, verdictDeny, codePDPDeny, gateway.Asks{Made: 1, Denied: 1}},
		{core.ExternalDeniedObligations(), core.Block, verdictDeny, codeObligationNotUnderstood, gateway.Asks{Made: 1, DeniedObligations: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.answer.String(), func(t *testing.T) {
			dp := &fakeDecisionPoint{answer: tc.answer}
			h := build(t, modeEnforce, snapshot(t, allowReads, allowWrites, vetoWrites), withDecisionPoint(dp))
			env := writeEnvelope()
			d := h.admit(env, []byte(`{"k":1}`))
			if d.Action != tc.action {
				t.Errorf("Action = %d, want %d", d.Action, tc.action)
			}
			dp.expectAsks(t, 1)
			if q, want := dp.questions(), cleanRun(env); len(q) == 1 && !proto.Equal(q[0], want) {
				t.Errorf("the decision point was asked about %v, want the proposed envelope %v", q[0], want)
			}
			recorded := h.recorded(t, "req-1")
			expectConsulted(t, recorded, tc.verdict, tc.code)
			if recorded.GetDecisionId() != d.Decision.GetDecisionId() {
				t.Errorf("answered with decision %s, recorded %s", d.Decision.GetDecisionId(), recorded.GetDecisionId())
			}
			if err := evidence.ValidateChain(h.trailOf("req-1")); err != nil {
				t.Errorf("ValidateChain: %v", err)
			}
			if got := h.p.Stats().Asks; got != tc.counted {
				t.Errorf("Stats.Asks = %+v, want %+v", got, tc.counted)
			}
		})
	}
}

// TestAFirstDenyIsNotAskedAbout: a write a local rule denies is not asked
// about although a veto covers it too, since no answer can lift a DENY.
func TestAFirstDenyIsNotAskedAbout(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
	h := build(t, modeEnforce, snapshot(t, allowReads, denyWrites, vetoWrites), withDecisionPoint(dp))
	d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
	expectBlock(t, d, verdictDeny, codeRuleDeny, "builtin")
	dp.expectAsks(t, 0)
	if d.Decision.GetPdpInstance() != "" {
		t.Errorf("a decision that consulted no answer names %q", d.Decision.GetPdpInstance())
	}
}

// TestTheRewritePathAsksNothingMore: a refund whose obligations rewrite its
// arguments is decided again as the authorized call with the answer the
// proposed one got; the decision point is asked once.
func TestTheRewritePathAsksNothingMore(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
	h := build(t, modeEnforce, snapshot(t, cappedRefunds, vetoRefunds), withDecisionPoint(dp))
	d := h.admit(refundEnvelope(t, refundArgs()), refundArgs())
	want := `{"amount":1000,"currency":"EUR"}`
	if d.Action != core.ExecuteWithObligations || string(d.AuthorizedArgs) != want {
		t.Fatalf("the capped refund: Action = %d, args %s, decision %+v; want ExecuteWithObligations with %s",
			d.Action, d.AuthorizedArgs, d.Decision, want)
	}
	dp.expectAsks(t, 1)
	recorded := h.recorded(t, "req-1")
	expectConsulted(t, recorded, verdictObligations, codePDPAllow)
	if recorded.GetActionDigest() == "" || recorded.GetDecisionId() != d.Decision.GetDecisionId() {
		t.Errorf("recorded %+v, answered %+v; want the authorized call's decision on both", recorded, d.Decision)
	}
}

// TestPreviewAsksNothing: a listing of a write a veto covers is decided
// without the answer, which leaves the veto undetermined.
func TestPreviewAsksNothing(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
	h := build(t, modeEnforce, snapshot(t, allowWrites, vetoWrites), withDecisionPoint(dp))
	d := h.p.Preview(context.Background(), admission(writeEnvelope(), nil)).Decision
	if d.GetVerdict() != verdictIndeterminate || !slices.Contains(d.GetReasonCodes(), codeRuleUndetermined) || d.GetPdpInstance() != "" {
		t.Errorf("a vetoed write previews as %+v; want INDETERMINATE with the veto undetermined", d)
	}
	dp.expectAsks(t, 0)
	expectUntouched(t, "enforce", h)
}

// TestARetryAsksAgain: a refund held on an allowing answer and then approved
// is asked about again at its retry; a decision point that now denies blocks
// the retry on its own trail and the held request never runs, and once it
// allows again the retry resumes the hold.
func TestARetryAsksAgain(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
	h := build(t, modeEnforce, snapshot(t, approveRefunds, vetoRefunds), withDecisionPoint(dp))
	first := hold(t, h)
	expectConsulted(t, h.recorded(t, "req-1"), verdictApproval, codePDPAllow)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}

	dp.set(core.ExternalDenied())
	denied := h.admit(retry(t, "req-2"), refundArgs())
	expectBlock(t, denied, verdictDeny, codePDPDeny, "builtin")
	dp.expectAsks(t, 2)
	expectKinds(t, kindsOf(h.trailOf("req-2")), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	expectConsulted(t, h.recorded(t, "req-2"), verdictDeny, codePDPDeny)
	for _, id := range []string{"req-1", "req-2"} {
		if err := evidence.ValidateChain(h.trailOf(id)); err != nil {
			t.Errorf("ValidateChain over %s: %v", id, err)
		}
	}
	if got := len(h.trailOf("req-1")); got != 3 {
		t.Errorf("the held trail has %d event(s); a retry the decision point denies does not touch it", got)
	}
	if s := h.p.Stats(); s.Executed != 0 {
		t.Errorf("Stats.Executed = %d; the held request ran on a denied retry", s.Executed)
	}

	dp.set(core.ExternalAllowed())
	run := h.admit(retry(t, "req-3"), refundArgs())
	if run.Action != core.Execute {
		t.Fatalf("the retry once the decision point allows again: Action = %d, decision %+v", run.Action, run.Decision)
	}
	dp.expectAsks(t, 3)
	expectKinds(t, kindsOf(h.trailOf("req-1")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalDecided, kindStarted})
}

// TestAnApprovalThatExpiresDuringTheAskIsNotConsumed: a retry that reaches
// the plane a millisecond before the approval expires, and waits on the
// decision point past that expiry, is judged at the clock after the ask: it
// is held anew and the expired hold never runs.
func TestAnApprovalThatExpiresDuringTheAskIsNotConsumed(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
	h := build(t, modeEnforce, snapshot(t, approveRefunds, vetoRefunds), withDecisionPoint(dp),
		func(c *gateway.Config) { c.ApprovalTTL = time.Minute })
	first := hold(t, h)
	if err := h.store.Answer(first.Pending.ApprovalID, approved, "alice", "", base()); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	h.clock.set(first.Pending.ExpiresAt.Add(-time.Millisecond))
	dp.during = func() { h.clock.set(first.Pending.ExpiresAt.Add(time.Millisecond)) }
	run := h.admit(retry(t, "req-2"), refundArgs())
	if run.Action != core.AwaitApproval || run.Pending == nil || run.Pending.ApprovalID == first.Pending.ApprovalID {
		t.Fatalf("a retry whose approval expired during the ask: Action = %d, pending %+v; want it held anew", run.Action, run.Pending)
	}
	dp.expectAsks(t, 2)
	if kinds := kindsOf(h.trailOf("req-1")); slices.Contains(kinds, kindStarted) || slices.Contains(kinds, kindApprovalDecided) {
		t.Errorf("the held trail went on past its expiry: %v", kinds)
	}
	if s := h.p.Stats(); s.Executed != 0 {
		t.Errorf("Stats.Executed = %d; the held request ran on an expired approval", s.Executed)
	}
}

// unanswered is every state that is not an answer, with the code it leaves on
// a decision; a decision point that returns the zero value, which is not an
// answer either, is read as unavailable.
func unanswered() []struct {
	name  string
	dp    func() *fakeDecisionPoint
	code  string
	count func(gateway.Asks) uint64
} {
	return []struct {
		name  string
		dp    func() *fakeDecisionPoint
		code  string
		count func(gateway.Asks) uint64
	}{
		{"timeout", func() *fakeDecisionPoint { return &fakeDecisionPoint{block: true} }, codePDPTimeout,
			func(a gateway.Asks) uint64 { return a.TimedOut }},
		{"unavailable", func() *fakeDecisionPoint { return &fakeDecisionPoint{answer: core.ExternalUnavailable()} }, codePDPUnavailable,
			func(a gateway.Asks) uint64 { return a.Unavailable }},
		{"answer refused", func() *fakeDecisionPoint { return &fakeDecisionPoint{answer: core.ExternalAnswerRefused()} }, codePDPAnswerRefused,
			func(a gateway.Asks) uint64 { return a.AnswerRefused }},
		{"not asked", func() *fakeDecisionPoint { return &fakeDecisionPoint{} }, codePDPUnavailable,
			func(a gateway.Asks) uint64 { return a.Unavailable }},
	}
}

// everyEffectClass is every declared effect class but the zero value, and a
// rule that allows them all and one that vetoes them all.
func everyEffectClass() (effects []controlv1.EffectClass, allowAll, vetoAll string) {
	values := controlv1.EffectClass(0).Descriptor().Values()
	var names []string
	for i := range values.Len() {
		effect := controlv1.EffectClass(values.Get(i).Number())
		if effect == controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
			continue
		}
		effects = append(effects, effect)
		names = append(names, `"`+strings.TrimPrefix(effect.String(), "EFFECT_CLASS_")+`"`)
	}
	when := `{"action":{"effect":[` + strings.Join(names, ",") + `]}`
	allowAll = `{"id":"allow-all","effect":"ALLOW","when":` + when + `}}`
	vetoAll = `{"id":"veto-all","effect":"DENY","when":` + when + `,"external":{"denies":true}}}`
	return effects, allowAll, vetoAll
}

// classEnvelope is a call of effect carrying every field any class requires.
func classEnvelope(t *testing.T, effect controlv1.EffectClass) *controlv1.ActionEnvelope {
	t.Helper()
	env := readEnvelope()
	env.Action = &controlv1.Action{Kind: channel.KindTool, Name: "orders.act", Effect: effect, Provider: "orders", Protocol: testProtocol}
	env.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, []byte(`{}`))}
	env.Destination = &controlv1.Destination{TrustZone: controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL, Host: "orders.internal"}
	env.Delegation = []*controlv1.Delegation{{
		From: "user-1", To: "agent-1", Scopes: []string{"orders"},
		IssuedAt: timestamppb.New(base().Add(-time.Hour)), ExpiresAt: timestamppb.New(base().Add(time.Hour)),
	}}
	return env
}

// TestSilenceBlocksEveryEffectClassUnderEnforce: each unanswered state blocks
// a call of every declared effect class whose veto it leaves undetermined,
// with fail_open_read on and off, on a trail that validates, and is counted
// once as what it was.
func TestSilenceBlocksEveryEffectClassUnderEnforce(t *testing.T) {
	effects, allowAll, vetoAll := everyEffectClass()
	ran := 0
	for _, tc := range unanswered() {
		for _, effect := range effects {
			for _, failOpen := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/fail_open_read=%v", tc.name, effect, failOpen), func(t *testing.T) {
					ran++
					dp := tc.dp()
					h := build(t, modeEnforce, snapshot(t, allowAll, vetoAll), withDecisionPoint(dp),
						func(c *gateway.Config) { c.KernelOptions.FailOpenRead = failOpen })
					d := h.admit(classEnvelope(t, effect), []byte(`{}`))
					if d.Action != core.Block || d.AuthorizedArgs != nil {
						t.Errorf("Action = %d, want Block", d.Action)
					}
					expectConsulted(t, h.recorded(t, "req-1"), verdictIndeterminate, tc.code)
					expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
					if err := evidence.ValidateChain(h.events()); err != nil {
						t.Errorf("ValidateChain: %v", err)
					}
					dp.expectAsks(t, 1)
					if s := h.p.Stats().Asks; s.Made != 1 || tc.count(s) != 1 {
						t.Errorf("Stats.Asks = %+v, want one ask counted as %s", s, tc.name)
					}
				})
			}
		}
	}
	declared := controlv1.EffectClass(0).Descriptor().Values().Len() - 1
	if want := len(unanswered()) * declared * 2; ran != want {
		t.Errorf("%d cases ran, want %d", ran, want)
	}
}

// TestADecisionPointCannotChangeWhatIsRecorded: a decision point that writes
// to the envelope it was handed changes neither the proposal on the trail nor
// what the kernel decides again.
func TestADecisionPointCannotChangeWhatIsRecorded(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed(), scribble: true}
	h := build(t, modeEnforce, snapshot(t, allowWrites, vetoWrites), withDecisionPoint(dp))
	env := writeEnvelope()
	d := h.admit(env, []byte(`{"k":1}`))
	if d.Action != core.Execute {
		t.Fatalf("Action = %d, decision %+v", d.Action, d.Decision)
	}
	if got := h.events()[0].GetProposed(); !proto.Equal(got, cleanRun(writeEnvelope())) {
		t.Errorf("ACTION_PROPOSED records %v, want the envelope as proposed", got)
	}
	if !proto.Equal(env, writeEnvelope()) {
		t.Errorf("the caller's envelope became %v", env)
	}
}

// TestObserveRunsASilentCallWithItsDecisionRecorded: OBSERVE enforces no
// decision, so an unanswered write runs, and its trail carries the
// INDETERMINATE decision that names the cause.
func TestObserveRunsASilentCallWithItsDecisionRecorded(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalUnavailable()}
	h := build(t, modeObserve, snapshot(t, allowWrites, vetoWrites), withDecisionPoint(dp))
	d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
	if d.Action != core.Execute {
		t.Fatalf("an unanswered write under OBSERVE: Action = %d", d.Action)
	}
	dp.expectAsks(t, 1)
	expectConsulted(t, h.recorded(t, "req-1"), verdictIndeterminate, codePDPUnavailable)
}

// TestLockdownAsksOnlyAboutWhatItMayRun: under LOCKDOWN a read a veto covers
// is asked about once and runs on the allowing answer. A write, which LOCKDOWN
// blocks whatever the answer, is asked nothing: POLICY_DECIDED keeps the
// kernel's decision with the veto undetermined, no PDP_ code and no
// instance, and the plane's decision is LOCKDOWN (ADR-0019 narrows ADR-0017).
func TestLockdownAsksOnlyAboutWhatItMayRun(t *testing.T) {
	rules := []string{allowReads, allowWrites, vetoReads, vetoWrites}
	t.Run("read", func(t *testing.T) {
		dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
		h := build(t, modeLockdown, snapshot(t, rules...), withDecisionPoint(dp))
		d := h.admit(readEnvelope(), []byte(`{}`))
		if d.Action != core.Execute || d.Decision.GetVerdict() != verdictAllow {
			t.Errorf("a vetoed read on an allowing answer under LOCKDOWN: Action = %d, decision %+v", d.Action, d.Decision)
		}
		dp.expectAsks(t, 1)
		expectConsulted(t, h.recorded(t, "req-1"), verdictAllow, codePDPAllow)
		if s := h.p.Stats().Asks; s != (gateway.Asks{Made: 1, Allowed: 1}) {
			t.Errorf("Stats.Asks = %+v, want one allowing ask", s)
		}
	})
	t.Run("write", func(t *testing.T) {
		dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
		h := build(t, modeLockdown, snapshot(t, rules...), withDecisionPoint(dp))
		d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
		expectBlock(t, d, verdictDeny, codeLockdown, gateway.PDPType)
		if !slices.Equal(d.Decision.GetReasonCodes(), []string{codeLockdown}) || d.Decision.GetEnforcementMode() != modeLockdown {
			t.Errorf("the plane's decision = %+v; want LOCKDOWN alone, in LOCKDOWN mode", d.Decision)
		}
		dp.expectAsks(t, 0)
		expectNotAsked(t, h.recorded(t, "req-1"))
		expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
		if err := evidence.ValidateChain(h.events()); err != nil {
			t.Errorf("ValidateChain: %v", err)
		}
		if s := h.p.Stats().Asks; s != (gateway.Asks{}) {
			t.Errorf("Stats.Asks = %+v, want none", s)
		}
	})
}

// expectNotAsked asserts a recorded decision that did not consult the
// decision point: no PDP_ code, no instance, and the veto it would have read
// left undetermined.
func expectNotAsked(t *testing.T, decided *controlv1.Decision) {
	t.Helper()
	for _, code := range decided.GetReasonCodes() {
		if strings.HasPrefix(code, "PDP_") {
			t.Errorf("POLICY_DECIDED carries %s from a decision point nobody asked: %v", code, decided.GetReasonCodes())
		}
	}
	if decided.GetPdpInstance() != "" {
		t.Errorf("POLICY_DECIDED names instance %q; nobody was asked", decided.GetPdpInstance())
	}
	if !slices.Contains(decided.GetReasonCodes(), codeRuleUndetermined) || decided.GetVerdict() != verdictIndeterminate {
		t.Errorf("POLICY_DECIDED = %s %v; want the unasked veto undetermined", decided.GetVerdict(), decided.GetReasonCodes())
	}
}

// TestAnAskIsTimedApartFromTheKernel: the time spent waiting on the decision
// point is counted by the plane's clock, and the decision's own latency does
// not include it.
func TestAnAskIsTimedApartFromTheKernel(t *testing.T) {
	dp := &fakeDecisionPoint{answer: core.ExternalAllowed()}
	h := build(t, modeEnforce, snapshot(t, allowWrites, vetoWrites), withDecisionPoint(dp))
	dp.during = func() { h.clock.set(h.clock.read().Add(1500 * time.Microsecond)) }
	d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
	if d.Action != core.Execute {
		t.Fatalf("Action = %d, decision %+v", d.Action, d.Decision)
	}
	want := gateway.Asks{Made: 1, Allowed: 1, Micros: 1500}
	if s := h.p.Stats().Asks; s != want {
		t.Errorf("Stats.Asks = %+v, want %+v", s, want)
	}
	if got := h.recorded(t, "req-1").GetDecisionLatencyUs(); got != 0 {
		t.Errorf("decision_latency_us = %d; the kernel's clock did not move while it decided", got)
	}
}

// TestAPolicyThatReadsAnAnswerNobodyGivesBlocks: a bundle that starts reading
// external after New, with no decision point configured, blocks the call as
// unavailable, and names no decision point.
func TestAPolicyThatReadsAnAnswerNobodyGivesBlocks(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowWrites))
	h.policy.snap = snapshot(t, allowWrites, vetoWrites)
	d := h.admit(writeEnvelope(), []byte(`{"k":1}`))
	expectBlock(t, d, verdictIndeterminate, codePDPUnavailable, "builtin")
	if d.Decision.GetPdpInstance() != "" {
		t.Errorf("pdp_instance = %q with no decision point configured", d.Decision.GetPdpInstance())
	}
	if s := h.p.Stats().Asks; s != (gateway.Asks{}) {
		t.Errorf("Stats.Asks = %+v; nothing was asked", s)
	}
}

// TestNewRefusesAMisconfiguredDecisionPoint: a decision point and the
// policy's reading of it are configured together, with an identifier and a
// positive deadline, or not at all.
func TestNewRefusesAMisconfiguredDecisionPoint(t *testing.T) {
	reads := snapshot(t, allowWrites, vetoWrites)
	plain := snapshot(t, allowWrites)
	dp := &fakeDecisionPoint{}
	cases := []struct {
		name string
		mut  func(*gateway.Config)
		want error
	}{
		{"a policy that reads external with no decision point", func(c *gateway.Config) {
			c.Policy = &snapshotSource{snap: reads}
		}, gateway.ErrNoDecisionPoint},
		{"a decision point the policy never consults", func(c *gateway.Config) {
			c.Policy = &snapshotSource{snap: plain}
			withDecisionPoint(dp)(c)
		}, gateway.ErrDecisionPointUnused},
		{"a decision point with no policy yet", withDecisionPoint(dp), gateway.ErrDecisionPointUnused},
		{"a decision point with no identifier", func(c *gateway.Config) {
			c.Policy = &snapshotSource{snap: reads}
			withDecisionPoint(dp)(c)
			c.DecisionPointID = ""
		}, gateway.ErrDecisionPointID},
		{"an identifier with no decision point", func(c *gateway.Config) { c.DecisionPointID = decisionPointID }, gateway.ErrDecisionPointID},
		{"an identifier the kernel refuses", func(c *gateway.Config) {
			c.Policy = &snapshotSource{snap: reads}
			withDecisionPoint(dp)(c)
			c.DecisionPointID = " pdp-1"
		}, core.ErrDecisionPoint},
		{"a zero deadline", func(c *gateway.Config) {
			c.Policy = &snapshotSource{snap: reads}
			withDecisionPoint(dp)(c)
			c.DecisionTimeout = 0
		}, gateway.ErrDecisionTimeout},
		{"a negative deadline", func(c *gateway.Config) {
			c.Policy = &snapshotSource{snap: reads}
			withDecisionPoint(dp)(c)
			c.DecisionTimeout = -time.Nanosecond
		}, gateway.ErrDecisionTimeout},
		{"a deadline with no decision point", func(c *gateway.Config) { c.DecisionTimeout = time.Second }, gateway.ErrDecisionTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			tc.mut(&cfg)
			if p, err := gateway.New(cfg); p != nil || !errors.Is(err, tc.want) {
				t.Errorf("New = (a pipeline: %v), %v; want nil, %v", p != nil, err, tc.want)
			}
		})
	}
	cfg := validConfig(t)
	cfg.Policy = &snapshotSource{snap: reads}
	withDecisionPoint(dp)(&cfg)
	cfg.DecisionTimeout = time.Nanosecond
	if _, err := gateway.New(cfg); err != nil {
		t.Errorf("New with a decision point the policy reads and the smallest deadline: %v", err)
	}
}
