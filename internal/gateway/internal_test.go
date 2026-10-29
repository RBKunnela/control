package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
)

// The guards in this file have no input that reaches them through Admit: the
// kernel reads no argument value, so the second decision of one call repeats
// the first, and a bundle that changes changes the binding as well. They are
// held here against the state they defend against, so neither can be replaced
// with a pass.

// capping rewrites a refund's arguments, so a second decision carries
// obligations of its own.
const capping = `{"id":"capping","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_amount","params":{"max":"1000"}}],"when":{"action":{"name":["refund"]}}}`

func internalClock() time.Time {
	return time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
}

type internalAdapter struct{}

func (internalAdapter) Name() string { return channel.ProtocolMCP }

func (internalAdapter) Capabilities() Capabilities {
	return Capabilities{ObserveRequest: true, ObserveResult: true, Enforcement: EnforcementInline}
}

// internalPipeline is a pipeline over one rule, with everything else the
// smallest thing New accepts.
func internalPipeline(t *testing.T) (*Pipeline, *policy.Snapshot) {
	t.Helper()
	document := []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"payments","version":"1","serial":1,"maxStaleSeconds":600},"rules":[` + capping + `]}`)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	signed, err := policy.Sign(document, key, "k1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	keyring := bundle.Keyring{"k1": ed25519.PublicKey(slices.Clone(key[ed25519.SeedSize:]))}
	snap, err := policy.Load(signed, keyring, internalClock())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ids := 0
	p, err := New(Config{
		Mode:          modeEnforce,
		Adapter:       internalAdapter{},
		KernelOptions: core.Options{MaxStale: 10 * time.Minute},
		Policy:        staticPolicy{snap},
		Pause:         PauseDisabled(),
		Stops:         StopsDisabled(),
		Sink:          &evidence.MemorySink{},
		Approvals:     &MemoryApprovals{},
		Clock:         internalClock,
		NewID:         func() string { ids++; return "id-" + strconv.Itoa(ids) },
		ApprovalTTL:   time.Minute,
		RetryAfter:    time.Second,
		MaxHeld:       4,
		MaxOpen:       4,
		MaxRuns:       4,
	})
	if err != nil {
		t.Fatalf("New refused a configuration this test builds as valid: %v", err)
	}
	return p, snap
}

type staticPolicy struct{ snap *policy.Snapshot }

func (s staticPolicy) Current() *policy.Snapshot { return s.snap }

// refundCall is a call whose proposed arguments the capping rule rewrites, at
// the point authorize has decided the proposed envelope.
func refundCall(t *testing.T, p *Pipeline, snap *policy.Snapshot, authorized []byte) *call {
	t.Helper()
	proposed := []byte(`{"amount":5000}`)
	hash, err := canon.ArgumentsHashV1(proposed)
	if err != nil {
		t.Fatalf("ArgumentsHashV1: %v", err)
	}
	env := &controlv1.ActionEnvelope{
		SchemaVersion: "1.0",
		RequestId:     "req-1",
		ProjectId:     "proj-1",
		TenantId:      "tenant-1",
		Environment:   "prod",
		OccurredAt:    timestamppb.New(internalClock().Add(-time.Minute)),
		Context:       &controlv1.RunContext{RunId: "run-1"},
		Principal:     &controlv1.Principal{Id: "user-1", TenantId: "tenant-1"},
		Agent:         &controlv1.Agent{Id: "agent-1"},
		Action:        &controlv1.Action{Kind: channel.KindTool, Name: "refund", Effect: controlv1.EffectClass_EFFECT_CLASS_TRANSACT, Provider: "payments", Protocol: channel.ProtocolMCP},
		Resource:      &controlv1.Resource{Type: "order", Id: "ord-1", TenantId: "tenant-1", Environment: "prod"},
		Arguments:     &controlv1.Arguments{CanonicalHash: hash},
	}
	c := p.newCall(context.Background(), Admission{Envelope: env, Arguments: proposed})
	c.decideProposed(snap, true)
	authorizedHash, err := canon.ArgumentsHashV1(authorized)
	if err != nil {
		t.Fatalf("ArgumentsHashV1: %v", err)
	}
	c.args, c.digest, c.env = authorized, authorizedHash, authorizedEnvelope(env, authorizedHash)
	return c
}

// TestDecideAuthorizedRefusesBytesTheSecondDecisionDoesNotProduce: the second
// decision is enforced as it is, and it may let the call proceed only when its
// own rewriting obligations give exactly the bytes it was asked about
// (ADR-0013).
func TestDecideAuthorizedRefusesBytesTheSecondDecisionDoesNotProduce(t *testing.T) {
	p, snap := internalPipeline(t)
	c := refundCall(t, p, snap, []byte(`{"amount":5000}`))
	if c.decideAuthorized(snap) {
		t.Fatalf("decideAuthorized accepted bytes the obligations do not produce: %s", c.args)
	}
	if c.action != core.Block || c.decision.GetVerdict() != verdictDeny || firstCode(c.decision) != codeObligationNotApplied {
		t.Errorf("the refusal is action %d, %s, %v; want a DENY blocked with %s",
			c.action, c.decision.GetVerdict(), c.decision.GetReasonCodes(), codeObligationNotApplied)
	}
	// The bytes the same obligations do produce go on, with nothing left over.
	p, snap = internalPipeline(t)
	c = refundCall(t, p, snap, []byte(`{"amount":1000}`))
	if !c.decideAuthorized(snap) || c.action == core.Block || len(c.rest) != 0 {
		t.Errorf("the capped bytes: %v, action %d, %d obligation(s) left", c.decision.GetReasonCodes(), c.action, len(c.rest))
	}
}

// TestSameDecisionHoldsEveryFieldAnApprovalWasGivenFor: a held request resumes
// only while the fresh decision equals the held one in verdict, digest, rule
// ids and obligations, so each has an input at which it refuses the resume.
func TestSameDecisionHoldsEveryFieldAnApprovalWasGivenFor(t *testing.T) {
	held := &controlv1.Decision{
		Verdict:       controlv1.Verdict_VERDICT_REQUIRE_APPROVAL,
		ActionDigest:  "sha256:" + string(bytes.Repeat([]byte{'a'}, 64)),
		PolicyRuleIds: []string{"approve-refunds"},
		Obligations:   []*controlv1.Obligation{obligation("cap_amount", false, "max", "1000")},
	}
	if !sameDecision(held, proto.CloneOf(held)) {
		t.Fatalf("the same decision twice is not the same decision")
	}
	for name, mut := range map[string]func(*controlv1.Decision){
		"another verdict":    func(d *controlv1.Decision) { d.Verdict = controlv1.Verdict_VERDICT_ALLOW },
		"another digest":     func(d *controlv1.Decision) { d.ActionDigest = "sha256:" + string(bytes.Repeat([]byte{'b'}, 64)) },
		"another rule":       func(d *controlv1.Decision) { d.PolicyRuleIds = []string{"approve-tainted-refunds"} },
		"one rule more":      func(d *controlv1.Decision) { d.PolicyRuleIds = append(d.PolicyRuleIds, "other") },
		"another cap":        func(d *controlv1.Decision) { d.Obligations[0].Params["max"] = "2000" },
		"another obligation": func(d *controlv1.Decision) { d.Obligations[0].Type = "redact_fields" },
		"an advisory cap":    func(d *controlv1.Decision) { d.Obligations[0].Advisory = true },
		"one obligation more": func(d *controlv1.Decision) {
			d.Obligations = append(d.Obligations, obligation("cap_rate", true, "per_minute", "60"))
		},
		"no obligation": func(d *controlv1.Decision) { d.Obligations = nil },
	} {
		fresh := proto.CloneOf(held)
		mut(fresh)
		if sameDecision(held, fresh) {
			t.Errorf("a decision with %s resumes the hold", name)
		}
	}
	if sameDecision(nil, held) || sameDecision(held, nil) || sameDecision(nil, nil) {
		t.Errorf("a decision nobody made resumes a hold")
	}
}

// SetRunStateWait makes d the bound on a raise's wait for its root's lock
// until the returned function restores it.
func SetRunStateWait(d time.Duration) (restore func()) {
	saved := runStateWait
	runStateWait = d
	return func() { runStateWait = saved }
}
