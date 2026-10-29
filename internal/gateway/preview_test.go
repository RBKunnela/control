package gateway_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
)

// unclassified is a call nothing classifies, as an adapter hands it over:
// every part of the envelope but the effect, and the sentinel wrapped.
func unclassified(args []byte) gateway.Admission {
	env := writeEnvelope()
	env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	a := admission(env, args)
	a.Refusal = fmt.Errorf("adapter: tool %q: %w", "orders.update", gateway.ErrUnclassified)
	return a
}

// TestAnUnclassifiedCallIsBlockedInEveryModeButObserve: the plane's own
// INDETERMINATE ACTION_UNCLASSIFIED blocks it, and the kernel's decision is
// what POLICY_DECIDED records. Under LOCKDOWN the call, whose effect nothing
// names, is material too, so both causes are listed, the DENY first.
func TestAnUnclassifiedCallIsBlockedInEveryModeButObserve(t *testing.T) {
	for _, mode := range []controlv1.EnforcementMode{modeEnforce, modeApprove, modeLockdown} {
		h := build(t, mode, snapshot(t, allowWrites))
		d := h.p.Admit(context.Background(), unclassified([]byte(`{}`)))
		verdict, codes := verdictIndeterminate, []string{codeActionUnclassified}
		if mode == modeLockdown {
			verdict, codes = verdictDeny, []string{codeLockdown, codeActionUnclassified}
		}
		expectBlock(t, d, verdict, codeActionUnclassified, gateway.PDPType)
		if !slices.Equal(d.Decision.GetReasonCodes(), codes) {
			t.Errorf("%s: the plane's codes = %v, want %v", mode, d.Decision.GetReasonCodes(), codes)
		}
		events := h.events()
		expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
		if decided := events[1].GetDecision(); decided.GetPdpType() != "builtin" || slices.Contains(decided.GetReasonCodes(), codeActionUnclassified) {
			t.Errorf("%s: POLICY_DECIDED = %+v; want the kernel's decision as it is", mode, decided)
		}
		if err := evidence.ValidateChain(events); err != nil {
			t.Errorf("%s: ValidateChain: %v", mode, err)
		}
		if h.p.Stats().Blocks[codes[0]] != 1 {
			t.Errorf("%s: Stats().Blocks = %v, want one under %s", mode, h.p.Stats().Blocks, codes[0])
		}
	}
}

// TestAnUnclassifiedCallRunsUnderObserve: OBSERVE enforces no decision and
// takes a call nothing classifies, so the call runs with its proposed bytes,
// the trail holds the kernel's decision alone, and it closes clean with the
// digest of the bytes sent, which the refused decision does not carry; a nil
// envelope still blocks.
func TestAnUnclassifiedCallRunsUnderObserve(t *testing.T) {
	h := build(t, modeObserve, snapshot(t, allowWrites))
	args := []byte(`{"k": 1}`)
	a := unclassified(args)
	d := h.p.Admit(context.Background(), a)
	if d.Action != core.Execute || !bytes.Equal(d.AuthorizedArgs, args) {
		t.Fatalf("under OBSERVE: Action = %d, args %q; want the proposed bytes run", d.Action, d.AuthorizedArgs)
	}
	for _, e := range h.events() {
		if slices.Contains(e.GetDecision().GetReasonCodes(), codeActionUnclassified) {
			t.Errorf("under OBSERVE the trail carries %s on %s", codeActionUnclassified, e.GetKind())
		}
	}
	if err := h.p.Close(context.Background(), d, args, result(controlv1.ResultStatus_RESULT_STATUS_SUCCESS)); err != nil {
		t.Errorf("Close of the observed call: %v", err)
	}
	expectSentDigestOnly(t, h.events(), actionDigest(t, a.Envelope, string(args)))
	if s := h.p.Stats(); s.Halted || s.Mismatches != 0 {
		t.Errorf("Stats = %+v", s)
	}
	// A nil envelope blocks under OBSERVE too: nothing can be written about it.
	if d := h.p.Admit(context.Background(), gateway.Admission{Refusal: gateway.ErrUnclassified}); d.Action != core.Block {
		t.Errorf("a nil envelope under OBSERVE: Action = %d, want Block", d.Action)
	}
}

// expectSentDigestOnly asserts a trail whose POLICY_DECIDED carries no action
// digest and whose ACTION_COMPLETED carries sent, the digest of the bytes sent.
func expectSentDigestOnly(t *testing.T, events []*controlv1.Event, sent string) {
	t.Helper()
	decided, closing := events[1], events[len(events)-1]
	if decided.GetKind() != kindDecided || decided.GetDecision().GetActionDigest() != "" ||
		closing.GetKind() != kindCompleted || closing.GetResult().GetExecutedActionDigest() != sent {
		t.Errorf("the refused decision carries digest %q and the closing %s carries %q; want none on the decision and the sent bytes' on %s",
			decided.GetDecision().GetActionDigest(), closing.GetKind(), closing.GetResult().GetExecutedActionDigest(), kindCompleted)
	}
}

// TestPreviewDecidesWithoutActing: the kernel's decision, the mode's block
// on top of it, and nothing written, held, rewritten or counted.
func TestPreviewDecidesWithoutActing(t *testing.T) {
	locked := build(t, modeLockdown, snapshot(t, allowReads, allowWrites))
	if d := locked.p.Preview(context.Background(), admission(writeEnvelope(), nil)); d.GetVerdict() != verdictDeny ||
		!slices.Equal(d.GetReasonCodes(), []string{codeLockdown}) || d.GetPdpType() != gateway.PDPType {
		t.Errorf("a write under LOCKDOWN previews as %+v; want the plane's LOCKDOWN", d)
	}
	if d := locked.p.Preview(context.Background(), admission(readEnvelope(), nil)); d.GetVerdict() != verdictAllow {
		t.Errorf("a read under LOCKDOWN previews as %+v; want the kernel's ALLOW", d)
	}
	h := build(t, modeEnforce, snapshot(t, denyWrites, approveRefunds, allowReads))
	if d := h.p.Preview(context.Background(), admission(writeEnvelope(), nil)); d.GetVerdict() != verdictDeny || d.GetPdpType() != "builtin" {
		t.Errorf("a denied write previews as %+v", d)
	}
	if d := h.p.Preview(context.Background(), admission(refundEnvelope(t, nil), nil)); d.GetVerdict() != verdictApproval {
		t.Errorf("a refund previews as %+v; want the kernel's REQUIRE_APPROVAL", d)
	}
	if d := h.p.Preview(context.Background(), unclassified(nil)); !slices.Equal(d.GetReasonCodes(), []string{codeActionUnclassified}) {
		t.Errorf("an unclassified call previews as %+v", d)
	}
	for name, p := range map[string]*harness{"lockdown": locked, "enforce": h} {
		expectUntouched(t, name, p)
	}
}

// expectUntouched asserts nothing was written or counted.
func expectUntouched(t *testing.T, name string, h *harness) {
	t.Helper()
	if n := len(h.events()); n != 0 {
		t.Errorf("%s: Preview wrote %d event(s)", name, n)
	}
	if s := h.p.Stats(); len(s.Blocks) != 0 || s.Pending != 0 || s.Executed != 0 || s.Held != 0 || s.Open != 0 {
		t.Errorf("%s: Preview counted %+v", name, s)
	}
}

// TestAnUnbuiltPipelinePreviewsTheUnbuiltDecision: nil and zero answer the
// decision of a kernel nobody built.
func TestAnUnbuiltPipelinePreviewsTheUnbuiltDecision(t *testing.T) {
	for name, p := range map[string]*gateway.Pipeline{"nil": nil, "zero": new(gateway.Pipeline)} {
		d := p.Preview(context.Background(), admission(readEnvelope(), nil))
		if d.GetVerdict() != verdictIndeterminate || !slices.Equal(d.GetReasonCodes(), []string{codePolicyUnavailable}) {
			t.Errorf("%s pipeline previews as %+v", name, d)
		}
	}
}
