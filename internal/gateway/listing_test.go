package gateway_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
)

// readOrderOne allows a read of one order alone; a preview, which carries no
// resource id, leaves its match unknown. readAsService allows a read by a
// principal of a type the test envelopes never carry. writeInFlow allows a
// write the run's flow decides, which a preview, reading no run, cannot
// tell; writeOrderOne allows the write of ord-1.
const (
	readOrderOne  = `{"id":"read-order-one","effect":"ALLOW","when":{"action":{"effect":["READ"]},"resource":{"id":["ord-1"]}}}`
	readAsService = `{"id":"read-as-service","effect":"ALLOW","when":{"action":{"effect":["READ"]},"principal":{"type":["service"]}}}`
	writeInFlow   = `{"id":"write-in-flow","effect":"ALLOW","when":{"action":{"effect":["WRITE"]},"flow":{"toxicAtLeast":"CONFIDENTIAL"}}}`
	writeOrderOne = `{"id":"write-order-one","effect":"ALLOW","when":{"action":{"effect":["WRITE"]},"resource":{"id":["ord-1"]}}}`
)

// listed is env as a listing previews a tool: no resource id, and the
// classification pointer the call's id would be read from, when from is set.
func listed(env *controlv1.ActionEnvelope, from string) gateway.Admission {
	env.Resource.Id = ""
	a := admission(env, nil)
	a.Classification = classify.Classification{Effect: env.GetAction().GetEffect(), ResourceType: "order", ResourceFrom: from}
	return a
}

// orderTwo is a write of ord-2, which writeOrderOne does not allow, as a
// listing previews it.
func orderTwo() gateway.Admission {
	env := writeEnvelope()
	env.Resource.Id = "ord-2"
	return admission(env, nil)
}

func expectListing(t *testing.T, what string, got gateway.Previewed, verdict controlv1.Verdict, codes []string, listing gateway.Listing) {
	t.Helper()
	if got.Decision.GetVerdict() != verdict || !slices.Equal(got.Decision.GetReasonCodes(), codes) || got.Listing != listing {
		t.Errorf("%s previews as %s %q listing %d, want %s %q listing %d",
			what, got.Decision.GetVerdict(), got.Decision.GetReasonCodes(), got.Listing, verdict, codes, listing)
	}
}

// TestAToolOnlyItsCallCanDecideIsDecidedPerCall: an ALLOW that reads the
// resource id cannot be told without the call, so the kernel's DENY for no
// matching rule leaves a tool whose call brings that id to be decided per
// call, and the decision itself is unchanged. The call that names the
// allowed id runs; one that names another is denied.
func TestAToolOnlyItsCallCanDecideIsDecidedPerCall(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, readOrderOne))
	expectListing(t, "a read of an unnamed order", h.p.Preview(context.Background(), listed(readEnvelope(), "/order")),
		verdictDeny, []string{codeNoMatchingRule}, gateway.ListingPerCall)
	if d := h.admit(readEnvelope(), []byte(`{}`)); d.Decision.GetVerdict() != verdictAllow || d.ExecutionID == "" {
		t.Errorf("a read of ord-1 is %s %v, want ALLOW and handed out", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
	other := requestNamed(readEnvelope(), "req-2")
	other.Resource.Id = "ord-2"
	if d := h.admit(other, []byte(`{}`)); d.Decision.GetVerdict() != verdictDeny || d.ExecutionID != "" ||
		!slices.Equal(d.Decision.GetReasonCodes(), []string{codeNoMatchingRule}) {
		t.Errorf("a read of ord-2 is %s %v, want the DENY of no matching rule", d.Decision.GetVerdict(), d.Decision.GetReasonCodes())
	}
}

// TestAnAllowNoCallCanMeetIsDenied: an ALLOW unknown on an input no call
// brings differently from the preview leaves every call denied, so the tool
// is denied to the listing: a resource id with no pointer to read it from,
// and a principal's type, which the call carries as the preview did.
func TestAnAllowNoCallCanMeetIsDenied(t *testing.T) {
	ctx := context.Background()
	h := build(t, modeEnforce, snapshot(t, readOrderOne))
	expectListing(t, "a read with no pointer", h.p.Preview(ctx, listed(readEnvelope(), "")),
		verdictDeny, []string{codeNoMatchingRule}, gateway.ListingDenied)
	typed := build(t, modeEnforce, snapshot(t, readAsService))
	expectListing(t, "a read as a service", typed.p.Preview(ctx, listed(readEnvelope(), "/order")),
		verdictDeny, []string{codeNoMatchingRule}, gateway.ListingDenied)
}

// TestADenyThatHoldsWithoutTheCallIsDenied: beside an ALLOW a call could
// meet, a DENY that needs nothing of the call is denied to the listing: a
// matched DENY rule, LOCKDOWN on a material call and the plane's halt after
// a mismatch. So is the DENY of no matching rule when no ALLOW was unknown.
// Each has a twin that is decided per call, so what the twin lacks is what
// denies it.
func TestADenyThatHoldsWithoutTheCallIsDenied(t *testing.T) {
	ctx := context.Background()
	matched := build(t, modeEnforce, snapshot(t, readOrderOne, denyReads))
	expectListing(t, "a read beside a matched DENY", matched.p.Preview(ctx, listed(readEnvelope(), "/order")),
		verdictDeny, []string{codeRuleDeny}, gateway.ListingDenied)

	writes := build(t, modeEnforce, snapshot(t, writeInFlow, writeOrderOne))
	expectListing(t, "a read nothing could allow", writes.p.Preview(ctx, listed(readEnvelope(), "/order")),
		verdictDeny, []string{codeNoMatchingRule}, gateway.ListingDenied)
	expectListing(t, "a write of ord-2 under ENFORCE", writes.p.Preview(ctx, orderTwo()),
		verdictDeny, []string{codeNoMatchingRule}, gateway.ListingPerCall)

	locked := build(t, modeLockdown, snapshot(t, writeInFlow, writeOrderOne))
	expectListing(t, "a write of ord-2 under LOCKDOWN", locked.p.Preview(ctx, orderTwo()),
		verdictDeny, []string{codeLockdown}, gateway.ListingDenied)

	earlier := writes.admit(writeEnvelope(), []byte(`{"amount":1}`))
	if err := writes.p.Close(ctx, earlier, []byte(`{"amount":2}`), successResult); !errors.Is(err, gateway.ErrExecutedArgsMismatch) {
		t.Fatalf("setup: Close with other bytes = %v, want ErrExecutedArgsMismatch", err)
	}
	expectListing(t, "a write of ord-2 after a mismatch", writes.p.Preview(ctx, orderTwo()),
		verdictDeny, []string{codeExecutedArgsMismatch}, gateway.ListingDenied)
}

// TestAVerdictThatLetsTheCallGoIsDecided: ALLOW, ALLOW_WITH_OBLIGATIONS and
// REQUIRE_APPROVAL are decided; INDETERMINATE, and a pipeline nobody built,
// are decided per call.
func TestAVerdictThatLetsTheCallGoIsDecided(t *testing.T) {
	ctx := context.Background()
	h := build(t, modeEnforce, snapshot(t, allowReads, approveRefunds))
	expectListing(t, "a read", h.p.Preview(ctx, admission(readEnvelope(), nil)),
		verdictAllow, []string{codeRuleAllow}, gateway.ListingDecided)
	expectListing(t, "a refund", h.p.Preview(ctx, admission(refundEnvelope(t, nil), nil)),
		verdictApproval, []string{codeApprovalRequired}, gateway.ListingDecided)
	capped := build(t, modeEnforce, snapshot(t, cappedRefunds))
	expectListing(t, "a capped refund", capped.p.Preview(ctx, admission(refundEnvelope(t, nil), nil)),
		verdictObligations, []string{codeObligationsAttached}, gateway.ListingDecided)
	expectListing(t, "an unclassified call", h.p.Preview(ctx, unclassified(nil)),
		verdictIndeterminate, []string{codeActionUnclassified}, gateway.ListingPerCall)
	expectListing(t, "a nil pipeline's read", (*gateway.Pipeline)(nil).Preview(ctx, admission(readEnvelope(), nil)),
		verdictIndeterminate, []string{codePolicyUnavailable}, gateway.ListingPerCall)
}
