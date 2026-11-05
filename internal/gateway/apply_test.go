package gateway_test

import (
	"bytes"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policy/rules"
)

// checkedOrders is a rule over orders.read and orders.update that attaches
// the obligations, written as JSON.
func checkedOrders(obligations string) string {
	return `{"id":"checked-orders","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[` + obligations + `],"when":{"action":{"name":["orders.read","orders.update"]}}}`
}

// uncheckedSnapshot signs a document the way a signer without the
// catalogue's parameter check would, and loads it: Load does not run that
// check, so the bundle carries what Sign refuses.
func uncheckedSnapshot(t *testing.T, ruleJSON ...string) *policy.Snapshot {
	t.Helper()
	doc, canonical, err := rules.Parse(document(ruleJSON...))
	if err != nil {
		t.Fatalf("Parse refused a document this test builds as valid: %v", err)
	}
	signature, err := bundle.SignBytes(canonical, key())
	if err != nil {
		t.Fatal(err)
	}
	b := &controlv1.PolicyBundle{
		Ref:             &controlv1.PolicyBundleRef{BundleId: doc.Bundle.ID, Version: doc.Bundle.Version, Digest: bundle.Digest(canonical)},
		Canonical:       canonical,
		SignatureAlg:    bundle.SignatureAlg,
		Signature:       signature,
		KeyId:           "k1",
		MaxStaleSeconds: doc.Bundle.MaxStaleSeconds,
	}
	snap, err := policy.Load(b, pinned(), base())
	if err != nil {
		t.Fatalf("Load refused a bundle this test builds as valid: %v", err)
	}
	return snap
}

// executes reports whether d hands the call out to run.
func executes(d gateway.Disposition) bool {
	return d.Action == core.Execute || d.Action == core.ExecuteWithObligations
}

func withResource(env *controlv1.ActionEnvelope, id string) *controlv1.ActionEnvelope {
	env.Resource.Id = id
	return env
}

func withZone(env *controlv1.ActionEnvelope, zone controlv1.TrustZone) *controlv1.ActionEnvelope {
	env.Destination = &controlv1.Destination{TrustZone: zone}
	return env
}

// TestThePipelineAppliesTheEnvelopeChecks: read_only, restrict_resources and
// deny_external_sink are applied by the pipeline for an adapter that declares
// none of them. A call that fails a non-advisory one is the plane's DENY with
// OBLIGATION_NOT_UNDERSTOOD over the kernel's ALLOW_WITH_OBLIGATIONS; one that
// holds executes with nothing left for the adapter. A trust zone or a
// resource id nobody stated restricts.
func TestThePipelineAppliesTheEnvelopeChecks(t *testing.T) {
	const (
		readOnly = `{"type":"read_only"}`
		noSink   = `{"type":"deny_external_sink"}`
		srvData  = `{"type":"restrict_resources","params":{"prefix":"/srv/data/"}}`
	)
	ids := func(list string) string { return `{"type":"restrict_resources","params":{"ids":"` + list + `"}}` }
	prefix := func(p string) string { return `{"type":"restrict_resources","params":{"prefix":"` + p + `"}}` }
	cases := []struct {
		name  string
		rule  string
		env   *controlv1.ActionEnvelope
		allow bool
	}{
		{"read_only on a read", readOnly, readEnvelope(), true},
		{"read_only on a write", readOnly, writeEnvelope(), false},
		{"deny_external_sink to a trusted zone", noSink, withZone(readEnvelope(), controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL), true},
		{"deny_external_sink to a partner", noSink, withZone(readEnvelope(), controlv1.TrustZone_TRUST_ZONE_PARTNER), true},
		{"deny_external_sink to an untrusted zone", noSink, withZone(readEnvelope(), controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL), false},
		{"deny_external_sink to an unstated zone", noSink, withZone(readEnvelope(), controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED), false},
		{"deny_external_sink with no destination", noSink, readEnvelope(), false},
		{"restrict_resources, an exact id", ids("ord-0,ord-1"), readEnvelope(), true},
		{"restrict_resources, exact ids only", ids("ord-0,ord-10"), readEnvelope(), false},
		{"restrict_resources, under the prefix", srvData, withResource(readEnvelope(), "/srv/data/x"), true},
		{"restrict_resources, a string prefix only", srvData, withResource(readEnvelope(), "/srv/database"), false},
		{"restrict_resources, dot-dot", prefix("a/"), withResource(readEnvelope(), "a/../b"), false},
		{"restrict_resources, an encoded dot-dot", prefix("a/"), withResource(readEnvelope(), "a/%2e%2e"), false},
		{"restrict_resources, an empty segment", prefix("a/"), withResource(readEnvelope(), "a//b"), false},
		{"restrict_resources, a plain id under the same prefix", prefix("a/"), withResource(readEnvelope(), "a/b"), true},
		{"restrict_resources, an empty id", prefix("ord"), withResource(readEnvelope(), ""), false},
		{"all three hold", readOnly + "," + noSink + "," + ids("ord-1"), withZone(readEnvelope(), controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL), true},
		{"the last of three fails", readOnly + "," + noSink + "," + ids("ord-2"), withZone(readEnvelope(), controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := build(t, modeEnforce, snapshot(t, checkedOrders(tc.rule)))
			args := []byte(`{"id": 1}`)
			d := h.admit(tc.env, args)
			events := h.events()
			if len(events) < 2 || events[1].GetDecision().GetVerdict() != verdictObligations {
				t.Fatalf("POLICY_DECIDED is not the kernel's ALLOW_WITH_OBLIGATIONS: %v", kindsOf(events))
			}
			if !tc.allow {
				expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
				expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
				return
			}
			if !executes(d) || len(d.Obligations) != 0 || !bytes.Equal(d.AuthorizedArgs, args) {
				t.Errorf("Action = %d, obligations %v, args %q; want it run with the proposed bytes and nothing left", d.Action, d.Obligations, d.AuthorizedArgs)
			}
			expectKinds(t, kindsOf(events), []controlv1.EventKind{kindProposed, kindDecided, kindStarted})
		})
	}
}

// TestAnEnvelopeCheckWithAnUnreadParameterDenies: a bundle signed without the
// catalogue's check can carry a parameter the type does not read; the
// obligation carrying it is not applied, so the call is denied, and an
// advisory one is neither applied nor passed on.
func TestAnEnvelopeCheckWithAnUnreadParameterDenies(t *testing.T) {
	for _, tc := range []struct{ name, without, with string }{
		{"read_only", `{"type":"read_only"}`, `{"type":"read_only","params":{"ids":"ord-1"}}`},
		{"restrict_resources", `{"type":"restrict_resources","params":{"ids":"ord-1"}}`, `{"type":"restrict_resources","params":{"ids":"ord-1","ms":"5"}}`},
		{"deny_external_sink", `{"type":"deny_external_sink"}`, `{"type":"deny_external_sink","params":{"x":"1"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := func() *controlv1.ActionEnvelope {
				return withZone(readEnvelope(), controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL)
			}
			if d := build(t, modeEnforce, uncheckedSnapshot(t, checkedOrders(tc.without))).admit(env(), []byte(`{}`)); !executes(d) || len(d.Obligations) != 0 {
				t.Fatalf("without the extra parameter: Action = %d, %v", d.Action, d.Decision.GetReasonCodes())
			}
			d := build(t, modeEnforce, uncheckedSnapshot(t, checkedOrders(tc.with))).admit(env(), []byte(`{}`))
			expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
			advisory := tc.with[:len(tc.with)-1] + `,"advisory":true}`
			d = build(t, modeEnforce, uncheckedSnapshot(t, checkedOrders(advisory))).admit(env(), []byte(`{}`))
			if !executes(d) || len(d.Obligations) != 0 {
				t.Errorf("advisory with an extra parameter: Action = %d, obligations %v", d.Action, d.Obligations)
			}
		})
	}
}

// TestAnAdvisoryEnvelopeCheckIsNeitherAppliedNorPassedOn: a failing advisory
// check lets the call run and reaches no adapter, which could not apply it;
// the other obligations still travel.
func TestAnAdvisoryEnvelopeCheckIsNeitherAppliedNorPassedOn(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, checkedOrders(`{"type":"read_only","advisory":true},{"type":"cap_rate","advisory":true}`)))
	d := h.admit(writeEnvelope(), []byte(`{}`))
	if d.Action != core.ExecuteWithObligations {
		t.Fatalf("Action = %d, %v; want ExecuteWithObligations", d.Action, d.Decision.GetReasonCodes())
	}
	if len(d.Obligations) != 1 || d.Obligations[0].GetType() != "cap_rate" {
		t.Errorf("Obligations = %v, want cap_rate alone", d.Obligations)
	}
	h = build(t, modeEnforce, snapshot(t, checkedOrders(`{"type":"read_only","advisory":true}`)))
	if d := h.admit(writeEnvelope(), []byte(`{}`)); !executes(d) || len(d.Obligations) != 0 {
		t.Errorf("an advisory read_only alone: Action = %d, obligations %v; want it run with none", d.Action, d.Obligations)
	}
}

// TestObserveAppliesNoEnvelopeCheck: under OBSERVE a call that fails a check
// executes with the proposed bytes and the kernel's decision recorded.
func TestObserveAppliesNoEnvelopeCheck(t *testing.T) {
	h := build(t, modeObserve, snapshot(t, checkedOrders(`{"type":"read_only"},{"type":"deny_external_sink"}`)))
	args := []byte(`{"k": 1}`)
	d := h.admit(writeEnvelope(), args)
	if d.Action != core.Execute || !bytes.Equal(d.AuthorizedArgs, args) || d.Obligations != nil {
		t.Errorf("under OBSERVE: Action = %d, args %q, obligations %v", d.Action, d.AuthorizedArgs, d.Obligations)
	}
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindStarted})
	// The same call under ENFORCE is the control.
	d = build(t, modeEnforce, snapshot(t, checkedOrders(`{"type":"read_only"},{"type":"deny_external_sink"}`))).admit(writeEnvelope(), args)
	expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
}

// TestApproveDeniesACallThatFailsACheck: under APPROVE a material call that
// fails a check is denied, not held for an approval that could not let it
// run; one that holds is held.
func TestApproveDeniesACallThatFailsACheck(t *testing.T) {
	h := build(t, modeApprove, snapshot(t, checkedOrders(`{"type":"restrict_resources","params":{"ids":"ord-2"}}`)))
	d := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
	if slices.Contains(h.kinds(), kindApprovalRequested) {
		t.Errorf("a call that fails a check was held: %v", h.kinds())
	}
	h = build(t, modeApprove, snapshot(t, checkedOrders(`{"type":"restrict_resources","params":{"ids":"ord-1"}}`)))
	if d := h.admit(writeEnvelope(), []byte(`{}`)); d.Action != core.AwaitApproval || d.Pending == nil {
		t.Errorf("a call that holds under APPROVE: Action = %d, pending %+v; want it held", d.Action, d.Pending)
	}
}

// TestARequiredApprovalThatFailsACheckIsBlocked: under ENFORCE a
// REQUIRE_APPROVAL rule's failing check blocks the call instead of holding it
// for an approval that could not let it run; one that holds is held.
func TestARequiredApprovalThatFailsACheckIsBlocked(t *testing.T) {
	held := func(obligation string) string {
		return `{"id":"held-orders","effect":"REQUIRE_APPROVAL","obligations":[` + obligation + `],"when":{"action":{"name":["orders.update"]}}}`
	}
	h := build(t, modeEnforce, snapshot(t, held(`{"type":"read_only"}`)))
	d := h.admit(writeEnvelope(), []byte(`{}`))
	expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
	if codes := d.Decision.GetReasonCodes(); !slices.Equal(codes, []string{codeObligationNotUnderstood}) {
		t.Errorf("the block carries %v, want %s alone", codes, codeObligationNotUnderstood)
	}
	expectKinds(t, h.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	h = build(t, modeEnforce, snapshot(t, held(`{"type":"restrict_resources","params":{"ids":"ord-1"}}`)))
	if d := h.admit(writeEnvelope(), []byte(`{}`)); d.Action != core.AwaitApproval || d.Pending == nil {
		t.Errorf("a required approval whose check holds: Action = %d, pending %+v; want it held", d.Action, d.Pending)
	}
}

// TestPlaneObligationsAreTheRewritingThenTheCheckingTypes: the list New
// declares to the kernel, as a copy.
func TestPlaneObligationsAreTheRewritingThenTheCheckingTypes(t *testing.T) {
	want := []string{"redact_fields", "cap_amount", "read_only", "restrict_resources", "deny_external_sink"}
	got := gateway.PlaneObligations()
	if !slices.Equal(got, want) {
		t.Fatalf("PlaneObligations = %v, want %v", got, want)
	}
	got[0] = "cap_rate"
	if again := gateway.PlaneObligations(); !slices.Equal(again, want) {
		t.Errorf("a caller's change reached the list: %v", again)
	}
}
