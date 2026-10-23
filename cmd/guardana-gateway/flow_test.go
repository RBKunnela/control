package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	toolclass "github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
)

// TestAnOverrideCarriesWhatItsToolReturns: the result classification reaches
// the adapter apart from the destination, and a silent override declares the
// restrictive answers.
func TestAnOverrideCarriesWhatItsToolReturns(t *testing.T) {
	cfg := &gatewayconfig.Config{Overrides: []gatewayconfig.OverrideConfig{
		{
			Upstream:    "u",
			Tool:        "fetch",
			Fingerprint: "f",
			Spelling: toolclass.Spelling{
				Effect:             "READ",
				ResourceType:       "page",
				TrustZone:          "UNTRUSTED_EXTERNAL",
				ReturnsTrust:       "PARTNER",
				ReturnsSensitivity: "RESTRICTED",
			},
		},
		{Upstream: "u", Tool: "mail", Fingerprint: "f", Spelling: toolclass.Spelling{Effect: "COMMUNICATE", ResourceType: "mailbox", TrustZone: "PARTNER"}},
	}}
	out, err := overrides(cfg)
	if err != nil {
		t.Fatalf("overrides: %v", err)
	}
	if o := out[0]; o.TrustZone != controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL ||
		o.ReturnsTrust != controlv1.TrustZone_TRUST_ZONE_PARTNER || o.ReturnsSensitivity != controlv1.Sensitivity_SENSITIVITY_RESTRICTED {
		t.Errorf("a declared override: %s, returns %s %s", o.TrustZone, o.ReturnsTrust, o.ReturnsSensitivity)
	}
	if o := out[1]; o.TrustZone != controlv1.TrustZone_TRUST_ZONE_PARTNER ||
		o.ReturnsTrust != controlv1.TrustZone_TRUST_ZONE_UNSPECIFIED || o.ReturnsSensitivity != controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED {
		t.Errorf("a silent override: %s, returns %s %s", o.TrustZone, o.ReturnsTrust, o.ReturnsSensitivity)
	}
	cfg.Overrides[1].ReturnsSensitivity = "UNSPECIFIED"
	if _, err := overrides(cfg); err == nil {
		t.Error("an override declaring its results UNSPECIFIED was taken")
	}
}

// TestHealthCountsTheRuns: /healthz reports the runs the plane keeps a flow
// state for and the calls it decided with none, each from its own field.
func TestHealthCountsTheRuns(t *testing.T) {
	out := pipelineCounters(gateway.Stats{Runs: 3, FlowUncomputed: 5}, adaptermcp.Stats{})
	if out["runs"] != 3 || out["flow_uncomputed"] != uint64(5) {
		t.Errorf("runs %v, flow_uncomputed %v; want 3 and 5", out["runs"], out["flow_uncomputed"])
	}
}

// TestDoctorSaysWhatEachToolReturns: an override's result classification is
// printed beside its destination, and an absent one as what absence means.
func TestDoctorSaysWhatEachToolReturns(t *testing.T) {
	tr := newTree(t)
	withConfig(t, tr, "\noverrides:\n"+
		"  - upstream: orders\n    tool: fetch\n    fingerprint: sha256:00\n    effect: READ\n    resource_type: page\n"+
		"    returns:\n      trust: PARTNER\n      sensitivity: INTERNAL\n"+
		"  - upstream: orders\n    tool: mail\n    fingerprint: sha256:01\n    effect: READ\n    resource_type: page\n")
	var out bytes.Buffer
	doctor(context.Background(), tr.config, &out, &out)
	for _, want := range []string{"orders/fetch is READ on page from \"\", returns PARTNER INTERNAL", "orders/mail is READ on page from \"\", returns untrusted unknown"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor does not print %q:\n%s", want, out.String())
		}
	}
}
