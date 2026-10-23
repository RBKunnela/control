package mcp_test

import (
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// declaredZones and declaredSensitivities are every number each enum
// declares, the zero value included.
func declaredZones() []controlv1.TrustZone {
	values := controlv1.TrustZone(0).Descriptor().Values()
	out := make([]controlv1.TrustZone, 0, values.Len())
	for i := range values.Len() {
		out = append(out, controlv1.TrustZone(values.Get(i).Number()))
	}
	return out
}

func declaredSensitivities() []controlv1.Sensitivity {
	values := controlv1.Sensitivity(0).Descriptor().Values()
	out := make([]controlv1.Sensitivity, 0, values.Len())
	for i := range values.Len() {
		out = append(out, controlv1.Sensitivity(values.Get(i).Number()))
	}
	return out
}

// TestWhatAToolReturnsReachesThePipelineApartFromTheLabels: over every
// declared result trust and sensitivity and two destinations of a message,
// the admission carries the override's classification of the result as it
// was declared, and the envelope carries no data label and the destination
// the override declared. A destination the operator trusts says nothing about
// what the tool returns.
func TestWhatAToolReturnsReachesThePipelineApartFromTheLabels(t *testing.T) {
	for _, destination := range []controlv1.TrustZone{controlv1.TrustZone_TRUST_ZONE_PARTNER, zoneExternal} {
		for _, trust := range declaredZones() {
			for _, read := range declaredSensitivities() {
				overrides := func(v *victim, t *testing.T) []mcp.Override {
					out := v.overrides(t)
					for i := range out {
						if out[i].Tool == "send_mail" {
							out[i].TrustZone, out[i].ReturnsTrust, out[i].ReturnsSensitivity = destination, trust, read
						}
					}
					return out
				}
				r := newRig(t, mcp.KindStdio, rigOptions{overrides: overrides})
				agent := r.connect(t, "agent-a")
				if _, err := callTool(t, agent, "send_mail", map[string]any{"to": "a@example.net"}); err != nil {
					t.Fatalf("send_mail: %v", err)
				}
				adm := r.pipe.admitted()
				if len(adm) != 1 {
					t.Fatalf("%d admissions", len(adm))
				}
				a := adm[0].a
				if a.ResultTrust != trust || a.ResultSensitivity != read {
					t.Errorf("destination %s, declared %s %s: the admission says %s %s", destination, trust, read, a.ResultTrust, a.ResultSensitivity)
				}
				if a.Envelope.GetData() != nil {
					t.Errorf("declared %s %s: the envelope carries data labels %v", trust, read, a.Envelope.GetData())
				}
				if got := a.Envelope.GetDestination().GetTrustZone(); got != destination {
					t.Errorf("declared %s %s: the destination is %s, want %s", trust, read, got, destination)
				}
			}
		}
	}
}

// TestWhatAReadReturnsSetsNoDestination: a read with no destination of its
// own keeps none, whatever trust its results declare: what a tool returns is
// never where a call sends data (ADR-0021).
func TestWhatAReadReturnsSetsNoDestination(t *testing.T) {
	for _, trust := range declaredZones() {
		overrides := func(v *victim, t *testing.T) []mcp.Override {
			out := v.overrides(t)
			for i := range out {
				if out[i].Tool == "read_file" {
					out[i].TrustZone, out[i].ReturnsTrust = 0, trust
				}
			}
			return out
		}
		r := newRig(t, mcp.KindStdio, rigOptions{overrides: overrides})
		agent := r.connect(t, "agent-a")
		if _, err := callTool(t, agent, "read_file", map[string]any{"path": "/a"}); err != nil {
			t.Fatalf("read_file: %v", err)
		}
		adm := r.pipe.admitted()
		if len(adm) != 1 {
			t.Fatalf("%d admissions", len(adm))
		}
		if a := adm[0].a; a.ResultTrust != trust || a.Envelope.GetDestination() != nil {
			t.Errorf("returns %s: the admission says %s and the envelope's destination is %v, want none",
				trust, a.ResultTrust, a.Envelope.GetDestination())
		}
	}
}

// TestWhatNoOverrideClassifiesReturnsTheRestrictiveAnswer: a resource read, a
// prompt and a tool nobody classified each reach the pipeline as returning
// untrusted content of unknown sensitivity.
func TestWhatNoOverrideClassifiesReturnsTheRestrictiveAnswer(t *testing.T) {
	overrides := func(v *victim, t *testing.T) []mcp.Override {
		out := v.overrides(t)
		for i := range out {
			out[i].ReturnsTrust = controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL
			out[i].ReturnsSensitivity = controlv1.Sensitivity_SENSITIVITY_PUBLIC
		}
		return out
	}
	r := newRig(t, mcp.KindStdio, rigOptions{overrides: overrides})
	agent := r.connect(t, "agent-a")
	_, _ = agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"})
	_, _ = agent.GetPrompt(ctxT(t), &sdk.GetPromptParams{Name: "p", Arguments: map[string]string{"q": "x"}})
	_, _ = callTool(t, agent, "unlisted", map[string]any{"path": "x"})
	if _, err := callTool(t, agent, "read_file", map[string]any{"path": "x"}); err != nil {
		t.Fatalf("read_file: %v", err)
	}
	adm := r.pipe.admitted()
	if len(adm) != 4 {
		t.Fatalf("%d admissions, want 4", len(adm))
	}
	for i, want := range []string{"file:///r", "p", "unlisted"} {
		a := adm[i].a
		if got := a.Envelope.GetAction().GetName(); got != want {
			t.Errorf("admission %d names %q, want %q", i, got, want)
		}
		if a.ResultTrust != 0 || a.ResultSensitivity != 0 {
			t.Errorf("%s: the admission says %s %s", a.Envelope.GetAction().GetName(), a.ResultTrust, a.ResultSensitivity)
		}
	}
	if a := adm[3].a; a.ResultTrust != controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL || a.ResultSensitivity != controlv1.Sensitivity_SENSITIVITY_PUBLIC {
		t.Errorf("the classified read says %s %s", a.ResultTrust, a.ResultSensitivity)
	}
}
