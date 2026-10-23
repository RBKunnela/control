package gatewayconfig

import (
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/classify"
)

const classified = `
overrides:
  - upstream: orders
    tool: read_order
    fingerprint: sha256:00
    effect: READ
    resource_type: order
    trust_zone: PARTNER
`

// TestFlowDefaultsStandWhereTheFileIsSilent: sixty-four runs, and an override
// that says nothing about its results declares none.
func TestFlowDefaultsStandWhereTheFileIsSilent(t *testing.T) {
	cfg := load(t, write(t, classified))
	if cfg.Flow.MaxRuns != 64 {
		t.Errorf("flow.max_runs = %d, want 64", cfg.Flow.MaxRuns)
	}
	o := cfg.Overrides[0]
	c, err := o.Classification()
	if o.ReturnsTrust != "" || o.ReturnsSensitivity != "" || err != nil ||
		c.ReturnsTrust.String() != "TRUST_ZONE_UNSPECIFIED" || c.ReturnsSensitivity.String() != "SENSITIVITY_UNSPECIFIED" {
		t.Errorf("an override silent on its results: %q %q -> %v %v, %v", o.ReturnsTrust, o.ReturnsSensitivity, c.ReturnsTrust, c.ReturnsSensitivity, err)
	}
}

// TestAnOverrideDeclaresWhatItsToolReturns: returns.trust and
// returns.sensitivity are read as the contract's values, and leave the
// destination alone.
func TestAnOverrideDeclaresWhatItsToolReturns(t *testing.T) {
	cfg := load(t, write(t, "\nflow:\n  max_runs: 3\n"+classified+"    returns:\n      trust: TRUSTED_INTERNAL\n      sensitivity: CONFIDENTIAL\n"))
	c, err := cfg.Overrides[0].Classification()
	if cfg.Flow.MaxRuns != 3 || err != nil ||
		c.ReturnsTrust.String() != "TRUST_ZONE_TRUSTED_INTERNAL" || c.ReturnsSensitivity.String() != "SENSITIVITY_CONFIDENTIAL" {
		t.Errorf("flow.max_runs %d, returns %v %v, %v", cfg.Flow.MaxRuns, c.ReturnsTrust, c.ReturnsSensitivity, err)
	}
	if c.TrustZone.String() != "TRUST_ZONE_PARTNER" {
		t.Errorf("returns.trust changed the destination: %v", c.TrustZone)
	}
}

// TestTheBoundOnRunsHasToBePositive: at one a plane keeps one run; at zero or
// below it would keep none and decide every call uncomputed.
func TestTheBoundOnRunsHasToBePositive(t *testing.T) {
	for _, c := range []struct {
		value string
		ok    bool
	}{{"1", true}, {"0", false}, {"-1", false}} {
		path := write(t, "")
		setEnv(t, "flow.max_runs", c.value)
		_, err := Load(path, os.Environ())
		switch {
		case c.ok && err != nil:
			t.Errorf("flow.max_runs=%s was refused: %v", c.value, err)
		case !c.ok && err == nil:
			t.Errorf("flow.max_runs=%s was accepted", c.value)
		case !c.ok && !strings.Contains(err.Error(), "flow.max_runs"):
			t.Errorf("the refusal does not name the key: %v", err)
		}
	}
}

// TestWhatAToolReturnsTakesTheContractsNames: a spelling the contract does not
// declare is refused, naming the key.
func TestWhatAToolReturnsTakesTheContractsNames(t *testing.T) {
	for _, c := range []string{"      trust: INTERNAL\n", "      sensitivity: SENSITIVITY_SECRET\n", "      sensitivity: TOP_SECRET\n"} {
		_, err := Load(write(t, classified+"    returns:\n"+c), os.Environ())
		if err == nil || !strings.Contains(err.Error(), "returns.") {
			t.Errorf("%q: %v", strings.TrimSpace(c), err)
		}
	}
	for _, level := range []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"} {
		cfg := load(t, write(t, classified+"    returns:\n      sensitivity: "+level+"\n"))
		if c, err := cfg.Overrides[0].Classification(); err != nil || c.ReturnsSensitivity.String() != "SENSITIVITY_"+level {
			t.Errorf("%s: %v %v", level, c.ReturnsSensitivity, err)
		}
	}
	silent := &OverrideConfig{Spelling: classify.Spelling{Effect: "READ", ResourceType: "order", ReturnsSensitivity: "UNSPECIFIED"}}
	if _, err := silent.Classification(); err == nil {
		t.Error("Classification accepted the zero value's spelling, which says nothing")
	}
}
