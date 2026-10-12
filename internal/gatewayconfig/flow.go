package gatewayconfig

import (
	"fmt"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// FlowConfig bounds what the plane keeps about each run (ADR-0021).
type FlowConfig struct {
	// MaxRuns bounds the runs a plane keeps a flow state for. A call whose
	// run would be past it is decided with the state nobody computed, and no
	// run is ever dropped.
	MaxRuns int
}

// ReturnsZone is the trust zone of what the override's tool returns, as the
// contract names it. Empty is UNSPECIFIED, which counts as untrusted.
func (o *OverrideConfig) ReturnsZone() (controlv1.TrustZone, error) {
	return zoneNamed(o.ReturnsTrust)
}

// ReturnsLevel is the highest sensitivity the override's tool returns, as the
// contract names it. Empty is UNSPECIFIED, which is unknown.
func (o *OverrideConfig) ReturnsLevel() (controlv1.Sensitivity, error) {
	return sensitivityNamed(o.ReturnsSensitivity)
}

func sensitivityNamed(name string) (controlv1.Sensitivity, error) {
	if name == "" {
		return controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED, nil
	}
	number, ok := controlv1.Sensitivity_value["SENSITIVITY_"+name]
	if !ok || number == int32(controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED) {
		return 0, fmt.Errorf("the contract declares no sensitivity %q", name)
	}
	return controlv1.Sensitivity(number), nil
}

// checkFlow refuses a bound on runs that is not positive: a plane that keeps
// no run decides every call with the state nobody computed.
func (c *Config) checkFlow() error {
	if c.Flow.MaxRuns <= 0 {
		return fmt.Errorf("flow.max_runs: %d; the bound has to be positive", c.Flow.MaxRuns)
	}
	return nil
}
