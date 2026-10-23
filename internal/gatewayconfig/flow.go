package gatewayconfig

import "fmt"

// FlowConfig bounds what the plane keeps about each run (ADR-0021).
type FlowConfig struct {
	// MaxRuns bounds the runs a plane keeps a flow state for. A call whose
	// run would be past it is decided with the state nobody computed, and no
	// run is ever dropped.
	MaxRuns int
}

// checkFlow refuses a bound on runs that is not positive: a plane that keeps
// no run decides every call with the state nobody computed.
func (c *Config) checkFlow() error {
	if c.Flow.MaxRuns <= 0 {
		return fmt.Errorf("flow.max_runs: %d; the bound has to be positive", c.Flow.MaxRuns)
	}
	return nil
}
