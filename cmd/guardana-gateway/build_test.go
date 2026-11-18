package main

import (
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
)

// TestThePipelineTakesTheConfiguredBoundOnRuns: flow.max_runs is the bound the
// pipeline is built with, for values that are neither the default nor the
// pipeline tests' own.
func TestThePipelineTakesTheConfiguredBoundOnRuns(t *testing.T) {
	for _, runs := range []int{1, 3, 97} {
		p := &plane{cfg: &gatewayconfig.Config{Flow: gatewayconfig.FlowConfig{MaxRuns: runs}}}
		if got := p.pipelineConfig(nil, controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, nil).MaxRuns; got != runs {
			t.Errorf("flow.max_runs %d reaches the pipeline as %d", runs, got)
		}
	}
}

// TestThePipelineTakesTheConfiguredBoundOnOneRunsHolds: approvals.max_held_per_run
// is the bound the pipeline holds one opened run to, for values that are not
// the default.
func TestThePipelineTakesTheConfiguredBoundOnOneRunsHolds(t *testing.T) {
	for _, held := range []int{1, 3, 97} {
		p := &plane{cfg: &gatewayconfig.Config{Approvals: gatewayconfig.ApprovalsConfig{MaxHeld: 128, MaxHeldPerRun: held}}}
		if got := p.pipelineConfig(nil, controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, nil).MaxHeldPerRun; got != held {
			t.Errorf("approvals.max_held_per_run %d reaches the pipeline as %d", held, got)
		}
	}
}

// TestThePipelineServesTheConfiguredListener: a stop of an agent or a
// principal is matched against the identity the pipeline is built with, so
// that identity is the listener's configured agent, principal and principal
// type, in the tenant the listener serves: its principal's tenant when one
// is set, else tenant_id.
func TestThePipelineServesTheConfiguredListener(t *testing.T) {
	listener := gatewayconfig.ListenerConfig{AgentID: "orders-assistant", PrincipalID: "agent-runner", PrincipalType: "service"}
	p := &plane{cfg: &gatewayconfig.Config{TenantID: "acme", Listener: listener}}
	want := gateway.RunIdentity{TenantID: "acme", PrincipalType: "service", PrincipalID: "agent-runner", AgentID: "orders-assistant"}
	if got := p.pipelineConfig(nil, controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, nil).Listener; got != want {
		t.Errorf("the pipeline serves %+v, want %+v", got, want)
	}
	p.cfg.Listener.PrincipalTenant = "globex"
	want.TenantID = "globex"
	if got := p.pipelineConfig(nil, controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE, nil).Listener; got != want {
		t.Errorf("with the principal's tenant set the pipeline serves %+v, want %+v", got, want)
	}
}
