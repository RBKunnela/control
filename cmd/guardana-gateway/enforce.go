package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/runs"
)

// servedKind refuses a listener kind this binary has no adapter for, before
// anything is opened.
func servedKind(kind string) error {
	switch kind {
	case gatewayconfig.ListenerStatelessHTTP, gatewayconfig.ListenerStatefulHTTP, gatewayconfig.ListenerStdio, gatewayconfig.ListenerEnforceAPI:
		return nil
	}
	return fmt.Errorf("listener.kind: %s is not a listener this build serves", strconv.Quote(kind))
}

// newEnforcer builds the enforcement API adapter over the runs directory the
// plane opened, which every request's token is resolved in.
func newEnforcer(cfg *gatewayconfig.Config, dir *runs.Plane) (*enforce.Adapter, error) {
	if dir == nil {
		return nil, errors.New("runs.dir: an enforce_api listener resolves a run token on every request, and no runs directory is open")
	}
	tools, err := enforceTools(cfg)
	if err != nil {
		return nil, err
	}
	return enforce.New(enforce.Config{
		Socket:            cfg.Resolve(cfg.Listener.Socket),
		ExecutionLifetime: cfg.Listener.ExecutionLifetime,
		MaxBodyBytes:      cfg.Listener.MaxBodyBytes,
		MaxOpenPerRun:     cfg.Listener.MaxOpenPerRun,
		ProjectID:         cfg.ProjectID,
		TenantID:          cfg.TenantID,
		Environment:       cfg.Environment,
		Identity: enforce.Identity{
			Principal: &controlv1.Principal{Id: cfg.Listener.PrincipalID, Type: cfg.Listener.PrincipalType, TenantId: listenerTenant(cfg)},
			Agent:     &controlv1.Agent{Id: cfg.Listener.AgentID, Framework: cfg.Listener.AgentFramework, Version: cfg.Listener.AgentVersion},
		},
		Runs:  planeRuns(cfg, dir),
		Tools: tools,
		Clock: time.Now,
		NewID: newID,
	})
}

// enforceTools turns the operator's tool table into the adapter's.
func enforceTools(cfg *gatewayconfig.Config) ([]enforce.Tool, error) {
	out := make([]enforce.Tool, 0, len(cfg.Tools))
	for i := range cfg.Tools {
		t := &cfg.Tools[i]
		c, err := t.Classification()
		if err != nil {
			return nil, fmt.Errorf("tools.%d.%w", i, err)
		}
		out = append(out, enforce.Tool{Name: t.Name, Provider: t.Provider, Classification: c})
	}
	return out, nil
}

// sweepEvery is how often the sweep looks for expired executions: a quarter
// of their lifetime, so one is abandoned at most a quarter late, and at
// least once a second.
func sweepEvery(lifetime time.Duration) time.Duration {
	return min(lifetime/4, time.Second)
}

// sweep abandons the executions whose handles expired, reading the plane's
// clock, until ctx ends.
func (p *plane) sweep(ctx context.Context) {
	tick := time.NewTicker(sweepEvery(p.cfg.Listener.ExecutionLifetime))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if n := p.enforce.Sweep(ctx, time.Now()); n > 0 {
				p.logger.Info("abandoned expired executions", "count", n)
			}
		}
	}
}

// stopEnforcing refuses every request from now on, waits up to the grace for
// those in flight, abandons every execution still open, and then shuts the
// plane's own answers. A request still in flight at the grace may append its
// closing record after the spool closed, so that is an error.
func (p *plane) stopEnforcing(bound []listening) error {
	ctx, done := context.WithTimeout(context.Background(), p.grace)
	defer done()
	err := p.enforce.Shutdown(ctx)
	for _, b := range bound {
		shutdown, cancel := context.WithTimeout(context.Background(), p.grace)
		if serr := b.server.Shutdown(shutdown); serr != nil {
			p.logger.Error("listener did not shut down cleanly", "addr", b.server.Addr, "err", serr)
		}
		cancel()
	}
	if err != nil {
		return fmt.Errorf("requests still in flight %s after the stop began were cut; their closing records may be missing: %w", p.grace, err)
	}
	return nil
}

// enforceLost is the closing records an enforcement API plane could not
// append: those of completions, which the pipeline counts, and those of the
// executions the adapter abandoned or aborted, a client's abort included.
func (p *plane) enforceLost() int64 {
	n := p.pipeline.Stats().SinkFailuresAfterEffect + p.enforce.Stats().RecordsFailed
	return int64(min(n, uint64(1<<63-1)))
}

// enforceCounters is what the enforcement API adapter counted: the handles
// open now, its answers by outcome, how executions ended, the closings it
// made whose record the pipeline did not confirm, and its refusals by the
// contract's error code.
func enforceCounters(s enforce.Stats) map[string]any {
	refused := map[string]uint64{}
	for code, n := range s.Refused {
		if code != 0 {
			refused[strings.ToLower(strings.TrimPrefix(code.String(), "ERROR_CODE_"))] = n
		}
	}
	return map[string]any{
		"open_handles": s.Open, "executed": s.Executed, "blocked": s.Blocked, "pending": s.Pending,
		"completed": s.Completed, "aborted": s.Aborted, "abandoned": s.Abandoned,
		"records_failed": s.RecordsFailed, "refused": refused,
	}
}

// printTools prints the tool table for doctor, as overrides are printed.
func printTools(w func(string), tools []gatewayconfig.ToolConfig) {
	for i, t := range tools {
		w(fmt.Sprintf("       %-28s %s is %s on %s/%s from %s, returns %s %s",
			fmt.Sprintf("tools.%d", i), oneLine(t.Name), t.Effect, oneLine(t.Provider), oneLine(t.ResourceType),
			oneLine(strconv.Quote(t.ResourceFrom)), orWord(t.ReturnsTrust, "untrusted"), orWord(t.ReturnsSensitivity, "unknown")))
	}
}
