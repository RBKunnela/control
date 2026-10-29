package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/guardana/control/adapters/authzen"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/spool"
)

// pipelineConfig is the pipeline's configuration over the seams this plane
// holds, the adapter and the decision point's client.
func (p *plane) pipelineConfig(adapter gateway.Adapter, mode controlv1.EnforcementMode, pdp *authzen.Client) gateway.Config {
	c := gateway.Config{
		Mode:    mode,
		Adapter: adapter,
		KernelOptions: core.Options{
			MaxStale:     p.cfg.Policy.MaxStale,
			FailOpenRead: p.cfg.Policy.FailOpenRead,
		},
		Policy:               p.holder,
		Pause:                p.pauseSource(),
		Stops:                p.stopSource(),
		Sink:                 p.spool,
		Approvals:            p.store,
		Journal:              p.holds,
		ReconcileMax:         p.cfg.Approvals.ReconcileMax,
		Clock:                time.Now,
		NewID:                newID,
		ApprovalTTL:          p.cfg.Approvals.TTL,
		RetryAfter:           p.cfg.Approvals.RetryAfter,
		MaxHeld:              p.cfg.Approvals.MaxHeld,
		MaxHeldPerRun:        p.cfg.Approvals.MaxHeldPerRun,
		MaxOpen:              p.cfg.Approvals.MaxOpen,
		MaxRuns:              p.cfg.Flow.MaxRuns,
		AllowReadsUnrecorded: p.cfg.Evidence.OnUnwritable == gatewayconfig.UnwritableAllowReads,
	}
	if p.runsDir != nil {
		c.Runs = planeRuns(p.cfg, p.runsDir)
	}
	withDecisionPoint(&c, pdp, p.cfg.PDP.Timeout)
	return c
}

// pauseSource is what the pipeline reads the pause state from. A nil poller
// is never handed over as a source: it would be a non-nil interface serving
// the unknown state, which blocks every call of a plane that configured no
// pause at all.
func (p *plane) pauseSource() gateway.PauseSource {
	if p.poller == nil {
		return gateway.PauseDisabled()
	}
	return p.poller
}

// openPause opens the reader of the pause file, whose first read has to find
// a state it can serve: a plane never starts on a pause state it cannot read
// (ADR-0019). The reader takes no lock and writes nothing, so doctor opens it
// too; it logs with each change the entries unlisted names. Without pause.file
// there is nothing to read and it returns nil.
func openPause(cfg *gatewayconfig.Config, logger *slog.Logger, unlisted func([]pause.Entry) []string) (*pause.Poller, error) {
	if cfg.Pause.File == "" {
		return nil, nil
	}
	poller, err := pause.Open(pause.Options{
		Path:         cfg.Resolve(cfg.Pause.File),
		Interval:     cfg.Pause.PollInterval,
		Clock:        time.Now,
		Logger:       logger,
		UnlistedOnly: unlisted,
	})
	if err != nil {
		return nil, fmt.Errorf("pause.file: %w", err)
	}
	return poller, nil
}

func openSpool(cfg *gatewayconfig.Config) (*spool.Spool, error) {
	fsync := spool.FsyncEveryRecord
	if cfg.Evidence.Fsync == gatewayconfig.FsyncInterval {
		fsync = spool.FsyncInterval
	}
	sp, err := spool.Open(spool.Options{
		Dir:            cfg.Resolve(cfg.Evidence.Dir),
		MaxBytes:       cfg.Evidence.MaxBytes,
		SegmentBytes:   cfg.Evidence.SegmentBytes,
		ClosingReserve: cfg.Evidence.ClosingReserve,
		Fsync:          fsync,
		Interval:       cfg.Evidence.FsyncInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	return sp, nil
}

// newID names decisions, events, approvals and executions. Every call returns
// a fresh value; the pipeline probes that at start.
func newID() string { return rand.Text() }
