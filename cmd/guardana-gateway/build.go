package main

import (
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/guardana/control/adapters/authzen"
	"github.com/guardana/control/adapters/enforce"
	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/adapters/otel"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/spool"
)

// plane is one gateway: the seams, built and wired, with nothing serving yet.
// build makes every one of them or none, so a refusal leaves no listener bound
// and no directory locked.
type plane struct {
	cfg    *gatewayconfig.Config
	logger *slog.Logger
	spool  *spool.Spool
	holder *policy.Holder
	// policy holds the holder's floor directory and the refresher that keeps
	// it current.
	policy   *planePolicy
	pipeline *gateway.Pipeline
	// adapter is the MCP adapter of an MCP listener and enforce the
	// enforcement API's of an enforce_api listener; one of them is nil.
	adapter  *adaptermcp.Adapter
	enforce  *enforce.Adapter
	reader   *spool.Reader
	exporter *otel.Exporter
	// pdp is the decision point's client, nil where none is configured.
	pdp *authzen.Client
	// store is what the pipeline asks about a held request, and records is
	// the same directory when the file provider named one: the plane prunes
	// it and nothing else here reaches it.
	store   gateway.ApprovalStore
	records *approvals.Plane
	// holds is the seam the pipeline writes its journal through, and journal
	// the directory behind it. Both are nil where no journal is configured.
	holds   gateway.HoldJournal
	journal *holdjournal.Journal
	// poller reads the operator's pause file, and is nil where none is
	// configured: the pipeline is then handed the disabled source.
	poller *pause.Poller
	// stops is the route and the stop list's reader of a serving plane with a
	// route, and nil otherwise: the pipeline is then handed the disabled
	// source.
	stops *planeStops
	// runsDir is the runs directory a serving plane opened, nil where runs
	// are local; runToken is a stdio plane's one token.
	runsDir  *runs.Plane
	runToken string
	// listed is set once the upstreams answered and the manifest holds what
	// they list, so a pause entry's tool can be judged against it.
	listed  atomic.Bool
	started time.Time
	// stopped holds why the exporter's run ended, which /healthz reports. An
	// export that stopped blocks no decision; it fills the spool.
	stopped atomic.Pointer[error]
	// grace bounds a listener's shutdown, and callBound how long a stop
	// waits for the agents' calls in flight before it cuts them.
	grace, callBound time.Duration
	calls            inflight
	// lost is the count of lost closing records lostClosings last reported.
	lost atomic.Int64
	// socket is the enforcement API's listener once bound.
	socket net.Listener
}

// role says what the plane being built is for. It is a parameter and not a
// default because both commands call this one function: `run` opens the
// durable approval directories, which takes their locks and makes a directory
// nobody has used yet a store; `doctor` opens neither, so a command that
// serves nothing holds no lock an approver's probe can read as a plane, and
// writes nothing in either (ADR-0016).
type role int

const (
	// roleServe is the plane that will serve, with the directories the
	// configuration names.
	roleServe role = iota
	// roleInspect is the plane a check builds to make the refusals of the
	// adapter, the kernel and the pipeline. Its approval store touches no
	// directory and it keeps no hold journal.
	roleInspect
)

// build wires the plane from cfg. It connects no upstream and binds no
// address: everything that can be refused is refused here, before anything
// serves.
func build(cfg *gatewayconfig.Config, logger *slog.Logger, now time.Time, r role, tokenPath string) (*plane, error) {
	if err := servedKind(cfg.Listener.Kind); err != nil {
		return nil, err
	}
	pp, err := startPolicy(cfg, logger, r)
	if err != nil {
		return nil, err
	}
	p := &plane{cfg: cfg, logger: logger, holder: pp.holder, policy: pp, started: now, grace: shutdownGrace, callBound: callBound(cfg)}
	if p.poller, err = openPause(cfg, logger, p.strayIDs); err != nil {
		return nil, errors.Join(err, p.close())
	}
	if p.spool, err = openSpool(cfg); err != nil {
		return nil, errors.Join(err, p.close())
	}
	if err := p.open(r, tokenPath); err != nil {
		return nil, errors.Join(err, p.close())
	}
	return p, nil
}

// open takes the durable directories a serving plane needs and wires the
// seams over them. Nothing here reconciles anything, whatever the role: a
// reconciliation writes evidence and resolves records, and `run` is the one
// command that calls for it (ADR-0016).
//
// An inspecting plane reads no route and no stop list; doctor examines each
// on its own. It opens no runs directory and serves local runs, but over an
// enforce_api listener, whose adapter resolves a run on every request: it
// opens the directory then as run does, which takes no lock and writes
// nothing there.
func (p *plane) open(r role, tokenPath string) error {
	if r == roleInspect {
		p.store = &gateway.MemoryApprovals{}
		if p.cfg.Listener.Kind == gatewayconfig.ListenerEnforceAPI {
			dir, _, err := openRuns(p.cfg, "")
			if err != nil {
				return err
			}
			p.runsDir = dir
		}
		return p.wire()
	}
	dir, token, err := openRuns(p.cfg, tokenPath)
	if err != nil {
		return err
	}
	p.runsDir, p.runToken = dir, token
	if p.stops, err = openStops(p.cfg, p.logger); err != nil {
		return err
	}
	store, records, err := openApprovals(p.cfg)
	if err != nil {
		return err
	}
	p.store, p.records = store, records
	holds, journal, err := openJournal(p.cfg)
	if err != nil {
		return err
	}
	p.holds, p.journal = holds, journal
	return p.wire()
}

// wire builds the adapter the listener's kind serves, the decision point's
// client, the pipeline and the exporter over the spool this plane already
// holds.
func (p *plane) wire() error {
	var (
		seam     gateway.Adapter
		mcp      *adaptermcp.Adapter
		enforcer *enforce.Adapter
		err      error
	)
	if p.cfg.Listener.Kind == gatewayconfig.ListenerEnforceAPI {
		enforcer, err = newEnforcer(p.cfg, p.runsDir)
		seam = enforcer
	} else {
		mcp, err = p.newMCPAdapter()
		seam = mcp
	}
	if err != nil {
		return err
	}
	mode, err := p.cfg.Mode()
	if err != nil {
		return err
	}
	pdp, err := decisionPoint(p.cfg)
	if err != nil {
		return err
	}
	pipeline, err := gateway.New(p.pipelineConfig(seam, mode, pdp))
	if err != nil {
		return explainDecisionPoint(err)
	}
	reader, err := p.spool.Reader(spool.Cursor{})
	if err != nil {
		return err
	}
	exporter, err := otel.New(otel.Options{
		Endpoint:       p.cfg.Export.Endpoint,
		AllowPlaintext: p.cfg.Export.AllowPlaintext,
		Headers:        p.cfg.Export.Headers,
		InFlight:       p.cfg.Export.InFlight,
		Timeout:        p.cfg.Export.Timeout,
		MaxBatch:       p.cfg.Export.MaxBatch,
		Linger:         p.cfg.Export.Linger,
		Backoff:        p.cfg.Export.Backoff,
		MaxBackoff:     p.cfg.Export.MaxBackoff,
		Logger:         p.logger,
	}, reader)
	if err != nil {
		return err
	}
	p.adapter, p.enforce, p.pipeline, p.reader, p.exporter, p.pdp = mcp, enforcer, pipeline, reader, exporter, pdp
	return nil
}

// newMCPAdapter builds the MCP adapter over the runs this plane opened.
func (p *plane) newMCPAdapter() (*adaptermcp.Adapter, error) {
	adapterConfig, err := adapterConfig(p.cfg, p.logger)
	if err != nil {
		return nil, err
	}
	if p.runsDir != nil {
		adapterConfig.Listener.Runs = planeRuns(p.cfg, p.runsDir)
		adapterConfig.Listener.RunToken = p.runToken
	}
	return adaptermcp.New(adapterConfig)
}

// seam is the adapter the pipeline was built over.
func (p *plane) seam() gateway.Adapter {
	if p.enforce != nil {
		return p.enforce
	}
	return p.adapter
}

// close releases what build took, in the order that leaves nothing holding the
// spool's directory.
func (p *plane) close() error {
	var errs []error
	if p.adapter != nil {
		errs = append(errs, p.adapter.Close())
	}
	if p.reader != nil {
		errs = append(errs, p.reader.Close())
	}
	if p.spool != nil {
		errs = append(errs, p.spool.Close())
	}
	if p.journal != nil {
		errs = append(errs, p.journal.Close())
	}
	if p.records != nil {
		errs = append(errs, p.records.Close())
	}
	if p.runsDir != nil {
		errs = append(errs, p.runsDir.Close())
	}
	if p.policy != nil {
		errs = append(errs, p.policy.floor.Close())
	}
	return errors.Join(errs...)
}
