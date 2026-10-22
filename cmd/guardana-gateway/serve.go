package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gatewayconfig"
)

// readHeaderTimeout bounds how long a client may take over sending its
// headers, so an idle connection cannot hold a slot open.
const readHeaderTimeout = 10 * time.Second

// idleTimeout bounds how long a kept-alive connection may wait for its next
// request.
const idleTimeout = 2 * time.Minute

// healthReadTimeout bounds how long a request to the plane's own answers may
// take over its headers and body, as the agents' listener bounds a body. The
// server reads what body a handler leaves before it answers, so without it a
// client trickling one holds the connection and the handler.
const healthReadTimeout = adaptermcp.DefaultBodyTimeout

// serve builds the plane and serves it until ctx ends. Nothing is bound and
// nothing is connected until every seam is built: a configuration the pipeline,
// the adapter or the spool refuses is printed and nothing starts.
func serve(ctx context.Context, path, tokenPath string, stdout, stderr io.Writer) int {
	cfg, err := gatewayconfig.Load(path, os.Environ())
	if err != nil {
		return fail(stderr, "run", err)
	}
	p, err := startPlane(ctx, cfg, stderr, tokenPath)
	if err != nil {
		return fail(stderr, "run", err)
	}
	// A stdio listener speaks the protocol on standard output, so what the
	// plane says about itself goes to standard error there.
	report := stdout
	if cfg.Listener.Kind == gatewayconfig.ListenerStdio {
		report = stderr
	}
	writeLine(report, startLine(cfg))
	p.settle(ctx, report)
	return p.finish(p.run(ctx, report, listenTCP, 0), stderr)
}

// finish releases a plane whose run returned ran and says how `run` exits. A
// closing record lost after run returned, by a call that outlived the stop,
// fails it as one lost before.
func (p *plane) finish(ran error, stderr io.Writer) int {
	closed := p.closeReporting(stderr, "run")
	if err := errors.Join(ran, p.lostClosings()); err != nil {
		return fail(stderr, "run", err)
	}
	if !closed {
		return exitFail
	}
	return exitOK
}

// startLine is what run prints once the plane is up. It names the risk
// setting a read runs under while the policy is unavailable, on either side.
func startLine(cfg *gatewayconfig.Config) string {
	return fmt.Sprintf("%s %s: mode %s, bundle %s, policy.fail_open_read %t, evidence in %s",
		brand.Gateway, version, cfg.ModeName, oneLine(cfg.Policy.BundleID), cfg.Policy.FailOpenRead, oneLine(cfg.Resolve(cfg.Evidence.Dir)))
}

// startPlane builds the serving plane from cfg and starts its adapter: an
// MCP adapter connects its upstreams, the enforcement API's binds the
// pipeline. That is everything a plane does before it binds. A plane it
// cannot start is released before the refusal returns.
func startPlane(ctx context.Context, cfg *gatewayconfig.Config, stderr io.Writer, tokenPath string) (*plane, error) {
	p, err := build(cfg, newLogger(cfg.LogLevel, stderr), time.Now(), roleServe, tokenPath)
	if err != nil {
		return nil, err
	}
	if p.enforce != nil {
		err = p.enforce.Start(p.pipeline)
	} else {
		err = p.startUpstreams(ctx)
	}
	if err != nil {
		return nil, errors.Join(err, p.close())
	}
	return p, nil
}

// closeReporting releases the plane, reports on stderr what could not be
// released, and says whether everything was: the spool's last sync is part
// of it.
func (p *plane) closeReporting(stderr io.Writer, command string) bool {
	if err := p.close(); err != nil {
		writeLine(stderr, brand.CLI+": "+command+": shutdown: "+oneLine(err.Error()))
		return false
	}
	return true
}

// settle closes the trails of the holds this plane lost to a restart and then
// forgets the approval records that expired. It runs on `run` and on nothing
// else: `doctor` builds the same plane and never reaches this, because closing
// a trail writes evidence and resolves records (ADR-0016). An incomplete pass
// is reported and the plane serves either way.
func (p *plane) settle(ctx context.Context, stdout io.Writer) {
	if p.holds == nil {
		writeLine(stdout, "no hold journal is configured: a hold this plane loses to a restart is never closed")
		return
	}
	r := p.pipeline.Reconcile(ctx)
	measured := "the pass read every entry"
	if !r.Complete {
		measured = "the pass did not read every entry, so these are a floor and not a total"
	}
	writeLine(stdout, fmt.Sprintf("lost holds: %d closed, %d left open, %d interrupted, %d unreadable; %s",
		r.Closed, r.Unclosed, r.Interrupted, r.Unreadable, measured))
	p.prune(ctx, stdout)
}

// prune forgets the approval records whose approvals expired, after the
// reconciliation has resolved the holds it closed: pruning first would drop a
// record an approver had answered before anything read the answer. A sweep
// that stopped on a record it could not read reports what it forgot so far,
// which is unmeasured and never done.
func (p *plane) prune(ctx context.Context, stdout io.Writer) {
	if p.records == nil {
		return
	}
	forgotten, err := p.records.Prune(ctx, time.Now())
	if err != nil {
		writeLine(stdout, fmt.Sprintf("expired approval records: %d forgotten, and the sweep is unmeasured: %s",
			forgotten, oneLine(err.Error())))
		p.logger.Error("the sweep of expired approval records stopped early", "forgotten", forgotten, "err", err)
		return
	}
	writeLine(stdout, fmt.Sprintf("expired approval records: %d forgotten", forgotten))
}

// run starts the exporter, the pause file's and the stop list's readers, the
// policy's refresher, the health answers and the listener, and returns when
// ctx ends or a listener stops on its own.
// listen binds each address the configuration names, or hands over one bound
// already. The pause file and the stop list are read once more before
// anything is bound: the
// read the start made is as old as the start took, which can be past what it
// answers for. Once the listeners are shut and the calls in flight have
// closed, the exporter is given up to drain to ship what the spool holds
// before it is stopped. A call cut at the stop, or one whose closing record
// was lost, is an error, since its trail may stay open.
func (p *plane) run(ctx context.Context, stdout io.Writer, listen listenFunc, drain time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	exportCtx, stopExport := context.WithCancel(context.WithoutCancel(ctx))
	defer stopExport()
	if p.poller != nil {
		p.poller.Poll()
		p.warnStray()
	}
	if p.stops != nil {
		p.stops.poller.Poll()
	}
	bound, err := p.bind(stdout, listen)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	stopped := make(chan error, len(bound)+1)
	p.startReaders(ctx, exportCtx, &wg)
	if p.enforce != nil {
		p.serveEnforcing(ctx, &wg, stopped)
	}
	for _, b := range bound {
		wg.Add(1)
		go func(b listening) {
			defer wg.Done()
			if err := b.server.Serve(b.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				stopped <- err
			}
		}(b)
	}
	if p.cfg.Listener.Kind == gatewayconfig.ListenerStdio {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopped <- p.adapter.ServeStdio(ctx, os.Stdin, os.Stdout)
		}()
	}
	var first error
	select {
	case <-ctx.Done():
	case first = <-stopped:
	}
	cancel()
	cut := p.stopServing(bound)
	p.drainSpool(drain)
	stopExport()
	wg.Wait()
	return errors.Join(first, cut, p.lostClosings())
}

// serveEnforcing answers the enforcement API on the bound socket and runs its
// sweep, each until ctx ends and counted in wg; a socket that stops serving on
// its own is sent on stopped.
func (p *plane) serveEnforcing(ctx context.Context, wg *sync.WaitGroup, stopped chan<- error) {
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.enforce.Serve(ctx, p.socket); err != nil && !errors.Is(err, http.ErrServerClosed) {
			stopped <- err
		}
	}()
	go func() {
		defer wg.Done()
		p.sweep(ctx)
	}()
}

// startReaders runs what feeds a serving plane: the exporter until exportCtx
// ends, and until ctx ends the pause file's and the stop list's readers and
// the policy's refresher, each counted in wg.
func (p *plane) startReaders(ctx, exportCtx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.export(exportCtx)
	}()
	if p.poller != nil {
		// A poller that stopped leaves its last read standing for three
		// intervals and then blocks every call, so it runs as long as the
		// plane does. It logs each change of the snapshot, never a reason.
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.poller.Run(ctx)
		}()
	}
	if p.stops != nil {
		// As the pause file's reader: one that stopped blocks every call
		// once its last read is three intervals old.
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.stops.poller.Run(ctx)
		}()
	}
	if p.policy != nil && p.policy.refresher != nil {
		// The refresher keeps the policy confirmed; one that stopped leaves
		// the last confirmation to run out, after which every call is stale.
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.policy.refresher.Run(ctx)
		}()
	}
}

// drainPoll is how often a drain reads the spool's depth.
const drainPoll = 20 * time.Millisecond

// drainSpool waits up to bound until the spool holds nothing unacknowledged.
// It returns early once the exporter has stopped, or when the spool cannot
// say: then nothing more would be shipped by waiting.
func (p *plane) drainSpool(bound time.Duration) {
	deadline := time.Now().Add(bound)
	tick := time.NewTicker(drainPoll)
	defer tick.Stop()
	for time.Now().Before(deadline) && p.stopped.Load() == nil {
		st, err := p.spool.Stats()
		if err != nil || st.Unacknowledged == 0 {
			return
		}
		<-tick.C
	}
}

// export drains the spool into the collector. A run that ends is recorded and
// reported by /healthz: it never blocks a decision, and the spool's depth is
// what says how much an outage is costing.
func (p *plane) export(ctx context.Context) {
	err := p.exporter.Run(ctx)
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	p.stopped.Store(&err)
	p.logger.Error("the evidence exporter stopped; the spool will fill to its budget and then block material calls", "err", err)
}

// newLogger writes the plane's own log as lines on stderr at the configured
// level, every value through oneLine. Nothing a policy or an agent sent is
// logged here; the evidence trail is the record.
func newLogger(level string, stderr io.Writer) *slog.Logger {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError,
	}
	return slog.New(printableLog(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: levels[level]})))
}
