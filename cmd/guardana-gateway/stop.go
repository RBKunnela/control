package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
)

// shutdownGrace bounds how long a listener is given to finish what it is
// answering once the process is asked to stop, and is what a call in flight
// is given past its own bound to append its closing record.
const shutdownGrace = 10 * time.Second

// callBound is the longest a call admitted before a stop may still take: the
// decision point's question, the upstream call and the grace to append its
// closing record.
func callBound(cfg *gatewayconfig.Config) time.Duration {
	bound := cfg.Upstream.CallTimeout + shutdownGrace
	if cfg.PDP.Identifier != "" {
		bound += cfg.PDP.Timeout
	}
	return bound
}

// inflight counts the agents' requests a handler is still answering, so that
// the answer to a call that closed during a stop can reach its agent. A GET is
// not counted: it is a stream a session holds open for as long as its client
// does, and it carries no call.
type inflight struct{ n atomic.Int64 }

// await waits until no counted request is in flight or bound has passed, and
// returns how many still are.
func (f *inflight) await(bound time.Duration) int64 {
	deadline := time.Now().Add(bound)
	for {
		n := f.n.Load()
		if n == 0 || !time.Now().Before(deadline) {
			return n
		}
		time.Sleep(drainPoll)
	}
}

func (f *inflight) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			f.n.Add(1)
			defer f.n.Add(-1)
		}
		next.ServeHTTP(w, r)
	})
}

// stopServing stops the adapter admitting calls, shuts every listener, then
// waits for the calls admitted before the stop until callBound has passed
// since it began. It counts calls and not requests: a call runs on after its
// agent drops the connection that carried it, and a request whose body was
// still arriving at the stop is refused and carries no call. A call running
// at the bound is cut from its agent by closing the connection, which does
// not end the call itself, so the stop is an error: that call's closing
// record may come after the spool closed, or never.
//
// An enforcement API plane holds no call: its clients run the tools. Its stop
// abandons every execution it handed out instead (ADR-0051).
func (p *plane) stopServing(bound []listening) error {
	if p.enforce != nil {
		return p.stopEnforcing(bound)
	}
	deadline := time.Now().Add(p.callBound)
	p.adapter.StopAdmitting()
	for _, b := range bound {
		shutdown, done := context.WithTimeout(context.Background(), p.grace)
		if err := b.server.Shutdown(shutdown); err != nil {
			p.logger.Error("listener did not shut down cleanly", "addr", b.server.Addr, "err", err)
		}
		done()
	}
	left := p.adapter.Drain(time.Until(deadline))
	if left == 0 {
		p.calls.await(min(p.grace, time.Until(deadline)))
		return nil
	}
	errs := []error{fmt.Errorf("%d call(s) still in flight %s after the stop began were cut; their closing records may be missing", left, p.callBound)}
	for _, b := range bound {
		errs = append(errs, b.server.Close())
	}
	return errors.Join(errs...)
}

// lostClosings is an error once a call's closing or aborting record could not
// be appended since it was last asked: that trail stays open in the spool. It
// is asked when run returns and again once the plane is released, for a call
// that outlived the stop.
func (p *plane) lostClosings() error {
	var n int64
	if p.enforce != nil {
		n = p.enforceLost()
	} else {
		n = p.adapter.Stats().CloseFailures
	}
	if seen := p.lost.Swap(n); n > seen {
		return fmt.Errorf("%d call(s) could not append their closing record; their trails stay open", n-seen)
	}
	return nil
}
