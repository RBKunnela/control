package enforce

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/gateway"
)

// The version of the API the receiver serves, the operations' paths under it
// and the header every request presents its run token in. Any other path,
// another version's included, is answered ERROR_CODE_UNSUPPORTED_VERSION.
const (
	APIVersion     = "v1alpha1"
	PathAdmit      = "/enforce/" + APIVersion + "/admit"
	PathComplete   = "/enforce/" + APIVersion + "/complete"
	PathAbort      = "/enforce/" + APIVersion + "/abort"
	RunTokenHeader = adapterkit.RunTokenHeader
)

// Pipeline is what the adapter asks: the enforcement pipeline of
// internal/gateway, or a wrapper of the same shape in a test. Admit answers
// and never fails; an error from the others means the record is not known to
// be durable.
type Pipeline interface {
	Admit(ctx context.Context, a gateway.Admission) gateway.Disposition
	CloseReported(ctx context.Context, d gateway.Disposition, sent []byte, result *controlv1.ActionResult) error
	Abort(ctx context.Context, d gateway.Disposition, cause gateway.AbortCause) error
	Abandon(ctx context.Context, d gateway.Disposition) error
}

var _ Pipeline = (*gateway.Pipeline)(nil)

// Stats counts what the adapter did, for health and for a test that has to
// see what nothing else reports.
type Stats struct {
	// Executed, Blocked and Pending count admit answers by outcome.
	Executed, Blocked, Pending uint64
	// Completed, Aborted and Abandoned count executions by how they ended.
	Completed, Aborted, Abandoned uint64
	// Open is how many handles are open now.
	Open int
	// RecordsFailed counts the closings whose record the pipeline did not
	// confirm and does not count after the effect: those the adapter made on
	// its own, an abandon or the abort of a call whose resource moved, which
	// no client is told of, and a client's abort.
	RecordsFailed uint64
	// RunsRefused counts refused run tokens by cause; every cause of
	// gateway.RunCauses is a key.
	RunsRefused map[gateway.RunCause]uint64
	// Refused counts the contract's refusals by code, run tokens included.
	Refused map[enforcev1alpha1.ErrorCode]uint64
}

// Adapter is the enforcement API adapter as the pipeline sees it and as a
// tool reaches it.
type Adapter struct {
	cfg      Config
	tools    map[string]Tool
	maxBody  int64
	sweepMax int
	timeout  time.Duration

	mu       sync.RWMutex
	pipeline Pipeline

	handles *handles
	flights flights
	counts  *counters
}

var _ gateway.Adapter = (*Adapter)(nil)

// New checks cfg once and returns an adapter with no pipeline: Start binds
// one. It refuses a socket path that is empty, relative or too long, an
// execution lifetime outside its bounds, a body bound outside its bounds, an
// identity with no principal id or agent id, a nil run resolver, a tool table
// that is empty or holds a repeated tool, one of a class that needs a
// delegation, or one whose name, provider or classification no envelope could
// carry, one of a class that needs an environment while Environment is empty
// or the resource's tenant while TenantID is, a negative bound, and a nil
// clock or id source.
func New(cfg Config) (*Adapter, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg: cfg, tools: make(map[string]Tool, len(cfg.Tools)),
		maxBody: orDefault(cfg.MaxBodyBytes, DefaultBodyBytes), sweepMax: orDefault(cfg.SweepMax, DefaultSweepMax),
		timeout: orDefault(cfg.RequestTimeout, DefaultRequestTimeout),
		handles: newHandles(orDefault(cfg.MaxSpent, DefaultMaxSpent), orDefault(cfg.MaxOpenPerRun, DefaultMaxOpenPerRun)),
		counts:  newCounters(),
	}
	for _, tool := range cfg.Tools {
		a.tools[tool.Name] = tool
	}
	return a, nil
}

func orDefault[T int | int64 | time.Duration](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

// Name is the protocol's.
func (*Adapter) Name() string { return "enforce" }

// Capabilities declares what the adapter does, each backed by a test in this
// package: it sees the call and the reported result, hands the decision to a
// client that enforces it, resolves a run on every request and names the
// resource from the arguments. It applies no obligation of its own.
func (*Adapter) Capabilities() gateway.Capabilities {
	return gateway.Capabilities{
		ObserveRequest: true,
		ObserveResult:  true,
		Enforcement:    gateway.EnforcementCooperative,
		PresentsRuns:   true,
		SeeResourceIDs: true,
	}
}

// Start binds the pipeline; until then every request is answered
// ERROR_CODE_UNAVAILABLE.
func (a *Adapter) Start(p Pipeline) error {
	if p == nil {
		return ErrNoPipeline
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pipeline != nil {
		return ErrStarted
	}
	a.pipeline = p
	return nil
}

func (a *Adapter) started() Pipeline {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.pipeline
}

// Serve answers requests on ln until ctx ends, then closes ln and returns.
// Each request is bounded by the configured request timeout over its
// headers, its body and its answer. It refuses with ErrListener, serving
// nothing, any listener but one this adapter's Listen returned, and that one
// a second time: the socket's owner and mode limit who can present a run
// token, and its lock keeps a second plane off it.
func (a *Adapter) Serve(ctx context.Context, ln net.Listener) error {
	if !a.claim(ln) {
		return ErrListener
	}
	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: a.timeout,
		ReadTimeout:       a.timeout,
		WriteTimeout:      a.timeout,
		IdleTimeout:       a.timeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.timeout)
	defer cancel()
	err := srv.Shutdown(shutdown)
	if served := <-done; !errors.Is(served, http.ErrServerClosed) {
		err = errors.Join(err, served)
	}
	return err
}

// Sweep abandons the executions whose handles expired by now, at most the
// configured number per pass, earliest expiry first, and forgets the spent
// handles that expired. It returns how many it abandoned. Before Start it
// abandons nothing, since nothing was handed out.
func (a *Adapter) Sweep(ctx context.Context, now time.Time) int {
	p := a.started()
	if p == nil {
		return 0
	}
	expired := a.handles.expired(now, a.sweepMax)
	a.abandon(ctx, p, expired)
	return len(expired)
}

// Shutdown refuses every request from now on, waits until ctx ends for the
// requests in flight, and then abandons every open execution, so nothing it
// handed out is left open when the plane's spool drains. An execution a
// request in flight is handed after that is abandoned by the request: one
// not yet minted is answered ERROR_CODE_UNAVAILABLE, and one whose EXECUTE was
// being written is abandoned once the answer is out. It returns ErrDraining
// when ctx ended first.
func (a *Adapter) Shutdown(ctx context.Context) error {
	idle := a.flights.shut()
	var err error
	select {
	case <-idle:
	case <-ctx.Done():
		err = ErrDraining
	}
	open := a.handles.shutdown()
	if p := a.started(); p != nil {
		a.abandon(ctx, p, open)
	}
	return err
}

// abandon closes each execution as abandoned and spends its handle.
func (a *Adapter) abandon(ctx context.Context, p Pipeline, executions []taken) {
	for _, t := range executions {
		a.release(ctx, p, t.e.d)
		a.handles.spend(t.id, t.e, enforcev1alpha1.Ending_ENDING_ABANDONED)
	}
}

// Stats returns the counters.
func (a *Adapter) Stats() Stats {
	s := a.counts.snapshot()
	s.Open = a.handles.open()
	return s
}
