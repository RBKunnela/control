package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gateway"
)

// Stats counts what the adapter did, for health and for a test that has to
// see a failure nothing else reports.
type Stats struct {
	Admitted      int64
	Blocked       int64
	Sent          int64
	CloseFailures int64
	// RefreshFailures counts tools/list reads that failed, each of which
	// dropped that upstream's entries.
	RefreshFailures int64
	// RunsRefusedAtRequest counts run tokens the HTTP listener refused before
	// the library read the request; RunsRefusedAtMessage counts those refused
	// at a message, on HTTP or stdio. A request refused at the first never
	// reaches the second.
	RunsRefusedAtRequest RunRefusals
	RunsRefusedAtMessage RunRefusals
	// SessionsRefused counts the sessionless POSTs a stateful listener
	// counted as opens and refused at its cap on live sessions; SessionsLive
	// is how many sessions it holds now, zero on any other listener.
	SessionsRefused int64
	SessionsLive    int64
	// Withheld counts the answers to calls and forwarded lists that quoted a
	// credential the gateway holds, or could not be scanned, and reached the
	// agent as a fixed answer.
	Withheld int64
}

// Adapter is the MCP adapter as the pipeline sees it and as the agent
// reaches it: it translates, and the meaning of a call lives in the envelope
// it builds and in the policy, never here.
type Adapter struct {
	cfg      Config
	server   *mcp.Server
	manifest *manifest
	names    []string
	logger   *slog.Logger

	mu        sync.RWMutex
	pipeline  Pipeline
	upstreams map[string]*mcp.ClientSession
	lists     *listCache

	admitted, blocked, sent, closeFailures, refreshFailures atomic.Int64
	sessionsRefused, withheld                               atomic.Int64
	refusedAtRequest, refusedAtMessage                      *adapterkit.RunCounter
	flights                                                 flights
}

// ErrDraining is a call that reached the adapter after Drain began: it is
// neither admitted nor recorded.
const ErrDraining Error = "mcp: the gateway is stopping and admits no call"

// flights counts the calls from admission to their closing or aborting
// record. Once shut it admits none, so a stop can wait for every call it let
// in: a call cannot slip in after the wait read zero.
type flights struct {
	mu sync.Mutex
	n  int64
	// idle is made by shut and closed once no admitted call is left.
	idle chan struct{}
}

func (f *flights) enter() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idle != nil {
		return false
	}
	f.n++
	return true
}

func (f *flights) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n--
	if f.n == 0 && f.idle != nil {
		close(f.idle)
	}
}

func (f *flights) shut() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idle == nil {
		f.idle = make(chan struct{})
		if f.n == 0 {
			close(f.idle)
		}
	}
	return f.idle
}

func (f *flights) count() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// StopAdmitting refuses every call from now on with ErrDraining.
func (a *Adapter) StopAdmitting() { a.flights.shut() }

// Drain admits no further call and waits up to bound for the calls admitted
// before it to append their closing or aborting records, on every listener
// kind. It returns how many have not; each of their trails may stay open.
func (a *Adapter) Drain(bound time.Duration) int64 {
	idle := a.flights.shut()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-idle:
	case <-timer.C:
	}
	return a.flights.count()
}

var _ gateway.Adapter = (*Adapter)(nil)

// New checks cfg once and returns an adapter that is not yet connected to
// anything: Start connects it. It refuses a listener kind it does not serve,
// an authenticator on stdio, a listener without an identity, a run token
// source that does not fit the listener, an upstream without a transport or
// with a name no envelope can carry, two upstreams with one name, an override
// that names no known upstream, is incomplete, carries a classification
// classify.Check refuses or needs an environment or a tenant the listener or
// its upstream leaves empty, a shaping it does not know, a negative call or
// list timeout, and a nil clock, id source or secret set.
func New(cfg Config) (*Adapter, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg: cfg, manifest: newManifest(cfg.Overrides, cfg.Secrets), lists: newListCache(cfg.ListTTL), logger: cfg.Logger,
		refusedAtRequest: adapterkit.NewRunCounter(), refusedAtMessage: adapterkit.NewRunCounter(),
	}
	if a.logger == nil {
		a.logger = slog.New(slog.DiscardHandler)
	}
	for _, up := range cfg.Upstreams {
		a.names = append(a.names, up.Name)
	}
	// The library emits tools/list_changed only when its own registry
	// changes, and the gateway registers no tools of its own, so a listener
	// that promised the notification would never send one.
	a.server = mcp.NewServer(&mcp.Implementation{Name: brand.Gateway, Version: "0"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools:     &mcp.ToolCapabilities{ListChanged: false},
			Resources: &mcp.ResourceCapabilities{},
			Prompts:   &mcp.PromptCapabilities{},
		},
	})
	a.server.AddReceivingMiddleware(a.middleware)
	return a, nil
}

// Name is the protocol's.
func (*Adapter) Name() string { return "mcp" }

// Capabilities declares what the adapter does, each backed by a conformance
// test in this package. Authenticates and BindEndUser hold only for a
// listener with an authenticator. Obligations are the ones the adapter
// applies to a call itself; the pipeline applies the ones that rewrite.
func (a *Adapter) Capabilities() gateway.Capabilities {
	authenticates := a.cfg.Listener.Authenticator != nil
	return gateway.Capabilities{
		ObserveRequest: true,
		ObserveResult:  true,
		Enforcement:    gateway.EnforcementInline,
		Authenticates:  authenticates,
		BindEndUser:    authenticates,
		PresentsRuns:   a.cfg.Listener.Runs != nil,
		SeeResourceIDs: true,
		Obligations:    AppliedObligations(),
	}
}

// Start connects every upstream, reads its tools into the manifest and
// binds the pipeline. An upstream that cannot be reached, or whose list
// cannot be read or is longer than the bound, fails Start rather than
// serving without it.
func (a *Adapter) Start(ctx context.Context, p Pipeline) error {
	if p == nil {
		return ErrNoPipeline
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.upstreams != nil {
		return ErrStarted
	}
	sessions := map[string]*mcp.ClientSession{}
	for _, up := range a.cfg.Upstreams {
		cs, err := a.connect(ctx, up)
		if err != nil {
			closeAll(sessions)
			return startFailed("connect", up.Name, err)
		}
		sessions[up.Name] = cs
		if err := a.refresh(ctx, up.Name, cs); err != nil {
			closeAll(sessions)
			return startFailed("tools/list from", up.Name, err)
		}
	}
	a.pipeline, a.upstreams = p, sessions
	return nil
}

// refresh reads one upstream's tools into the manifest under the list
// timeout, drops every shaped list, which was shaped from what the manifest
// held before, and logs each definition the scan withheld.
func (a *Adapter) refresh(ctx context.Context, upstream string, cs *mcp.ClientSession) error {
	ctx, cancel := context.WithTimeout(ctx, a.listTimeout())
	defer cancel()
	err := a.manifest.refresh(ctx, upstream, cs)
	a.lists.reset(a.manifest.currentGeneration())
	a.logWithheldDefinitions(upstream)
	return err
}

// connect is bounded by the list timeout: an upstream that takes the
// connection and never answers its initialization would otherwise hold Start,
// with no listener bound, until a signal. The session the library keeps does
// not inherit this deadline.
func (a *Adapter) connect(ctx context.Context, up Upstream) (*mcp.ClientSession, error) {
	ctx, cancel := context.WithTimeout(ctx, a.listTimeout())
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: brand.Gateway, Version: "0"}, &mcp.ClientOptions{
		// The library would answer an upstream's input request itself and
		// send the admitted call again; the plane decided one send.
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
		ToolListChangedHandler: func(ctx context.Context, req *mcp.ToolListChangedRequest) {
			if err := a.refresh(ctx, up.Name, req.Session); err != nil {
				a.refreshFailures.Add(1)
				a.logger.Error("manifest refresh failed", "upstream", up.Name, "err", logText(err))
			}
		},
	})
	return client.Connect(ctx, up.Transport, nil)
}

// startFailed is a failure of Start as logText words it, after what failed
// and the upstream's name: the transport's text can quote the endpoint and
// the upstream's the credential it reflects. Only the list bound, the
// adapter's own, is kept for errors.Is.
func startFailed(what, upstream string, err error) error {
	if errors.Is(err, ErrListBound) {
		return fmt.Errorf("mcp: %s %s: %w", what, upstream, ErrListBound)
	}
	return fmt.Errorf("mcp: %s %s: %s", what, upstream, logText(err))
}

func closeAll(sessions map[string]*mcp.ClientSession) {
	for _, cs := range sessions {
		_ = cs.Close() // the sessions are being abandoned; nothing reads a close error here
	}
}

// Close disconnects every upstream. A failure names the upstream and its cause
// as logText words it, since the library's text quotes the endpoint.
func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var errs []error
	for name, cs := range a.upstreams {
		if err := cs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("mcp: close %s: %s", name, logText(err)))
		}
	}
	a.upstreams = nil
	return errors.Join(errs...)
}

// Stats returns the counters.
func (a *Adapter) Stats() Stats {
	return Stats{
		Admitted: a.admitted.Load(), Blocked: a.blocked.Load(), Sent: a.sent.Load(),
		CloseFailures: a.closeFailures.Load(), RefreshFailures: a.refreshFailures.Load(),
		RunsRefusedAtRequest: RunRefusals(a.refusedAtRequest.Snapshot()), RunsRefusedAtMessage: RunRefusals(a.refusedAtMessage.Snapshot()),
		SessionsRefused: a.sessionsRefused.Load(), SessionsLive: a.statefulSessions(),
		Withheld: a.withheld.Load(),
	}
}

// InFlight is how many calls are admitted and not yet closed or aborted.
func (a *Adapter) InFlight() int64 { return a.flights.count() }

// statefulSessions is the sessions a stateful listener holds; every other
// listener's are a request's own, and none is counted.
func (a *Adapter) statefulSessions() int64 {
	if a.cfg.Listener.Kind != KindStatefulHTTP {
		return 0
	}
	return int64(a.liveSessions())
}

// Entries returns the manifest as it stands, one entry per listed tool.
func (a *Adapter) Entries() []Entry {
	out, _ := a.manifest.snapshot(a.names)
	return out
}

// started returns the pipeline and the upstream session for name, or
// ErrNotStarted before Start.
func (a *Adapter) started() (Pipeline, map[string]*mcp.ClientSession, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.upstreams == nil {
		return nil, nil, ErrNotStarted
	}
	return a.pipeline, a.upstreams, nil
}
