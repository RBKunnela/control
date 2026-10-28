package mcp

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/secretscan"
	"github.com/guardana/control/pkg/contract"
)

// Kind is the transport a listener serves toward the agent.
type Kind int

const (
	// KindUnspecified is no listener; New refuses it.
	KindUnspecified Kind = iota
	// KindStatelessHTTP is Streamable HTTP without sessions, which serves
	// protocol 2026-07-28.
	KindStatelessHTTP
	// KindStatefulHTTP is Streamable HTTP with sessions, which serves
	// 2025-11-25 and older and answers a 2026-07-28 request with -32022.
	KindStatefulHTTP
	// KindStdio is one agent over a pipe; nothing authenticates it.
	KindStdio
)

// Shaping is what tools/list subtracts for a principal.
type Shaping int

const (
	// ShapeNone answers the upstream's list.
	ShapeNone Shaping = iota
	// ShapeAnnotate marks each tool with the verdict the policy gives a call
	// to it, and an unclassified tool with ACTION_UNCLASSIFIED.
	ShapeAnnotate
	// ShapeHide omits a tool the policy denies and every unclassified tool.
	ShapeHide
)

// Identity is who a listener's calls are made by when nothing authenticates
// them, and what an authenticated listener fills in around the user it
// bound.
type Identity struct {
	Principal *controlv1.Principal
	Agent     *controlv1.Agent
}

// Listener is the agent-facing side.
type Listener struct {
	Kind Kind
	// Origins are the browser origins an HTTP listener accepts, loopback
	// included: a request whose Origin is outside them is refused. The
	// adapter serves a handler and binds no address of its own.
	Origins []string
	// Authenticator wraps the HTTP handler and establishes the end user in
	// the request's context, the way auth.RequireBearerToken does. With one,
	// the principal's id is the user the token names; without one, nobody is
	// authenticated and the principal is Identity's.
	Authenticator func(http.Handler) http.Handler
	// AuthnStrength is recorded on a principal the Authenticator bound.
	AuthnStrength string
	Identity      Identity
	// Runs resolves the run token at every request and every message
	// (ADR-0034): the RunTokenHeader on HTTP, RunToken on stdio. Nil serves
	// local runs.
	Runs gateway.RunResolver
	// RunToken is a stdio listener's token, read from the operator's file;
	// set exactly when Runs is, and on stdio only.
	RunToken string
	// SessionIdle ends a stateful HTTP session that has been idle this long;
	// zero is DefaultSessionIdle. Without a bound, sessions a client opens and
	// abandons hold their memory until the plane stops.
	SessionIdle time.Duration
	// MaxSessions caps the stateful HTTP sessions live at once; zero is
	// DefaultMaxSessions. A request that would open one more is refused until
	// one closes or idles out.
	MaxSessions int
	// BodyTimeout bounds how long an HTTP request may take over sending its
	// body, and how long its answer may wait on a client that stops reading;
	// zero is DefaultBodyTimeout.
	BodyTimeout time.Duration
}

// DefaultSessionIdle is how long a stateful HTTP session may sit idle.
const DefaultSessionIdle = 30 * time.Minute

// DefaultMaxSessions is how many stateful HTTP sessions may be live at once:
// far more than the agents one plane serves, and a bound on what clients that
// open sessions and never close them can hold.
const DefaultMaxSessions = 1024

// DefaultBodyTimeout is how long an HTTP request may take over its body, and
// its answer may make no progress.
const DefaultBodyTimeout = 30 * time.Second

// Upstream is one server the gateway calls as itself.
type Upstream struct {
	Name      string
	Transport mcp.Transport
	// TenantID and Environment are the resources' the upstream serves, for
	// the envelope's resource.tenant_id and resource.environment.
	TenantID    string
	Environment string
}

// Config configures an Adapter once, at New.
type Config struct {
	Listener  Listener
	Upstreams []Upstream
	Overrides []Override
	Shaping   Shaping
	// ListTTL is the ttlMs a shaped tools/list carries and how long the
	// adapter keeps one per principal; zero means immediately stale.
	ListTTL time.Duration
	// CallTimeout bounds every upstream call; zero means no bound of the
	// adapter's own, and New refuses a negative one.
	CallTimeout time.Duration
	// ListTimeout bounds reading one upstream's list, on a manifest refresh
	// and on a forwarded list; zero takes the package's own bound.
	ListTimeout time.Duration
	// ProjectID, TenantID and Environment say where the request was received.
	ProjectID   string
	TenantID    string
	Environment string
	Clock       func() time.Time
	NewID       func() string
	// Secrets are the plane's credentials, which no upstream answer may carry
	// to the agent (ADR-0042). An empty set scans and finds nothing.
	Secrets *secretscan.Set
	// Logger takes what the adapter cannot answer to anyone: a closing record
	// that failed, a manifest that could not be refreshed. Nil discards.
	Logger *slog.Logger
}

// ErrCallTimeout is a negative bound on an upstream call, which would also
// discard an obligation's shorter one.
const ErrCallTimeout Error = "mcp: the call timeout cannot be negative"

// ErrNoScanSet is a configuration with no set of secrets: a forgotten wiring
// would otherwise turn the scan of answers off unseen.
const ErrNoScanSet Error = "mcp: no set of secrets to scan answers for"

func checkConfig(cfg Config) error {
	if err := checkListener(cfg.Listener); err != nil {
		return err
	}
	if cfg.Shaping < ShapeNone || cfg.Shaping > ShapeHide {
		return fmt.Errorf("%w: %d", ErrShaping, cfg.Shaping)
	}
	if cfg.Clock == nil {
		return ErrNoClock
	}
	if cfg.NewID == nil {
		return ErrNoIDSource
	}
	if cfg.Secrets == nil {
		return ErrNoScanSet
	}
	if cfg.ListTimeout < 0 {
		return fmt.Errorf("%w: %v", ErrListTimeout, cfg.ListTimeout)
	}
	if cfg.CallTimeout < 0 {
		return fmt.Errorf("%w: %v", ErrCallTimeout, cfg.CallTimeout)
	}
	names, err := checkUpstreams(cfg.Upstreams)
	if err != nil {
		return err
	}
	if err := checkOverrides(cfg.Overrides, names); err != nil {
		return err
	}
	return checkUpstreamKeys(cfg)
}

func checkListener(l Listener) error {
	switch l.Kind {
	case KindStatelessHTTP, KindStatefulHTTP:
	case KindStdio:
		if l.Authenticator != nil {
			return fmt.Errorf("%w: stdio has no request to authenticate", ErrListener)
		}
	default:
		return fmt.Errorf("%w: kind %d", ErrListener, l.Kind)
	}
	if err := checkSessionCap(l); err != nil {
		return err
	}
	if l.Identity.Principal == nil || l.Identity.Agent == nil {
		return ErrIdentity
	}
	if err := checkRunsSource(l); err != nil {
		return err
	}
	if l.Authenticator == nil {
		return nil
	}
	// The token names the user; configuration says only which tenant and
	// which type of principal the listener serves. An id, a strength or
	// attributes set here would be a claim about a user nobody authenticated.
	p := l.Identity.Principal
	if p.GetId() != "" || p.GetAuthnStrength() != "" || len(p.GetAttributes()) > 0 {
		return fmt.Errorf("%w: an authenticated listener configures the tenant and the type only", ErrIdentity)
	}
	return nil
}

// checkSessionCap refuses a negative cap on sessions, and any cap on a
// listener that keeps none.
func checkSessionCap(l Listener) error {
	switch {
	case l.MaxSessions < 0:
		return fmt.Errorf("%w: a negative cap on sessions", ErrListener)
	case l.MaxSessions > 0 && l.Kind != KindStatefulHTTP:
		return fmt.Errorf("%w: a cap on sessions on a listener that keeps none", ErrListener)
	}
	return nil
}

func checkUpstreams(upstreams []Upstream) (map[string]bool, error) {
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("%w: no upstream", ErrUpstream)
	}
	names := map[string]bool{}
	for i, up := range upstreams {
		// The name is every call's action.provider.
		if err := classify.CheckEnvelopeString(up.Name); err != nil {
			return nil, fmt.Errorf("%w: Upstreams[%d]: name: %w", ErrUpstream, i, err)
		}
		if up.Transport == nil || names[up.Name] {
			return nil, fmt.Errorf("%w: Upstreams[%d]", ErrUpstream, i)
		}
		names[up.Name] = true
	}
	return names, nil
}

// checkOverrides refuses an entry that cannot classify, naming the key
// classify.Check refuses, and a second entry for one upstream's tool, which
// the manifest would let replace the first.
func checkOverrides(overrides []Override, names map[string]bool) error {
	type key struct{ upstream, tool string }
	seen := make(map[key]int, len(overrides))
	for i, o := range overrides {
		if first, ok := seen[key{o.Upstream, o.Tool}]; ok {
			return fmt.Errorf("%w: Overrides[%d] classifies the tool Overrides[%d] does", ErrOverride, i, first)
		}
		seen[key{o.Upstream, o.Tool}] = i
		switch {
		case !names[o.Upstream]:
			return fmt.Errorf("%w: Overrides[%d] names no configured upstream", ErrOverride, i)
		case o.Tool == "" || o.Fingerprint == "":
			return fmt.Errorf("%w: Overrides[%d] needs a tool and a fingerprint", ErrOverride, i)
		}
		if err := o.Check(); err != nil {
			return fmt.Errorf("%w: Overrides[%d]: %w", ErrOverride, i, err)
		}
	}
	return nil
}

// checkUpstreamKeys refuses an override whose envelope needs, by the
// contract's table, the environment, the resource's or the resource's tenant
// while the value it is read from, the listener's or the override's
// upstream's, is empty: every call to the tool would be refused, OBSERVE
// included. checkOverrides has found each override's upstream.
func checkUpstreamKeys(cfg Config) error {
	for i, o := range cfg.Overrides {
		required := contract.EffectRequires(o.Effect)
		up := slices.IndexFunc(cfg.Upstreams, func(u Upstream) bool { return u.Name == o.Upstream })
		switch {
		case cfg.Environment == "" && slices.Contains(required, "environment"):
			return fmt.Errorf("%w: Overrides[%d]: %s needs Environment, which is empty", ErrOverride, i, o.Effect)
		case cfg.Upstreams[up].Environment == "" && slices.Contains(required, "resource.environment"):
			return fmt.Errorf("%w: Overrides[%d]: %s needs Upstreams[%d].Environment, which is empty", ErrOverride, i, o.Effect, up)
		case cfg.Upstreams[up].TenantID == "" && slices.Contains(required, "resource.tenant_id"):
			return fmt.Errorf("%w: Overrides[%d]: %s needs Upstreams[%d].TenantID, which is empty", ErrOverride, i, o.Effect, up)
		}
	}
	return nil
}
