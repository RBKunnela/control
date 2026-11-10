package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"

	"github.com/guardana/control/adapters/authzen"
	"github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/secretscan"
	"github.com/guardana/control/internal/spool"
)

const (
	upstreamName = "victim"
	bundleID     = "e2e"

	v20260728 = "2026-07-28"
	v20251125 = "2025-11-25"
)

// The rules the planes decide against. No rule reads an argument value.
const (
	allowReads   = `{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}`
	allowDeletes = `{"id":"allow-deletes","effect":"ALLOW","when":{"action":{"effect":["DELETE"]}}}`
	denyDeletes  = `{"id":"deny-deletes","effect":"DENY","when":{"action":{"effect":["DELETE"]}}}`
	// cappedTransfers rewrites the bytes that go upstream: the amount is
	// capped and the named field is removed.
	cappedTransfers = `{"id":"capped-transfers","effect":"ALLOW_WITH_OBLIGATIONS",` +
		`"obligations":[{"type":"redact_fields","params":{"fields":"ssn"}},{"type":"cap_amount","params":{"max":"1000"}}],` +
		`"when":{"action":{"effect":["TRANSACT"]}}}`
	approveTransfers = `{"id":"approve-transfers","effect":"REQUIRE_APPROVAL","when":{"action":{"effect":["TRANSACT"]}}}`
)

// The reason codes a plane's answer carries, spelled as the registry spells
// them. internal/policy/reasons is the source; a literal here that drifts
// from it fails the assertion it is used in.
const (
	codeRuleAllow            = "RULE_ALLOW"
	codeRuleDeny             = "RULE_DENY"
	codeApprovalPending      = "APPROVAL_PENDING"
	codeApprovalAlreadyUsed  = "APPROVAL_ALREADY_USED"
	codeObligations          = "OBLIGATIONS_ATTACHED"
	codeUnclassified         = "ACTION_UNCLASSIFIED"
	codeEvidenceUnavailable  = "EVIDENCE_UNAVAILABLE"
	codeExecutedArgsMismatch = "EXECUTED_ARGS_MISMATCH"
)

// The modes the planes run in, and the enforcement point the blocks of the
// plane's own carry.
const (
	modeObserve = controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	modeEnforce = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE

	gatewayPDP = gateway.PDPType
)

const (
	kindProposed  = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	kindDecided   = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	kindStarted   = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	kindCompleted = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	kindFailed    = controlv1.EventKind_EVENT_KIND_ACTION_FAILED
	kindBlocked   = controlv1.EventKind_EVENT_KIND_ACTION_BLOCKED
	kindRequested = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
	kindApproved  = controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED
)

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// options is one arrangement of the plane.
type options struct {
	kind mcp.Kind
	mode controlv1.EnforcementMode
	// rules go into the signed bundle the kernel decides against, and
	// policyAge is how long before the plane starts it was last confirmed.
	rules     []string
	policyAge time.Duration
	// unconfirmed starts the plane with no statement bound to its bundle.
	unconfirmed bool
	// allowReadsUnrecorded is evidence.on_unwritable: allow_reads.
	allowReadsUnrecorded bool
	callTimeout          time.Duration
	// spoolBytes and closingReserve bound the log; zero takes room enough for
	// any test that is not about the budget.
	spoolBytes     int64
	closingReserve int64
	// wrap sits between the adapter and the pipeline, for the one thing no
	// honest adapter does: send or report bytes other than the authorized
	// ones.
	wrap func(mcp.Pipeline) mcp.Pipeline
	// noExport leaves the exporter unstarted, so nothing releases the spool.
	noExport bool
	// decisionPoint is the external decision point the pipeline asks, and
	// failOpenRead the kernel's risk setting for reads.
	decisionPoint *authzen.Client
	failOpenRead  bool
	// shaping is what tools/list subtracts.
	shaping mcp.Shaping
	// pause is the operator's pause state; nil is a plane with no pause file.
	pause gateway.PauseSource
	// classify edits the operator's classification of the victim's tools.
	classify func([]mcp.Override) []mcp.Override
}

// confirmedAt is when the plane's statement was issued, or the zero time for
// a plane that has none.
func (o options) confirmedAt() time.Time {
	if o.unconfirmed {
		return time.Time{}
	}
	return time.Now().Add(-o.policyAge)
}

// plane is one agent -> adapter -> pipeline -> upstream arrangement, with the
// spool on disk and the exporter draining it.
type plane struct {
	victim    *victim
	gate      *upstreamGate
	spool     *spool.Spool
	sink      *teeSink
	approvals *gateway.MemoryApprovals
	pipeline  *gateway.Pipeline
	adapter   *mcp.Adapter
	collector *collector
	exporter  *otel.Exporter
	version   string
	connect   func(t *testing.T, clientName string) *sdk.ClientSession
	// url is the HTTP listener's; empty on stdio.
	url string
}

// teeSink is the spool, mirrored in memory. The spool is what the pipeline
// writes to and what refuses an append; the mirror is how a test reads a trail
// while the exporter is draining segments and releasing them, which is the
// spool's own business and would otherwise race the reading.
type teeSink struct {
	sp *spool.Spool

	mu       sync.Mutex
	kept     []*controlv1.Event
	refusals int
}

func (s *teeSink) Append(ctx context.Context, event *controlv1.Event) error {
	if err := s.sp.Append(ctx, event); err != nil {
		s.mu.Lock()
		s.refusals++
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.kept = append(s.kept, proto.CloneOf(event))
	s.mu.Unlock()
	return nil
}

func (s *teeSink) events() []*controlv1.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*controlv1.Event(nil), s.kept...)
}

func (s *teeSink) refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refusals
}

// newPlane builds and starts everything, and tears it down in the order that
// leaves nothing holding the spool's directory.
func newPlane(t *testing.T, o options) *plane {
	t.Helper()
	p := &plane{victim: newVictim(), collector: newCollector(t)}
	upstream := p.upstream(t)
	p.openSpool(t, o)
	adapter, err := mcp.New(p.adapterConfig(t, o, upstream))
	if err != nil {
		t.Fatalf("mcp.New refused a configuration this test builds as valid: %v", err)
	}
	p.adapter = adapter
	p.approvals = &gateway.MemoryApprovals{}
	cfg := gateway.Config{
		Mode:                 o.mode,
		Adapter:              adapter,
		KernelOptions:        core.Options{MaxStale: 10 * time.Minute, FailOpenRead: o.failOpenRead},
		Policy:               holder(t, o.confirmedAt(), o.rules...),
		Pause:                o.pause,
		Stops:                gateway.StopsDisabled(),
		Sink:                 p.sink,
		Approvals:            p.approvals,
		Authority:            p.approvals,
		AuthorityKind:        gateway.AuthorityDirectory,
		Ledger:               &gateway.MemoryLedger{},
		Clock:                time.Now,
		NewID:                ids(),
		ApprovalTTL:          10 * time.Minute,
		RetryAfter:           time.Second,
		MaxHeld:              16,
		MaxOpen:              16,
		MaxRuns:              16,
		AllowReadsUnrecorded: o.allowReadsUnrecorded,
	}
	if cfg.Pause == nil {
		cfg.Pause = gateway.PauseDisabled()
	}
	if o.decisionPoint != nil {
		cfg.DecisionPoint, cfg.DecisionPointID, cfg.DecisionTimeout = o.decisionPoint, o.decisionPoint.Identifier(), askTimeout
	}
	pipeline, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New refused a configuration this test builds as valid: %v", err)
	}
	p.pipeline = pipeline
	var driven mcp.Pipeline = pipeline
	if o.wrap != nil {
		driven = o.wrap(pipeline)
	}
	if err := adapter.Start(ctxT(t), driven); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	p.export(t, o)
	p.listen(t, o)
	return p
}

// upstream serves the victim over Streamable HTTP behind a gate, whatever the
// listener toward the agent is: the revision under test is the agent's, and
// one upstream transport keeps the arrangements comparable.
func (p *plane) upstream(t *testing.T) sdk.Transport {
	t.Helper()
	handler := sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return p.victim.server },
		&sdk.StreamableHTTPOptions{Stateless: true})
	p.gate = &upstreamGate{next: handler}
	ts := httptest.NewServer(p.gate)
	t.Cleanup(ts.Close)
	return &sdk.StreamableClientTransport{Endpoint: ts.URL}
}

func (p *plane) openSpool(t *testing.T, o options) {
	t.Helper()
	maxBytes, reserve := o.spoolBytes, o.closingReserve
	if maxBytes == 0 {
		maxBytes, reserve = 8<<20, spool.DefaultClosingReserve
	}
	sp, err := spool.Open(spool.Options{
		Dir:            t.TempDir(),
		MaxBytes:       maxBytes,
		SegmentBytes:   maxBytes / 4,
		ClosingReserve: reserve,
	})
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	p.spool, p.sink = sp, &teeSink{sp: sp}
}

func (p *plane) adapterConfig(t *testing.T, o options, upstream sdk.Transport) mcp.Config {
	t.Helper()
	overrides := p.victim.overrides(t)
	if o.classify != nil {
		overrides = o.classify(overrides)
	}
	return mcp.Config{
		Listener: mcp.Listener{
			Kind: o.kind,
			Identity: mcp.Identity{
				Principal: &controlv1.Principal{Id: "svc-agent", Type: "service", TenantId: "t1"},
				Agent:     &controlv1.Agent{Id: "agent-1", Framework: "test"},
			},
		},
		Upstreams:   []mcp.Upstream{{Name: upstreamName, Transport: upstream, TenantID: "t1", Environment: "prod"}},
		Overrides:   overrides,
		Shaping:     o.shaping,
		CallTimeout: o.callTimeout,
		ProjectID:   "p1", TenantID: "t1", Environment: "prod",
		Clock:   time.Now,
		NewID:   ids(),
		Secrets: noSecrets(t),
	}
}

// noSecrets is the empty set, which scans every answer and finds nothing.
func noSecrets(t *testing.T) *secretscan.Set {
	t.Helper()
	set, err := secretscan.New(nil)
	if err != nil {
		t.Fatalf("secretscan.New(nil): %v", err)
	}
	return set
}

// export starts the real exporter over the spool, unless the arrangement wants
// nothing releasing the log.
func (p *plane) export(t *testing.T, o options) {
	t.Helper()
	if o.noExport {
		return
	}
	reader, err := p.spool.Reader(spool.Cursor{})
	if err != nil {
		t.Fatalf("spool.Reader: %v", err)
	}
	exporter, err := otel.New(otel.Options{
		Endpoint:   p.collector.url,
		Client:     p.collector.client,
		InFlight:   2,
		Timeout:    2 * time.Second,
		MaxBatch:   8,
		Linger:     10 * time.Millisecond,
		Backoff:    20 * time.Millisecond,
		MaxBackoff: 40 * time.Millisecond,
	}, reader)
	if err != nil {
		t.Fatalf("otel.New: %v", err)
	}
	p.exporter = exporter
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exporter.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the exporter stopped with %v", err)
		}
		_ = reader.Close()
	})
}

// listen binds the agent-facing side and gives the plane its connect function.
func (p *plane) listen(t *testing.T, o options) {
	t.Helper()
	if o.kind == mcp.KindStdio {
		p.version = v20260728
		p.connect = func(t *testing.T, clientName string) *sdk.ClientSession {
			t.Helper()
			return connectStdio(t, p.adapter, clientName)
		}
		return
	}
	p.version = v20260728
	if o.kind == mcp.KindStatefulHTTP {
		p.version = v20251125
	}
	handler, err := p.adapter.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	p.url = ts.URL
	p.connect = func(t *testing.T, clientName string) *sdk.ClientSession {
		t.Helper()
		client := sdk.NewClient(&sdk.Implementation{Name: clientName, Version: "0"}, nil)
		cs, err := client.Connect(ctxT(t), &sdk.StreamableClientTransport{Endpoint: ts.URL},
			&sdk.ClientSessionOptions{ProtocolVersion: p.version})
		if err != nil {
			t.Fatalf("connect at %s as %s: %v", p.version, clientName, err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		return cs
	}
}

func connectStdio(t *testing.T, a *mcp.Adapter, clientName string) *sdk.ClientSession {
	t.Helper()
	toServer, fromAgent := newPipe()
	toAgent, fromServer := newPipe()
	ctx, cancel := context.WithCancel(ctxT(t))
	t.Cleanup(cancel)
	go func() { _ = a.ServeStdio(ctx, toServer, fromServer) }()
	client := sdk.NewClient(&sdk.Implementation{Name: clientName, Version: "0"}, nil)
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: toAgent, Writer: fromAgent}, nil)
	if err != nil {
		t.Fatalf("stdio connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// ids is an id source that returns a fresh value on every call, which the
// pipeline probes at start.
func ids() func() string {
	var n atomic.Int64
	return func() string { return "id-" + strconv.FormatInt(n.Add(1), 10) }
}

func key() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
}

// holder installs a signed bundle of rules in a holder pinned to its id over
// a floor on disk, the way the command builds one: confirmed by a statement
// issued at confirmed, to the second, or unconfirmed when confirmed is the
// zero time.
func holder(t *testing.T, confirmed time.Time, rules ...string) *policy.Holder {
	t.Helper()
	doc := []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"` + bundleID +
		`","version":"2026-09-20.1","serial":1,"maxStaleSeconds":600},"rules":[` + strings.Join(rules, ",") + `]}`)
	b, err := policy.Sign(doc, key(), "k1")
	if err != nil {
		t.Fatalf("Sign refused a document this test builds as valid: %v", err)
	}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "floors")
	if err := policystate.Init(ctx, dir, policystate.KindPlane, bundleID); err != nil {
		t.Fatalf("policystate.Init: %v", err)
	}
	store, err := policystate.Open(dir, policystate.KindPlane)
	if err != nil {
		t.Fatalf("policystate.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h, err := policy.NewFloorHolder(bundleID, store)
	if err != nil {
		t.Fatalf("NewFloorHolder: %v", err)
	}
	pub := ed25519.PublicKey(slices.Clone(key()[ed25519.SeedSize:]))
	keys := bundle.Keyring{"k1": pub}
	if confirmed.IsZero() {
		if err := h.InstallUnconfirmed(ctx, b, keys); err != nil {
			t.Fatalf("InstallUnconfirmed refused a bundle this test builds as valid: %v", err)
		}
		return h
	}
	issued := confirmed.UTC().Truncate(time.Second)
	env, err := policy.SignStatement(bundleID, 1, b.GetRef().GetDigest(), issued, key(), "k1")
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	st, err := policy.VerifyStatement(env, keys)
	if err != nil {
		t.Fatalf("VerifyStatement: %v", err)
	}
	if err := h.InstallConfirmed(ctx, b, keys, st, issued); err != nil {
		t.Fatalf("InstallConfirmed refused a bundle this test builds as valid: %v", err)
	}
	return h
}
