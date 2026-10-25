package enforce_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
)

const (
	effectRead     = controlv1.EffectClass_EFFECT_CLASS_READ
	effectTransact = controlv1.EffectClass_EFFECT_CLASS_TRANSACT
	effectComm     = controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE
	zoneExternal   = controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL

	modeEnforce = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
	modeApprove = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE

	runA     = "run-a.a1"
	runB     = "run-b.b1"
	runOther = "run-o.o1"
	runShut  = "run-c.c1"
)

// Rules, as JSON, for document below.
const (
	allowReads     = `{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}`
	allowRefunds   = `{"id":"allow-refunds","effect":"ALLOW","when":{"action":{"name":["refund"]}}}`
	denyRefunds    = `{"id":"deny-refunds","effect":"DENY","when":{"action":{"name":["refund"]}}}`
	approveRefunds = `{"id":"approve-refunds","effect":"REQUIRE_APPROVAL","when":{"action":{"name":["refund"]}}}`
	cappedRefunds  = `{"id":"capped-refunds","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_rate","advisory":true},{"type":"cap_amount","params":{"max":"1000"}}],"when":{"action":{"name":["refund"]}}}`
)

func base() time.Time { return time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC) }

func listenerIdentity() enforce.Identity {
	return enforce.Identity{
		Principal: &controlv1.Principal{Id: "user-1", TenantId: "tenant-1", Type: "user"},
		Agent:     &controlv1.Agent{Id: "agent-1"},
	}
}

func listenerWho() gateway.RunIdentity {
	return gateway.RunIdentity{TenantID: "tenant-1", PrincipalType: "user", PrincipalID: "user-1", AgentID: "agent-1"}
}

func tools() []enforce.Tool {
	return []enforce.Tool{
		{Name: "refund", Provider: "payments", Classification: classify.Classification{Effect: effectTransact, ResourceType: "account", ResourceFrom: "/account"}},
		{Name: "read_file", Provider: "files", Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}},
		{Name: "send_mail", Provider: "mail", Classification: classify.Classification{Effect: effectComm, ResourceType: "mailbox", ResourceFrom: "/to", TrustZone: zoneExternal}},
	}
}

func document(rules ...string) []byte {
	return []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"tools","version":"2026-10-11.1","serial":1,"maxStaleSeconds":3600},"rules":[` +
		strings.Join(rules, ",") + `]}`)
}

func signingKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

func snapshot(t testing.TB, rules ...string) *policy.Snapshot {
	t.Helper()
	b, err := policy.Sign(document(rules...), signingKey(), "k1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, ok := signingKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("no ed25519 public key")
	}
	snap, err := policy.Load(b, bundle.Keyring{"k1": pub}, base())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return snap
}

type fixedPolicy struct{ snap *policy.Snapshot }

func (p fixedPolicy) Current() *policy.Snapshot { return p.snap }

// clock is a settable clock shared by the plane and the adapter.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeRun is one run the fake directory holds.
type fakeRun struct {
	run    gateway.OpenedRun
	closed bool
}

// fakeRuns is a runs directory in memory: it resolves the tokens it holds by
// the identity and expiry rules of internal/runs, and keeps each root's state.
type fakeRuns struct {
	mu     sync.Mutex
	tokens map[string]*fakeRun
	states map[string]gateway.RunState
	asked  atomic.Int64
}

func newFakeRuns() *fakeRuns {
	f := &fakeRuns{tokens: map[string]*fakeRun{}, states: map[string]gateway.RunState{}}
	f.add(runA, "run-a", listenerWho())
	f.add(runB, "run-b", listenerWho())
	f.add(runShut, "run-c", listenerWho())
	other := listenerWho()
	other.AgentID = "agent-2"
	f.add(runOther, "run-o", other)
	return f
}

func (f *fakeRuns) add(token, id string, who gateway.RunIdentity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[token] = &fakeRun{run: gateway.OpenedRun{ID: id, Root: id, Who: who, Expires: base().Add(24 * time.Hour)}}
	f.states[id] = gateway.RunState{Trusted: true, MaxRead: controlv1.Sensitivity_SENSITIVITY_PUBLIC}
}

func (f *fakeRuns) close(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[token].closed = true
}

func (f *fakeRuns) Resolve(_ context.Context, token string, who gateway.RunIdentity, now time.Time) (gateway.OpenedRun, error) {
	f.asked.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.tokens[token]
	switch {
	case !ok:
		return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunUnknown}
	case r.run.Who != who:
		return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunOtherIdentity}
	case r.closed:
		return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunClosed}
	case !now.Before(r.run.Expires):
		return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunExpired}
	}
	return r.run, nil
}

func (f *fakeRuns) State(_ context.Context, root string) (gateway.RunState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[root], nil
}

func (f *fakeRuns) Raise(_ context.Context, root string, join func(gateway.RunState) gateway.RunState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[root] = join(f.states[root])
	return nil
}

// rig is an adapter served on a real socket in front of a real pipeline.
type rig struct {
	a      *enforce.Adapter
	p      *gateway.Pipeline
	sink   *evidence.MemorySink
	store  *gateway.MemoryApprovals
	clock  *clock
	runs   *fakeRuns
	socket string
	http   *http.Client
}

// options are what a test or a conformance case changes about a rig.
type options struct {
	mode     controlv1.EnforcementMode
	rules    []string
	tools    []enforce.Tool
	lifetime time.Duration
	adapter  func(*enforce.Config)
	pipeline func(enforce.Pipeline) enforce.Pipeline
	resolver func(gateway.RunResolver) gateway.RunResolver
	plane    func(*gateway.Config)
}

func defaults() options {
	return options{mode: modeEnforce, rules: []string{allowReads, allowRefunds}, tools: tools(), lifetime: time.Minute}
}

func newRig(t *testing.T, o options) *rig {
	t.Helper()
	r := &rig{sink: &evidence.MemorySink{}, store: &gateway.MemoryApprovals{}, clock: &clock{now: base()}, runs: newFakeRuns()}
	var ids atomic.Int64
	newID := func() string { return "id-" + strconv.FormatInt(ids.Add(1), 10) }
	r.socket = socketPath(t)
	var resolver gateway.RunResolver = r.runs
	if o.resolver != nil {
		resolver = o.resolver(resolver)
	}
	cfg := enforce.Config{
		Socket: r.socket, ExecutionLifetime: o.lifetime,
		ProjectID: "proj-1", TenantID: "tenant-1", Environment: "prod",
		Identity: listenerIdentity(), Runs: resolver, Tools: o.tools,
		Clock: r.clock.read, NewID: newID,
	}
	if o.adapter != nil {
		o.adapter(&cfg)
	}
	a, err := enforce.New(cfg)
	if err != nil {
		t.Fatalf("enforce.New refused a configuration this test builds as valid: %v", err)
	}
	pcfg := gateway.Config{
		Mode: o.mode, Adapter: a, KernelOptions: core.Options{MaxStale: time.Hour},
		Policy: fixedPolicy{snapshot(t, o.rules...)}, Pause: gateway.PauseDisabled(), Stops: gateway.StopsDisabled(),
		Sink: r.sink, Approvals: r.store, Runs: r.runs, Clock: r.clock.read, NewID: newID,
		ApprovalTTL: 10 * time.Minute, RetryAfter: 5 * time.Second, MaxHeld: 16, MaxOpen: 16, MaxRuns: 16,
	}
	if o.plane != nil {
		o.plane(&pcfg)
	}
	p, err := gateway.New(pcfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	r.a, r.p = a, p
	var pipe enforce.Pipeline = p
	if o.pipeline != nil {
		pipe = o.pipeline(pipe)
	}
	if err := a.Start(pipe); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ln, err := a.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	r.http = unixClient(r.socket)
	return r
}

// socketPath is a socket in a fresh directory of this user's with mode 0700.
// The directory is short because a socket path is bounded at about 104 bytes.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "enf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

func unixClient(socket string) *http.Client {
	dialer := &net.Dialer{}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		}},
	}
}

// post sends body to path under token, with no Run-Token header when token is
// empty, and returns the status and the answer's bytes.
func (r *rig) post(t testing.TB, token, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://enforce"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set(enforce.RunTokenHeader, token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func (r *rig) kinds() []controlv1.EventKind {
	var out []controlv1.EventKind
	for _, e := range r.sink.Events() {
		out = append(out, e.GetKind())
	}
	return out
}

func (r *rig) count(kind controlv1.EventKind) int {
	return len(slices.DeleteFunc(r.kinds(), func(k controlv1.EventKind) bool { return k != kind }))
}
