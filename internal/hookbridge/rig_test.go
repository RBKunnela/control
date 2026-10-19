package hookbridge_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/enforceclient"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
)

const runToken = "run-a.a1"

// Rules for the plane, as JSON.
const (
	allowRefunds   = `{"id":"allow-refunds","effect":"ALLOW","when":{"action":{"name":["refund"]}}}`
	denyRefunds    = `{"id":"deny-refunds","effect":"DENY","when":{"action":{"name":["refund"]}}}`
	approveRefunds = `{"id":"approve-refunds","effect":"REQUIRE_APPROVAL","when":{"action":{"name":["refund"]}}}`
	redactNotes    = `{"id":"redact-notes","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"redact_fields","params":{"fields":"note"}}],"when":{"action":{"name":["refund"]}}}`
)

func planeStart() time.Time { return time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC) }

func who() gateway.RunIdentity {
	return gateway.RunIdentity{TenantID: "tenant-1", PrincipalType: "user", PrincipalID: "user-1", AgentID: "agent-1"}
}

// runs is one open run in memory.
type runs struct {
	mu    sync.Mutex
	state gateway.RunState
}

func (r *runs) Resolve(_ context.Context, token string, w gateway.RunIdentity, _ time.Time) (gateway.OpenedRun, error) {
	if token != runToken || w != who() {
		return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunUnknown}
	}
	return gateway.OpenedRun{ID: "run-a", Root: "run-a", Who: who(), Expires: planeStart().Add(24 * time.Hour)}, nil
}

func (r *runs) State(context.Context, string) (gateway.RunState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state, nil
}

func (r *runs) Raise(_ context.Context, _ string, join func(gateway.RunState) gateway.RunState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = join(r.state)
	return nil
}

type fixedPolicy struct{ snap *policy.Snapshot }

func (p fixedPolicy) Current() *policy.Snapshot { return p.snap }

func snapshot(t *testing.T, rules ...string) *policy.Snapshot {
	t.Helper()
	doc := `{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"tools","version":"2026-10-11.1","serial":1,"maxStaleSeconds":3600},"rules":[` +
		strings.Join(rules, ",") + `]}`
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	b, err := policy.Sign([]byte(doc), key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("no ed25519 public key")
	}
	snap, err := policy.Load(b, bundle.Keyring{"k1": pub}, planeStart())
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// withObligation adds an obligation no client knows to every execution the
// pipeline hands out.
type withObligation struct{ enforce.Pipeline }

func (w withObligation) Admit(ctx context.Context, a gateway.Admission) gateway.Disposition {
	d := w.Pipeline.Admit(ctx, a)
	if d.Action == core.Execute {
		d.Obligations = append(d.Obligations, &controlv1.Obligation{Type: "notify_owner"})
	}
	return d
}

// plane is the enforcement adapter served on a real socket in front of a
// real pipeline, as the gateway runs it.
type plane struct {
	a      *enforce.Adapter
	sink   *evidence.MemorySink
	store  *gateway.MemoryApprovals
	clock  *clock
	socket string
}

// clock is the plane's clock, which a test moves.
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

type planeOptions struct {
	mode       controlv1.EnforcementMode
	rules      []string
	obligation bool
	// tools replaces the plane's one tool, refund, when set.
	tools []enforce.Tool
}

func newPlane(t *testing.T, o planeOptions) *plane {
	t.Helper()
	if o.mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		o.mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE
	}
	pl := &plane{sink: &evidence.MemorySink{}, store: &gateway.MemoryApprovals{}, clock: &clock{now: planeStart()}, socket: socketPath(t)}
	var ids atomic.Int64
	newID := func() string { return "id-" + strconv.FormatInt(ids.Add(1), 10) }
	clock := pl.clock.read
	r := &runs{state: gateway.RunState{Trusted: true, MaxRead: controlv1.Sensitivity_SENSITIVITY_PUBLIC}}
	if o.tools == nil {
		o.tools = []enforce.Tool{{Name: "refund", Effect: controlv1.EffectClass_EFFECT_CLASS_TRANSACT, Provider: "payments", ResourceType: "account", ResourceFrom: "/account"}}
	}
	a, err := enforce.New(enforce.Config{
		Socket: pl.socket, ExecutionLifetime: time.Minute,
		ProjectID: "proj-1", TenantID: "tenant-1", Environment: "prod",
		Identity: enforce.Identity{
			Principal: &controlv1.Principal{Id: "user-1", TenantId: "tenant-1", Type: "user"},
			Agent:     &controlv1.Agent{Id: "agent-1"},
		},
		Runs:  r,
		Tools: o.tools,
		Clock: clock, NewID: newID,
	})
	if err != nil {
		t.Fatalf("enforce.New: %v", err)
	}
	p, err := gateway.New(gateway.Config{
		Mode: o.mode, Adapter: a, KernelOptions: core.Options{MaxStale: time.Hour},
		Policy: fixedPolicy{snapshot(t, o.rules...)}, Pause: gateway.PauseDisabled(), Stops: gateway.StopsDisabled(),
		Sink: pl.sink, Approvals: pl.store, Runs: r, Clock: clock, NewID: newID,
		ApprovalTTL: 10 * time.Minute, RetryAfter: 5 * time.Second, MaxHeld: 16, MaxOpen: 16, MaxRuns: 16,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	var pipe enforce.Pipeline = p
	if o.obligation {
		pipe = withObligation{p}
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
	pl.a = a
	return pl
}

// socketPath is a socket in a fresh directory of this user's. The directory
// is short because a socket path is bounded at about 104 bytes.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

func clientFor(t *testing.T, socket string) *enforceclient.Client {
	t.Helper()
	c, err := enforceclient.New(enforceclient.Config{Socket: socket, Token: runToken, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (pl *plane) kinds() []controlv1.EventKind {
	var out []controlv1.EventKind
	for _, e := range pl.sink.Events() {
		out = append(out, e.GetKind())
	}
	return out
}

// closings are the closing records the plane wrote.
func (pl *plane) closings() []*controlv1.Event {
	var out []*controlv1.Event
	for _, e := range pl.sink.Events() {
		if k := e.GetKind(); k == controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED || k == controlv1.EventKind_EVENT_KIND_ACTION_FAILED {
			out = append(out, e)
		}
	}
	return out
}
