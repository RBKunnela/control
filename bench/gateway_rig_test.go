package bench_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"

	"github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/secretscan"
	"github.com/guardana/control/internal/spool"
)

const (
	rtUpstream = "files"
	rtTool     = "lookup"
	rtBundle   = "bench-gateway"
)

// fsyncMode is one spool durability setting the plane is measured under. The
// gateway's default is every_record; interval is the operator's other choice,
// measured because forcing each record to disk is most of the cost.
type fsyncMode struct {
	name     string
	policy   spool.FsyncPolicy
	interval time.Duration
}

func fsyncModes() []fsyncMode {
	return []fsyncMode{
		{name: "fsync=every_record", policy: spool.FsyncEveryRecord},
		{name: "fsync=interval_100ms", policy: spool.FsyncInterval, interval: 100 * time.Millisecond},
	}
}

// newUpstream serves one READ tool that answers at once with the path it was
// given, so a caller can tell the arguments arrived.
func newUpstream() (*sdk.Server, *sdk.Tool) {
	tool := &sdk.Tool{
		Name:        rtTool,
		Description: "looks a path up",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}},
	}
	server := sdk.NewServer(&sdk.Implementation{Name: rtUpstream, Version: "0"}, nil)
	server.AddTool(tool, func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, err
		}
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "found " + args.Path}}}, nil
	})
	return server, tool
}

// serveUpstream connects server to a fresh in-memory pipe and returns the
// client end.
func serveUpstream(tb testing.TB, server *sdk.Server) sdk.Transport {
	tb.Helper()
	serverEnd, clientEnd := sdk.NewInMemoryTransports()
	ss, err := server.Connect(context.Background(), serverEnd, nil)
	if err != nil {
		tb.Fatalf("upstream Connect: %v", err)
	}
	tb.Cleanup(func() { _ = ss.Close() })
	return clientEnd
}

func connectClient(tb testing.TB, transport sdk.Transport) *sdk.ClientSession {
	tb.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "agent", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		tb.Fatalf("client Connect: %v", err)
	}
	tb.Cleanup(func() { _ = cs.Close() })
	return cs
}

// directSession is the baseline: the agent's client on the upstream itself.
func directSession(tb testing.TB) *sdk.ClientSession {
	tb.Helper()
	server, _ := newUpstream()
	return connectClient(tb, serveUpstream(tb, server))
}

// recordingSink passes every event to the spool and keeps the ones the spool
// accepted. Only the guard test uses it; the benchmark appends to the spool
// directly.
type recordingSink struct {
	next *spool.Spool
	mu   sync.Mutex
	kept []*controlv1.Event
}

func (s *recordingSink) Append(ctx context.Context, event *controlv1.Event) error {
	if err := s.next.Append(ctx, event); err != nil {
		return err
	}
	s.mu.Lock()
	s.kept = append(s.kept, proto.CloneOf(event))
	s.mu.Unlock()
	return nil
}

func (s *recordingSink) events() []*controlv1.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.kept)
}

func rtHolder(tb testing.TB) *policy.Holder {
	tb.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	doc := []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"` + rtBundle +
		`","version":"1","serial":1,"maxStaleSeconds":3600},"rules":[` +
		`{"id":"allow-reads","effect":"ALLOW","when":{"action":{"effect":["READ"]}}}]}`)
	signed, err := policy.Sign(doc, key, "k1")
	if err != nil {
		tb.Fatalf("Sign: %v", err)
	}
	keys := bundle.Keyring{"k1": ed25519.PublicKey(slices.Clone(key[ed25519.SeedSize:]))}
	ctx := context.Background()
	dir := filepath.Join(tb.TempDir(), "floors")
	if err := policystate.Init(ctx, dir, policystate.KindPlane, rtBundle); err != nil {
		tb.Fatalf("policystate.Init: %v", err)
	}
	store, err := policystate.Open(dir, policystate.KindPlane)
	if err != nil {
		tb.Fatalf("policystate.Open: %v", err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	h, err := policy.NewFloorHolder(rtBundle, store)
	if err != nil {
		tb.Fatalf("NewFloorHolder: %v", err)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	env, err := policy.SignStatement(rtBundle, 1, signed.GetRef().GetDigest(), issued, key, "k1")
	if err != nil {
		tb.Fatalf("SignStatement: %v", err)
	}
	st, err := policy.VerifyStatement(env, keys)
	if err != nil {
		tb.Fatalf("VerifyStatement: %v", err)
	}
	if err := h.InstallConfirmed(ctx, signed, keys, st, issued); err != nil {
		tb.Fatalf("InstallConfirmed: %v", err)
	}
	return h
}

func counterIDs() func() string {
	var n atomic.Int64
	return func() string { return "rt-" + strconv.FormatInt(n.Add(1), 10) }
}

// rig is one plane with its exporter running.
type rig struct {
	agent    *sdk.ClientSession
	recorded *recordingSink
	exporter *otel.Exporter
	// requests counts the export requests the collector accepted.
	requests atomic.Int64
	// stopped receives the exporter's Run error when it returns.
	stopped chan error
}

// exporterFailure is why the exporter stopped or did not deliver every
// request at the first attempt, or nil while neither happened. A benchmark
// whose exporter quietly failed would time a plane with nothing draining it.
func (r *rig) exporterFailure() error {
	select {
	case err := <-r.stopped:
		return fmt.Errorf("the exporter stopped: %w", err)
	default:
	}
	if st := r.exporter.Stats(); st.Retries != 0 || st.Quarantined != 0 || st.Refused != 0 || st.PartialRejected != 0 {
		return fmt.Errorf("the exporter did not deliver cleanly: %+v", st)
	}
	return nil
}

// collector accepts every OTLP request after reading its body, which an
// empty 200 says, and does nothing else.
func (r *rig) collector(tb testing.TB) string {
	tb.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	tb.Cleanup(ts.Close)
	return ts.URL + "/v1/logs"
}

// newRig builds the plane under mode, starts the exporter with the
// gateway's defaults for batch, linger, requests in flight and timeout, and
// returns the agent's session on the stdio listener. record puts a
// recordingSink in front of the spool.
func newRig(tb testing.TB, mode fsyncMode, record bool) *rig {
	tb.Helper()
	r := &rig{stopped: make(chan error, 1)}
	server, tool := newUpstream()
	fingerprint, err := mcp.Fingerprint(tool)
	if err != nil {
		tb.Fatalf("Fingerprint: %v", err)
	}
	sp, err := spool.Open(spool.Options{
		Dir:            tb.TempDir(),
		MaxBytes:       1 << 30,
		SegmentBytes:   64 << 20,
		ClosingReserve: 64 << 10,
		Fsync:          mode.policy,
		Interval:       mode.interval,
	})
	if err != nil {
		tb.Fatalf("spool.Open: %v", err)
	}
	tb.Cleanup(func() { _ = sp.Close() })
	var sink evidence.Sink = sp
	if record {
		r.recorded = &recordingSink{next: sp}
		sink = r.recorded
	}

	adapter, err := mcp.New(mcp.Config{
		Listener: mcp.Listener{
			Kind: mcp.KindStdio,
			Identity: mcp.Identity{
				Principal: &controlv1.Principal{Id: "svc-agent", Type: "service", TenantId: "t1"},
				Agent:     &controlv1.Agent{Id: "agent-1", Framework: "bench"},
			},
		},
		Upstreams: []mcp.Upstream{{Name: rtUpstream, Transport: serveUpstream(tb, server), TenantID: "t1", Environment: "prod"}},
		Overrides: []mcp.Override{{
			Upstream:    rtUpstream,
			Tool:        rtTool,
			Fingerprint: fingerprint,
			Classification: classify.Classification{
				Effect:       controlv1.EffectClass_EFFECT_CLASS_READ,
				ResourceType: "file",
				ResourceFrom: "/path",
			},
		}},
		ProjectID: "p1", TenantID: "t1", Environment: "prod",
		Clock:   time.Now,
		NewID:   counterIDs(),
		Secrets: noSecrets(tb),
	})
	if err != nil {
		tb.Fatalf("mcp.New: %v", err)
	}
	pipeline, err := gateway.New(gateway.Config{
		Mode:          controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		Adapter:       adapter,
		KernelOptions: core.Options{MaxStale: time.Hour},
		Policy:        rtHolder(tb),
		Pause:         gateway.PauseDisabled(),
		Stops:         gateway.StopsDisabled(),
		Sink:          sink,
		Approvals:     &gateway.MemoryApprovals{},
		Clock:         time.Now,
		NewID:         counterIDs(),
		ApprovalTTL:   10 * time.Minute,
		RetryAfter:    time.Second,
		MaxHeld:       16,
		MaxOpen:       16,
		MaxRuns:       64,
	})
	if err != nil {
		tb.Fatalf("gateway.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tb.Cleanup(cancel)
	if err := adapter.Start(ctx, pipeline); err != nil {
		tb.Fatalf("Start: %v", err)
	}
	tb.Cleanup(func() { _ = adapter.Close() })

	reader, err := sp.Reader(spool.Cursor{})
	if err != nil {
		tb.Fatalf("spool.Reader: %v", err)
	}
	// MaxBatch and Linger are left zero, which is the exporter's defaults;
	// InFlight and Timeout are the gateway configuration's.
	exporter, err := otel.New(otel.Options{
		Endpoint:       r.collector(tb),
		AllowPlaintext: true,
		InFlight:       4,
		Timeout:        10 * time.Second,
	}, reader)
	if err != nil {
		tb.Fatalf("otel.New: %v", err)
	}
	r.exporter = exporter
	go func() { r.stopped <- exporter.Run(ctx) }()
	tb.Cleanup(func() {
		cancel()
		_ = reader.Close()
	})

	planeEnd, agentEnd := net.Pipe()
	go func() { _ = adapter.ServeStdio(ctx, planeEnd, planeEnd) }()
	r.agent = connectClient(tb, &sdk.IOTransport{Reader: agentEnd, Writer: agentEnd})
	return r
}

func callLookup(cs *sdk.ClientSession, path string) (*sdk.CallToolResult, error) {
	return cs.CallTool(context.Background(), &sdk.CallToolParams{Name: rtTool, Arguments: map[string]any{"path": path}})
}

func answerText(res *sdk.CallToolResult) string {
	if res == nil || len(res.Content) != 1 {
		return ""
	}
	text, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		return ""
	}
	return text.Text
}

// noSecrets is the empty set, which scans every answer and finds nothing.
func noSecrets(tb testing.TB) *secretscan.Set {
	tb.Helper()
	set, err := secretscan.New(nil)
	if err != nil {
		tb.Fatalf("secretscan.New(nil): %v", err)
	}
	return set
}
