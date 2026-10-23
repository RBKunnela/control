package mcp_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/policy"
)

// corpusDir holds the bodies an agent can POST to the listener, as files. It
// sits outside this package because it is the gateway's corpus, seeded from
// what both revisions send.
const corpusDir = "../../testdata/gateway/fuzz"

// upstreamOperations is every name the victim records a call under: the tools
// and the two read methods. served sums them, so an execution of any of them
// is seen whatever the fuzzer got the listener to do.
var upstreamOperations = []string{
	"read_file", "delete_file", "transfer", "send_mail", "slow", "unlisted",
	"resources/read", "prompts/get",
}

func served(v *victim) int {
	n := 0
	for _, name := range upstreamOperations {
		n += v.count(name)
	}
	return n
}

// discardingSink takes every record and keeps none: a fuzz run opens as many
// trails as it has inputs, and what is under test is what the listener
// answers, not what a trail holds.
type discardingSink struct{}

func (discardingSink) Append(context.Context, *controlv1.Event) error { return nil }

// FuzzJSONRPCDecode sends arbitrary bytes to a bound listener whose policy
// authorizes nothing, and holds two things: the listener never panics, and it
// never answers a block as a success. Nothing the agent can send may reach the
// upstream or bring an upstream answer back, whatever the body decodes as.
func FuzzJSONRPCDecode(f *testing.F) {
	victim := newVictim()
	url := fuzzListener(f, victim)
	for _, seed := range corpus(f) {
		f.Add(seed)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	f.Fuzz(func(t *testing.T, body []byte) {
		before := served(victim)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("building the request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", v20260728)
		res, err := client.Do(req)
		if err != nil {
			// The listener may close the connection on a body it cannot frame.
			// What it may not do is crash, which the engine reports itself.
			return
		}
		answer, readErr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		if after := served(victim); after != before {
			t.Fatalf("%d upstream call(s) for a body nothing authorized: %q", after-before, body)
		}
		if readErr != nil {
			return
		}
		if bytes.Contains(answer, []byte(upstreamMark)) {
			t.Fatalf("an upstream answer reached the agent for a call nothing authorized: %s", answer)
		}
		if res.StatusCode >= http.StatusInternalServerError {
			t.Fatalf("the listener answered %d: %s", res.StatusCode, answer)
		}
	})
}

// TestAnAllowedAnswerCarriesTheUpstreamMark: the fuzz oracle looks for the
// mark in what the agent gets, so an answer that did reach the agent must
// carry it.
func TestAnAllowedAnswerCarriesTheUpstreamMark(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	r.pipe.decide = executeWith()
	res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/x"})
	if err != nil || res.IsError || len(res.Content) != 1 {
		t.Fatalf("an allowed call: %v %+v", err, res)
	}
	text, ok := res.Content[0].(*sdk.TextContent)
	if !ok || !strings.Contains(text.Text, upstreamMark) {
		t.Fatalf("the upstream's answer %+v lacks the mark %q", res.Content[0], upstreamMark)
	}
}

// fuzzListener builds a plane over an in-process upstream whose policy has no
// rule, so the kernel refuses every call and any execution at all is a hole in
// the listener. It returns the listener's URL.
func fuzzListener(f *testing.F, v *victim) string {
	f.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.Cleanup(cancel)
	upstream, server := sdk.NewInMemoryTransports()
	session, err := v.server.Connect(ctx, server, nil)
	if err != nil {
		f.Fatalf("connecting the upstream: %v", err)
	}
	f.Cleanup(func() { _ = session.Close() })

	var n atomic.Int64
	ids := func() string { return "id-" + strconv.FormatInt(n.Add(1), 10) }
	adapter, err := mcp.New(mcp.Config{
		Listener:    mcp.Listener{Kind: mcp.KindStatelessHTTP, Identity: identity(false)},
		Upstreams:   []mcp.Upstream{{Name: "victim", Transport: upstream, TenantID: "t1", Environment: "prod"}},
		Overrides:   fuzzOverrides(f, v),
		ProjectID:   "p1",
		TenantID:    "t1",
		Environment: "prod",
		CallTimeout: 5 * time.Second,
		Clock:       time.Now,
		NewID:       ids,
		Secrets:     noSecrets(f),
	})
	if err != nil {
		f.Fatalf("mcp.New: %v", err)
	}
	pipeline, err := gateway.New(gateway.Config{
		Mode:          controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		Adapter:       adapter,
		KernelOptions: core.Options{MaxStale: time.Hour},
		Policy:        fixedPolicy{snap: fuzzSnapshot(f)},
		Pause:         gateway.PauseDisabled(),
		Stops:         gateway.StopsDisabled(),
		Sink:          discardingSink{},
		Approvals:     &gateway.MemoryApprovals{},
		Clock:         time.Now,
		NewID:         ids,
		ApprovalTTL:   time.Minute,
		RetryAfter:    time.Second,
		MaxHeld:       8,
		MaxOpen:       8,
		MaxRuns:       8,
	})
	if err != nil {
		f.Fatalf("gateway.New: %v", err)
	}
	if err := adapter.Start(ctx, pipeline); err != nil {
		f.Fatalf("Start: %v", err)
	}
	f.Cleanup(func() { _ = adapter.Close() })
	handler, err := adapter.Handler()
	if err != nil {
		f.Fatalf("Handler: %v", err)
	}
	ts := httptest.NewServer(handler)
	f.Cleanup(ts.Close)
	return ts.URL
}

// fuzzSnapshot is a signed bundle whose one rule denies everything this
// listener's principal asks for, so nothing the fuzzer sends can be allowed.
func fuzzSnapshot(f *testing.F) *policy.Snapshot {
	f.Helper()
	doc := []byte(`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"fuzz","version":"2026-09-20.1","serial":1,"maxStaleSeconds":600},"rules":[` +
		`{"id":"deny-everything","effect":"DENY","when":{"principal":{"id":["svc-agent"]}}}]}`)
	b, err := policy.Sign(doc, key(), "k1")
	if err != nil {
		f.Fatalf("Sign refused a document this test builds as valid: %v", err)
	}
	snap, err := policy.Load(b, pinned(), time.Now())
	if err != nil {
		f.Fatalf("Load refused a bundle this test builds as valid: %v", err)
	}
	return snap
}

// fuzzOverrides classifies the victim's tools, so a call to one of them reaches
// the policy as a classified action instead of stopping at the manifest: the
// refusal under test is the policy's.
func fuzzOverrides(f *testing.F, v *victim) []mcp.Override {
	f.Helper()
	out := []mcp.Override{}
	for _, name := range []string{"read_file", "delete_file", "transfer", "send_mail", "slow"} {
		fp, err := mcp.Fingerprint(v.tools[name])
		if err != nil {
			f.Fatalf("Fingerprint(%s): %v", name, err)
		}
		out = append(out, mcp.Override{
			Upstream:    "victim",
			Tool:        name,
			Fingerprint: fp,
			Classification: classify.Classification{
				Effect:       effectRead,
				ResourceType: "file",
				ResourceFrom: "/path",
			},
		})
	}
	return out
}

// corpus is every file under corpusDir: the seed corpus of what an agent sends
// on both revisions, and the shapes a decoder has to survive.
func corpus(f *testing.F) [][]byte {
	f.Helper()
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		f.Fatalf("reading the corpus: %v", err)
	}
	var out [][]byte
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(corpusDir, entry.Name()))
		if err != nil {
			f.Fatalf("reading %s: %v", entry.Name(), err)
		}
		out = append(out, raw)
	}
	if len(out) == 0 {
		f.Fatalf("the corpus at %s is empty; a target with no seed examines only what the engine invents", corpusDir)
	}
	return out
}
