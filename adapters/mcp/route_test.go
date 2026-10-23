package mcp_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
)

// twoUpstreams starts the adapter over two victims: the first serves the
// usual tools, the second serves "other" and, when shared is set, a second
// read_file under the same name.
func twoUpstreams(t *testing.T, shared bool) (*mcp.Adapter, *fakePipeline, *victim, *victim, string) {
	t.Helper()
	first, second := newVictim(), newVictim()
	for _, name := range []string{"delete_file", "transfer", "send_mail", "slow", "unlisted"} {
		second.server.RemoveTools(name)
	}
	if !shared {
		second.server.RemoveTools("read_file")
	}
	other := &sdk.Tool{Name: "other", InputSchema: objectSchema(map[string]any{"path": map[string]any{"type": "string"}})}
	second.tools["other"] = other
	second.server.AddTool(other, second.handler("other"))
	connect := func(v *victim) sdk.Transport {
		ct, st := sdk.NewInMemoryTransports()
		ss, err := v.server.Connect(ctxT(t), st, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ss.Close() })
		return ct
	}
	cfg := newConfig(t, first, mcp.KindStatelessHTTP, connect(first), rigOptions{})
	cfg.Upstreams = append(cfg.Upstreams, mcp.Upstream{Name: "second", Transport: connect(second), TenantID: "t1", Environment: "prod"})
	cfg.Overrides = append(cfg.Overrides,
		mcp.Override{Upstream: "second", Tool: "other", Fingerprint: second.fingerprint(t, "other"), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}},
		mcp.Override{Upstream: "second", Tool: "read_file", Fingerprint: second.fingerprint(t, "read_file"), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}},
	)
	a, err := mcp.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pipe := &fakePipeline{decide: execute}
	if err := a.Start(ctxT(t), pipe); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return a, pipe, first, second, serveHTTP(t, h)
}

// TestRoutesByToolName: each tool reaches the one upstream that lists it,
// and the envelope's provider names that upstream.
func TestRoutesByToolName(t *testing.T) {
	_, pipe, first, second, url := twoUpstreams(t, false)
	agent := connectHTTP(t, url, "agent-a", v20260728, nil)
	for _, name := range []string{"read_file", "other"} {
		if res, err := callTool(t, agent, name, map[string]any{"path": "/x"}); err != nil || res.IsError {
			t.Fatalf("%s: %v %+v", name, err, res)
		}
	}
	counts := []int{first.count("read_file"), first.count("other"), second.count("read_file"), second.count("other")}
	if want := []int{1, 0, 0, 1}; !slices.Equal(counts, want) {
		t.Errorf("first ran read_file, other; second ran read_file, other = %v, want %v", counts, want)
	}
	adm := pipe.admitted()
	if len(adm) != 2 || adm[0].a.Envelope.GetAction().GetProvider() != "victim" || adm[1].a.Envelope.GetAction().GetProvider() != "second" {
		t.Errorf("providers %v", adm)
	}
	assertReadUnroutable(t, agent, pipe, first, second)
}

// assertReadUnroutable: a read cannot be routed between two upstreams and
// is refused before either is asked.
func assertReadUnroutable(t *testing.T, agent *sdk.ClientSession, pipe *fakePipeline, first, second *victim) {
	t.Helper()
	_, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: "file:///r"})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != mcp.CodeBlocked {
		t.Fatalf("read over two upstreams: %v", err)
	}
	if first.count("resources/read") != 0 || second.count("resources/read") != 0 {
		t.Errorf("a read reached an upstream")
	}
	if adm := pipe.admitted(); !errors.Is(adm[len(adm)-1].a.Refusal, gateway.ErrUnclassified) {
		t.Errorf("refusal %v", adm[len(adm)-1].a.Refusal)
	}
	// Nothing says which upstream would serve the read, so the execution the
	// plane opened is aborted as unroutable, not as a mismatch.
	aborts := pipe.aborted()
	if len(aborts) != 1 || aborts[0].cause != gateway.AbortUnroutable {
		t.Errorf("Abort calls %+v, want one AbortUnroutable", aborts)
	}
	if !bytes.Contains(werr.Data, []byte(`"ACTION_UNCLASSIFIED"`)) {
		t.Errorf("the block says %s", werr.Data)
	}
}

// TestSharedNameRoutesAgainWhenTheOtherUpstreamDropsIt: a name two upstreams
// serve routes nowhere; once the second stops serving it, the first one's
// tool routes again, because ambiguity lives in the index and not on the
// entry.
func TestSharedNameRoutesAgainWhenTheOtherUpstreamDropsIt(t *testing.T) {
	a, pipe, first, second, url := twoUpstreams(t, true)
	agent := connectHTTP(t, url, "agent-a", v20260728, nil)
	assertSharedNameIsUnroutable(t, agent, pipe, first, second)
	second.server.RemoveTools("read_file")
	waitFor(t, "one entry for read_file", func() bool { return entriesNamed(a, "read_file") == 1 })
	if res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("after the second upstream dropped it: %v %+v", err, res)
	}
	if first.count("read_file") != 1 || second.count("read_file") != 0 {
		t.Errorf("the call ran first %d times, second %d", first.count("read_file"), second.count("read_file"))
	}
	if adm := pipe.admitted(); len(adm) != 2 || adm[1].a.Refusal != nil {
		t.Errorf("the second admission was refused: %+v", adm)
	}
}

// assertSharedNameIsUnroutable: a call on a name two upstreams list is
// refused as unclassified and reaches neither.
func assertSharedNameIsUnroutable(t *testing.T, agent *sdk.ClientSession, pipe *fakePipeline, first, second *victim) {
	t.Helper()
	res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"})
	if err != nil || !res.IsError || codesOf(t, res)[0] != "ACTION_UNCLASSIFIED" {
		t.Fatalf("a shared name: %v %+v", err, res)
	}
	// Each upstream may list the name with a schema of its own, and the
	// plane cannot tell which one the agent holds.
	if res.StructuredContent != nil {
		t.Errorf("a shared name's block carries structured content %v", res.StructuredContent)
	}
	if first.count("read_file")+second.count("read_file") != 0 {
		t.Fatalf("a call on a shared name reached an upstream")
	}
	aborts := pipe.aborted()
	if len(aborts) != 1 || aborts[0].cause != gateway.AbortUnroutable {
		t.Fatalf("Abort calls %+v, want one AbortUnroutable", aborts)
	}
}

// TestRefreshNeverMutatesAPublishedEntry: while one upstream's list changes
// under a reader, every entry the manifest hands out is marked ambiguous
// exactly when its name is served twice. Run under -race, a refresh writing
// into a published entry is a data race as well.
func TestRefreshNeverMutatesAPublishedEntry(t *testing.T) {
	a, _, _, second, url := twoUpstreams(t, true)
	agent := connectHTTP(t, url, "agent-a", v20260728, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			second.server.RemoveTools("read_file")
			time.Sleep(2 * time.Millisecond)
			second.server.AddTool(second.tools["read_file"], second.handler("read_file"))
			time.Sleep(2 * time.Millisecond)
		}
	}()
	for reads := 0; ; reads++ {
		select {
		case <-done:
			return
		default:
		}
		assertAmbiguityMatchesTheIndex(t, a.Entries())
		if reads%20 == 0 {
			if _, err := callTool(t, agent, "other", map[string]any{"path": "/x"}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// assertAmbiguityMatchesTheIndex: an entry is marked ambiguous exactly when
// the manifest holds more than one entry under its name.
func assertAmbiguityMatchesTheIndex(t *testing.T, entries []mcp.Entry) {
	t.Helper()
	names := map[string]int{}
	for _, e := range entries {
		names[e.Tool.Name]++
	}
	for _, e := range entries {
		if e.Ambiguous != (names[e.Tool.Name] > 1) {
			t.Fatalf("%s/%s is marked ambiguous=%v while the manifest holds %d of it",
				e.Upstream, e.Tool.Name, e.Ambiguous, names[e.Tool.Name])
		}
	}
}

// entriesNamed counts the manifest's entries for one tool name.
func entriesNamed(a *mcp.Adapter, name string) int {
	n := 0
	for _, e := range a.Entries() {
		if e.Tool.Name == name {
			n++
		}
	}
	return n
}
