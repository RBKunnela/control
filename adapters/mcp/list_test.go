package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gateway"
)

var metaVerdict = brand.OTelNamespace + "/verdict"

// shapingRules deny what leaves the trust zone, allow the rest: send_mail is
// the one classified tool the preview can decide against on its own.
var shapingRules = []string{allowReads, denyMail, allowDeletes, allowTransacts}

func toolNames(res *sdk.ListToolsResult) []string {
	var names []string
	for _, t := range res.Tools {
		names = append(names, t.Name)
	}
	return names
}

func listTools(t *testing.T, cs *sdk.ClientSession) *sdk.ListToolsResult {
	t.Helper()
	res, err := cs.ListTools(ctxT(t), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	return res
}

// TestListShapingNone: the upstream's list, unclassified tools included,
// with the adapter's own cache scope and TTL on the wire, and nothing
// decided about any tool.
func TestListShapingNone(t *testing.T) {
	forEachKind(t, rigOptions{listTTL: 5 * time.Second, mode: modeEnforce, rules: shapingRules}, func(t *testing.T, r *rig) {
		res := listTools(t, r.connect(t, "agent-a"))
		if got := strings.Join(toolNames(res), ","); got != "delete_file,read_file,send_mail,slow,transfer,unlisted" {
			t.Errorf("tools %s", got)
		}
		if res.CacheScope != "private" || res.TTLMs != 5000 {
			t.Errorf("cacheable ttl %d scope %q", res.TTLMs, res.CacheScope)
		}
		if n := r.real.previews.Load(); n != 0 {
			t.Errorf("an unshaped list previewed %d tools", n)
		}
	})
}

// TestListShapingHide: hide omits what the policy denies and what nobody
// classified, and keeps a tool the preview cannot decide without the call's
// arguments, because that call is decided when it is made. Nothing is
// recorded: a preview is no proposed action.
func TestListShapingHide(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, mode: modeEnforce, rules: shapingRules})
	res := listTools(t, r.connect(t, "agent-a"))
	if got := strings.Join(toolNames(res), ","); got != "delete_file,read_file,slow,transfer" {
		t.Errorf("hide: tools %s", got)
	}
	if n := r.real.previews.Load(); n != 5 {
		t.Errorf("hide previewed %d tools, want the five classified ones", n)
	}
	if events := r.events(); len(events) != 0 {
		t.Errorf("shaping a list wrote %d events", len(events))
	}
	if s := r.adapter.Stats(); s.Admitted != 0 {
		t.Errorf("shaping a list admitted %d calls", s.Admitted)
	}
}

// TestListShapingAnnotate: annotate keeps everything and marks each tool
// with what the policy says about it, on a copy; the manifest's definition
// is never written.
func TestListShapingAnnotate(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeAnnotate, mode: modeEnforce, rules: shapingRules})
	res := listTools(t, r.connect(t, "agent-a"))
	want := map[string]string{
		"read_file":   "VERDICT_ALLOW",
		"slow":        "VERDICT_ALLOW",
		"send_mail":   "VERDICT_DENY",
		"delete_file": "DECIDED_PER_CALL",
		"transfer":    "DECIDED_PER_CALL",
		"unlisted":    "ACTION_UNCLASSIFIED",
	}
	if len(res.Tools) != len(want) {
		t.Fatalf("annotate: %d tools", len(res.Tools))
	}
	for _, tool := range res.Tools {
		if w := want[tool.Name]; tool.Meta[metaVerdict] != w {
			t.Errorf("annotate: %s carries %v, want %s", tool.Name, tool.Meta[metaVerdict], w)
		}
	}
	for _, e := range r.adapter.Entries() {
		if _, marked := e.Tool.Meta[metaVerdict]; marked {
			t.Errorf("annotate wrote into the manifest: %s", e.Tool.Name)
		}
	}
}

// TestShapedListIsCachedPerPrincipal: with a TTL the second list for one
// principal asks the policy only which bundle is in force, and another principal on the same
// listener gets its own evaluation and its own list.
func TestShapedListIsCachedPerPrincipal(t *testing.T) {
	rules := []string{allowReads, allowMail, allowDeletes, allowTransacts, denyAliceMail}
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, mode: modeEnforce, rules: rules, listTTL: time.Minute, auth: bearer()})
	alice := r.connect(t, "agent-a")
	for range 2 {
		if got := strings.Join(toolNames(listTools(t, alice)), ","); got != "delete_file,read_file,slow,transfer" {
			t.Fatalf("alice sees %s", got)
		}
	}
	// The library's own client cache would also answer the second list, so
	// ask on the wire with no client cache in the way.
	if _, body := rawPost(t, r.url, http.Header{"Authorization": {"Bearer alice-token"}}, listBody(3)); bytes.Contains(body, []byte(`"send_mail"`)) {
		t.Fatalf("alice's raw list shows what the policy denies her: %s", body)
	}
	// Five shape her first list; the raw list is answered from the cache
	// after one preview names the bundle in force.
	if n := r.real.previews.Load(); n != 6 {
		t.Fatalf("%d previews for alice's three lists, want 6", n)
	}
	bob := connectHTTP(t, r.url, "agent-a", r.version, http.Header{"Authorization": {"Bearer bob-token"}})
	if got := strings.Join(toolNames(listTools(t, bob)), ","); got != "delete_file,read_file,send_mail,slow,transfer" {
		t.Fatalf("bob sees %s, want his own list", got)
	}
	if n := r.real.previews.Load(); n != 11 {
		t.Fatalf("%d previews after bob's list, want 11", n)
	}
}

// TestANewBundleReshapesACachedList: within the TTL, a list shaped under one
// bundle answers again while that bundle is in force, and never once another
// is: the list shows what the new bundle allows and hides what it denies.
func TestANewBundleReshapesACachedList(t *testing.T) {
	src := &swappedPolicy{}
	src.snap.Store(snapshot(t, allowReads, allowMail, allowDeletes, allowTransacts))
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, mode: modeEnforce, policy: src, listTTL: time.Minute})
	listed := func(id int) string {
		t.Helper()
		_, body := rawPost(t, r.url, nil, listBody(id))
		var names []string
		for _, n := range []string{"read_file", "send_mail"} {
			if bytes.Contains(body, []byte(`"`+n+`"`)) {
				names = append(names, n)
			}
		}
		return strings.Join(names, ",")
	}
	if got := listed(1); got != "read_file,send_mail" {
		t.Fatalf("under the first bundle: %s", got)
	}
	if got := listed(2); got != "read_file,send_mail" {
		t.Fatalf("a second list under the same bundle: %s", got)
	}
	cached := r.real.previews.Load()
	src.snap.Store(snapshot(t, shapingRules...))
	if got := listed(3); got != "read_file" {
		t.Errorf("under a bundle that denies mail: %s, want read_file alone", got)
	}
	src.snap.Store(snapshot(t, allowReads, allowMail, allowDeletes, allowTransacts))
	if got := listed(4); got != "read_file,send_mail" {
		t.Errorf("back under a bundle that allows mail: %s", got)
	}
	// Five previews shape the first list; the cached answer asks one, which
	// names the bundle in force.
	if cached != 6 {
		t.Errorf("%d previews after two lists under one bundle, want 6", cached)
	}
}

// TestAListShapedUnderNoBundleIsNotCached: a preview that names no bundle
// leaves nothing to tell the next bundle from, so its list is shaped again
// each time, TTL or not.
func TestAListShapedUnderNoBundleIsNotCached(t *testing.T) {
	var previews atomic.Int64
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, listTTL: time.Minute})
	r.pipe.preview = func(gateway.Admission) gateway.Previewed {
		previews.Add(1)
		return previewOf(decision(controlv1.Verdict_VERDICT_ALLOW))
	}
	for id := range 2 {
		if _, body := rawPost(t, r.url, nil, listBody(id)); !bytes.Contains(body, []byte(`"read_file"`)) {
			t.Fatalf("list %d: %s", id, body)
		}
	}
	if n := previews.Load(); n != 10 {
		t.Errorf("%d previews over two lists under no bundle, want 10", n)
	}
}

// TestAListShapedAcrossTwoBundlesIsNotCached: a bundle installed while a
// list is being shaped leaves a list decided partly under each, and it is
// cached under neither: the next list, under the first bundle again, is
// shaped whole under it.
func TestAListShapedAcrossTwoBundlesIsNotCached(t *testing.T) {
	var previews atomic.Int64
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, listTTL: time.Minute})
	r.pipe.preview = func(gateway.Admission) gateway.Previewed {
		// The second to the fifth preview of the first list run under a
		// bundle that denies everything.
		if n := previews.Add(1); n > 1 && n <= 5 {
			d := decision(controlv1.Verdict_VERDICT_DENY)
			d.PolicyBundleDigest = "sha256:second"
			return previewOf(d)
		}
		d := decision(controlv1.Verdict_VERDICT_ALLOW)
		d.PolicyBundleDigest = "sha256:first"
		return previewOf(d)
	}
	for id := range 3 {
		_, body := rawPost(t, r.url, nil, listBody(id))
		if id > 0 && !bytes.Contains(body, []byte(`"transfer"`)) {
			t.Fatalf("list %d under the first bundle hides what it allows: %s", id, body)
		}
	}
	if n := previews.Load(); n != 11 {
		t.Errorf("%d previews, want 5 for the straddling list, 5 for the next and 1 for the cached one", n)
	}
}

// TestUnshapedListIsNotCachedWithoutATTL: with no TTL every list is shaped
// again.
func TestUnshapedListIsNotCachedWithoutATTL(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, mode: modeEnforce, rules: shapingRules})
	agent := r.connect(t, "agent-a")
	for range 2 {
		listTools(t, agent)
		if _, body := rawPost(t, r.url, nil, listBody(4)); !bytes.Contains(body, []byte(`"read_file"`)) {
			t.Fatalf("raw list: %s", body)
		}
	}
	if n := r.real.previews.Load(); n != 20 {
		t.Fatalf("%d previews over four lists with no TTL, want 20", n)
	}
}

// TestListChangedRefreshesTheManifest: a tool whose description changes
// upstream is a different tool until classified again; the list a principal
// already had is dropped, the new list omits it, and the call is refused.
func TestListChangedRefreshesTheManifest(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{shaping: mcp.ShapeHide, mode: modeEnforce, rules: shapingRules, listTTL: time.Minute})
	agent := r.connect(t, "agent-a")
	if _, body := rawPost(t, r.url, nil, listBody(1)); !bytes.Contains(body, []byte(`"read_file"`)) {
		t.Fatalf("before the change: %s", body)
	}
	if res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"}); err != nil || res.IsError {
		t.Fatalf("before the change: %v %+v", err, res)
	}
	changed := *r.victim.tools["read_file"]
	changed.Description = "reads a file, and now also deletes it"
	r.victim.server.RemoveTools("read_file")
	r.victim.server.AddTool(&changed, r.victim.handler("read_file"))
	waitFor(t, "the manifest to unclassify the changed tool", func() bool {
		e := entryOf(r.adapter, "read_file")
		return e != nil && !e.Classified
	})
	res, err := callTool(t, agent, "read_file", map[string]any{"path": "/x"})
	if err != nil || !res.IsError || codesOf(t, res)[0] != "ACTION_UNCLASSIFIED" {
		t.Fatalf("after the change: %v %+v", err, res)
	}
	if n := r.victim.count("read_file"); n != 1 {
		t.Fatalf("victim ran %d times, want 1", n)
	}
	if _, body := rawPost(t, r.url, nil, listBody(5)); bytes.Contains(body, []byte(`"read_file"`)) {
		t.Errorf("the cached list still shows the changed tool: %s", body)
	}
}

// TestListenerPromisesNoListChanged: the gateway registers no tools of its
// own, and the library sends tools/list_changed only when its own registry
// changes, so the listener does not promise the notification.
func TestListenerPromisesNoListChanged(t *testing.T) {
	forEachKind(t, rigOptions{}, func(t *testing.T, r *rig) {
		caps := r.connect(t, "agent-a").InitializeResult().Capabilities
		if caps.Tools == nil || caps.Tools.ListChanged {
			t.Errorf("tools capability %+v, want listChanged false", caps.Tools)
		}
	})
}

// TestUpstreamListIsBounded: an upstream that paginates forever is refused,
// at the manifest and at a forwarded list, and the refusal names the bound.
func TestUpstreamListIsBounded(t *testing.T) {
	t.Run("tools", func(t *testing.T) {
		v := newVictim()
		var pages atomic.Int64
		endlessPages(v, "tools/list", func(n int64) sdk.Result {
			out := &sdk.ListToolsResult{Tools: []*sdk.Tool{{Name: "t" + strconv.FormatInt(n, 10), InputSchema: objectSchema(nil)}}}
			out.NextCursor = "c" + strconv.FormatInt(n, 10)
			return out
		}, &pages)
		a := adapterOver(t, v, rigOptions{})
		err := a.Start(ctxT(t), &fakePipeline{decide: execute})
		if !errors.Is(err, mcp.ErrListBound) {
			t.Fatalf("Start over an endless tools/list = %v, want ErrListBound", err)
		}
		if got := pages.Load(); got > 200 {
			t.Errorf("the adapter read %d pages before giving up", got)
		}
		if len(a.Entries()) != 0 {
			t.Errorf("entries %d, want none", len(a.Entries()))
		}
	})
	t.Run("resources", func(t *testing.T) {
		v := newVictim()
		var pages atomic.Int64
		endlessPages(v, "resources/list", func(n int64) sdk.Result {
			out := &sdk.ListResourcesResult{Resources: []*sdk.Resource{{URI: "file:///" + strconv.FormatInt(n, 10), Name: "r"}}}
			out.NextCursor = "c" + strconv.FormatInt(n, 10)
			return out
		}, &pages)
		a := adapterOver(t, v, rigOptions{})
		if err := a.Start(ctxT(t), &fakePipeline{decide: execute}); err != nil {
			t.Fatal(err)
		}
		h, err := a.Handler()
		if err != nil {
			t.Fatal(err)
		}
		agent := connectHTTP(t, serveHTTP(t, h), "agent-a", v20260728, nil)
		_, err = agent.ListResources(ctxT(t), nil)
		if err == nil {
			t.Fatalf("an endless resources/list was forwarded whole")
		}
		if !strings.Contains(err.Error(), mcp.ErrListBound.Error()) {
			t.Errorf("the forwarded list's refusal %q does not name the bound", err)
		}
	})
}

// TestUpstreamListIsTimedOut: an upstream that never answers a list does not
// hold the adapter: the refresh fails under the operator's bound, and so does
// a forwarded list.
func TestUpstreamListIsTimedOut(t *testing.T) {
	t.Run("refresh", func(t *testing.T) {
		v := newVictim()
		blockMethod(t, v, "tools/list")
		a := adapterOver(t, v, rigOptions{listTimeout: 100 * time.Millisecond})
		start := time.Now()
		if err := a.Start(ctxT(t), &fakePipeline{decide: execute}); err == nil {
			t.Fatal("Start over an upstream that never lists its tools succeeded")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("Start waited %v; the list timeout did not apply", elapsed)
		}
	})
	t.Run("forwarded", func(t *testing.T) {
		v := newVictim()
		blockMethod(t, v, "resources/list")
		// The bound also covers the tools/list Start reads, which a loaded
		// machine can take well over 100ms to answer.
		a := adapterOver(t, v, rigOptions{listTimeout: time.Second})
		if err := a.Start(ctxT(t), &fakePipeline{decide: execute}); err != nil {
			t.Fatal(err)
		}
		h, err := a.Handler()
		if err != nil {
			t.Fatal(err)
		}
		agent := connectHTTP(t, serveHTTP(t, h), "agent-a", v20260728, nil)
		start := time.Now()
		if _, err := agent.ListResources(ctxT(t), nil); err == nil {
			t.Fatal("a forwarded list an upstream never answers came back")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("the list waited %v; the list timeout did not apply", elapsed)
		}
	})
}

// blockMethod makes v answer method only when its context ends, or when the
// test is over.
func blockMethod(t *testing.T, v *victim, method string) {
	over := make(chan struct{})
	t.Cleanup(func() { close(over) })
	v.server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, m string, req sdk.Request) (sdk.Result, error) {
			if m != method {
				return next(ctx, m, req)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-over:
				return nil, errors.New("the test is over")
			}
		}
	})
}

// endlessPages makes v answer method with page after page, counting them.
func endlessPages(v *victim, method string, page func(int64) sdk.Result, pages *atomic.Int64) {
	v.server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, m string, req sdk.Request) (sdk.Result, error) {
			if m == method {
				return page(pages.Add(1)), nil
			}
			return next(ctx, m, req)
		}
	})
}

// adapterOver builds an unstarted adapter over v, reached in memory.
func adapterOver(t *testing.T, v *victim, o rigOptions) *mcp.Adapter {
	t.Helper()
	ct, st := sdk.NewInMemoryTransports()
	ss, err := v.server.Connect(ctxT(t), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	a, err := mcp.New(newConfig(t, v, mcp.KindStatelessHTTP, ct, o))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// waitFor polls until the adapter reached the state the refresh brings, or
// fails saying which state never came.
func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("waited five seconds for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func entryOf(a *mcp.Adapter, name string) *mcp.Entry {
	for _, e := range a.Entries() {
		if e.Tool.Name == name {
			return &e
		}
	}
	return nil
}

func listBody(id int) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": map[string]any{"_meta": meta()}})
	return string(b)
}

// meta is the per-request triple a 2026-07-28 request carries, as a client
// the tests build by hand sends it.
func meta() map[string]any {
	return map[string]any{
		sdk.MetaKeyProtocolVersion:    v20260728,
		sdk.MetaKeyClientInfo:         map[string]any{"name": "raw-agent", "version": "0"},
		sdk.MetaKeyClientCapabilities: map[string]any{},
	}
}

// rawPost sends one hand-built JSON-RPC request with the 2026-07-28 headers
// and returns the HTTP status and the JSON-RPC message body.
func rawPost(t *testing.T, url string, headers http.Header, body string) (int, []byte) {
	t.Helper()
	return rawPostWith(t, url, headers, body, "")
}

func rawPostWith(t *testing.T, url string, headers http.Header, body, mcpName string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxT(t), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal([]byte(body), &probe)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", v20260728)
	req.Header.Set("Mcp-Method", probe.Method)
	if mcpName != "" {
		req.Header.Set("Mcp-Name", mcpName)
	}
	for k, vs := range headers {
		req.Header[k] = vs
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return resp.StatusCode, raw
	}
	var last []byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			last = []byte(data)
		}
	}
	return resp.StatusCode, last
}
