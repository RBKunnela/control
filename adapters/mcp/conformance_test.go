package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// legacyVersion is a revision that still allows a JSON-RPC batch.
const legacyVersion = "2025-03-26"

// sessionPost sends body in session at version and returns every JSON-RPC
// message the answer holds, a batch's members one by one, and the status.
func sessionPost(t *testing.T, url, session, version, body string) (int, []json.RawMessage) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctxT(t), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", version)
	if session != "" {
		req.Header.Set(sessionHeader, session)
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
	var docs [][]byte
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				docs = append(docs, []byte(data))
			}
		}
	} else if len(bytes.TrimSpace(raw)) > 0 {
		docs = append(docs, raw)
	}
	var out []json.RawMessage
	for _, d := range docs {
		var batch []json.RawMessage
		if json.Unmarshal(d, &batch) == nil {
			out = append(out, batch...)
			continue
		}
		out = append(out, json.RawMessage(d))
	}
	return resp.StatusCode, out
}

// answerOf is the message among msgs answering id.
func answerOf(t *testing.T, msgs []json.RawMessage, id int) json.RawMessage {
	t.Helper()
	for _, m := range msgs {
		var head struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(m, &head) == nil && string(head.ID) == strconv.Itoa(id) {
			return m
		}
	}
	t.Fatalf("no answer to %d among %s", id, msgs)
	return nil
}

// TestALegacyBatchIsDecidedCallByCall: a batch on a revision that allows one
// is decided message by message, as if each were sent alone: the allowed
// read runs and is answered by the upstream, the denied mail is blocked and
// never sent, and each has its own trail.
func TestALegacyBatchIsDecidedCallByCall(t *testing.T) {
	r := newRig(t, mcp.KindStatefulHTTP, rigOptions{mode: modeEnforce, rules: []string{allowReads, denyMail}})
	session := openLegacySession(t, r.url)
	batch := `[` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x"}}},` +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_mail","arguments":{"to":"x@example.com"}}}]`
	status, msgs := sessionPost(t, r.url, session, legacyVersion, batch)
	if status != http.StatusOK {
		t.Fatalf("the batch: %d %s", status, msgs)
	}
	read, mail := answerOf(t, msgs, 2), answerOf(t, msgs, 3)
	if !bytes.Contains(read, []byte(upstreamMark)) || bytes.Contains(read, []byte(`"isError":true`)) {
		t.Errorf("the allowed read was not answered by the upstream: %s", read)
	}
	if bytes.Contains(mail, []byte(upstreamMark)) || !bytes.Contains(mail, []byte(`"`+metaAnswer+`":"blocked"`)) {
		t.Errorf("the denied mail was not blocked by the plane: %s", mail)
	}
	if reads, mails := r.victim.count("read_file"), len(r.victim.args("send_mail")); reads != 1 || mails != 0 {
		t.Errorf("the upstream ran the read %d time(s) and the mail %d, want 1 and 0", reads, mails)
	}
	counted := map[controlv1.EventKind]int{}
	for _, e := range r.events() {
		counted[e.GetKind()]++
	}
	if p, b, c := counted[controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED], counted[kindBlocked], counted[kindCompleted]; p != 2 || b != 1 || c != 1 {
		t.Errorf("trails: %d proposed, %d blocked, %d completed; want 2, 1 and 1", p, b, c)
	}
}

// openLegacySession opens a session at legacyVersion and says it is
// initialized, as a client of that revision does.
func openLegacySession(t *testing.T, url string) string {
	t.Helper()
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + legacyVersion +
		`","capabilities":{},"clientInfo":{"name":"raw-agent","version":"0"}}}`
	opened := post(t, url, init)
	if opened.status != http.StatusOK || opened.session == "" || !strings.Contains(opened.body, legacyVersion) {
		t.Fatalf("initialize at %s: %d %q, session %q", legacyVersion, opened.status, opened.body, opened.session)
	}
	sessionPost(t, url, opened.session, legacyVersion, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return opened.session
}

// TestACallSentAsANotificationIsDropped: a tools/call with no id asks for no
// answer, and the library drops it before the plane: nothing is decided,
// recorded or sent.
func TestACallSentAsANotificationIsDropped(t *testing.T) {
	r := newRig(t, mcp.KindStatelessHTTP, rigOptions{})
	m, err := json.Marshal(meta())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x"},"_meta":` + string(m) + `}}`
	status, out := rawPostWith(t, r.url, nil, body, "read_file")
	if status >= http.StatusInternalServerError {
		t.Fatalf("the notification: %d %s", status, out)
	}
	if bytes.Contains(out, []byte(upstreamMark)) {
		t.Errorf("the notification was answered by the upstream: %s", out)
	}
	// The call that follows is answered after the notification was read, so
	// a notification that reached the plane would be counted by now.
	if res, err := callTool(t, r.connect(t, "agent-a"), "read_file", map[string]any{"path": "/y"}); err != nil || res.IsError {
		t.Fatalf("the call after it: %v %+v", err, res)
	}
	if adm := r.pipe.admitted(); len(adm) != 1 || string(adm[0].a.Arguments) != `{"path":"/y"}` {
		t.Errorf("the plane was asked %d time(s), want once, for the call", len(adm))
	}
	if got := r.victim.args("read_file"); len(got) != 1 || string(got[0]) != `{"path":"/y"}` {
		t.Errorf("the upstream received %q, want the call alone", got)
	}
}

// TestACancelAfterTheSendReachesTheUpstream: an agent that gives up on a
// call the upstream is running cancels the upstream's call too; it is never
// sent again, and the trail records its result as unknown, since the effect
// may have happened.
func TestACancelAfterTheSendReachesTheUpstream(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{allowReads}})
	var calls atomic.Int64
	reached, cancelled := make(chan struct{}), make(chan struct{})
	replaceTool(r, "slow", func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		if calls.Add(1) == 1 {
			close(reached)
		}
		select {
		case <-ctx.Done():
			close(cancelled)
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: upstreamMark}}}, nil
		}
	})
	cs := r.connect(t, "agent-a")
	ctx, cancel := context.WithCancel(ctxT(t))
	defer cancel()
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		_, _ = cs.CallTool(ctx, &sdk.CallToolParams{Name: "slow", Arguments: map[string]any{"path": "/x"}})
	}()
	<-reached
	cancel()
	<-answered
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream's call was not cancelled when its agent gave up")
	}
	waitFor(t, "the trail to close", func() bool {
		return slices.ContainsFunc(r.events(), func(e *controlv1.Event) bool { return e.GetKind() == kindFailed })
	})
	if got := r.lastOf(t, kindFailed).GetResult().GetStatus(); got != controlv1.ResultStatus_RESULT_STATUS_UNKNOWN {
		t.Errorf("the cancelled call's result is recorded %v, want unknown", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("the upstream received the call %d times, want once", n)
	}
}

// TestAnUpstreamsOwnMessagesReachNoAgent: progress, a roots request and a
// sampling request an upstream sends while it runs a call reach no agent:
// the agent's handlers never run, and the roots the upstream reads are not
// the agent's.
func TestAnUpstreamsOwnMessagesReachNoAgent(t *testing.T) {
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeEnforce, rules: []string{allowReads}})
	var roots []string
	replaceTool(r, "read_file", func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_ = req.Session.NotifyProgress(ctx, &sdk.ProgressNotificationParams{ProgressToken: "agent-token", Progress: 1, Message: upstreamMark})
		if listed, err := req.Session.ListRoots(ctx, nil); err == nil { //nolint:staticcheck // deprecated, yet an upstream can still ask for roots
			for _, root := range listed.Roots {
				roots = append(roots, root.URI)
			}
		}
		sample := &sdk.CreateMessageParams{MaxTokens: 1, Messages: []*sdk.SamplingMessage{{Role: "user", Content: &sdk.TextContent{Text: upstreamMark}}}} //nolint:staticcheck // deprecated, yet an upstream can still ask to sample
		_, _ = req.Session.CreateMessage(ctx, sample)                                                                                                     //nolint:staticcheck // deprecated, yet an upstream can still ask to sample
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ran " + upstreamMark}}}, nil
	})
	var progress, sampled atomic.Int64
	c := sdk.NewClient(&sdk.Implementation{Name: "agent-a", Version: "0"}, &sdk.ClientOptions{
		ProgressNotificationHandler: func(context.Context, *sdk.ProgressNotificationClientRequest) { progress.Add(1) },
		CreateMessageHandler: func(context.Context, *sdk.CreateMessageRequest) (*sdk.CreateMessageResult, error) { //nolint:staticcheck // an agent can still offer sampling
			sampled.Add(1)
			return &sdk.CreateMessageResult{ //nolint:staticcheck // an agent can still offer sampling
				Model: "m", Role: "assistant", Content: &sdk.TextContent{Text: "sampled"}}, nil
		},
	})
	c.AddRoots(&sdk.Root{ //nolint:staticcheck // an agent can still offer roots
		URI: "file:///agent-only", Name: "agent"})
	cs := connectStdio(t, r.adapter, c)
	params := &sdk.CallToolParams{Name: "read_file", Arguments: map[string]any{"path": "/x"}}
	params.SetProgressToken("agent-token")
	res, err := cs.CallTool(ctxT(t), params)
	if err != nil || res.IsError {
		t.Fatalf("the call: %v %+v", err, res)
	}
	r.lastOf(t, kindCompleted)
	if n := progress.Load(); n != 0 {
		t.Errorf("the agent was sent %d progress notification(s) of the upstream's", n)
	}
	if n := sampled.Load(); n != 0 {
		t.Errorf("the agent was asked to sample %d time(s) for the upstream", n)
	}
	if slices.Contains(roots, "file:///agent-only") {
		t.Errorf("the upstream read the agent's roots: %v", roots)
	}
}

// connectStdio connects c to a over a pipe, as the stdio rig does for a
// client it builds itself.
func connectStdio(t *testing.T, a *mcp.Adapter, c *sdk.Client) *sdk.ClientSession {
	t.Helper()
	toServer, fromAgent := io.Pipe()
	toAgent, fromServer := io.Pipe()
	ctx, cancel := context.WithCancel(ctxT(t))
	t.Cleanup(cancel)
	go func() { _ = a.ServeStdio(ctx, toServer, fromServer) }()
	cs, err := c.Connect(ctx, &sdk.IOTransport{Reader: toAgent, Writer: fromAgent}, nil)
	if err != nil {
		t.Fatalf("stdio connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}
