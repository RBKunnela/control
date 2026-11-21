package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/scenario"
)

// The digest the fake plane serves, and canon's hash of each argument set the
// cases send: sha256 over "agent-arguments-hash/v1\n" and the canonical JSON.
const (
	fakeDigest = "sha256:6e99902208467e2fa5e63296a103dc0e1cac293ee41691e0317ceb9307372b96"
	hashOrd1   = "sha256:2cac45f9ef4c7278d9e379670ce67547433a13b4f8cb62175b722019ea389af2"
	hashOrd10  = "sha256:e0457ecf0f58dbbbbdd6018612bae5c92876bc5c18d39e5a9a432971b8fceba6"
	hashOrd11  = "sha256:207c37a8c7faa7086483f57938a3ae01504c372ff5e31f113912453feb279f06"
)

var (
	started       = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	completed     = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	approvalAsked = controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED
	executed      = []controlv1.EventKind{proposed, decided, started, completed}
)

// fakeTrail is one request's events of the kinds given, as an APPROVE plane
// on a fresh run records them: the proposal carries hash, the decision
// verdict and the fake's digest, and each APPROVAL_REQUESTED approval.
func fakeTrail(request string, verdict controlv1.Verdict, hash, approval string, kinds ...controlv1.EventKind) []*controlv1.Event {
	evs := trailOf(request, kinds...)
	for _, ev := range evs {
		ev.EnforcementMode = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE
		switch ev.Kind {
		case proposed:
			ev.Payload = &controlv1.Event_Proposed{Proposed: &controlv1.ActionEnvelope{
				Principal: &controlv1.Principal{Id: "p1"}, Agent: &controlv1.Agent{Id: "a1"},
				Arguments: &controlv1.Arguments{CanonicalHash: hash},
				Context:   &controlv1.RunContext{Tags: []string{"flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC"}}}}
		case decided:
			codes := []string{"RULE_ALLOW"}
			if verdict == controlv1.Verdict_VERDICT_DENY {
				codes = []string{"RULE_DENY"}
			}
			ev.Payload = &controlv1.Event_Decision{Decision: &controlv1.Decision{SchemaVersion: "1.0", DecisionId: "d-" + request,
				Verdict: verdict, ReasonCodes: codes, PolicyBundleDigest: fakeDigest}}
		case approvalAsked:
			ev.Payload = &controlv1.Event_Approval{Approval: &controlv1.Approval{ApprovalId: approval}}
		}
	}
	return evs
}

// continued is more events on request's trail after its first n, linked to
// the last of them.
func continued(request string, n int, kinds ...controlv1.EventKind) []*controlv1.Event {
	evs := trailOf(request, append(make([]controlv1.EventKind, n), kinds...)...)[n:]
	for _, ev := range evs {
		ev.EnforcementMode = controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE
	}
	return evs
}

// fakeCall is what the fake plane does with its n-th call: the events it
// appends to the trail file, the request its answer names, and the approval
// a pending answer names, empty for a result.
type fakeCall struct {
	request, pending string
	events           []*controlv1.Event
}

// fakePlane answers /healthz with counters that agree with what it wrote,
// and every tools/call with onCall's answer after writing onCall's events.
type fakePlane struct {
	admitted, acked atomic.Uint64
	mu              sync.Mutex
	trail           string
	calls           int
	onCall          func(n int) fakeCall
}

func (f *fakePlane) appendEvents(evs []*controlv1.Event) error {
	var b bytes.Buffer
	if err := evidence.EncodeJSONL(&b, evs); err != nil {
		return err
	}
	fh, err := os.OpenFile(f.trail, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(b.Bytes()); err != nil {
		_ = fh.Close()
		return err
	}
	f.acked.Add(uint64(len(evs)))
	return fh.Close()
}

func (f *fakePlane) answer(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
	f.mu.Lock()
	n := f.calls
	f.calls++
	f.mu.Unlock()
	f.admitted.Add(1)
	c := f.onCall(n)
	if err := f.appendEvents(c.events); err != nil {
		return nil, err
	}
	meta := sdk.Meta{keyRequestID: c.request, keyDecisionID: "d-" + c.request}
	if c.pending == "" {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}, Meta: meta}, nil
	}
	meta[keyAnswerMarker] = "pending"
	meta[brand.OTelNamespace+"/reason_code"] = "APPROVAL_PENDING"
	meta[brand.OTelNamespace+"/approval_id"] = c.pending
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "held"}}, Meta: meta}, nil
}

// startFake serves the fake plane and returns a runner pointed at it.
func startFake(t *testing.T, f *fakePlane) *runner {
	t.Helper()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"mode":"APPROVE","halted":false,"bundle":{"id":"scenario-fixture","digest":%q},"pipeline":{"admitted":%d},`+
			`"spool":{"unacknowledged":0,"quarantined_records":0},"exporter":{"acknowledged":%d,"partial_rejected":0},`+
			`"pause":{"state":"clear","entries":0,"polls":{"made":1}},"policy":{"freshness":"confirmed"}}`, fakeDigest, f.admitted.Load(), f.acked.Load())
	}))
	t.Cleanup(health.Close)
	server := sdk.NewServer(&sdk.Implementation{Name: "fake-plane", Version: "0"}, nil)
	for _, name := range []string{"read_order", "update_order"} {
		server.AddTool(&sdk.Tool{Name: name, InputSchema: map[string]any{"type": "object"}}, f.answer)
	}
	mcp := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: true}))
	t.Cleanup(mcp.Close)
	return &runner{plane: planeTarget{mcpURL: mcp.URL, protocol: "2026-07-28", healthURL: health.URL + "/healthz", callTimeout: time.Second},
		trail: f.trail, timeout: 2 * time.Second, http: &http.Client{}}
}

// runFake runs the scenario document raw, under name, against a fake plane
// whose calls onCall answers, and returns the exit and every line.
func runFake(t *testing.T, name, raw string, onCall func(n int) fakeCall, set func(*runner)) (int, []string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := scenario.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := startFake(t, &fakePlane{trail: filepath.Join(dir, "trail.jsonl"), onCall: onCall})
	if set != nil {
		set(r)
	}
	var out bytes.Buffer
	r.out = &out
	return r.run(context.Background(), s), lines(out.String())
}

const twoReads = `{"kind":"agent-scenario/v1alpha1","about":"two allowed reads","plane":{"mode":"APPROVE","bundle":{"id":"scenario-fixture"}},
"steps":[
 {"call":{"tool":"read_order","args":{"id":"ord-1"},"answer":{"kind":"result","codes":[]},
   "decided":{"verdict":"ALLOW","codes":["RULE_ALLOW"],"obligations":[]},
   "trail":{"request":"new","kinds":["ACTION_PROPOSED","POLICY_DECIDED","ACTION_STARTED","ACTION_COMPLETED"]}}},
 {"call":{"tool":"read_order","args":{"id":"ord-1"},"answer":{"kind":"result","codes":[]},
   "decided":{"verdict":"ALLOW","codes":["RULE_ALLOW"],"obligations":[]},
   "trail":{"request":"new","kinds":["ACTION_PROPOSED","POLICY_DECIDED","ACTION_STARTED","ACTION_COMPLETED"]}}}]}`

// TestEveryEventOfAStepIsOnTheTrailItNames: a plane that also writes a
// second trail, a denied action that ran, or that appends to a trail an
// earlier step judged, differs on trail.others at that step. The plane that
// writes only the trails its answers name passes the same scenario.
func TestEveryEventOfAStepIsOnTheTrailItNames(t *testing.T) {
	for _, c := range []struct {
		name  string
		extra func(n int) []*controlv1.Event
		want  []string
	}{
		{"only the named trails", func(int) []*controlv1.Event { return nil }, []string{
			"others.json identity: principal p1, agent a1", "others.json step[0] call: ok", "others.json step[1] call: ok", "others.json passed",
		}},
		{"a second trail", func(n int) []*controlv1.Event {
			if n > 0 {
				return nil
			}
			return fakeTrail("stray-0", controlv1.Verdict_VERDICT_DENY, "", "", executed...)
		}, []string{
			"others.json identity: principal p1, agent a1", "others.json step[0].trail.others: want none, got [stray-0]", "others.json failed",
		}},
		{"a judged trail grows", func(n int) []*controlv1.Event {
			if n != 1 {
				return nil
			}
			return continued("req-0", len(executed), started)
		}, []string{
			"others.json identity: principal p1, agent a1", "others.json step[0] call: ok",
			"others.json step[1].trail.others: want none, got [req-0]", "others.json failed",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			exit, got := runFake(t, "others.json", twoReads, func(n int) fakeCall {
				req := "req-" + strconv.Itoa(n)
				return fakeCall{request: req, events: append(fakeTrail(req, controlv1.Verdict_VERDICT_ALLOW, hashOrd1, "", executed...), c.extra(n)...)}
			}, nil)
			wantExit := exitDiffered
			if c.name == "only the named trails" {
				wantExit = exitOK
			}
			if exit != wantExit || !slices.Equal(got, c.want) {
				t.Fatalf("exit %d, output:\n%s\nwant exit %d and:\n%s", exit, strings.Join(got, "\n"), wantExit, strings.Join(c.want, "\n"))
			}
		})
	}
}

// TestTheArgumentsSentAreHeldToTheProposal: a plane whose trail records the
// hash of arguments other than those sent differs on args, on a new trail
// and on a retry, whose trail must carry the held call's arguments.
func TestTheArgumentsSentAreHeldToTheProposal(t *testing.T) {
	single := strings.Replace(twoReads, `,
 {"call":{"tool":"read_order","args":{"id":"ord-1"},"answer":{"kind":"result","codes":[]},
   "decided":{"verdict":"ALLOW","codes":["RULE_ALLOW"],"obligations":[]},
   "trail":{"request":"new","kinds":["ACTION_PROPOSED","POLICY_DECIDED","ACTION_STARTED","ACTION_COMPLETED"]}}}]}`, `]}`, 1)
	exit, got := runFake(t, "args.json", single, func(int) fakeCall {
		return fakeCall{request: "req-0", events: fakeTrail("req-0", controlv1.Verdict_VERDICT_ALLOW, hashOrd10, "", executed...)}
	}, nil)
	want := []string{"args.json identity: principal p1, agent a1", "args.json step[0].args: want " + hashOrd1 + ", got " + hashOrd10, "args.json failed"}
	if exit != exitDiffered || !slices.Equal(got, want) {
		t.Fatalf("a new trail: exit %d, output:\n%s\nwant exit 1 and:\n%s", exit, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	for _, c := range []struct {
		name, retried string
		exit          int
		want          []string
	}{
		{"the held arguments", "ord-10", exitOK, []string{"retry.json step[1] call: ok", "retry.json passed"}},
		{"other arguments", "ord-11", exitDiffered, []string{"retry.json step[1].args: want " + hashOrd11 + ", got " + hashOrd10, "retry.json failed"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			retry := `{"kind":"agent-scenario/v1alpha1","about":"a held update retried","plane":{"mode":"APPROVE","bundle":{"id":"scenario-fixture"}},
"steps":[
 {"call":{"tool":"update_order","args":{"id":"ord-10"},"answer":{"kind":"pending","codes":["APPROVAL_PENDING"]},
   "decided":{"verdict":"ALLOW","codes":["RULE_ALLOW"],"obligations":[]},
   "trail":{"request":"new","kinds":["ACTION_PROPOSED","POLICY_DECIDED","APPROVAL_REQUESTED"]}}},
 {"call":{"tool":"update_order","args":{"id":"` + c.retried + `"},"answer":{"kind":"result","codes":[]},
   "decided":{"verdict":"ALLOW","codes":["RULE_ALLOW"],"obligations":[]},
   "trail":{"request":"step[0]","kinds":["ACTION_PROPOSED","POLICY_DECIDED","APPROVAL_REQUESTED","APPROVAL_DECIDED","ACTION_STARTED","ACTION_COMPLETED"]}}}]}`
			exit, got := runFake(t, "retry.json", retry, func(n int) fakeCall {
				if n == 0 {
					return fakeCall{request: "req-0", pending: "ap-1",
						events: fakeTrail("req-0", controlv1.Verdict_VERDICT_ALLOW, hashOrd10, "ap-1", proposed, decided, approvalAsked)}
				}
				return fakeCall{request: "req-0", events: continued("req-0", 3, controlv1.EventKind_EVENT_KIND_APPROVAL_DECIDED, started, completed)}
			}, nil)
			want := append([]string{"retry.json identity: principal p1, agent a1", "retry.json step[0] call: ok"}, c.want...)
			if exit != c.exit || !slices.Equal(got, want) {
				t.Fatalf("exit %d, output:\n%s\nwant exit %d and:\n%s", exit, strings.Join(got, "\n"), c.exit, strings.Join(want, "\n"))
			}
		})
	}
}
