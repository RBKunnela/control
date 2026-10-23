// Package e2e_test drives the whole plane through a bound listener: an agent
// built on the protocol library, the MCP adapter, the protocol-neutral
// pipeline, the policy kernel over a signed bundle, the spool on disk and the
// OTLP exporter against a collector of its own. Nothing here is a fake of a
// seam the gateway owns; what the tests fake is the world around it, an
// upstream server and a collector.
package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
)

// The tools the victim serves, and what the operator classifies them as.
const (
	toolRead     = "read_file"
	toolDelete   = "delete_file"
	toolTransfer = "transfer"
	toolMail     = "send_mail"
	toolSlow     = "slow"
	toolUnlisted = "unlisted"
)

const (
	effectRead     = controlv1.EffectClass_EFFECT_CLASS_READ
	effectDelete   = controlv1.EffectClass_EFFECT_CLASS_DELETE
	effectTransact = controlv1.EffectClass_EFFECT_CLASS_TRANSACT
	effectComm     = controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE
	zoneExternal   = controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL
)

// slowCall is how long the slow tool stays in the upstream, long enough for a
// test to fill the spool while one call is in flight.
const slowCall = 2 * time.Second

// victim is the upstream server the gateway calls. Every tool records the raw
// argument bytes it received, so a test sees what reached the wire and what
// did not.
type victim struct {
	server *sdk.Server
	tools  map[string]*sdk.Tool

	mu    sync.Mutex
	calls map[string][]json.RawMessage
}

func objectSchema(props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props}
}

func newVictim() *victim {
	v := &victim{calls: map[string][]json.RawMessage{}, tools: map[string]*sdk.Tool{}}
	v.server = sdk.NewServer(&sdk.Implementation{Name: "victim", Version: "0"}, nil)
	path := objectSchema(map[string]any{"path": map[string]any{"type": "string"}})
	for _, tool := range []*sdk.Tool{
		{Name: toolRead, Description: "reads a file", InputSchema: path},
		{Name: toolDelete, Description: "deletes a file", InputSchema: path},
		{Name: toolTransfer, InputSchema: objectSchema(map[string]any{
			"amount":  map[string]any{"type": "integer"},
			"account": map[string]any{"type": "string"},
			"ssn":     map[string]any{"type": "string"},
		})},
		{Name: toolMail, InputSchema: objectSchema(map[string]any{"to": map[string]any{"type": "string"}})},
		{Name: toolSlow, InputSchema: path},
		{Name: toolUnlisted, InputSchema: path},
	} {
		v.tools[tool.Name] = tool
		v.server.AddTool(tool, v.handler(tool.Name))
	}
	for _, class := range declaredEffectClasses() {
		tool := &sdk.Tool{Name: classTool(class), InputSchema: path}
		v.tools[tool.Name] = tool
		v.server.AddTool(tool, v.handler(tool.Name))
	}
	return v
}

// declaredEffectClasses is every effect class the contract's enum declares,
// in the enum's order, without the unspecified one.
func declaredEffectClasses() []controlv1.EffectClass {
	values := controlv1.EffectClass(0).Descriptor().Values()
	out := make([]controlv1.EffectClass, 0, values.Len())
	for i := range values.Len() {
		if n := controlv1.EffectClass(values.Get(i).Number()); n != controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
			out = append(out, n)
		}
	}
	return out
}

// effectSpelling is class as a bundle's rules spell it.
func effectSpelling(class controlv1.EffectClass) string {
	return strings.TrimPrefix(class.String(), "EFFECT_CLASS_")
}

// classTool is the victim's tool the operator classifies as class and as
// nothing else.
func classTool(class controlv1.EffectClass) string {
	return "effect_" + strings.ToLower(effectSpelling(class))
}

func (v *victim) handler(name string) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		v.mu.Lock()
		v.calls[name] = append(v.calls[name], bytes.Clone(req.Params.Arguments))
		v.mu.Unlock()
		if name == toolSlow {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(slowCall):
			}
		}
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: name + " ran"}}}, nil
	}
}

func (v *victim) count(name string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.calls[name])
}

// args is the argument bytes of every call to name, as the upstream received
// them.
func (v *victim) args(name string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.calls[name]))
	for _, raw := range v.calls[name] {
		out = append(out, string(raw))
	}
	return out
}

// ran is how many tool calls of any name the upstream served.
func (v *victim) ran() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, calls := range v.calls {
		n += len(calls)
	}
	return n
}

func (v *victim) fingerprint(t *testing.T, name string) string {
	t.Helper()
	fp, err := mcp.Fingerprint(v.tools[name])
	if err != nil {
		t.Fatalf("Fingerprint(%s): %v", name, err)
	}
	return fp
}

// overrides is the operator's classification of the victim's tools, one tool
// per declared effect class among them. unlisted is left out on purpose:
// nothing classifies it.
func (v *victim) overrides(t *testing.T) []mcp.Override {
	t.Helper()
	out := []mcp.Override{
		{Upstream: upstreamName, Tool: toolRead, Fingerprint: v.fingerprint(t, toolRead), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}},
		{Upstream: upstreamName, Tool: toolDelete, Fingerprint: v.fingerprint(t, toolDelete), Classification: classify.Classification{Effect: effectDelete, ResourceType: "file", ResourceFrom: "/path"}},
		{Upstream: upstreamName, Tool: toolTransfer, Fingerprint: v.fingerprint(t, toolTransfer), Classification: classify.Classification{Effect: effectTransact, ResourceType: "account", ResourceFrom: "/account"}},
		{Upstream: upstreamName, Tool: toolMail, Fingerprint: v.fingerprint(t, toolMail), Classification: classify.Classification{Effect: effectComm, ResourceType: "mailbox", ResourceFrom: "/to", TrustZone: zoneExternal}},
		{Upstream: upstreamName, Tool: toolSlow, Fingerprint: v.fingerprint(t, toolSlow), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}},
	}
	for _, class := range declaredEffectClasses() {
		name := classTool(class)
		o := mcp.Override{Upstream: upstreamName, Tool: name, Fingerprint: v.fingerprint(t, name), Classification: classify.Classification{Effect: class, ResourceType: "file", ResourceFrom: "/path"}}
		if class == effectComm {
			o.TrustZone = zoneExternal
		}
		out = append(out, o)
	}
	return out
}

// upstreamGate sits between the gateway's upstream client and the victim, so a
// test can make a reachable upstream answer something no client can read. The
// manifest is read at Start, through the gate in its passing state.
type upstreamGate struct {
	mu      sync.RWMutex
	next    http.Handler
	garbage atomic.Bool
}

// wrap puts f around the handler while the server may be serving.
func (g *upstreamGate) wrap(f func(http.Handler) http.Handler) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next = f(g.next)
}

func (g *upstreamGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.garbage.Load() {
		g.mu.RLock()
		next := g.next
		g.mu.RUnlock()
		next.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{\"jsonrpc\":\"2.0\",\"id\":"))
}

// collector is the OTLP endpoint the exporter drains into. answer, when set,
// is what it replies; by default it accepts, which an empty 200 says.
type collector struct {
	url string

	mu     sync.Mutex
	answer func(w http.ResponseWriter)
	bodies []string
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{}
	ts := httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(ts.Close)
	c.url = ts.URL + "/v1/logs"
	return c
}

func (c *collector) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Body struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	var lines []string
	if json.NewDecoder(r.Body).Decode(&req) == nil {
		for _, rl := range req.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					lines = append(lines, lr.Body.StringValue)
				}
			}
		}
	}
	c.mu.Lock()
	answer := c.answer
	if answer == nil {
		c.bodies = append(c.bodies, lines...)
	}
	c.mu.Unlock()
	if answer != nil {
		answer(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// refuse makes the collector answer every request with answer, and leaves the
// records it was sent uncounted, since it never accepted them.
func (c *collector) refuse(answer func(w http.ResponseWriter)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answer = answer
}

func (c *collector) accept() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answer = nil
}

// delivered is the JSONL lines of every record a collector accepted.
func (c *collector) delivered() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}
