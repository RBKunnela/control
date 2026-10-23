package mcp_test

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
)

// leakyVictim is a victim that also serves a tool whose description quotes
// secret, pinned by an override, so that only the scan keeps it unlisted.
func leakyVictim(t *testing.T, secret string) (*victim, func(*victim, *testing.T) []mcp.Override) {
	t.Helper()
	v := newVictim()
	leaky := &sdk.Tool{Name: "leaky", Description: "calls home with " + secret, InputSchema: objectSchema(map[string]any{"path": map[string]any{"type": "string"}})}
	v.tools["leaky"] = leaky
	v.server.AddTool(leaky, v.handler("leaky"))
	return v, func(v *victim, t *testing.T) []mcp.Override {
		return append(v.overrides(t), mcp.Override{Upstream: "victim", Tool: "leaky", Fingerprint: v.fingerprint(t, "leaky"), Classification: classify.Classification{Effect: effectRead, ResourceType: "file", ResourceFrom: "/path"}})
	}
}

// TestADefinitionQuotingASecretIsNeverListed: a tool whose definition quotes
// a secret is never classified, whatever pins it, never listed under any
// shaping, and a call to it is refused as unclassified. The same definition
// without the secret is listed, which is what the test could otherwise not
// tell from a tool that was never served.
func TestADefinitionQuotingASecretIsNeverListed(t *testing.T) {
	for _, l := range leaks() {
		for _, shaping := range []mcp.Shaping{mcp.ShapeNone, mcp.ShapeAnnotate, mcp.ShapeHide} {
			assertDefinitionWithheld(t, l, shaping)
		}
	}
	v, overrides := leakyVictim(t, "nothing-configured")
	r := newRigOver(t, v, mcp.KindStdio, rigOptions{overrides: overrides, secrets: leakSet(t)})
	if names := toolNames(listTools(t, r.connect(t, "agent-a"))); !slices.Contains(names, "leaky") {
		t.Errorf("the clean definition is not listed: %v", names)
	}
	if e := entryOf(r.adapter, "leaky"); e == nil || !e.Classified {
		t.Errorf("the clean definition is not classified: %+v", e)
	} else if _, withheld := e.Withheld(); withheld {
		t.Errorf("the clean definition says it was withheld")
	}
}

func assertDefinitionWithheld(t *testing.T, l leak, shaping mcp.Shaping) {
	t.Helper()
	v, overrides := leakyVictim(t, l.value)
	r := newRigOver(t, v, mcp.KindStdio, rigOptions{shaping: shaping, overrides: overrides, secrets: leakSet(t)})
	agent := r.connect(t, "agent-a")
	names := toolNames(listTools(t, agent))
	if slices.Contains(names, "leaky") || !slices.Contains(names, "read_file") {
		t.Errorf("%s, shaping %d: listed %v, want read_file and not leaky", l.name, shaping, names)
	}
	e := entryOf(r.adapter, "leaky")
	if e == nil || e.Classified {
		t.Fatalf("%s: the manifest classified the definition: %+v", l.name, e)
	}
	if why, withheld := e.Withheld(); !withheld || why == "" || strings.Contains(why, l.value) {
		t.Errorf("%s: the entry says withheld %v because %q, want withheld naming no value", l.name, withheld, why)
	}
	if _, err := callTool(t, agent, "leaky", map[string]any{"path": "/x"}); err != nil {
		t.Fatal(err)
	}
	adm := r.pipe.admitted()
	refusal := adm[len(adm)-1].a.Refusal
	if !errors.Is(refusal, gateway.ErrUnclassified) || strings.Contains(refusal.Error(), l.value) {
		t.Errorf("%s: a call to the tool was admitted with refusal %v, want ErrUnclassified naming no value", l.name, refusal)
	}
	if r.adapter.Stats().Withheld != 0 {
		t.Errorf("%s: a withheld definition counted as a withheld answer", l.name)
	}
}

// TestAWithheldAnswerIsLoggedByKeyAndSpelling: each withheld answer is one
// log line naming the request, the method, the upstream, the secret's key
// and the spelling it was found in, never the value; a withheld definition
// is logged at refresh the same way.
func TestAWithheldAnswerIsLoggedByKeyAndSpelling(t *testing.T) {
	logs := &lockedBuffer{}
	secret := leaks()[2]
	v, overrides := leakyVictim(t, secret.value)
	e := &echo{}
	e.install(v)
	r := newRigOver(t, v, mcp.KindStatelessHTTP, rigOptions{overrides: overrides, secrets: leakSet(t), logger: slog.New(slog.NewTextHandler(logs, nil))})
	agent := r.connect(t, "agent-a")
	e.set("tools/call", func() (sdk.Result, error) {
		return &sdk.CallToolResult{Content: toolText("token " + secret.value)}, nil
	})
	if _, err := ask(t, agent, "tools/call"); err != nil {
		t.Fatal(err)
	}
	e.set("prompts/list", func() (sdk.Result, error) {
		return &sdk.ListPromptsResult{Prompts: []*sdk.Prompt{{Name: "p", Description: secret.value}}}, nil
	})
	if _, err := ask(t, agent, "prompts/list"); err == nil {
		t.Fatal("a list quoting a secret was delivered")
	}
	if got := r.adapter.Stats().Withheld; got != 2 {
		t.Errorf("Stats.Withheld = %d, want 2", got)
	}
	out := logs.String()
	if strings.Contains(out, secret.value) {
		t.Fatalf("the log carries the secret's value: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, want := range [][]string{
		{"level=WARN", `msg="upstream answer withheld"`, "request_id=" + pipelineRequestID, "method=tools/call", "upstream=victim", "secret=" + secret.key, "spelling=raw"},
		{"level=WARN", `msg="upstream answer withheld"`, "method=prompts/list", "upstream=victim", "secret=" + secret.key, "spelling=raw"},
		{`msg="tool definition withheld"`, "upstream=victim", "tool=leaky", "secret=" + secret.key, "spelling=raw"},
	} {
		if !slices.ContainsFunc(lines, func(line string) bool { return containsAll(line, want) }) {
			t.Errorf("no log line holds %v:\n%s", want, out)
		}
	}
}

func containsAll(line string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(line, p) {
			return false
		}
	}
	return true
}

// TestAToolNameHoldingASecretIsNeverLogged: a withheld definition whose name
// itself quotes a secret is logged by its upstream, key and spelling, with no
// tool name; the name is what the scan found.
func TestAToolNameHoldingASecretIsNeverLogged(t *testing.T) {
	logs := &lockedBuffer{}
	secret := leaks()[0]
	v := newVictim()
	name := "fetch_" + secret.value
	leaky := &sdk.Tool{Name: name, Description: "reads", InputSchema: objectSchema(map[string]any{"path": map[string]any{"type": "string"}})}
	v.tools[name] = leaky
	v.server.AddTool(leaky, v.handler(name))
	r := newRigOver(t, v, mcp.KindStdio, rigOptions{secrets: leakSet(t), logger: slog.New(slog.NewTextHandler(logs, nil))})
	if names := toolNames(listTools(t, r.connect(t, "agent-a"))); slices.Contains(names, name) {
		t.Fatalf("the tool whose name quotes a secret is listed: %v", names)
	}
	out := logs.String()
	if strings.Contains(out, secret.value) || strings.Contains(out, "tool=") {
		t.Fatalf("the log names the tool or carries the value:\n%s", out)
	}
	if !strings.Contains(out, `msg="tool definition withheld" upstream=victim secret=`+secret.key) {
		t.Errorf("no log line names the withheld definition by its upstream and key:\n%s", out)
	}
}
