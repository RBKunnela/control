package mcp_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
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

// TestACalledToolNameHoldingASecretIsNeverRecorded: an agent that calls the
// withheld tool by its name gets a trail and a log without it. The proposal
// names the call by the digest of the name, in every mode, whether the call
// is blocked or runs.
func TestACalledToolNameHoldingASecretIsNeverRecorded(t *testing.T) {
	secret := leaks()[0]
	name := "fetch_" + secret.value
	recorded := withheldName(name)
	for _, mode := range []controlv1.EnforcementMode{modeObserve, modeEnforce} {
		t.Run(mode.String(), func(t *testing.T) {
			logs := &lockedBuffer{}
			v := newVictim()
			leaky := &sdk.Tool{Name: name, Description: "reads", InputSchema: objectSchema(map[string]any{"path": map[string]any{"type": "string"}})}
			v.tools[name] = leaky
			v.server.AddTool(leaky, v.handler(name))
			r := newRigOver(t, v, mcp.KindStdio, rigOptions{mode: mode, rules: []string{allowEverything}, secrets: leakSet(t), logger: slog.New(slog.NewTextHandler(logs, nil))})
			res, err := callTool(t, r.connect(t, "agent-a"), name, map[string]any{"path": "/x"})
			if err != nil {
				t.Fatalf("the call by name: %v", err)
			}
			// The refusal of a call nothing classifies names why its tool is
			// unclassified, which for this one quotes the secret's key.
			if mode == modeEnforce {
				if !res.IsError || !slices.Equal(codesOf(t, res), []string{"ACTION_UNCLASSIFIED"}) {
					t.Fatalf("the unclassified call is not blocked as unclassified: %+v", res)
				}
				if refused, ok := structured(t, res)["refused"]; ok {
					t.Errorf("the block answers refused %q", refused)
				}
			}
			proposed := r.lastOf(t, controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED)
			if got := proposed.GetProposed().GetAction().GetName(); got != recorded {
				t.Errorf("the proposal names the call %q, want %q", got, recorded)
			}
			noEventCarries(t, r, secret.value)
			if strings.Contains(logs.String(), secret.value) {
				t.Errorf("the log carries the secret:\n%s", logs.String())
			}
		})
	}
}

// TestAReadNameHoldingASecretIsNeverRecorded: a prompt name and a resource
// URI that quote a secret reach the upstream as the agent spelled them, and
// the trail names each read by the digest of what was read, in the action's
// name and the resource's id alike.
func TestAReadNameHoldingASecretIsNeverRecorded(t *testing.T) {
	secret := leaks()[0]
	prompt, uri := "p_"+secret.value, "file:///"+secret.value
	for _, mode := range []controlv1.EnforcementMode{modeObserve, modeEnforce} {
		t.Run(mode.String(), func(t *testing.T) {
			r := newRig(t, mcp.KindStdio, rigOptions{mode: mode, rules: []string{allowEverything}, secrets: leakSet(t)})
			agent := r.connect(t, "agent-a")
			reads := []struct {
				name string
				read func() error
			}{
				{prompt, func() error {
					_, err := agent.GetPrompt(ctxT(t), &sdk.GetPromptParams{Name: prompt})
					return err
				}},
				{uri, func() error {
					_, err := agent.ReadResource(ctxT(t), &sdk.ReadResourceParams{URI: uri})
					return err
				}},
			}
			for _, c := range reads {
				before := len(r.events())
				// The victim serves neither, so its refusal is what proves the
				// read was sent.
				if err := c.read(); err == nil {
					t.Fatalf("the victim answered a read of something it does not serve")
				}
				proposed := r.lastOf(t, controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED).GetProposed()
				if len(r.events()) == before || proposed == nil {
					t.Fatalf("the read left no proposal")
				}
				want := withheldName(c.name)
				if got := proposed.GetAction().GetName(); got != want {
					t.Errorf("action.name = %q, want %q", got, want)
				}
				if got := proposed.GetResource().GetId(); got != want {
					t.Errorf("resource.id = %q, want %q", got, want)
				}
			}
			noEventCarries(t, r, secret.value)
		})
	}
}

// TestANameSpelledAsWithheldIsWithheldAgain: a name that starts as a
// withheld one does is recorded by its own digest, so a withheld name on the
// trail is never one an agent spelled.
func TestANameSpelledAsWithheldIsWithheldAgain(t *testing.T) {
	spelled := withheldName("anything")
	r := newRig(t, mcp.KindStdio, rigOptions{mode: modeObserve, rules: []string{allowEverything}})
	// The victim serves no such tool; what it answers does not matter here.
	_, _ = callTool(t, r.connect(t, "agent-a"), spelled, map[string]any{"path": "/x"})
	if got, want := r.lastOf(t, controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED).GetProposed().GetAction().GetName(), withheldName(spelled); got != want {
		t.Errorf("the proposal names the call %q, want %q", got, want)
	}
}

// withheldName is the name the trail records in place of name.
func withheldName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "withheld:sha256:" + hex.EncodeToString(sum[:])
}

// noEventCarries fails for every event the rig's sink kept that holds value.
func noEventCarries(t *testing.T, r *rig, value string) {
	t.Helper()
	for _, e := range r.events() {
		raw, err := protojson.Marshal(e)
		if err != nil {
			t.Fatalf("an event does not encode: %v", err)
		}
		if strings.Contains(string(raw), value) {
			t.Errorf("the %v event carries the secret: %s", e.GetKind(), raw)
		}
	}
}
