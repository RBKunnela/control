package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
)

const (
	codePaused                = "PAUSED"
	codePauseStateUnavailable = "PAUSE_STATE_UNAVAILABLE"

	pauseInterval = time.Minute

	pauseGlobal   = `{"kind":"global"}`
	pauseOrders   = `{"kind":"provider","provider":"orders"}`
	pausePayments = `{"kind":"provider","provider":"payments"}`
	pauseRead     = `{"kind":"action","action":"tool","provider":"orders","name":"orders.read"}`
)

// pauseFile writes a pause file holding one entry per scope into a fresh
// directory of mode 0700 and returns its path.
func pauseFile(t *testing.T, scopes ...string) string {
	t.Helper()
	entries := make([]string, len(scopes))
	for i, scope := range scopes {
		entries[i] = fmt.Sprintf(`{"id":"p%d","scope":%s,"created_at":"2026-09-11T11:00:00Z","reason":"test"}`, i, scope)
	}
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pause.json")
	body := `{"schema_version":"1","entries":[` + strings.Join(entries, ",") + `]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// paused is the snapshot a plane reads at base() from a file of scopes.
func paused(t *testing.T, scopes ...string) pause.Snapshot {
	t.Helper()
	s := pause.Read(pauseFile(t, scopes...), base(), pauseInterval)
	if len(scopes) > 0 && s.State() != pause.Paused || len(scopes) == 0 && s.State() != pause.Clear {
		t.Fatalf("the pause file read as %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
	return s
}

// tool is env as the adapter sends a tools/call: its kind of call is set.
func tool(env *controlv1.ActionEnvelope) *controlv1.ActionEnvelope {
	env.Action.Kind = "tool"
	return env
}

// expectPlaneBlock asserts the plane's own block, the codes it lists in their
// order and the verdict they make, no rule, obligation or decision point on
// it, a trail of three events whose POLICY_DECIDED is the kernel's own, and
// the block counted by its first code.
func expectPlaneBlock(t *testing.T, h *harness, d gateway.Disposition, verdict controlv1.Verdict, codes ...string) {
	t.Helper()
	expectBlock(t, d, verdict, codes[0], gateway.PDPType)
	if got := d.Decision.GetReasonCodes(); !slices.Equal(got, codes) {
		t.Errorf("the plane's codes = %v, want %v", got, codes)
	}
	if ids := d.Decision.GetPolicyRuleIds(); len(ids) != 0 {
		t.Errorf("the plane's decision names rules %v; a pause entry is no rule of the bundle", ids)
	}
	if d.Decision.GetObligations() != nil || d.Decision.GetPdpInstance() != "" {
		t.Errorf("the plane's decision carries obligations %v and decision point %q; want neither",
			d.Decision.GetObligations(), d.Decision.GetPdpInstance())
	}
	trail := h.trailOf(d.Decision.GetRequestId())
	expectKinds(t, kindsOf(trail), []controlv1.EventKind{kindProposed, kindDecided, kindBlocked})
	if len(trail) == 3 {
		if decided := trail[1].GetDecision(); decided.GetPdpType() != "builtin" {
			t.Errorf("POLICY_DECIDED = %+v; want the kernel's decision", decided)
		}
	}
	if err := evidence.ValidateChain(trail); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
	if got := h.p.Stats().Blocks[codes[0]]; got == 0 {
		t.Errorf("Stats.Blocks = %v; want the block counted as %s", h.p.Stats().Blocks, codes[0])
	}
}

func TestNewRefusesAMissingPauseSource(t *testing.T) {
	cfg := validConfig(t)
	cfg.Pause = nil
	if _, err := gateway.New(cfg); !errors.Is(err, gateway.ErrNoPause) {
		t.Errorf("New with no pause source = %v, want ErrNoPause", err)
	}
	cfg.Pause = gateway.PauseDisabled()
	if _, err := gateway.New(cfg); err != nil {
		t.Errorf("New with the disabled source: %v", err)
	}
}

// TestASnapshotNobodyReadBlocks: the zero snapshot is unknown, so a read the
// policy allows is blocked INDETERMINATE with the plane's own code.
func TestASnapshotNobodyReadBlocks(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads))
	h.pause.set(pause.Snapshot{})
	d := h.admit(tool(readEnvelope()), []byte(`{}`))
	expectPlaneBlock(t, h, d, verdictIndeterminate, codePauseStateUnavailable)
	if decided := h.recorded(t, "req-1"); decided.GetVerdict() != verdictAllow {
		t.Errorf("POLICY_DECIDED = %s; want the kernel's ALLOW", decided.GetVerdict())
	}
}

// TestAPauseAtEachScopeBlocksExactlyItsCalls: in every mode, reads included,
// a pause blocks the calls its scope covers and no other.
func TestAPauseAtEachScopeBlocksExactlyItsCalls(t *testing.T) {
	refund := func() *controlv1.ActionEnvelope {
		env := tool(writeEnvelope())
		env.Action.Name, env.Action.Provider = "refund", "payments"
		return env
	}
	calls := map[string]func() *controlv1.ActionEnvelope{
		"read":   func() *controlv1.ActionEnvelope { return tool(readEnvelope()) },
		"write":  func() *controlv1.ActionEnvelope { return tool(writeEnvelope()) },
		"refund": refund,
	}
	cases := []struct {
		scope  string
		blocks []string
	}{
		{pauseGlobal, []string{"read", "write", "refund"}},
		{pauseOrders, []string{"read", "write"}},
		{pausePayments, []string{"refund"}},
		{pauseRead, []string{"read"}},
	}
	allowAll := `{"id":"allow-all","effect":"ALLOW","when":{"action":{"effect":["READ","WRITE"]}}}`
	for _, mode := range []controlv1.EnforcementMode{modeObserve, modeApprove, modeEnforce, modeLockdown} {
		for _, c := range cases {
			for name, env := range calls {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, c.scope, name), func(t *testing.T) {
					h := build(t, mode, snapshot(t, allowAll))
					h.pause.set(paused(t, c.scope))
					d := h.admit(env(), []byte(`{}`))
					if !slices.Contains(c.blocks, name) {
						if d.Action == core.Block && slices.Contains(d.Decision.GetReasonCodes(), codePaused) {
							t.Errorf("a call outside the scope was paused: %v", d.Decision.GetReasonCodes())
						}
						return
					}
					want := []string{codePaused}
					if mode == modeLockdown && name != "read" {
						want = append(want, codeLockdown)
					}
					expectPlaneBlock(t, h, d, verdictDeny, want...)
				})
			}
		}
	}
}

// TestAProviderPauseBlocksACallNothingClassifies: under OBSERVE such a call
// runs, and it carries no provider, so every entry pauses it.
func TestAProviderPauseBlocksACallNothingClassifies(t *testing.T) {
	loose := func() gateway.Admission {
		a := unclassified([]byte(`{}`))
		a.Envelope.Action.Provider = ""
		a.Envelope.Action.Kind = "tool"
		return a
	}
	h := build(t, modeObserve, snapshot(t, allowWrites), observer)
	if d := h.p.Admit(context.Background(), loose()); d.Action != core.Execute {
		t.Fatalf("with nothing paused, an unclassified call under OBSERVE: Action = %d", d.Action)
	}
	h = build(t, modeObserve, snapshot(t, allowWrites), observer)
	h.pause.set(paused(t, pausePayments))
	expectPlaneBlock(t, h, h.p.Admit(context.Background(), loose()), verdictDeny, codePaused)
}

// TestPreviewSkipsThePause: a listing answers under a global pause, or a
// pause state nobody can read, what it answers under none, and reads no
// pause state at all.
func TestPreviewSkipsThePause(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, allowReads, denyWrites))
	want := map[string][]string{}
	for name, env := range map[string]*controlv1.ActionEnvelope{"read": tool(readEnvelope()), "write": tool(writeEnvelope())} {
		want[name] = h.p.Preview(context.Background(), admission(env, []byte(`{}`))).GetReasonCodes()
	}
	for _, snap := range []pause.Snapshot{paused(t, pauseGlobal), {}} {
		h.pause.set(snap)
		before := h.pause.calls.Load()
		for name, env := range map[string]*controlv1.ActionEnvelope{"read": tool(readEnvelope()), "write": tool(writeEnvelope())} {
			got := h.p.Preview(context.Background(), admission(env, []byte(`{}`)))
			if !slices.Equal(got.GetReasonCodes(), want[name]) {
				t.Errorf("%s under %s: %v, want %v", name, snap.State(), got.GetReasonCodes(), want[name])
			}
		}
		if h.pause.calls.Load() != before {
			t.Errorf("Preview read the pause source")
		}
	}
	if want["read"][0] != codeRuleAllow || want["write"][0] != codeRuleDeny {
		t.Fatalf("the unpaused listing is %v; the comparison above compared nothing", want)
	}
}

// TestAnEntryNoUpstreamServesPausesOnlyCallsWithNoProvider: an entry naming
// an upstream the plane lacks, or a tool its upstream does not list, pauses a
// call to a name no upstream lists, which the adapter routes with no provider,
// and leaves a routed call alone. Under OBSERVE each call runs unpaused.
func TestAnEntryNoUpstreamServesPausesOnlyCallsWithNoProvider(t *testing.T) {
	unlisted := func(name string) gateway.Admission {
		env := tool(readEnvelope())
		env.Action.Provider, env.Action.Name = "", name
		a := admission(env, []byte(`{}`))
		a.Refusal = fmt.Errorf("adapter: tool %q: %w: no upstream lists it", name, gateway.ErrUnclassified)
		return a
	}
	routed := func(string) gateway.Admission { return admission(tool(readEnvelope()), []byte(`{}`)) }
	hiddenTool := `{"kind":"action","action":"tool","provider":"orders","name":"orders.hidden"}`
	for _, c := range []struct {
		name   string
		scopes []string
		call   func(string) gateway.Admission
		target string
		paused bool
	}{
		{"nothing paused", nil, unlisted, "orders.hidden", false},
		{"an unlisted tool, called by its name", []string{hiddenTool}, unlisted, "orders.hidden", true},
		{"an unlisted tool, another unlisted name", []string{hiddenTool}, unlisted, "orders.other", false},
		{"an upstream the plane lacks, an unlisted name", []string{pausePayments}, unlisted, "orders.other", true},
		{"an upstream the plane lacks, a routed call", []string{pausePayments}, routed, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, modeObserve, snapshot(t, allowReads))
			h.pause.set(paused(t, c.scopes...))
			d := h.p.Admit(context.Background(), c.call(c.target))
			if c.paused {
				expectPlaneBlock(t, h, d, verdictDeny, codePaused)
				return
			}
			if d.Action != core.Execute {
				t.Errorf("Action = %d, codes %v; want the call run", d.Action, d.Decision.GetReasonCodes())
			}
		})
	}
}
