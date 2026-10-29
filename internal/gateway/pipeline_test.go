package gateway_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

func assertUnbuilt(t *testing.T, d gateway.Disposition) {
	t.Helper()
	if d.Action != core.Block {
		t.Errorf("Action = %d, want Block", d.Action)
	}
	if d.Decision.GetVerdict() != verdictIndeterminate {
		t.Errorf("Verdict = %s, want INDETERMINATE", d.Decision.GetVerdict())
	}
	if codes := d.Decision.GetReasonCodes(); !slices.Equal(codes, []string{codePolicyUnavailable}) {
		t.Errorf("ReasonCodes = %v, want [POLICY_UNAVAILABLE]", codes)
	}
	if d.AuthorizedArgs != nil || d.AuthorizedDigest != "" || d.Pending != nil || d.Obligations != nil {
		t.Errorf("a block handed out arguments, a pending state or obligations: %+v", d)
	}
}

// TestUnbuiltPipelinesBlock: the zero value and a nil pipeline answer with the
// decision of a kernel nobody built, never with an allow, close nothing and
// report themselves halted.
func TestUnbuiltPipelinesBlock(t *testing.T) {
	admission := gateway.Admission{Envelope: readEnvelope(), Arguments: []byte("{}")}
	for name, p := range map[string]*gateway.Pipeline{"nil": nil, "zero": new(gateway.Pipeline)} {
		d := p.Admit(context.Background(), admission)
		assertUnbuilt(t, d)
		if err := p.Close(context.Background(), d, []byte("{}"), &controlv1.ActionResult{}); !errors.Is(err, gateway.ErrUnbuilt) {
			t.Errorf("%s: Close = %v, want ErrUnbuilt", name, err)
		}
		if err := p.Abort(context.Background(), d, gateway.AbortArgsMismatch); !errors.Is(err, gateway.ErrUnbuilt) {
			t.Errorf("%s: Abort = %v, want ErrUnbuilt", name, err)
		}
		if !p.Stats().Halted {
			t.Errorf("%s: Stats().Halted = false; a pipeline nobody built takes no material call", name)
		}
	}
}

func TestZeroDispositionBlocks(t *testing.T) {
	var d gateway.Disposition
	if d.Action != core.Block {
		t.Errorf("the zero Disposition's action is %d, want Block", d.Action)
	}
}

func TestNewRefusesEachMisconfiguration(t *testing.T) {
	observing := gateway.Capabilities{ObserveRequest: true, ObserveResult: true}
	cases := []struct {
		name string
		mut  func(*gateway.Config)
		want error
	}{
		{"zero mode", func(c *gateway.Config) { c.Mode = 0 }, gateway.ErrMode},
		{"undeclared mode", func(c *gateway.Config) { c.Mode = 99 }, gateway.ErrMode},
		{"planned mode", func(c *gateway.Config) { c.Mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_SHADOW }, gateway.ErrModePlanned},
		{"nil adapter", func(c *gateway.Config) { c.Adapter = nil }, gateway.ErrNoAdapter},
		{"an adapter that cannot block under ENFORCE", func(c *gateway.Config) {
			c.Adapter = fakeAdapter{name: testProtocol, caps: observing}
		}, gateway.ErrCapability},
		{"an adapter that cannot block under LOCKDOWN", func(c *gateway.Config) {
			c.Mode = modeLockdown
			c.Adapter = fakeAdapter{name: testProtocol, caps: observing}
		}, gateway.ErrCapability},
		{"an adapter that sees nothing under OBSERVE", func(c *gateway.Config) {
			c.Mode = modeObserve
			c.Adapter = fakeAdapter{name: "blind"}
		}, gateway.ErrCapability},
		{"an adapter named after no protocol", func(c *gateway.Config) {
			c.Adapter = fakeAdapter{name: "echo", caps: enforcing}
		}, gateway.ErrProtocol},
		{"an adapter with no name", func(c *gateway.Config) {
			c.Adapter = fakeAdapter{name: "", caps: enforcing}
		}, gateway.ErrProtocol},
		{"a protocol spelled another way", func(c *gateway.Config) {
			c.Adapter = fakeAdapter{name: "MCP", caps: enforcing}
		}, gateway.ErrProtocol},
		{"the cooperative protocol declared inline", func(c *gateway.Config) {
			c.Adapter = fakeAdapter{name: channel.ProtocolEnforce, caps: enforcing}
		}, gateway.ErrStrength},
		{"the inline protocol declared cooperative", func(c *gateway.Config) {
			caps := enforcing
			caps.Enforcement = gateway.EnforcementCooperative
			c.Adapter = fakeAdapter{name: channel.ProtocolMCP, caps: caps}
		}, gateway.ErrStrength},
		{"an adapter that enforces nothing under OBSERVE", func(c *gateway.Config) {
			c.Mode = modeObserve
			c.Adapter = fakeAdapter{name: testProtocol, caps: observing}
		}, gateway.ErrStrength},
		{"an obligation outside the catalogue", func(c *gateway.Config) {
			caps := enforcing
			caps.Obligations = []string{"redact_fields", "teleport"}
			c.Adapter = fakeAdapter{name: testProtocol, caps: caps}
		}, gateway.ErrObligation},
		{"an end-user binding on an adapter that authenticates nobody", func(c *gateway.Config) {
			caps := enforcing
			caps.BindEndUser = true
			c.Adapter = fakeAdapter{name: testProtocol, caps: caps}
		}, gateway.ErrUnauthenticatedBinding},
		{"a staleness budget the kernel refuses", func(c *gateway.Config) { c.KernelOptions.MaxStale = 0 }, core.ErrMaxStale},
		{"nil policy", func(c *gateway.Config) { c.Policy = nil }, gateway.ErrNoPolicy},
		{"nil sink", func(c *gateway.Config) { c.Sink = nil }, gateway.ErrNoSink},
		{"nil approvals", func(c *gateway.Config) { c.Approvals = nil }, gateway.ErrNoApprovals},
		{"nil clock", func(c *gateway.Config) { c.Clock = nil }, gateway.ErrNoClock},
		{"nil id source", func(c *gateway.Config) { c.NewID = nil }, gateway.ErrNoIDSource},
		{"a zero approval lifetime", func(c *gateway.Config) { c.ApprovalTTL = 0 }, gateway.ErrApprovalTTL},
		{"a negative approval lifetime", func(c *gateway.Config) { c.ApprovalTTL = -1 }, gateway.ErrApprovalTTL},
		{"a zero retry interval", func(c *gateway.Config) { c.RetryAfter = 0 }, gateway.ErrRetryAfter},
		{"a negative retry interval", func(c *gateway.Config) { c.RetryAfter = -1 }, gateway.ErrRetryAfter},
		{"no bound on held requests", func(c *gateway.Config) { c.MaxHeld = 0 }, gateway.ErrMaxHeld},
		{"a negative bound on held requests", func(c *gateway.Config) { c.MaxHeld = -1 }, gateway.ErrMaxHeld},
		{"no bound on open executions", func(c *gateway.Config) { c.MaxOpen = 0 }, gateway.ErrMaxOpen},
		{"a negative bound on open executions", func(c *gateway.Config) { c.MaxOpen = -1 }, gateway.ErrMaxOpen},
		{"no bound on runs", func(c *gateway.Config) { c.MaxRuns = 0 }, gateway.ErrMaxRuns},
		{"a negative bound on runs", func(c *gateway.Config) { c.MaxRuns = -1 }, gateway.ErrMaxRuns},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			tc.mut(&cfg)
			p, err := gateway.New(cfg)
			if p != nil || !errors.Is(err, tc.want) {
				t.Errorf("New = %v, %v; want nil, %v", p, err, tc.want)
			}
		})
	}
}

// renamingAdapter answers one name and then another, as an adapter whose name
// is not fixed for its lifetime would.
type renamingAdapter struct {
	asked *int
	names []string
}

func (a renamingAdapter) Name() string {
	n := a.names[min(*a.asked, len(a.names)-1)]
	*a.asked++
	return n
}
func (a renamingAdapter) Capabilities() gateway.Capabilities { return enforcing }

// New keeps the name it checked: an adapter that would answer another one
// later is asked once, so the protocol its calls must name is the one whose
// strength was held to its declaration.
func TestNewAsksTheAdapterItsNameOnce(t *testing.T) {
	asked := 0
	cfg := validConfig(t)
	cfg.Adapter = renamingAdapter{asked: &asked, names: []string{channel.ProtocolMCP, channel.ProtocolEnforce}}
	if _, err := gateway.New(cfg); err != nil {
		t.Fatalf("New = %v", err)
	}
	if asked != 1 {
		t.Errorf("New asked the adapter its name %d times, want once", asked)
	}
}

// TestEveryCoversClauseIsHeldAtItsEdge: for each capability the table can
// need, an adapter declaring everything the mode needs but that one is
// refused, so no single clause of covers can be replaced with true.
func TestEveryCoversClauseIsHeldAtItsEdge(t *testing.T) {
	cases := []struct {
		name string
		mode controlv1.EnforcementMode
		caps gateway.Capabilities
	}{
		{"an adapter that sees the answer but not the call under OBSERVE", modeObserve, gateway.Capabilities{ObserveResult: true}},
		{"an adapter that sees the call but not the answer under OBSERVE", modeObserve, gateway.Capabilities{ObserveRequest: true}},
		{"an adapter that sees both and cannot block under ENFORCE", modeEnforce, gateway.Capabilities{ObserveRequest: true, ObserveResult: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Mode = tc.mode
			cfg.Adapter = fakeAdapter{name: "partial", caps: tc.caps}
			if p, err := gateway.New(cfg); p != nil || !errors.Is(err, gateway.ErrCapability) {
				t.Errorf("New = %v, %v; want nil, ErrCapability", p, err)
			}
		})
	}
	// No row needs Authenticates, BindEndUser, SeeDelegation or
	// SeeResourceIDs, so their clauses have no refusing input through New;
	// this pins that no row asks for them, and the day one does, the table
	// above gets its case.
	values := controlv1.EnforcementMode(0).Descriptor().Values()
	for i := range values.Len() {
		mode := controlv1.EnforcementMode(values.Get(i).Number())
		need, err := gateway.Requirements(mode)
		if errors.Is(err, gateway.ErrMode) {
			continue
		}
		if need.Authenticates || need.BindEndUser || need.SeeDelegation || need.SeeResourceIDs {
			t.Errorf("Requirements(%s) = %+v asks for a capability this test has no refusing case for", mode, need)
		}
	}
}

// TestNewAcceptsWhatTheModeNeeds: the cooperative protocol's adapter runs
// under OBSERVE and under every blocking mode, a declared obligation in the
// catalogue passes, and an adapter that authenticates may bind an end user.
func TestNewAcceptsWhatTheModeNeeds(t *testing.T) {
	var cfg gateway.Config
	for _, mode := range allModes {
		cfg = validConfig(t)
		cfg.Mode = mode
		cfg.Adapter = fakeAdapter{name: channel.ProtocolEnforce, caps: gateway.Capabilities{ObserveRequest: true, ObserveResult: true, Enforcement: gateway.EnforcementCooperative}}
		if _, err := gateway.New(cfg); err != nil {
			t.Errorf("New under %s with the cooperative protocol's adapter: %v", mode, err)
		}
	}
	// The kernel's mode and applicable set are the pipeline's to fix: a caller
	// cannot put the kernel in another mode or hand it an obligation type.
	cfg = validConfig(t)
	cfg.KernelOptions.Mode = modeObserve
	cfg.KernelOptions.Applicable = []string{"teleport"}
	if _, err := gateway.New(cfg); err != nil {
		t.Errorf("New overrides the kernel's mode and applicable set; got %v", err)
	}
	cfg = validConfig(t)
	caps := enforcing
	caps.Obligations = []string{"redact_fields"}
	caps.Authenticates, caps.BindEndUser = true, true
	cfg.Adapter = fakeAdapter{name: testProtocol, caps: caps}
	for _, mode := range []controlv1.EnforcementMode{modeApprove, modeEnforce, modeLockdown} {
		cfg.Mode = mode
		if _, err := gateway.New(cfg); err != nil {
			t.Errorf("New under %s: %v", mode, err)
		}
	}
}
