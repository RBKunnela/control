package enforce_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
)

func validConfig() enforce.Config {
	return enforce.Config{
		Socket: "/run/plane/enforce.sock", ExecutionLifetime: time.Minute,
		ProjectID: "proj-1", TenantID: "tenant-1", Environment: "prod",
		Identity: listenerIdentity(), Runs: newFakeRuns(), Tools: tools(),
		Clock: base, NewID: func() string { return "id" },
	}
}

func TestNewAcceptsAValidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*enforce.Config)
	}{
		{"as built", func(*enforce.Config) {}},
		{"the longest socket path", func(c *enforce.Config) { c.Socket = "/" + strings.Repeat("a", 102) }},
		{"the shortest lifetime", func(c *enforce.Config) { c.ExecutionLifetime = enforce.MinExecutionLifetime }},
		{"the longest lifetime", func(c *enforce.Config) { c.ExecutionLifetime = enforce.MaxExecutionLifetime }},
		{"the default body bound", func(c *enforce.Config) { c.MaxBodyBytes = 0 }},
		{"the smallest body bound", func(c *enforce.Config) { c.MaxBodyBytes = enforce.MinBodyBytes }},
		{"the largest body bound", func(c *enforce.Config) { c.MaxBodyBytes = enforce.MaxBodyBytes }},
		{"a tool naming no resource", func(c *enforce.Config) { c.Tools[1].ResourceFrom = "" }},
		{"a pointer of eight tokens", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "/a/b/c/d/e/f/g/h" }},
		{"a pointer token of 64 bytes", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "/" + strings.Repeat("t", 64) }},
		{"escaped pointer tokens", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "/a~0b/c~1d" }},
		{"a tool name at the bound", func(c *enforce.Config) { c.Tools[0].Name = strings.Repeat("n", 1024) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mut(&cfg)
			if _, err := enforce.New(cfg); err != nil {
				t.Fatalf("New refused: %v", err)
			}
		})
	}
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*enforce.Config)
		want error
	}{
		{"no socket", func(c *enforce.Config) { c.Socket = "" }, enforce.ErrSocket},
		{"a relative socket", func(c *enforce.Config) { c.Socket = "run/enforce.sock" }, enforce.ErrSocket},
		{"a socket past the address bound", func(c *enforce.Config) { c.Socket = "/" + strings.Repeat("a", 103) }, enforce.ErrSocket},
		{"no lifetime", func(c *enforce.Config) { c.ExecutionLifetime = 0 }, enforce.ErrLifetime},
		{"a lifetime under the bound", func(c *enforce.Config) { c.ExecutionLifetime = enforce.MinExecutionLifetime - 1 }, enforce.ErrLifetime},
		{"a lifetime over the bound", func(c *enforce.Config) { c.ExecutionLifetime = enforce.MaxExecutionLifetime + 1 }, enforce.ErrLifetime},
		{"a negative body bound", func(c *enforce.Config) { c.MaxBodyBytes = -1 }, enforce.ErrBodyBound},
		{"a body bound under the bound", func(c *enforce.Config) { c.MaxBodyBytes = enforce.MinBodyBytes - 1 }, enforce.ErrBodyBound},
		{"a body bound over the bound", func(c *enforce.Config) { c.MaxBodyBytes = enforce.MaxBodyBytes + 1 }, enforce.ErrBodyBound},
		{"no principal", func(c *enforce.Config) { c.Identity.Principal = nil }, enforce.ErrIdentity},
		{"no principal id", func(c *enforce.Config) { c.Identity.Principal = &controlv1.Principal{TenantId: "tenant-1"} }, enforce.ErrIdentity},
		{"no agent", func(c *enforce.Config) { c.Identity.Agent = nil }, enforce.ErrIdentity},
		{"no agent id", func(c *enforce.Config) { c.Identity.Agent = &controlv1.Agent{} }, enforce.ErrIdentity},
		{"no run resolver", func(c *enforce.Config) { c.Runs = nil }, enforce.ErrNoRuns},
		{"no tools", func(c *enforce.Config) { c.Tools = nil }, enforce.ErrTool},
		{"a tool with no name", func(c *enforce.Config) { c.Tools[0].Name = "" }, enforce.ErrTool},
		{"a tool name past the bound", func(c *enforce.Config) { c.Tools[0].Name = strings.Repeat("n", 1025) }, enforce.ErrTool},
		{"two tools with one name", func(c *enforce.Config) { c.Tools[1].Name = c.Tools[0].Name }, enforce.ErrTool},
		{"no effect", func(c *enforce.Config) { c.Tools[0].Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED }, enforce.ErrTool},
		{"an undeclared effect", func(c *enforce.Config) { c.Tools[0].Effect = 99 }, enforce.ErrTool},
		{"a spawn the API cannot decide", func(c *enforce.Config) { c.Tools[0].Effect = controlv1.EffectClass_EFFECT_CLASS_SPAWN_OR_DELEGATE }, enforce.ErrTool},
		{"no provider", func(c *enforce.Config) { c.Tools[0].Provider = "" }, enforce.ErrTool},
		{"no resource type", func(c *enforce.Config) { c.Tools[0].ResourceType = "" }, enforce.ErrTool},
		{"a pointer without a slash", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "account" }, enforce.ErrTool},
		{"a pointer of nine tokens", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "/a/b/c/d/e/f/g/h/i" }, enforce.ErrTool},
		{"a pointer token of 65 bytes", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "/" + strings.Repeat("t", 65) }, enforce.ErrTool},
		{"a bare tilde", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "/a~b" }, enforce.ErrTool},
		{"a trailing tilde", func(c *enforce.Config) { c.Tools[0].ResourceFrom = "/a~" }, enforce.ErrTool},
		{"an undeclared trust zone", func(c *enforce.Config) { c.Tools[0].TrustZone = 99 }, enforce.ErrTool},
		{"an undeclared result trust", func(c *enforce.Config) { c.Tools[0].ReturnsTrust = 99 }, enforce.ErrTool},
		{"an undeclared sensitivity", func(c *enforce.Config) { c.Tools[0].ReturnsSensitivity = 99 }, enforce.ErrTool},
		{"a negative spent bound", func(c *enforce.Config) { c.MaxSpent = -1 }, enforce.ErrBound},
		{"a negative open bound per run", func(c *enforce.Config) { c.MaxOpenPerRun = -1 }, enforce.ErrBound},
		{"a negative sweep bound", func(c *enforce.Config) { c.SweepMax = -1 }, enforce.ErrBound},
		{"a negative request timeout", func(c *enforce.Config) { c.RequestTimeout = -1 }, enforce.ErrBound},
		{"no clock", func(c *enforce.Config) { c.Clock = nil }, enforce.ErrNoClock},
		{"no id source", func(c *enforce.Config) { c.NewID = nil }, enforce.ErrNoIDSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mut(&cfg)
			a, err := enforce.New(cfg)
			if !errors.Is(err, tc.want) || a != nil {
				t.Fatalf("New = %v, %v; want %v", a, err, tc.want)
			}
		})
	}
}

// TestANameOrProviderNoEnvelopeCarriesIsRefused: the two strings a tool puts
// in an envelope beside its classification are held to the contract's string
// rule, and the refusal names the key; one byte under the bound and an inner
// space are the controls.
func TestANameOrProviderNoEnvelopeCarriesIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		mut       func(*enforce.Tool)
	}{
		{"a provider past the bound", "provider", func(tool *enforce.Tool) { tool.Provider = strings.Repeat("p", 1025) }},
		{"a provider led by a space", "provider", func(tool *enforce.Tool) { tool.Provider = " payments" }},
		{"a zero-width provider", "provider", func(tool *enforce.Tool) { tool.Provider = "pay\u200bments" }},
		{"a zero-width name", "name", func(tool *enforce.Tool) { tool.Name = "re\u200bfund" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mut(&cfg.Tools[0])
			_, err := enforce.New(cfg)
			var ce *classify.Error
			if !errors.Is(err, enforce.ErrTool) || !errors.As(err, &ce) || ce.Key != tc.key || !errors.Is(err, classify.ErrString) {
				t.Fatalf("New = %v; want ErrTool naming %s", err, tc.key)
			}
		})
	}
	for _, provider := range []string{strings.Repeat("p", 1024), "pay ments"} {
		cfg := validConfig()
		cfg.Tools[0].Provider = provider
		if _, err := enforce.New(cfg); err != nil {
			t.Errorf("a provider of %d bytes: %v", len(provider), err)
		}
	}
}

func TestTheAdapterCooperatesAndPresentsRuns(t *testing.T) {
	a, err := enforce.New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := a.Capabilities()
	if got.Enforcement != gateway.EnforcementCooperative || !got.PresentsRuns || !got.ObserveRequest || !got.ObserveResult ||
		!got.SeeResourceIDs || got.Authenticates || got.BindEndUser || got.SeeDelegation || len(got.Obligations) != 0 {
		t.Fatalf("Capabilities = %+v", got)
	}
	if a.Name() != "enforce" {
		t.Fatalf("Name = %q", a.Name())
	}
}

func TestStartTakesOnePipelineOnce(t *testing.T) {
	a, err := enforce.New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(nil); !errors.Is(err, enforce.ErrNoPipeline) {
		t.Fatalf("Start(nil) = %v", err)
	}
	r := newRig(t, defaults())
	if err := a.Start(r.p); err != nil {
		t.Fatalf("Start = %v", err)
	}
	if err := a.Start(r.p); !errors.Is(err, enforce.ErrStarted) {
		t.Fatalf("second Start = %v", err)
	}
}
