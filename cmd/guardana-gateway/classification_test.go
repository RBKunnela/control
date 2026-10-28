package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	adaptermcp "github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	toolclass "github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/pkg/contract"
)

// classificationRefusals are classifications no envelope can carry, each as
// a configuration file writes it and as the adapters take it, with the key a
// refusal names. The first row is the control every entry point accepts.
var classificationRefusals = []struct {
	name   string
	keys   map[string]string
	effect controlv1.EffectClass
	edit   func(*toolclass.Classification)
	key    string
}{
	{"the control", nil, controlv1.EffectClass_EFFECT_CLASS_WRITE, func(*toolclass.Classification) {}, ""},
	{"a write without its pointer", map[string]string{"resource_from": ""}, controlv1.EffectClass_EFFECT_CLASS_WRITE,
		func(c *toolclass.Classification) { c.ResourceFrom = "" }, "resource_from"},
	{"a transaction without its pointer", map[string]string{"effect": "TRANSACT", "resource_from": ""}, controlv1.EffectClass_EFFECT_CLASS_TRANSACT,
		func(c *toolclass.Classification) { c.ResourceFrom = "" }, "resource_from"},
	{"a message without its destination", map[string]string{"effect": "COMMUNICATE", "trust_zone": ""}, controlv1.EffectClass_EFFECT_CLASS_COMMUNICATE,
		func(c *toolclass.Classification) { c.TrustZone = 0 }, "trust_zone"},
	{"a resource type led by a space", map[string]string{"resource_type": " order"}, controlv1.EffectClass_EFFECT_CLASS_WRITE,
		func(c *toolclass.Classification) { c.ResourceType = " order" }, "resource_type"},
	{"a zero-width resource type", map[string]string{"resource_type": "or\u200bder"}, controlv1.EffectClass_EFFECT_CLASS_WRITE,
		func(c *toolclass.Classification) { c.ResourceType = "or\u200bder" }, "resource_type"},
	{"a resource type past the bound", map[string]string{"resource_type": strings.Repeat("r", 1025)}, controlv1.EffectClass_EFFECT_CLASS_WRITE,
		func(c *toolclass.Classification) { c.ResourceType = strings.Repeat("r", 1025) }, "resource_type"},
	{"a pointer that is not RFC 6901", map[string]string{"resource_from": "id"}, controlv1.EffectClass_EFFECT_CLASS_WRITE,
		func(c *toolclass.Classification) { c.ResourceFrom = "id" }, "resource_from"},
}

// classifiedOverride is a write of one order with every key set, which the
// environment of a row then changes.
const classifiedOverride = "\noverrides:\n  - upstream: orders\n    tool: update_order\n    fingerprint: sha256:00\n" +
	"    effect: WRITE\n    resource_type: order\n    resource_from: /id\n    trust_zone: PARTNER\n"

// refusalKey is the classification key err names, "" for none and "?" for
// a refusal that names no classification key.
func refusalKey(err error) string {
	var ce *toolclass.Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &ce):
		return ce.Key
	}
	return "?"
}

// TestAClassificationIsRefusedAlikeAtEveryEntryPoint: the configuration
// loader, the MCP adapter and the enforcement adapter each refuse a
// classification no envelope can carry, naming the same key, and each takes
// the control.
func TestAClassificationIsRefusedAlikeAtEveryEntryPoint(t *testing.T) {
	tr := newTree(t)
	withConfig(t, tr, classifiedOverride)
	base, err := gatewayconfig.Load(tr.config, []string{upstreamEnvironment})
	if err != nil {
		t.Fatalf("the control configuration is refused: %v", err)
	}
	mcpConfig, err := adapterConfig(base, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the control adapter configuration is refused: %v", err)
	}
	for _, row := range classificationRefusals {
		t.Run(row.name, func(t *testing.T) {
			environ := []string{upstreamEnvironment}
			for key, value := range row.keys {
				environ = append(environ, brand.Env(gatewayconfig.EnvName("overrides.0."+key))+"="+value)
			}
			_, err := gatewayconfig.Load(tr.config, environ)
			if got := refusalKey(err); got != row.key {
				t.Errorf("the configuration: %v names %q, want %q", err, got, row.key)
			}

			c := toolclass.Classification{Effect: row.effect, ResourceType: "order", ResourceFrom: "/id", TrustZone: controlv1.TrustZone_TRUST_ZONE_PARTNER}
			row.edit(&c)
			cfg := mcpConfig
			cfg.Overrides = []adaptermcp.Override{{Upstream: "orders", Tool: "update_order", Fingerprint: "sha256:00", Classification: c}}
			_, err = adaptermcp.New(cfg)
			if got := refusalKey(err); got != row.key || (row.key != "" && !errors.Is(err, adaptermcp.ErrOverride)) {
				t.Errorf("mcp.New: %v names %q, want %q", err, got, row.key)
			}

			_, err = enforce.New(enforceConfig(t, enforce.Tool{Name: "update_order", Provider: "orders", Classification: c}))
			if got := refusalKey(err); got != row.key || (row.key != "" && !errors.Is(err, enforce.ErrTool)) {
				t.Errorf("enforce.New: %v names %q, want %q", err, got, row.key)
			}
		})
	}
}

// upstreamEnvironment gives the fixture's one upstream the environment a
// write's resource needs.
var upstreamEnvironment = brand.Env(gatewayconfig.EnvName("upstreams.0.environment")) + "=prod"

// TestAnUnsetEnvelopeKeyIsRefusedAlikeAtEveryEntryPoint: a class whose
// envelope needs environment and resource.environment, or resource.tenant_id,
// is refused by the loader and by both adapters' New when the value one is
// read from is empty, and taken by each when all are set; a read needs none.
// The enforcement adapter reads them from the plane's keys, so the upstream's
// are not its to refuse.
func TestAnUnsetEnvelopeKeyIsRefusedAlikeAtEveryEntryPoint(t *testing.T) {
	tr := newTree(t)
	withConfig(t, tr, classifiedOverride)
	base, err := gatewayconfig.Load(tr.config, []string{upstreamEnvironment})
	if err != nil {
		t.Fatalf("the control configuration is refused: %v", err)
	}
	mcpConfig, err := adapterConfig(base, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the control adapter configuration is refused: %v", err)
	}
	planeKey, upstreamKey := brand.Env(gatewayconfig.EnvName("environment")), brand.Env(gatewayconfig.EnvName("upstreams.0.environment"))
	tenantKey := brand.Env(gatewayconfig.EnvName("upstreams.0.tenant_id"))
	effectKey := brand.Env(gatewayconfig.EnvName("overrides.0.effect"))
	for _, row := range []struct {
		name                    string
		effect                  string
		plane, upstream, tenant string
		loader, mcp, enforce    string
	}{
		{"a write with both", "WRITE", "dev", "prod", "", "", "", ""},
		{"a write without the plane's", "WRITE", "", "prod", "", "overrides.0.effect: WRITE needs environment,", "needs Environment,", "needs Environment,"},
		{"a write without the upstream's", "WRITE", "dev", "", "", "overrides.0.effect: WRITE needs upstreams.0.environment,", "needs Upstreams[0].Environment,", ""},
		{"a delete without either", "DELETE", "", "", "", "overrides.0.effect: DELETE needs environment,", "needs Environment,", "needs Environment,"},
		{"a transact with the upstream's tenant", "TRANSACT", "", "", "acme", "", "", ""},
		{"a transact without the upstream's tenant", "TRANSACT", "", "", "", "overrides.0.effect: TRANSACT needs upstreams.0.tenant_id,", "needs Upstreams[0].TenantID,", ""},
		{"a read without any", "READ", "", "", "", "", "", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := gatewayconfig.Load(tr.config, []string{planeKey + "=" + row.plane, upstreamKey + "=" + row.upstream, tenantKey + "=" + row.tenant, effectKey + "=" + row.effect})
			refusedNaming(t, "the configuration", err, nil, row.loader)

			effect, err := contract.ParseEffect(row.effect)
			if err != nil {
				t.Fatal(err)
			}
			c := toolclass.Classification{Effect: effect, ResourceType: "order", ResourceFrom: "/id", TrustZone: controlv1.TrustZone_TRUST_ZONE_PARTNER}
			cfg := mcpConfig
			cfg.Environment = row.plane
			cfg.Upstreams = slices.Clone(mcpConfig.Upstreams)
			cfg.Upstreams[0].Environment = row.upstream
			cfg.Upstreams[0].TenantID = row.tenant
			cfg.Overrides = []adaptermcp.Override{{Upstream: "orders", Tool: "update_order", Fingerprint: "sha256:00", Classification: c}}
			_, err = adaptermcp.New(cfg)
			refusedNaming(t, "mcp.New", err, adaptermcp.ErrOverride, row.mcp)

			ecfg := enforceConfig(t, enforce.Tool{Name: "update_order", Provider: "orders", Classification: c})
			ecfg.Environment, ecfg.TenantID = row.plane, "acme"
			_, err = enforce.New(ecfg)
			refusedNaming(t, "enforce.New", err, enforce.ErrTool, row.enforce)
		})
	}
}

// refusedNaming reports err unless it is nil where want is empty, or wraps
// sentinel and says want.
func refusedNaming(t *testing.T, who string, err, sentinel error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Errorf("%s refused: %v", who, err)
	case want != "" && err == nil:
		t.Errorf("%s accepted; want a refusal naming %s", who, want)
	case want != "" && ((sentinel != nil && !errors.Is(err, sentinel)) || !strings.Contains(err.Error(), want)):
		t.Errorf("%s: %v does not name %s", who, err, want)
	}
}

// enforceConfig is an enforcement adapter's configuration complete but for
// its one tool. New binds nothing, so the socket's directory is only named;
// it is a short one, since a test's own directory can be past what a socket
// path holds.
func enforceConfig(t *testing.T, tool enforce.Tool) enforce.Config {
	t.Helper()
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return enforce.Config{
		Socket: filepath.Join(dir, "s"), ExecutionLifetime: time.Minute, Environment: "dev",
		Identity: enforce.Identity{Principal: &controlv1.Principal{Id: "p"}, Agent: &controlv1.Agent{Id: "a"}},
		Runs:     runsDir{}, Tools: []enforce.Tool{tool}, Clock: time.Now, NewID: newID,
	}
}
