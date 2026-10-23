package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	adaptermcp "github.com/guardana/control/adapters/mcp"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	toolclass "github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gatewayconfig"
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
	base, err := gatewayconfig.Load(tr.config, nil)
	if err != nil {
		t.Fatalf("the control configuration is refused: %v", err)
	}
	mcpConfig, err := adapterConfig(base, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the control adapter configuration is refused: %v", err)
	}
	for _, row := range classificationRefusals {
		t.Run(row.name, func(t *testing.T) {
			var environ []string
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
		Socket: filepath.Join(dir, "s"), ExecutionLifetime: time.Minute,
		Identity: enforce.Identity{Principal: &controlv1.Principal{Id: "p"}, Agent: &controlv1.Agent{Id: "a"}},
		Runs:     runsDir{}, Tools: []enforce.Tool{tool}, Clock: time.Now, NewID: newID,
	}
}
