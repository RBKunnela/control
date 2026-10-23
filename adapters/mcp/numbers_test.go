package mcp

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
)

// fractionTool is a definition as the SDK hands it over after decoding a
// tools/list: every schema number a float64, among them a fraction, a step, a
// bound past 2^53 and negative zero; and two properties whose names fold
// together.
func fractionTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "sample",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"temperature": map[string]any{"type": "number", "default": 0.7, "multipleOf": 0.01, "minimum": math.Copysign(0, -1)},
				"seed":        map[string]any{"type": "integer", "maximum": float64(math.MaxInt64)},
				"ID":          map[string]any{"type": "string"},
				"id":          map[string]any{"type": "string"},
			},
		},
	}
}

// integerTool is a definition every number of which is an integer inside the
// JSON-safe range, whose fingerprint is the action form's bytes hashed.
func integerTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "page",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit": map[string]any{"type": "integer", "minimum": float64(1), "maximum": float64(100), "default": -5},
				"ID":    map[string]any{"type": "string"},
			},
		},
	}
}

// The pins were computed outside Go, from the JSON json.Marshal writes for
// each definition, by an RFC 8785 canonicalizer in an ECMAScript engine and
// sha256 over the fingerprint tag and its output.
const (
	fractionToolFingerprint = "sha256:c61e558dbfb3946c8f22c935c107cb4612732054925cfdffd906560573ce25c1"
	integerToolFingerprint  = "sha256:67b35c5986091814fa025a9ab6f8b849c40924f2a6f962d5fd55a4c5551b1307"
)

// TestAFractionInASchemaIsFingerprinted: a definition with fractions, a bound
// past the JSON-safe range and negative zero has a fingerprint, so an
// override can classify it, and a definition of integers has the pinned
// fingerprint of its action-form bytes.
func TestAFractionInASchemaIsFingerprinted(t *testing.T) {
	for name, tc := range map[string]struct {
		tool *mcp.Tool
		want string
	}{
		"fractions": {fractionTool(), fractionToolFingerprint},
		"integers":  {integerTool(), integerToolFingerprint},
	} {
		fp, err := Fingerprint(tc.tool)
		if err != nil || fp != tc.want {
			raw, _ := json.Marshal(tc.tool.InputSchema)
			t.Errorf("%s: Fingerprint = %s, %v; want %s (schema %s)", name, fp, err, tc.want, raw)
		}
	}

	m := newManifest([]Override{{Upstream: "up", Tool: "sample", Fingerprint: fractionToolFingerprint, Classification: classify.Classification{Effect: controlv1.EffectClass_EFFECT_CLASS_READ, ResourceType: "model"}}}, emptySecrets(t))
	if e := m.classify("up", fractionTool()); !e.Classified {
		t.Errorf("a pinned definition with fractions is unclassified: %s", e.why)
	}
	changed := fractionTool()
	changed.InputSchema.(map[string]any)["properties"].(map[string]any)["temperature"].(map[string]any)["default"] = 0.8
	if e := m.classify("up", changed); e.Classified {
		t.Error("a definition whose default moved from 0.7 to 0.8 kept its classification")
	}
}
