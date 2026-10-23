package gatewayconfig

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/classify"
)

// refusedAtKey loads doc with env and reports a load that is not refused as a
// *classify.Error naming key at the entry the prefix names.
func refusedAtKey(t *testing.T, doc string, env map[string]string, prefix, key string) {
	t.Helper()
	path := writeDocument(t, doc)
	for k, v := range env {
		setEnv(t, k, v)
	}
	_, err := Load(path, os.Environ())
	var ce *classify.Error
	switch {
	case err == nil:
		t.Fatalf("accepted; want %s%s refused", prefix, key)
	case !errors.As(err, &ce) || ce.Key != key:
		t.Errorf("the refusal %v names no classification key %s", err, key)
	case !strings.HasPrefix(err.Error(), prefix+key+": "):
		t.Errorf("the refusal %q does not start with %s%s", err, prefix, key)
	}
}

// TestAClassificationNoEnvelopeCarriesIsRefusedAtLoad: an override or a tool
// whose calls the contract would refuse every time is refused when the file
// loads, naming the key, and the same entry with the key mended loads.
func TestAClassificationNoEnvelopeCarriesIsRefusedAtLoad(t *testing.T) {
	override := "\noverrides:\n  - upstream: orders\n    tool: t\n    fingerprint: abc\n    effect: WRITE\n    resource_type: order\n    resource_from: /id\n    trust_zone: PARTNER\n"
	tool := strings.Replace(enforceDocument, "    resource_from: /order_id\n", "    resource_from: /order_id\n    trust_zone: PARTNER\n", 1)
	load(t, writeDocument(t, document+override))
	load(t, writeDocument(t, tool))
	for _, effect := range []string{"WRITE", "DELETE", "CONFIGURE", "TRANSACT", "IDENTITY_OR_ACCESS"} {
		doc := strings.Replace(strings.Replace(override, "WRITE", effect, 1), "    resource_from: /id\n", "", 1)
		refusedAtKey(t, document+doc, nil, "overrides.0.", "resource_from")
		doc = strings.Replace(strings.Replace(tool, "TRANSACT", effect, 1), "    resource_from: /order_id\n", "", 1)
		refusedAtKey(t, doc, nil, "tools.0.", "resource_from")
	}
	communicate := strings.Replace(override, "WRITE", "COMMUNICATE", 1)
	refusedAtKey(t, document+strings.Replace(communicate, "    trust_zone: PARTNER\n", "", 1), nil, "overrides.0.", "trust_zone")
	refusedAtKey(t, strings.Replace(strings.Replace(tool, "TRANSACT", "COMMUNICATE", 1), "    trust_zone: PARTNER\n", "", 1), nil, "tools.0.", "trust_zone")
	for _, bad := range []string{" order", "order ", "or\u200bder", "or\u00a0der", strings.Repeat("r", 1025)} {
		refusedAtKey(t, document+override, map[string]string{"overrides.0.resource_type": bad}, "overrides.0.", "resource_type")
		refusedAtKey(t, tool, map[string]string{"tools.0.resource_type": bad}, "tools.0.", "resource_type")
	}
	load(t, writeDocument(t, strings.Replace(document+override, "resource_type: order", "resource_type: "+strings.Repeat("r", 1024), 1)))
	for _, pointer := range []string{"id", "/a~2", strings.Repeat("/a", 9)} {
		refusedAtKey(t, document+override, map[string]string{"overrides.0.resource_from": pointer}, "overrides.0.", "resource_from")
	}
}

// TestAToolNameOrProviderNoEnvelopeCarriesIsRefused: the two strings a tool
// puts in an envelope beside its classification are held to the identifier
// rule as well as to the bound.
func TestAToolNameOrProviderNoEnvelopeCarriesIsRefused(t *testing.T) {
	for _, key := range []string{"name", "provider"} {
		for _, bad := range []string{" refund", "re\u200bfund", "re\u2028fund"} {
			refusedSaying(t, enforceDocument, map[string]string{"tools.0." + key: bad}, "tools.0."+key+": classify: not a string an envelope carries")
		}
	}
	cfg := load(t, writeDocument(t, strings.Replace(enforceDocument, "provider: payments", "provider: pay ments", 1)))
	if cfg.Tools[0].Provider != "pay ments" {
		t.Errorf("a provider with an inner space loaded as %q", cfg.Tools[0].Provider)
	}
}

// TestAnUpstreamNameNoEnvelopeCarriesIsRefused: an upstream's name is every
// MCP call's action.provider, so a name the contract's string rule refuses
// is refused when the file loads, naming the key; an inner space and a name
// at the bound are the controls.
func TestAnUpstreamNameNoEnvelopeCarriesIsRefused(t *testing.T) {
	for _, bad := range []string{" orders", "orders\u200b", "or\u2028ders", strings.Repeat("o", 1025)} {
		refusedSaying(t, document, map[string]string{"upstreams.0.name": bad}, "upstreams.0.name: classify: not a string an envelope carries")
	}
	for _, good := range []string{"my orders", strings.Repeat("o", 1024)} {
		path := writeDocument(t, document)
		setEnv(t, "upstreams.0.name", good)
		if _, err := Load(path, os.Environ()); err != nil {
			t.Errorf("an upstream name of %d bytes: %v", len(good), err)
		}
	}
}
