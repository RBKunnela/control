package gatewayconfig

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/pkg/contract"
)

// loadWith loads the document with each key set through its variable. The
// environment is handed to Load as a list, so a value may hold a NUL that no
// process environment can.
func loadWith(t *testing.T, doc string, values map[string]string) (*Config, error) {
	t.Helper()
	path := writeDocument(t, doc)
	environ := os.Environ()
	for key, value := range values {
		environ = append(environ, brand.Env(EnvName(key))+"="+value)
	}
	return Load(path, environ)
}

// TestAnIdentifierEveryEnvelopeCarriesIsRefusedAtLoad: every key an envelope
// carries, the plane's, an upstream's and the listener's principal and agent,
// is refused when the file loads, naming the key, for what the contract would
// refuse at the first call; the refusal never repeats the value.
func TestAnIdentifierEveryEnvelopeCarriesIsRefusedAtLoad(t *testing.T) {
	const marker = "acme-HUNTER2"
	keys := []string{"project_id", "tenant_id", "environment", "upstreams.0.tenant_id", "upstreams.0.environment",
		"listener.principal.id", "listener.principal.type", "listener.principal.tenant_id",
		"listener.agent.id", "listener.agent.framework", "listener.agent.version"}
	for _, key := range keys {
		for _, c := range []struct {
			name, value string
			want        error
		}{
			{"a leading space", " " + marker, contract.ErrInvalidValue},
			{"a NUL", marker + "\x00", contract.ErrInvalidValue},
			{"a trailing ideographic space", marker + "\u3000", contract.ErrInvalidValue},
			{"past the bound", strings.Repeat(marker, contract.MaxStringBytes/len(marker)+1), contract.ErrTooLarge},
		} {
			t.Run(key+"/"+c.name, func(t *testing.T) {
				_, err := loadWith(t, document, map[string]string{key: c.value})
				switch {
				case err == nil:
					t.Fatal("accepted")
				case !strings.HasPrefix(err.Error(), key+": ") || !errors.Is(err, c.want):
					t.Errorf("the refusal %q does not name %s with %v", err, key, c.want)
				case strings.Contains(err.Error(), marker):
					t.Errorf("the refusal repeats the value: %v", err)
				}
			})
		}
	}
	values := map[string]string{}
	for _, key := range keys {
		values[key] = "acme corp"
	}
	values["project_id"] = strings.Repeat("p", contract.MaxStringBytes)
	cfg, err := loadWith(t, document, values)
	if err != nil {
		t.Fatalf("inner spaces and a project at the bound were refused: %v", err)
	}
	if cfg.Upstreams[0].TenantID != "acme corp" || len(cfg.ProjectID) != contract.MaxStringBytes {
		t.Errorf("the values loaded as %q and %d bytes", cfg.Upstreams[0].TenantID, len(cfg.ProjectID))
	}
}

// TestTwoUpstreamsWithOneNameAreRefusedAtLoad: the adapter refuses a second
// upstream of one name, so the loader does, naming both entries; another name
// is the control.
func TestTwoUpstreamsWithOneNameAreRefusedAtLoad(t *testing.T) {
	second := "  - name: orders\n    endpoint: http://127.0.0.1:2/mcp\n"
	refusedSaying(t, compose(second), nil, "upstreams.1.name: the name of upstreams.0")
	cfg := load(t, write(t, strings.Replace(second, "orders", "billing", 1)))
	if len(cfg.Upstreams) != 2 || cfg.Upstreams[1].Name != "billing" {
		t.Errorf("the upstreams loaded as %+v", cfg.Upstreams)
	}
}
