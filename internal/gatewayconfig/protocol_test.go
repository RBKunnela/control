package gatewayconfig_test

import (
	"testing"

	"github.com/guardana/control/internal/gatewayconfig"
)

func TestProtocolOfEachListenerKind(t *testing.T) {
	for kind, want := range map[string]string{
		"stdio":          "mcp",
		"stateless_http": "mcp",
		"stateful_http":  "mcp",
		"enforce_api":    "enforce",
	} {
		got, err := gatewayconfig.ProtocolOf(kind)
		if err != nil || got != want {
			t.Errorf("ProtocolOf(%q) = %q, %v; want %q", kind, got, err, want)
		}
	}
	for _, kind := range []string{"", "Stdio", "stdio ", "enforce", "mcp", "grpc"} {
		if got, err := gatewayconfig.ProtocolOf(kind); err == nil || got != "" {
			t.Errorf("ProtocolOf(%q) = %q, %v; want a refusal", kind, got, err)
		}
	}
}
