//go:build unix

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
)

// strengthPlane writes a plane whose listener is kind and returns its
// configuration file: the MCP fixture for an MCP kind, the enforcement API
// tree for enforce_api.
func strengthPlane(t *testing.T, kind string) string {
	t.Helper()
	if kind == gatewayconfig.ListenerEnforceAPI {
		return newEnforceTree(t, "30s", "unix://"+exportSocket(t)).config
	}
	tr := newTree(t)
	const http = "  kind: stateless_http\n  address: 127.0.0.1:8080\n  origins:\n    - http://localhost:5173\n"
	raw, err := os.ReadFile(filepath.Clean(tr.config))
	if err != nil {
		t.Fatalf("reading the configuration: %v", err)
	}
	if !bytes.Contains(raw, []byte(http)) {
		t.Fatalf("the fixture's listener is not the stateless one this test rewrites:\n%s", raw)
	}
	listener := strings.Replace(http, "stateless_http", kind, 1)
	if kind == gatewayconfig.ListenerStdio {
		listener = "  kind: stdio\n"
	}
	if err := os.WriteFile(filepath.Clean(tr.config), bytes.Replace(raw, []byte(http), []byte(listener), 1), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	return tr.config
}

// TestEveryListenersStrengthIsItsProtocolsInTheOneTable: for every listener
// kind, the adapter the plane builds is named after the protocol coverage
// reads for that kind, and the strength the adapter declares and doctor
// prints is the one the protocol table states for it. A reader that took the
// strength from the listener or from a protocol by name would have to agree
// with the table on every kind to pass.
func TestEveryListenersStrengthIsItsProtocolsInTheOneTable(t *testing.T) {
	const inline, cooperative = "enforcement_inline", "enforcement_cooperative"
	for _, c := range []struct {
		kind, protocol  string
		want            gateway.Enforcement
		printed, absent string
	}{
		{gatewayconfig.ListenerStdio, "mcp", gateway.EnforcementInline, inline, cooperative},
		{gatewayconfig.ListenerStatelessHTTP, "mcp", gateway.EnforcementInline, inline, cooperative},
		{gatewayconfig.ListenerStatefulHTTP, "mcp", gateway.EnforcementInline, inline, cooperative},
		{gatewayconfig.ListenerEnforceAPI, "enforce", gateway.EnforcementCooperative, cooperative, inline},
	} {
		t.Run(c.kind, func(t *testing.T) {
			config := strengthPlane(t, c.kind)
			cfg, err := gatewayconfig.Load(config, os.Environ())
			if err != nil {
				t.Fatalf("Load refused the plane: %v", err)
			}
			protocol, err := gatewayconfig.ProtocolOf(cfg.Listener.Kind)
			if err != nil || protocol != c.protocol {
				t.Fatalf("coverage reads the protocol %q (%v) for %s, want %q", protocol, err, c.kind, c.protocol)
			}
			if got := channel.StrengthOf(protocol); got != c.want {
				t.Errorf("the table gives strength %d to %s, the protocol coverage reads for %s, want %d", got, protocol, c.kind, c.want)
			}
			name, enforcement := builtSeam(t, cfg)
			if name != protocol {
				t.Errorf("the %s plane built the %q adapter, and coverage judged it as %q", c.kind, name, protocol)
			}
			if enforcement != c.want {
				t.Errorf("the %s adapter declares strength %d, want %d", name, enforcement, c.want)
			}
			if seams := doctorSeams(t, config); !strings.Contains(seams, c.printed) || strings.Contains(seams, c.absent) {
				t.Errorf("doctor's seams line for %s does not name %s alone: %q", c.kind, c.printed, seams)
			}
		})
	}
}

// builtSeam builds the plane cfg describes, as doctor inspects it, and
// returns its adapter's name and declared strength.
func builtSeam(t *testing.T, cfg *gatewayconfig.Config) (string, gateway.Enforcement) {
	t.Helper()
	p, err := build(cfg, slog.New(slog.DiscardHandler), time.Now(), roleInspect, "")
	if err != nil {
		t.Fatalf("build refused the plane: %v", err)
	}
	name, enforcement := p.seam().Name(), p.seam().Capabilities().Enforcement
	if err := p.close(); err != nil {
		t.Errorf("closing the plane: %v", err)
	}
	return name, enforcement
}

// doctorSeams runs doctor over config and returns its passing seams line, or
// fails when there is none.
func doctorSeams(t *testing.T, config string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	doctor(context.Background(), config, &stdout, &stderr)
	for _, l := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(l, "ok      seams ") {
			return l
		}
	}
	t.Fatalf("doctor printed no passing seams line:\n%s\n%s", stdout.String(), stderr.String())
	return ""
}
