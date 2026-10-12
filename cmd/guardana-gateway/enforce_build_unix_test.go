//go:build unix

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/metrics"
)

func loadEnforce(t *testing.T, tr enforceTree) *gatewayconfig.Config {
	t.Helper()
	cfg, err := gatewayconfig.Load(tr.config, os.Environ())
	if err != nil {
		t.Fatalf("Load refused the enforcement API plane: %v", err)
	}
	return cfg
}

// TestAnEnforcementAPIPlaneBuildsNoMCPSide: the plane builds the enforcement
// adapter, cooperative, and nothing of the MCP adapter, whether it will serve
// or a check inspects it.
func TestAnEnforcementAPIPlaneBuildsNoMCPSide(t *testing.T) {
	for _, r := range []role{roleServe, roleInspect} {
		tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
		p, err := build(loadEnforce(t, tr), slog.New(slog.DiscardHandler), time.Now(), r, "")
		if err != nil {
			t.Fatalf("role %d: build refused the plane: %v", r, err)
		}
		if p.adapter != nil || p.enforce == nil || p.seam().Capabilities().Enforcement != gateway.EnforcementCooperative || p.seam().Name() != "enforce" {
			t.Errorf("role %d: built MCP adapter %v, enforcement adapter %v", r, p.adapter, p.enforce)
		}
		if err := p.close(); err != nil {
			t.Errorf("role %d: closing: %v", r, err)
		}
	}
}

// TestAListenerKindThisBuildDoesNotServeIsRefusedFirst: a kind the binary
// has no adapter for is refused by name before any store is opened, so the
// refusal is the kind's and nothing was taken.
func TestAListenerKindThisBuildDoesNotServeIsRefusedFirst(t *testing.T) {
	tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
	cfg := loadEnforce(t, tr)
	cfg.Listener.Kind = "carrier_pigeon"
	if err := os.Remove(filepath.Join(tr.dir, "policy.bundle")); err != nil {
		t.Fatal(err)
	}
	p, err := build(cfg, slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
	if err == nil || p != nil || !strings.Contains(err.Error(), "listener.kind") || !strings.Contains(err.Error(), `"carrier_pigeon"`) {
		t.Fatalf("build = %v, %v; want a refusal naming the kind", p, err)
	}
	entries, err := os.ReadDir(filepath.Join(tr.dir, "spool"))
	if err != nil || len(entries) != 0 {
		t.Errorf("the spool holds %v (%v); a refused kind opened it", entries, err)
	}
}

// TestDoctorChecksAnEnforcementAPIPlane: every check passes, the seams line
// names the cooperative adapter, the tool table is printed, and no upstream
// is reached.
func TestDoctorChecksAnEnforcementAPIPlane(t *testing.T) {
	tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
	var stdout, stderr bytes.Buffer
	if status := doctor(context.Background(), tr.config, &stdout, &stderr); status != exitOK {
		t.Fatalf("doctor exited %d:\n%s\n%s", status, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"ok      seams         the enforce adapter declares observe_request, observe_result, enforcement_cooperative, see_resource_ids",
		"tools.2                      refund is TRANSACT on payments/order from \"/id\", returns untrusted unknown",
		"ok      upstreams     an enforce_api plane calls no upstream; 3 tool(s) are classified by name, each decision handed to a cooperating client; the socket's directory is this user's alone",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor did not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "list shaping") {
		t.Errorf("doctor spoke of list shaping on a plane that lists nothing:\n%s", out)
	}
}

// TestDoctorRefusesASocketDirectoryRunWouldRefuse: a directory others may
// enter fails doctor where run's Listen would refuse it, and binds nothing.
func TestDoctorRefusesASocketDirectoryRunWouldRefuse(t *testing.T) {
	tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
	if err := os.Chmod(filepath.Dir(tr.socket), 0o755); err != nil { //nolint:gosec // the mode under test is the one doctor has to refuse
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if status := doctor(context.Background(), tr.config, &stdout, &stderr); status == exitOK {
		t.Fatalf("doctor passed a socket directory of mode 0755:\n%s", stdout.String())
	}
	if want := "fail    upstreams     enforce: the socket's directory is not the plane's own"; !strings.Contains(stdout.String(), want) {
		t.Errorf("doctor did not say %q:\n%s", want, stdout.String())
	}
	if _, err := os.Lstat(tr.socket); !os.IsNotExist(err) {
		t.Errorf("doctor left something at the socket path: %v", err)
	}
}

// TestMetricsOfAnEnforcementAPIPlane: the plane writes its adapter's counts,
// live, and none of the MCP adapter's, which it has not built.
func TestMetricsOfAnEnforcementAPIPlane(t *testing.T) {
	tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
	p, err := build(loadEnforce(t, tr), slog.New(slog.DiscardHandler), time.Now(), roleServe, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.close() }()
	if err := p.enforce.Start(p.pipeline); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		req := httptest.NewRequest(http.MethodPost, enforce.PathAdmit, strings.NewReader("{}"))
		req.Header.Set(enforce.RunTokenHeader, "rt_bogus")
		p.enforce.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	families := scraped(t, p)
	for _, f := range families {
		if strings.HasPrefix(f.Name, metrics.Prefix()+"adapter_") {
			t.Errorf("an enforcement API plane writes the MCP adapter's %s", f.Name)
		}
	}
	for _, c := range []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{"listener_enforce_api", nil, "1"},
		{"enforce_open_handles", nil, "0"},
		{"enforce_refused_total", map[string]string{"code": "unauthenticated"}, "3"},
		{"enforce_runs_refused_total", map[string]string{"cause": "malformed"}, "3"},
	} {
		if got := value(t, families, c.name, c.labels); got != c.want {
			t.Errorf("%s%v = %s, want %s", c.name, c.labels, got, c.want)
		}
	}
}

// TestAPauseEntryOfTheToolTableIsNotStray: on an enforcement API plane a
// pause entry is judged against the tool table, which has no upstream: an
// entry naming a provider or a tool the table classifies pauses calls the
// plane runs, and only one naming a provider or a tool it lacks pauses none.
func TestAPauseEntryOfTheToolTableIsNotStray(t *testing.T) {
	tr := newEnforceTree(t, "30s", "http://127.0.0.1:1/v1/logs")
	dir := filepath.Join(tr.dir, "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writePauseFile(t, filepath.Join(dir, "pause.json"), pauseDocument(
		pauseEntry("orders", scopeOrders),
		pauseEntry("payments", `{"kind":"provider","provider":"payments"}`),
		pauseEntry("read", scopeReadOrder),
		pauseEntry("gone", `{"kind":"action","action":"tool","provider":"orders","name":"delete_order"}`),
		pauseEntry("billing", scopeElsewhere),
	))
	setEnv(t, "pause.file", "pause/pause.json")
	setEnv(t, "pause.poll_interval", "1s")
	p, err := build(loadEnforce(t, tr), slog.New(slog.DiscardHandler), time.Now(), roleInspect, "")
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := p.health(p.pauseSource(), time.Now)
	if want := []string{"gone", "billing"}; !slices.Equal(answer.Pause.UnlistedOnly, want) {
		t.Errorf("unlisted_only = %v, want %v", answer.Pause.UnlistedOnly, want)
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if status := doctor(context.Background(), tr.config, &stdout, &stderr); status != exitOK {
		t.Fatalf("doctor exited %d:\n%s", status, stdout.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"pause entry gone names tool \"delete_order\" of provider \"orders\", which tools does not classify",
		"pause entry billing names provider \"billing\", which no tool in tools has",
		"5 entry(ies), 2 naming a provider or a tool the tool table does not have",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor did not say %q:\n%s", want, out)
		}
	}
	for _, id := range []string{"orders", "payments", "read"} {
		if strings.Contains(out, "pause entry "+id+" ") {
			t.Errorf("doctor named entry %s, which pauses calls of the tool table:\n%s", id, out)
		}
	}
}
