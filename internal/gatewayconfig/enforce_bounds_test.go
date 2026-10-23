package gatewayconfig

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/classify"
	"github.com/guardana/control/internal/gateway"
)

// TestThePerRunBoundDefaultsToTheAdapters: a plane silent on the key bounds a
// run as the adapter would.
func TestThePerRunBoundDefaultsToTheAdapters(t *testing.T) {
	cfg := load(t, writeDocument(t, enforceDocument))
	if cfg.Listener.MaxOpenPerRun != enforce.DefaultMaxOpenPerRun {
		t.Errorf("listener.max_open_per_run defaults to %d, the adapter to %d", cfg.Listener.MaxOpenPerRun, enforce.DefaultMaxOpenPerRun)
	}
}

// TestThePerRunBoundStaysBelowThePlanes: a run may hold fewer executions open
// than the plane, or a handful of runs fill every slot; the bound is
// positive, and only an enforce_api listener reads it.
func TestThePerRunBoundStaysBelowThePlanes(t *testing.T) {
	accepted := func(env map[string]string) {
		t.Helper()
		path := writeDocument(t, enforceDocument)
		for k, v := range env {
			setEnv(t, k, v)
		}
		if _, err := Load(path, os.Environ()); err != nil {
			t.Errorf("%v was refused: %v", env, err)
		}
	}
	accepted(map[string]string{"listener.max_open_per_run": "1", "approvals.max_open": "2"})
	accepted(map[string]string{"approvals.max_open": "17"})
	accepted(map[string]string{"listener.max_open_per_run": "255"})
	refusedSaying(t, enforceDocument, map[string]string{"listener.max_open_per_run": "2", "approvals.max_open": "2"}, "approvals.max_open: ")
	refusedSaying(t, enforceDocument, map[string]string{"approvals.max_open": "16"}, "approvals.max_open: ")
	refusedSaying(t, enforceDocument, map[string]string{"listener.max_open_per_run": "256"}, "approvals.max_open: ")
	refusedSaying(t, enforceDocument, map[string]string{"listener.max_open_per_run": "0"}, "listener.max_open_per_run: ")
	refusedSaying(t, enforceDocument, map[string]string{"listener.max_open_per_run": "-1"}, "listener.max_open_per_run: ")
	refusedSaying(t, document, map[string]string{"listener.max_open_per_run": "4"}, "listener.max_open_per_run: only an enforce_api listener")
}

// TestAToolTableIsWhatTheAdapterTakes: a resource pointer the adapter
// refuses and a name past its bound are refused when the file loads, so
// doctor never passes a table the plane refuses at start.
func TestAToolTableIsWhatTheAdapterTakes(t *testing.T) {
	for _, pointer := range []string{"not-a-pointer", "/order_id/~2"} {
		refusedSaying(t, strings.Replace(enforceDocument, "resource_from: /order_id", "resource_from: "+pointer, 1), nil, "tools.0.resource_from: ")
	}
	long := strings.Repeat("n", 1025)
	refusedSaying(t, strings.Replace(enforceDocument, "name: refund", "name: "+long, 1), nil, "tools.0.name: ")
	cfg := load(t, writeDocument(t, strings.Replace(enforceDocument, "name: refund", "name: "+long[:1024], 1)))
	if len(cfg.Tools[0].Name) != 1024 {
		t.Errorf("a name of 1024 bytes loaded as %d bytes", len(cfg.Tools[0].Name))
	}
	if _, err := enforce.New(adapterConfigOf(cfg, cfg.Resolve(cfg.Listener.Socket))); err != nil {
		t.Errorf("the adapter refuses what loaded: %v", err)
	}
	for _, c := range []struct{ line, key string }{
		{"provider: payments", "provider: "},
		{"resource_type: order", "resource_type: "},
	} {
		refusedSaying(t, strings.Replace(enforceDocument, c.line, c.key+long, 1), nil, "tools.0."+c.key)
		cfg := load(t, writeDocument(t, strings.Replace(enforceDocument, c.line, c.key+long[:1024], 1)))
		if _, err := enforce.New(adapterConfigOf(cfg, cfg.Resolve(cfg.Listener.Socket))); err != nil {
			t.Errorf("the adapter refuses a %s of 1024 bytes that loaded: %v", strings.TrimSuffix(c.key, ": "), err)
		}
	}
}

// TestTheSocketPathFitsWhatEveryPlatformBinds: the socket path as it
// resolves against the file's directory is at most 103 bytes, which a macOS
// sockaddr_un holds with its terminator; the adapter agrees at both sides.
func TestTheSocketPathFitsWhatEveryPlatformBinds(t *testing.T) {
	for _, total := range []int{103, 104} {
		resolved, cfg, err := loadSocketOf(t, total)
		_, adapterErr := enforce.New(adapterConfigOf(&Config{Tools: []ToolConfig{{Name: "refund"}}}, resolved))
		switch {
		case total <= 103 && (err != nil || adapterErr != nil):
			t.Errorf("a socket path of %d bytes: Load %v, adapter %v; want both to take it", total, err, adapterErr)
		case total > 103 && (err == nil || !strings.Contains(err.Error(), "listener.socket: ") || adapterErr == nil):
			t.Errorf("a socket path of %d bytes: Load %v, adapter %v; want both to refuse it", total, err, adapterErr)
		case err == nil && cfg.Resolve(cfg.Listener.Socket) != resolved:
			t.Errorf("the socket resolves to %q, want %q", cfg.Resolve(cfg.Listener.Socket), resolved)
		}
	}
}

// loadSocketOf loads enforceDocument from a short directory with a relative
// socket path that resolves to total bytes, and returns that path.
func loadSocketOf(t *testing.T, total int) (string, *Config, error) {
	t.Helper()
	writeDocument(t, enforceDocument)
	dir, err := os.MkdirTemp("", "gc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "g.yaml")
	if err := os.WriteFile(path, []byte(enforceDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	pad := total - len(dir) - len("/deep/s")
	if pad < 1 {
		t.Fatalf("the temporary directory %s is too long to build a path of %d bytes", dir, total)
	}
	rel := "deep/s" + strings.Repeat("o", pad)
	setEnv(t, "listener.socket", rel)
	resolved := filepath.Join(dir, rel)
	if len(resolved) != total {
		t.Fatalf("built a path of %d bytes, want %d", len(resolved), total)
	}
	cfg, err := Load(path, os.Environ())
	return resolved, cfg, err
}

type noRuns struct{}

func (noRuns) Resolve(context.Context, string, gateway.RunIdentity, time.Time) (gateway.OpenedRun, error) {
	return gateway.OpenedRun{}, &gateway.RunRefusal{Cause: gateway.RunCauses()[0]}
}

// adapterConfigOf is the adapter's configuration for cfg's tool names at
// socket, everything else at a value the adapter takes.
func adapterConfigOf(cfg *Config, socket string) enforce.Config {
	tools := make([]enforce.Tool, 0, len(cfg.Tools))
	for _, tool := range cfg.Tools {
		tools = append(tools, enforce.Tool{Name: tool.Name, Provider: "p", Classification: classify.Classification{Effect: controlv1.EffectClass_EFFECT_CLASS_READ, ResourceType: "r", ResourceFrom: tool.ResourceFrom}})
	}
	return enforce.Config{
		Socket: socket, ExecutionLifetime: time.Minute,
		Identity: enforce.Identity{Principal: &controlv1.Principal{Id: "p"}, Agent: &controlv1.Agent{Id: "a"}},
		Runs:     noRuns{}, Tools: tools, Clock: time.Now, NewID: func() string { return strconv.Itoa(1) },
	}
}
