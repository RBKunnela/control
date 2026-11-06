package main

import (
	"context"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/brand"
)

// reportEnvironment, as the positional argument of this test binary, turns it
// into the stdio upstream that answers with its own environment. An argument
// rather than a variable starts it, so what starts the helper does not depend
// on what the plane passes.
const reportEnvironment = "report-environment"

// TestHelperReportsItsEnvironment is this binary as a stdio upstream whose one
// tool answers with the process's environment, as a JSON array.
func TestHelperReportsItsEnvironment(t *testing.T) {
	if !slices.Contains(flag.Args(), reportEnvironment) {
		t.Skip("this case is the stdio upstream an environment case starts; it runs in that child process alone")
	}
	server := sdk.NewServer(&sdk.Implementation{Name: "environment-upstream", Version: "0"}, nil)
	server.AddTool(&sdk.Tool{Name: "environment", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			raw, err := json.Marshal(os.Environ())
			if err != nil {
				return nil, err
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(raw)}}}, nil
		})
	if err := server.Run(context.Background(), &sdk.StdioTransport{}); err != nil {
		t.Fatalf("the stdio upstream stopped: %v", err)
	}
}

// Values no child may see, and one it is given.
const (
	headerSentinel    = "sentinel-export-header-value"
	pdpHeaderSentinel = "sentinel-pdp-header-value"
	unrelatedSentinel = "sentinel-unrelated-value"
	listedValue       = "eu-fixture"
)

// childEnvironment starts the tree's one upstream through the transport the
// plane builds for it, and returns the environment the child reports, by
// name.
func childEnvironment(t *testing.T, tr tree) map[string]string {
	t.Helper()
	ups, err := upstreams(tr.load(t))
	if err != nil {
		t.Fatalf("building the upstream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "environment-test", Version: "0"}, nil).Connect(ctx, ups[0].Transport, nil)
	if err != nil {
		t.Fatalf("starting the stdio upstream: %v", err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "environment", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("the upstream did not report its environment: %v %+v", err, res)
	}
	var environ []string
	if err := json.Unmarshal([]byte(resultText(res)), &environ); err != nil {
		t.Fatalf("the upstream's report is not a list of variables: %v", err)
	}
	out := map[string]string{}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		out[name] = value
	}
	return out
}

// environmentTree is a tree whose upstream runs this binary as the
// environment helper and lists ORDERS_REGION, with a credential under both
// header maps and an unrelated variable in the plane's environment.
func environmentTree(t *testing.T) tree {
	t.Helper()
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("resolving the test binary: %v", err)
	}
	tr := newTree(t)
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(raw), "    endpoint: http://127.0.0.1:1/mcp\n",
		"    command: "+strconv.Quote(self)+"\n    args:\n      - -test.run=^TestHelperReportsItsEnvironment$\n"+
			"      - -test.timeout=5m\n      - "+reportEnvironment+"\n    env:\n      - ORDERS_REGION\n", 1)
	doc += "\npdp:\n  identifier: https://pdp.example.test\n"
	if err := os.WriteFile(tr.config, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	setEnv(t, "export.headers.authorization", headerSentinel)
	setEnv(t, "pdp.headers.authorization", pdpHeaderSentinel)
	t.Setenv("SENTINEL_X", unrelatedSentinel)
	return tr
}

// noSentinel fails the test for any variable of the child that carries the
// plane's prefix, the unrelated name, or a sentinel value.
func noSentinel(t *testing.T, env map[string]string) {
	t.Helper()
	for name, value := range env {
		if strings.HasPrefix(strings.ToUpper(name), brand.EnvPrefix) || name == "SENTINEL_X" {
			t.Errorf("the child received %s", name)
		}
		for _, sentinel := range []string{headerSentinel, pdpHeaderSentinel, unrelatedSentinel} {
			if strings.Contains(value, sentinel) {
				t.Errorf("the child received %s in %s", sentinel, name)
			}
		}
	}
}

// TestAStdioUpstreamGetsOnlyTheEnvironmentItIsGiven: the child of a stdio
// upstream holds the fixed few with the plane's values, and the variable the
// configuration lists; the credentials
// under both header maps and an unrelated variable of the plane never reach
// it.
func TestAStdioUpstreamGetsOnlyTheEnvironmentItIsGiven(t *testing.T) {
	tr := environmentTree(t)
	t.Setenv("ORDERS_REGION", listedValue)
	for _, name := range []string{"HOME", "LANG", "LC_ALL", "TMPDIR", "USER"} {
		t.Setenv(name, "fixture-"+strings.ToLower(name))
	}
	path := os.Getenv("PATH")
	if path == "" {
		t.Fatal("this test needs a PATH in its own environment to see it pass to the child")
	}
	env := childEnvironment(t, tr)

	noSentinel(t, env)
	if got := env["ORDERS_REGION"]; got != listedValue {
		t.Errorf("the listed variable reached the child as %q, want %q", got, listedValue)
	}
	if got := env["PATH"]; got != path {
		t.Errorf("PATH reached the child as %q, want the plane's %q", got, path)
	}
	allowed := []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "ORDERS_REGION"}
	for _, name := range allowed {
		if value, ok := os.LookupEnv(name); ok && env[name] != value {
			t.Errorf("%s reached the child as %q, want the plane's %q", name, env[name], value)
		}
	}
	for name := range env {
		if !slices.Contains(allowed, name) {
			t.Errorf("the child received %s, which is neither in the fixed set nor listed", name)
		}
	}
}

// TestAStdioUpstreamOfAnEmptyEnvironmentInheritsNothing: when the plane has
// none of the fixed few and not the listed variable, the child's environment
// is empty rather than the plane's whole one.
func TestAStdioUpstreamOfAnEmptyEnvironmentInheritsNothing(t *testing.T) {
	tr := environmentTree(t)
	for _, name := range []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "ORDERS_REGION"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unsetting %s: %v", name, err)
		}
	}
	env := childEnvironment(t, tr)

	noSentinel(t, env)
	if len(env) != 0 {
		names := slices.Sorted(maps.Keys(env))
		t.Errorf("the child received %d variable(s) from a plane that has none to give: %v", len(names), names)
	}
}

// TestDoctorPrintsAnUpstreamsEnvNamesNeverValues: doctor lists each name an
// upstream receives under its key, never the value, and says which of them
// the environment it runs in does not have.
func TestDoctorPrintsAnUpstreamsEnvNamesNeverValues(t *testing.T) {
	tr := newTree(t)
	raw, err := os.ReadFile(tr.config)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(raw), "    endpoint: http://127.0.0.1:1/mcp\n",
		"    command: server\n    env:\n      - ORDERS_REGION\n      - ORDERS_ZONE\n", 1)
	if err := os.WriteFile(tr.config, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ORDERS_REGION", unrelatedSentinel)
	t.Setenv("ORDERS_ZONE", "")
	if err := os.Unsetenv("ORDERS_ZONE"); err != nil {
		t.Fatal(err)
	}
	out := doctorOutput(t, tr.config)
	for _, want := range []string{"upstreams.0.env.0            ORDERS_REGION\n", "upstreams.0.env.1            ORDERS_ZONE (not set here)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor's output does not hold %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, unrelatedSentinel) {
		t.Errorf("doctor printed a value of a listed variable:\n%s", out)
	}
}
