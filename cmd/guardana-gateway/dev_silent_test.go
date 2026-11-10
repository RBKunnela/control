package main

import (
	"bufio"
	"bytes"
	gobuild "go/build"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
)

// TestDevDecisionPointTakesSilentAlone: --decision-point names one value;
// any other, an empty one and a missing one are usage errors, while silent
// passes the flags and meets the next refusal, the approver this test binary
// lacks.
func TestDevDecisionPointTakesSilentAlone(t *testing.T) {
	t.Parallel()
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "")
	base := []string{"--config", d.config, "--policy", d.policy}
	for _, flag := range [][]string{{"--decision-point=loud"}, {"--decision-point="}, {"--decision-point=Silent"}, {"--decision-point"}} {
		status, stdout, _ := runDev(t, append(slices.Clone(base), flag...)...)
		if status != exitUsage || stdout != "" {
			t.Errorf("%q: exit %d, stdout %q; want 2 and nothing printed", flag, status, stdout)
		}
	}
	status, _, stderr := runDev(t, append(slices.Clone(base), "--decision-point=silent")...)
	if status != exitFail || !strings.Contains(stderr, "go install ./cmd/...") {
		t.Fatalf("silent: exit %d, stderr %q; want 1 refusing the missing approver", status, stderr)
	}
}

// pdpKeys is every key under pdp, spelled here and not taken from the code
// that owns them, each as a demo would set it on the loopback.
var pdpKeys = []struct{ key, yaml string }{
	{"pdp.identifier", "pdp:\n  identifier: http://127.0.0.1:8443\n"},
	{"pdp.evaluation_endpoint", "pdp:\n  evaluation_endpoint: http://127.0.0.1:8443/access/v1/evaluation\n"},
	{"pdp.timeout", "pdp:\n  timeout: 250ms\n"},
	{"pdp.max_in_flight", "pdp:\n  max_in_flight: 4\n"},
	{"pdp.allow_plaintext", "pdp:\n  allow_plaintext: true\n"},
	{"pdp.proxy", "pdp:\n  proxy: http://127.0.0.1:3128\n"},
	{"pdp.headers", "pdp:\n  headers:\n    x-tenant: acme\n"},
	{"pdp.informational_context", "pdp:\n  informational_context:\n    - tier\n"},
}

// TestTheKeysSpelledCoverEveryPDPKey: a key the loader adds under pdp
// without a line in pdpKeys would go untested for dev's ownership.
func TestTheKeysSpelledCoverEveryPDPKey(t *testing.T) {
	t.Parallel()
	var loader []string
	for _, f := range gatewayconfig.Fields() {
		if strings.HasPrefix(f.Path, "pdp.") {
			loader = append(loader, f.Path)
		}
	}
	for _, c := range gatewayconfig.Collections() {
		if strings.HasPrefix(c.Path, "pdp.") {
			key, _, _ := strings.Cut(c.Path, "."+gatewayconfig.NamePlaceholder)
			key, _, _ = strings.Cut(key, "."+gatewayconfig.IndexPlaceholder)
			loader = append(loader, key)
		}
	}
	for _, key := range loader {
		if !slices.ContainsFunc(pdpKeys, func(k struct{ key, yaml string }) bool { return k.key == key }) {
			t.Errorf("the loader has %s, and pdpKeys lacks it", key)
		}
	}
	if len(loader) != len(pdpKeys) {
		t.Errorf("the loader has %d pdp keys %q, and pdpKeys spells %d", len(loader), loader, len(pdpKeys))
	}
}

// TestASilentDecisionPointOwnsEveryPDPKey: with --decision-point=silent a
// demo that sets any key under pdp is refused by that key, whether the layer
// sets it or leaves it at its default; without the flag the same keys are
// the demo's to set.
func TestASilentDecisionPointOwnsEveryPDPKey(t *testing.T) {
	t.Parallel()
	atDefaults := []struct{ key, yaml string }{
		{"pdp.allow_plaintext", "pdp:\n  allow_plaintext: false\n"},
		{"pdp.identifier", "pdp:\n  identifier: \"\"\n"},
		{"pdp.timeout", "pdp:\n  timeout: 100ms\n"},
	}
	for _, k := range append(slices.Clone(pdpKeys), atDefaults...) {
		t.Run(k.yaml, func(t *testing.T) {
			t.Parallel()
			d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", k.yaml)
			err := checkDemo(devInputs{config: d.config, silent: true}, filepath.Join(t.TempDir(), "state"))
			if err == nil || !strings.HasPrefix(err.Error(), k.key) || !strings.Contains(err.Error(), d.config+" sets it, and dev owns it") {
				t.Fatalf("checkDemo = %v, want the refusal naming %s", err, k.key)
			}
		})
	}
	var all strings.Builder
	all.WriteString("pdp:\n")
	for _, k := range pdpKeys {
		all.WriteString(strings.TrimPrefix(k.yaml, "pdp:\n"))
	}
	d := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", all.String())
	if err := checkDemo(devInputs{config: d.config}, filepath.Join(t.TempDir(), "state")); err != nil {
		t.Fatalf("without the flag, a demo setting every pdp key: %v", err)
	}
}

// resolveWith resolves the demo at config under a layer whose silent
// decision point is at silent, or absent when silent is empty.
func resolveWith(t *testing.T, config, silent string) *gatewayconfig.Config {
	t.Helper()
	keys := devKeys{bundle: publicHalf(seededKey(31)), freshness: publicHalf(seededKey(32))}
	st := devState{dir: filepath.Join(t.TempDir(), "state")}
	cfg, err := resolveDemo(config, newLayer(st, keys, "127.0.0.1:1", "127.0.0.1:2", "/run/dev/c.sock", newToken(), silent))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestASilentLayerNamesItsListenerAndLeavesTheRestAtDefaults: the layer
// makes the silent address the decision point over plaintext and sets no
// other pdp key.
func TestASilentLayerNamesItsListenerAndLeavesTheRestAtDefaults(t *testing.T) {
	t.Parallel()
	pdp := resolveWith(t, writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "").config, "127.0.0.1:4").PDP
	if pdp.Identifier != "http://127.0.0.1:4" || !pdp.AllowPlaintext || pdp.EvaluationEndpoint != "" ||
		pdp.Timeout != 100*time.Millisecond || pdp.MaxInFlight != 16 || pdp.Proxy != "" || len(pdp.Headers) != 0 {
		t.Errorf("the silent layer resolved pdp to %+v", pdp)
	}
}

// TestWithoutASilentLayerTheDemosDecisionPointStands: with no silent address
// the layer sets no pdp key and the demo's own stand.
func TestWithoutASilentLayerTheDemosDecisionPointStands(t *testing.T) {
	t.Parallel()
	own := writeDemo(t, "http://127.0.0.1:9/mcp", "5ms", "pdp:\n  identifier: http://127.0.0.1:8443\n  timeout: 250ms\n")
	pdp := resolveWith(t, own.config, "").PDP
	if pdp.Identifier != "http://127.0.0.1:8443" || pdp.AllowPlaintext || pdp.Timeout != 250*time.Millisecond {
		t.Errorf("without the flag, the demo's decision point resolved to %+v", pdp)
	}
}

// TestDevRunsWhereDevUnixBuilds: for every system the toolchain names,
// supported agrees with the build constraint of dev_unix.go, the file that
// starts the page in a process group of its own.
func TestDevRunsWhereDevUnixBuilds(t *testing.T) {
	t.Parallel()
	out, err := exec.Command("go", "tool", "dist", "list").Output()
	if err != nil {
		t.Fatalf("go tool dist list: %v", err)
	}
	seen := map[string]bool{}
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		goos, goarch, ok := strings.Cut(s.Text(), "/")
		if !ok {
			t.Fatalf("go tool dist list printed %q", s.Text())
		}
		ctx := gobuild.Default
		ctx.GOOS, ctx.GOARCH = goos, goarch
		matches, err := ctx.MatchFile(".", "dev_unix.go")
		if err != nil {
			t.Fatal(err)
		}
		if _, again := seen[goos]; !again && supported(goos) != matches {
			t.Errorf("supported(%q) = %v, and dev_unix.go builds there: %v", goos, !matches, matches)
		}
		seen[goos] = matches
	}
	if !seen["linux"] || !seen["darwin"] || seen["windows"] || len(seen) < 10 {
		t.Fatalf("the systems read are %v; want linux and darwin with dev_unix.go and windows without", seen)
	}
}

// TestDevRefusesAPlatformWithoutProcessGroups: the refusal names the
// platform and where dev runs.
func TestDevRefusesAPlatformWithoutProcessGroups(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"windows", "plan9", "js"} {
		err := refusePlatform(goos)
		if err == nil || !strings.Contains(err.Error(), goos) || !strings.Contains(err.Error(), "Linux and macOS") {
			t.Errorf("refusePlatform(%q) = %v", goos, err)
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		if err := refusePlatform(goos); err != nil {
			t.Errorf("refusePlatform(%q) = %v", goos, err)
		}
	}
}

// refusal names both archives before go install.
func TestTheSiblingRefusalNamesTheArchives(t *testing.T) {
	t.Parallel()
	for _, want := range []string{"demo archive", "release archive", "go install ./cmd/..."} {
		if !strings.Contains(installBoth, want) {
			t.Errorf("installBoth %q lacks %q", installBoth, want)
		}
	}
	if strings.Index(installBoth, "archive") > strings.Index(installBoth, "go install") {
		t.Errorf("installBoth %q names go install before the archives", installBoth)
	}
}
