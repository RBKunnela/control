package gatewayconfig

import (
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

// withEnv is the document with its one upstream run as a command that
// receives the variables items lists, each item a line of the sequence.
func withEnv(items ...string) string {
	block := "    command: /bin/echo\n    env:\n"
	for _, item := range items {
		block += "      - " + item + "\n"
	}
	return strings.Replace(document, "    endpoint: http://127.0.0.1:1/mcp\n", block, 1)
}

// TestAnUpstreamsEnvListIsRead: the names come from the file in order, and a
// variable replaces one the file declared.
func TestAnUpstreamsEnvListIsRead(t *testing.T) {
	path := writeDocument(t, withEnv("ORDERS_REGION", "_a1", "LANG"))
	setEnv(t, "upstreams.0.env.2", "LC_ALL")
	cfg := load(t, path)
	if want := []string{"ORDERS_REGION", "_a1", "LC_ALL"}; !slices.Equal(cfg.Upstreams[0].Env, want) {
		t.Errorf("the upstream's env is %q, want %q", cfg.Upstreams[0].Env, want)
	}
	if got := cfg.Sources()["upstreams.0.env.2"]; got != brand.Env("UPSTREAMS_0_ENV_2") {
		t.Errorf("upstreams.0.env.2 was set by %q, want the variable", got)
	}
}

// TestAnEnvNameThePlaneOwnsOrNoProcessTakesIsRefused: a name under the
// plane's prefix, in any case, would hand the plane's configuration and its
// credentials to the upstream; a name no environment can hold would pass
// nothing. Each refusal names the item's key, from the file and from a
// variable that replaces the file's item, and never repeats an item that is
// not a name, since a pasted NAME=value carries its value. The accepted cases
// sit at the edge of each rule.
func TestAnEnvNameThePlaneOwnsOrNoProcessTakesIsRefused(t *testing.T) {
	const secret = "sentinel-listed-value"
	for _, c := range []struct {
		name     string
		items    []string
		override string
		wants    string
		withheld string
	}{
		{name: "a header's variable", items: []string{brand.Env("EXPORT_HEADERS_AUTHORIZATION")},
			wants: "upstreams.0.env.0: " + brand.Env("EXPORT_HEADERS_AUTHORIZATION") + " is under " + brand.EnvPrefix},
		{name: "a header's variable from the environment", items: []string{"ORDERS_REGION"}, override: brand.Env("PDP_HEADERS_AUTHORIZATION"),
			wants: "upstreams.0.env.0: " + brand.Env("PDP_HEADERS_AUTHORIZATION") + " is under " + brand.EnvPrefix},
		{name: "the prefix alone", items: []string{"ORDERS_REGION", brand.EnvPrefix},
			wants: "upstreams.0.env.1: " + brand.EnvPrefix + " is under " + brand.EnvPrefix},
		{name: "the prefix in lower case", items: []string{strings.ToLower(brand.Env("MODE"))},
			wants: "upstreams.0.env.0: " + strings.ToLower(brand.Env("MODE")) + " is under " + brand.EnvPrefix},
		{name: "a name and its value", items: []string{"API_KEY=" + secret},
			wants: `upstreams.0.env.0: the item holds "=" after API_KEY; list the name only`, withheld: secret},
		{name: "a name and its value from the environment", items: []string{"ORDERS_REGION"}, override: "API_KEY=" + secret,
			wants: `upstreams.0.env.0: the item holds "=" after API_KEY; list the name only`, withheld: secret},
		{name: "a value alone before the equals sign", items: []string{secret + "=x"},
			wants: `upstreams.0.env.0: the item holds "="; list the name only`, withheld: secret},
		{name: "a plane's name and its value", items: []string{brand.Env("PDP_HEADERS_AUTHORIZATION") + "=" + secret},
			wants: `upstreams.0.env.0: the item holds "="`, withheld: secret},
		{name: "a leading digit", items: []string{"1REGION"}, wants: "upstreams.0.env.0: not a variable name", withheld: "1REGION"},
		{name: "a hyphen", items: []string{"ORDERS-REGION"}, wants: "upstreams.0.env.0: not a variable name", withheld: "ORDERS-REGION"},
		{name: "a value pasted alone", items: []string{"ORDERS_REGION"}, override: secret,
			wants: "upstreams.0.env.0: not a variable name", withheld: secret},
		{name: "a space", items: []string{`"A B"`}, wants: "upstreams.0.env.0: not a variable name", withheld: "A B"},
		{name: "an empty name", items: []string{`""`}, wants: "upstreams.0.env.0: not a variable name"},
		{name: "a letter outside ASCII", items: []string{"RÉGION"}, wants: "upstreams.0.env.0: not a variable name", withheld: "RÉGION"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeDocument(t, withEnv(c.items...))
			if c.override != "" {
				setEnv(t, "upstreams.0.env.0", c.override)
			}
			err := loadRecovering(t, path)
			if err == nil || !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("the refusal is %v, want one saying %q", err, c.wants)
			}
			if c.withheld != "" && strings.Contains(err.Error(), c.withheld) {
				t.Errorf("the refusal repeats %q: %v", c.withheld, err)
			}
		})
	}
	edge := load(t, writeDocument(t, withEnv(strings.TrimSuffix(brand.EnvPrefix, "_"), "_", "a", "Z9")))
	if want := []string{strings.TrimSuffix(brand.EnvPrefix, "_"), "_", "a", "Z9"}; !slices.Equal(edge.Upstreams[0].Env, want) {
		t.Errorf("the names at the edge of each rule loaded as %q, want %q", edge.Upstreams[0].Env, want)
	}
}

// TestAnEnvWrittenAsOneValueSaysItTakesAList: env: dev is most likely the
// deployment label under the wrong key, and the refusal says where it goes.
func TestAnEnvWrittenAsOneValueSaysItTakesAList(t *testing.T) {
	doc := strings.Replace(withEnv(), "    env:\n", "    env: dev\n", 1)
	err := loadRecovering(t, writeDocument(t, doc))
	for _, want := range []string{"upstreams.0.env takes a list of variable names", "the key environment"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal is %v, want one saying %q", err, want)
		}
	}
}

// TestAnHTTPUpstreamTakesNoEnvList: an HTTP upstream starts no process, so a
// list for it would pass nothing to anyone.
func TestAnHTTPUpstreamTakesNoEnvList(t *testing.T) {
	doc := strings.Replace(document, "    endpoint: http://127.0.0.1:1/mcp\n",
		"    endpoint: http://127.0.0.1:1/mcp\n    env:\n      - ORDERS_REGION\n", 1)
	err := loadRecovering(t, writeDocument(t, doc))
	if err == nil || !strings.Contains(err.Error(), "upstreams.0.env: ") {
		t.Fatalf("the refusal is %v, want one naming upstreams.0.env", err)
	}
}

// TestAnEnvIndexIsSpelledOnce: the env list's indexes follow the rule the
// arguments' do, from the file and from the environment.
func TestAnEnvIndexIsSpelledOnce(t *testing.T) {
	for _, c := range []struct {
		name  string
		doc   string
		env   string
		wants string
	}{
		{name: "upstreams.0.env past the items", doc: strings.Replace(withEnv(), "    env:\n", "    env:\n      1: A\n", 1), wants: "env takes a sequence"},
		{name: "upstreams.0.env.00", doc: strings.Replace(withEnv(), "    env:\n", "    env:\n      0: A\n      00: B\n", 1), wants: "env takes a sequence"},
		{name: "UPSTREAMS_0_ENV_1", doc: withEnv("A"), env: "UPSTREAMS_0_ENV_1", wants: "names no upstreams entry"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeDocument(t, c.doc)
			if c.env != "" {
				t.Setenv(brand.Env(c.env), "B")
			}
			err := loadRecovering(t, path)
			if err == nil || !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("the refusal is %v, want one saying %q", err, c.wants)
			}
		})
	}
}

// TestEveryKeyTheEnvironmentSetsIsListed: whatever key the environment sets
// is listed, sorted, a header by its key and never its value, even one set to
// the value the file gives it; a key the file alone sets is not.
func TestEveryKeyTheEnvironmentSetsIsListed(t *testing.T) {
	path := write(t, overrideOf("orders")+"\n"+identifierBlock)
	if got := EnvironmentOverrides(load(t, path)); len(got) != 0 {
		t.Errorf("EnvironmentOverrides with nothing set from the environment = %q, want none", got)
	}
	setEnv(t, "mode", "OBSERVE")
	setEnv(t, "overrides.0.effect", "READ")
	setEnv(t, "listener.address", "127.0.0.1:9090")
	t.Setenv(brand.Env("PDP_HEADERS_X_TENANT_KEY"), "tenant-secret")
	got := EnvironmentOverrides(load(t, path))
	want := []string{"listener.address", "mode", "overrides.0.effect", "pdp.headers.X-Tenant-Key"}
	if !slices.Equal(got, want) {
		t.Errorf("EnvironmentOverrides = %q, want %q", got, want)
	}
	if strings.Contains(strings.Join(got, " "), "tenant-secret") {
		t.Errorf("EnvironmentOverrides = %q quotes a header's value", got)
	}
}

// TestOnlyAVariableIsAnOverride: a key is listed when a variable's name set
// it, never when a file position did, even a file whose name looks like a
// variable's.
func TestOnlyAVariableIsAnOverride(t *testing.T) {
	c := &Config{source: map[string]string{
		"trust.root":      brand.Env("TRUST_ROOT"),
		"policy.key_id":   "gateway.yaml:7",
		"pause.file":      brand.Env("PAUSE_FILE") + ":3",
		"export.endpoint": "export.yaml:2",
	}}
	if got, want := EnvironmentOverrides(c), []string{"trust.root"}; !slices.Equal(got, want) {
		t.Errorf("EnvironmentOverrides = %q, want %q", got, want)
	}
}
