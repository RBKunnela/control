package gatewayconfig

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestTheCallTimeoutHasToBePositive: the smallest positive bound is taken; at
// zero a call would have no bound of the adapter's own, and below zero it
// would also lose an obligation's, so both are refused naming the key.
func TestTheCallTimeoutHasToBePositive(t *testing.T) {
	for _, c := range []struct {
		value string
		want  time.Duration
		ok    bool
	}{{"1ns", time.Nanosecond, true}, {"0s", 0, false}, {"-1ns", 0, false}, {"-30s", 0, false}} {
		path := write(t, "")
		setEnv(t, "upstream.call_timeout", c.value)
		cfg, err := Load(path, os.Environ())
		switch {
		case c.ok && err != nil:
			t.Errorf("upstream.call_timeout=%s was refused: %v", c.value, err)
		case c.ok && cfg.Upstream.CallTimeout != c.want:
			t.Errorf("upstream.call_timeout=%s read as %v, want %v", c.value, cfg.Upstream.CallTimeout, c.want)
		case !c.ok && err == nil:
			t.Errorf("upstream.call_timeout=%s was accepted", c.value)
		case !c.ok && !strings.Contains(err.Error(), "upstream.call_timeout"):
			t.Errorf("the refusal does not name the key: %v", err)
		}
	}
}

// TestTheOtherTimeoutsRefuseWhatTheirClientsRefuse: a negative bound is
// refused naming its key, for every timeout, where it is read. Zero keeps its
// meaning: the adapter's own bound for upstream.list_timeout, and for
// pdp.timeout and export.timeout a refusal, since neither client takes a bound
// that is not positive.
func TestTheOtherTimeoutsRefuseWhatTheirClientsRefuse(t *testing.T) {
	for _, c := range []struct {
		key, file, value string
		ok               bool
	}{
		{"upstream.list_timeout", "", "1ns", true},
		{"upstream.list_timeout", "", "0s", true},
		{"upstream.list_timeout", "", "-1ns", false},
		{"pdp.timeout", pdpBlock, "1ns", true},
		{"pdp.timeout", pdpBlock, "0s", false},
		{"pdp.timeout", pdpBlock, "-1ns", false},
		{"export.timeout", "", "1ns", true},
		{"export.timeout", "", "0s", false},
		{"export.timeout", "", "-1ns", false},
	} {
		t.Run(c.key+"="+c.value, func(t *testing.T) {
			path := write(t, c.file)
			setEnv(t, c.key, c.value)
			_, err := Load(path, os.Environ())
			switch {
			case c.ok && err != nil:
				t.Errorf("refused: %v", err)
			case !c.ok && err == nil:
				t.Error("accepted")
			case !c.ok && !strings.Contains(err.Error(), c.key+": "):
				t.Errorf("the refusal does not name the key: %v", err)
			}
		})
	}
}

// TestNoDurationTakesANegativeValue: every duration key refuses a negative
// value where it is parsed, naming the key, whatever block it belongs to. The
// list is the field table's own duration keys, held to a literal so a new key
// cannot join the table untested.
func TestNoDurationTakesANegativeValue(t *testing.T) {
	keys := []string{
		"listener.session_idle", "listener.execution_lifetime", "policy.max_stale", "policy.poll_interval", "pdp.timeout",
		"approvals.ttl", "approvals.retry_after", "pause.poll_interval", "reaction.poll_interval", "evidence.fsync_interval",
		"export.timeout", "export.linger", "export.backoff", "export.max_backoff",
		"list.ttl", "upstream.call_timeout", "upstream.list_timeout",
	}
	var table []string
	for _, f := range Fields() {
		if f.Kind == "duration" {
			table = append(table, f.Path)
		}
	}
	if !slices.Equal(slices.Sorted(slices.Values(table)), slices.Sorted(slices.Values(keys))) {
		t.Fatalf("the table's duration keys are %v, the test's %v", table, keys)
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			path := write(t, "")
			setEnv(t, key, "-1ns")
			_, err := Load(path, os.Environ())
			if err == nil || !strings.Contains(err.Error(), key+": a duration cannot be negative") {
				t.Errorf("%s=-1ns: %v", key, err)
			}
		})
	}
}

// TestASecondOverrideOfOneToolIsRefused: the adapter keeps the last entry of
// an upstream's tool, so a READ after a DELETE would classify a delete as a
// read. The same tool on another upstream, and another tool on the same one,
// are the controls.
func TestASecondOverrideOfOneToolIsRefused(t *testing.T) {
	entry := func(upstream, tool, effect string) string {
		return "  - upstream: " + upstream + "\n    tool: " + tool + "\n    fingerprint: abc\n" +
			"    effect: " + effect + "\n    resource_type: order\n    resource_from: /id\n"
	}
	billing := "  - name: billing\n    endpoint: http://127.0.0.1:2/mcp\n"
	for _, c := range []struct {
		name, overrides string
		wants           string
	}{
		{"one tool twice", entry("orders", "drop_order", "DELETE") + entry("orders", "drop_order", "READ"), `overrides.1: the tool "drop_order" of "orders" is classified by overrides.0 already`},
		{"one tool twice, apart", entry("orders", "drop_order", "DELETE") + entry("orders", "read_order", "READ") + entry("billing", "drop_order", "READ") + entry("orders", "drop_order", "DELETE"), `overrides.3: the tool "drop_order" of "orders" is classified by overrides.0 already`},
		{"one tool on two upstreams", entry("orders", "drop_order", "DELETE") + entry("billing", "drop_order", "READ"), ""},
		{"two tools on one upstream", entry("orders", "drop_order", "DELETE") + entry("orders", "read_order", "READ"), ""},
		{"a tool named as another's case", entry("orders", "drop_order", "DELETE") + entry("orders", "Drop_order", "READ"), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeDocument(t, document+billing+"\noverrides:\n"+c.overrides)
			_, err := Load(path, os.Environ())
			switch {
			case c.wants == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.wants != "" && err == nil:
				t.Error("accepted")
			case c.wants != "" && !strings.Contains(err.Error(), c.wants):
				t.Errorf("the refusal is %q, which does not say %q", err, c.wants)
			}
		})
	}
}
