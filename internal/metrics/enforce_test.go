package metrics

import (
	"maps"
	"slices"
	"testing"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/metrics/metricstest"
)

// planeReading has counts for both adapters, so a plane that writes the
// wrong one's shows them.
func planeReading(enforceAPI bool) Reading {
	return Reading{EnforceAPI: enforceAPI, Adapter: statsSent(7), Enforce: EnforceCounts{
		Open: 3, RecordsFailed: 2,
		Refused:     map[string]uint64{"malformed": 4, "made up": 1},
		RunsRefused: map[gateway.RunCause]uint64{gateway.RunExpired: 5},
	}}
}

var enforceOnly = []string{"enforce_open_handles", "enforce_records_failed_total", "enforce_refused_total", "enforce_runs_refused_total"}

// TestAnMCPPlaneWritesOnlyTheMCPAdaptersMetrics: whatever the enforcement API
// adapter's statistics hold, a plane not serving it writes none of them.
func TestAnMCPPlaneWritesOnlyTheMCPAdaptersMetrics(t *testing.T) {
	mcp := parse(t, planeReading(false))
	if s, _ := family(t, mcp, Prefix()+"adapter_sent_total").One(map[string]string{}); s.Raw != "7" {
		t.Errorf("an MCP plane's adapter_sent_total is %s, want 7", s.Raw)
	}
	if s, _ := family(t, mcp, Prefix()+"listener_enforce_api").One(map[string]string{}); s.Raw != "0" {
		t.Errorf("an MCP plane's listener_enforce_api is %s, want 0", s.Raw)
	}
	for _, name := range enforceOnly {
		if _, ok := metricstest.Find(mcp, Prefix()+name); ok {
			t.Errorf("an MCP plane writes %s", name)
		}
	}
}

// TestAnEnforcementAPIPlaneWritesOnlyItsAdaptersMetrics: a plane serving the
// enforcement API writes that adapter's counts and none of the MCP
// adapter's, whatever those hold.
func TestAnEnforcementAPIPlaneWritesOnlyItsAdaptersMetrics(t *testing.T) {
	api := parse(t, planeReading(true))
	for _, name := range []string{"adapter_sent_total", "adapter_sessions_live", "adapter_runs_refused_at_request_total"} {
		if _, ok := metricstest.Find(api, Prefix()+name); ok {
			t.Errorf("an enforcement API plane writes the MCP adapter's %s", name)
		}
	}
	for _, c := range []struct {
		name, label string
		want        map[string]string
	}{
		{"listener_enforce_api", "", map[string]string{"": "1"}},
		{"enforce_open_handles", "", map[string]string{"": "3"}},
		{"enforce_records_failed_total", "", map[string]string{"": "2"}},
		{"enforce_refused_total", "code", map[string]string{"malformed": "4", Other: "1"}},
		{"enforce_runs_refused_total", "cause", map[string]string{"expired": "5"}},
	} {
		f := family(t, api, Prefix()+c.name)
		if len(f.Samples) != len(c.want) {
			t.Errorf("%s: %+v, want %v", c.name, f.Samples, c.want)
		}
		for value, raw := range c.want {
			labels := map[string]string{}
			if c.label != "" {
				labels[c.label] = value
			}
			if s, ok := f.One(labels); !ok || s.Raw != raw {
				t.Errorf("%s%v is %+v, want %s", c.name, labels, s, raw)
			}
		}
	}
}

// TestEnforceOfNamesCodesAsHealthDoes: every code by its contract name, lower
// case and without its prefix, and a code counted zero times is no sample.
func TestEnforceOfNamesCodesAsHealthDoes(t *testing.T) {
	got := EnforceOf(enforce.Stats{
		Open: 2, Executed: 9, RecordsFailed: 1,
		Refused: map[enforcev1alpha1.ErrorCode]uint64{
			enforcev1alpha1.ErrorCode_ERROR_CODE_UNSPECIFIED:         0,
			enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED:     6,
			enforcev1alpha1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION: 1,
			enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_SPENT:        0,
		},
		RunsRefused: map[gateway.RunCause]uint64{gateway.RunUnknown: 6},
	})
	if want := map[string]uint64{"unauthenticated": 6, "unsupported_version": 1}; !maps.Equal(got.Refused, want) {
		t.Errorf("Refused = %v, want %v", got.Refused, want)
	}
	if got.Open != 2 || got.Executed != 9 || got.RecordsFailed != 1 || got.RunsRefused[gateway.RunUnknown] != 6 {
		t.Errorf("EnforceOf = %+v", got)
	}
	want := []string{"duplicate_request", "handle_spent", "handle_unknown", "malformed", "unauthenticated", "unavailable", "unsupported_version"}
	f := family(t, parse(t, Reading{EnforceAPI: true, Enforce: EnforceCounts{Refused: map[string]uint64{
		"duplicate_request": 1, "handle_spent": 1, "handle_unknown": 1, "malformed": 1,
		"unauthenticated": 1, "unavailable": 1, "unsupported_version": 1, "unspecified": 1,
	}}}), Prefix()+"enforce_refused_total")
	var labels []string
	for _, s := range f.Samples {
		labels = append(labels, s.Labels["code"])
	}
	if !slices.Equal(labels, append(want, Other)) {
		t.Errorf("the codes read %q, want every declared code and %s for the unspecified one", labels, Other)
	}
}
