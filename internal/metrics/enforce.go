package metrics

import (
	"maps"
	"slices"
	"strings"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/gateway"
)

// EnforceCounts is what the enforcement API adapter counted that /metrics
// answers. Refused is keyed by the contract's error code in lower case with
// its ERROR_CODE_ prefix taken off, as /healthz names it.
type EnforceCounts struct {
	Open                          int
	Executed, Blocked, Pending    uint64
	Completed, Aborted, Abandoned uint64
	RecordsFailed                 uint64
	Refused                       map[string]uint64
	RunsRefused                   map[gateway.RunCause]uint64
}

// EnforceOf is the part of s /metrics answers; a code counted zero times is
// left out.
func EnforceOf(s enforce.Stats) EnforceCounts {
	out := EnforceCounts{
		Open: s.Open, Executed: s.Executed, Blocked: s.Blocked, Pending: s.Pending,
		Completed: s.Completed, Aborted: s.Aborted, Abandoned: s.Abandoned, RecordsFailed: s.RecordsFailed,
		RunsRefused: maps.Clone(s.RunsRefused),
	}
	for code, n := range s.Refused {
		if n == 0 {
			continue
		}
		if out.Refused == nil {
			out.Refused = map[string]uint64{}
		}
		out.Refused[codeLabel(code)] += n
	}
	return out
}

func codeLabel(code enforcev1alpha1.ErrorCode) string {
	return strings.ToLower(strings.TrimPrefix(code.String(), "ERROR_CODE_"))
}

// enforceCodes is every error code the contract declares but the unspecified
// one, as a label spells it.
func enforceCodes() []string {
	out := make([]string, 0, len(enforcev1alpha1.ErrorCode_name))
	for n := range enforcev1alpha1.ErrorCode_name {
		if code := enforcev1alpha1.ErrorCode(n); code != enforcev1alpha1.ErrorCode_ERROR_CODE_UNSPECIFIED {
			out = append(out, codeLabel(code))
		}
	}
	slices.Sort(out)
	return out
}

// enforceRows are the enforcement API adapter's, written only where the plane
// serves the enforcement API.
var enforceRows = []Metric{
	flag("listener_enforce_api", "EnforceAPI",
		"1 when the plane serves the enforcement API: the metrics of its adapter are written and those of the MCP adapter left out.",
		func(r Reading) bool { return r.EnforceAPI }),
	level("enforce_open_handles", "Enforce.Open",
		"Executions the enforcement API handed out whose handle is still open.",
		func(r Reading) int64 { return int64(r.Enforce.Open) }),
	count("enforce_executed_total", "Enforce.Executed",
		"Admits answered EXECUTE.",
		func(r Reading) uint64 { return r.Enforce.Executed }),
	count("enforce_blocked_total", "Enforce.Blocked",
		"Admits answered BLOCK, including executions not handed out because their resource moved.",
		func(r Reading) uint64 { return r.Enforce.Blocked }),
	count("enforce_pending_total", "Enforce.Pending",
		"Admits answered PENDING.",
		func(r Reading) uint64 { return r.Enforce.Pending }),
	count("enforce_completed_total", "Enforce.Completed",
		"Executions a client completed.",
		func(r Reading) uint64 { return r.Enforce.Completed }),
	count("enforce_aborted_total", "Enforce.Aborted",
		"Executions a client aborted, and those the adapter aborted because their resource moved.",
		func(r Reading) uint64 { return r.Enforce.Aborted }),
	count("enforce_abandoned_total", "Enforce.Abandoned",
		"Executions the adapter abandoned: expired, open at shutdown, or handed to nobody.",
		func(r Reading) uint64 { return r.Enforce.Abandoned }),
	count("enforce_records_failed_total", "Enforce.RecordsFailed",
		"Abandons and aborts whose closing record could not be written; each leaves its trail open.",
		func(r Reading) uint64 { return r.Enforce.RecordsFailed }),
	labelled(Counter, "enforce_refused_total", "code", "Enforce.Refused",
		"Requests the enforcement API refused, by its error code, refused run tokens included; "+
			"a code the contract does not declare is counted under "+Other+".",
		func(r Reading) ([]sample, error) { return enforceCodeSamples(r.Enforce.Refused) }),
	labelled(Counter, "enforce_runs_refused_total", "cause", "Enforce.RunsRefused",
		"Requests refused because their run token did not resolve, by cause.",
		func(r Reading) ([]sample, error) { return runSamples(r.Enforce.RunsRefused) }),
}

func enforceCodeSamples(refused map[string]uint64) ([]sample, error) {
	codes := enforceCodes()
	return closedSamples(refused, func(c string) bool { return slices.Contains(codes, c) })
}
