package main

import (
	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/adapters/otel"
	"github.com/guardana/control/internal/gateway"
)

// haltOf names the plane's halts in stats.
func haltOf(stats gateway.Stats) haltAnswer {
	return haltAnswer{
		ExecutedArgsMismatch: stats.MismatchHalted,
		EvidenceUnwritable:   stats.SinkHalted,
	}
}

// pipelineCounters is the pipeline's counters and the MCP adapter's beside
// them.
func pipelineCounters(s gateway.Stats, adapter adaptermcp.Stats) map[string]any {
	out := pipelineOnly(s)
	out["admitted"], out["blocked"], out["sent"] = adapter.Admitted, adapter.Blocked, adapter.Sent
	out["close_failures"], out["refresh_failures"] = adapter.CloseFailures, adapter.RefreshFailures
	return out
}

// pipelineOnly is what the pipeline counted, whatever adapter it serves:
// executions abandoned and runs halted on a reported mismatch among them.
func pipelineOnly(s gateway.Stats) map[string]any {
	return map[string]any{
		"blocks": s.Blocks, "pending": s.Pending, "executed": s.Executed,
		"sink_failures_before_effect": s.SinkFailuresBeforeEffect,
		"sink_failures_after_effect":  s.SinkFailuresAfterEffect,
		"sink_failures_abandoned":     s.SinkFailuresAbandoned,
		"reads_unrecorded":            s.ReadsUnrecorded, "mismatches": s.Mismatches,
		"multi_use_refused": s.MultiUseRefused, "stale_handed_out": s.StaleHandedOut, "open": s.Open, "held": s.Held,
		"abandoned": s.Abandoned, "runs_halted": s.RunsHalted,
		"runs": s.Runs, "flow_uncomputed": s.FlowUncomputed,
		"asks": askCounters(s.Asks),
	}
}

// runCounters says where the plane's runs come from. Local runs live in
// memory, so a new process starts clean; opened runs are counted where the
// listener refused a token, by cause, and where a root's state failed.
func runCounters(opened bool, s gateway.Stats, adapter adaptermcp.Stats) map[string]any {
	if !opened {
		return map[string]any{"kind": "local", "kept": s.Runs}
	}
	return map[string]any{
		"kind":               "opened",
		"refused_at_request": adapter.RunsRefusedAtRequest,
		"refused_at_message": adapter.RunsRefusedAtMessage,
		"state_failures":     s.RunStateFailures,
	}
}

// askCounters is what the plane asked the external decision point, by what
// each ask came back as, and the time spent waiting on it.
func askCounters(a gateway.Asks) map[string]any {
	return map[string]any{
		"made": a.Made, "allowed": a.Allowed, "denied": a.Denied,
		"denied_obligations": a.DeniedObligations, "timed_out": a.TimedOut,
		"unavailable": a.Unavailable, "answer_refused": a.AnswerRefused, "wait_us": a.Micros,
	}
}

// approvalCounters is what an operator needs about the holds: the store a held
// request is kept in, whether a hold lost to a restart is closed at all, and
// whether the last reconciliation read every entry. An incomplete pass is
// reported and never stops the plane from serving (ADR-0016).
func approvalCounters(provider string, s gateway.Stats) map[string]any {
	out := map[string]any{
		"provider": provider, "hold_journal": s.HoldJournal,
		"reconcile_incomplete": s.ReconcileIncomplete,
		"holds_closed":         s.HoldsClosed, "holds_unmeasured": s.HoldsUnmeasured,
		"unheld_records": s.UnheldRecords, "journal_refusals": s.JournalRefusals,
		"held_trails_left_open": s.HeldTrailsLeftOpen,
	}
	if !s.HoldJournal {
		out["limits"] = []string{"a hold this plane loses to a restart is never closed: no hold journal is configured"}
	}
	return out
}

func exporterCounters(s otel.Stats) map[string]any {
	return map[string]any{
		"acknowledged": s.Acknowledged, "quarantined": s.Quarantined,
		"partial_rejected": s.PartialRejected, "refused": s.Refused, "retries": s.Retries,
		"retried_transport": s.RetriedTransport, "retried_redirect": s.RetriedRedirect,
		"retried_auth": s.RetriedAuth, "retried_throttled": s.RetriedThrottled,
		"retried_server": s.RetriedServer, "retried_answer": s.RetriedAnswer,
		"retried_status": s.RetriedStatus,
	}
}
