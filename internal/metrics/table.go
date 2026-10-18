package metrics

import (
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"slices"
	"strconv"
	"strings"

	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy/reasons"
)

// table is the one list of metrics: Render writes it, the reference page
// lists it, and the tests walk the statistics against it.
var table = slices.Concat(seamRows, enforceRows, stopRows, policyRows, storeRows)

// seamRows are the pipeline's, the decision point's, the adapter's and the
// pause file reader's.
var seamRows = []Metric{
	labelled(Counter, "pipeline_blocks_total", "code", "Pipeline.Blocks",
		"Calls and resumes blocked, expired holds swept and lost holds a reconciliation closed, by the first reason code "+
			"of the decision each carries; a code outside the reason registry is counted under "+Other+".",
		func(r Reading) ([]sample, error) { return blockSamples(r.Pipeline.Blocks) }),
	count("pipeline_pending_total", "Pipeline.Pending",
		"Admissions answered with a pending approval, first requests and retries alike.",
		func(r Reading) uint64 { return r.Pipeline.Pending }),
	count("pipeline_executed_total", "Pipeline.Executed",
		"Admissions handed to execution.",
		func(r Reading) uint64 { return r.Pipeline.Executed }),
	count("pipeline_sink_failures_before_effect_total", "Pipeline.SinkFailuresBeforeEffect",
		"Evidence appends that failed before anything ran.",
		func(r Reading) uint64 { return r.Pipeline.SinkFailuresBeforeEffect }),
	count("pipeline_sink_failures_after_effect_total", "Pipeline.SinkFailuresAfterEffect",
		"Closing records that could not be written; each halted material calls.",
		func(r Reading) uint64 { return r.Pipeline.SinkFailuresAfterEffect }),
	count("pipeline_reads_unrecorded_total", "Pipeline.ReadsUnrecorded",
		"Reads under allow_reads whose trail the sink refused an event of.",
		func(r Reading) uint64 { return r.Pipeline.ReadsUnrecorded }),
	count("pipeline_mismatches_total", "Pipeline.Mismatches",
		"Closings whose sent bytes were not the authorized ones.",
		func(r Reading) uint64 { return r.Pipeline.Mismatches }),
	level("pipeline_runs_halted", "Pipeline.RunsHalted",
		"Opened runs whose material calls are blocked until restart because a caller reported bytes that were not the authorized ones.",
		func(r Reading) int64 { return int64(r.Pipeline.RunsHalted) }),
	count("pipeline_abandoned_total", "Pipeline.Abandoned",
		"Executions nobody completed or aborted before they expired, closed with the outcome unknown.",
		func(r Reading) uint64 { return r.Pipeline.Abandoned }),
	count("pipeline_sink_failures_abandoned_total", "Pipeline.SinkFailuresAbandoned",
		"Closing records of abandoned executions that could not be written; none halts material calls.",
		func(r Reading) uint64 { return r.Pipeline.SinkFailuresAbandoned }),
	count("pipeline_multi_use_refused_total", "Pipeline.MultiUseRefused",
		"Approvals a store held as multi-use, which the plane left pending.",
		func(r Reading) uint64 { return r.Pipeline.MultiUseRefused }),
	count("pipeline_stale_handed_out_total", "Pipeline.StaleHandedOut",
		"Calls OBSERVE let through whose decision's policy was no longer current at hand-out, which ENFORCE would withhold.",
		func(r Reading) uint64 { return r.Pipeline.StaleHandedOut }),
	count("pipeline_unheld_records_total", "Pipeline.UnheldRecords",
		"Approval records for a request the plane did not hold, each held anew.",
		func(r Reading) uint64 { return r.Pipeline.UnheldRecords }),
	count("pipeline_journal_refusals_total", "Pipeline.JournalRefusals",
		"Hold journal writes that failed.",
		func(r Reading) uint64 { return r.Pipeline.JournalRefusals }),
	count("pipeline_holds_closed_total", "Pipeline.HoldsClosed",
		"Trails of holds lost to a restart that a reconciliation closed.",
		func(r Reading) uint64 { return r.Pipeline.HoldsClosed }),
	count("pipeline_holds_unmeasured_total", "Pipeline.HoldsUnmeasured",
		"Hold journal entries a reconciliation could not settle.",
		func(r Reading) uint64 { return r.Pipeline.HoldsUnmeasured }),
	count("pipeline_held_trails_left_open_total", "Pipeline.HeldTrailsLeftOpen",
		"Held trails a refused record or journal write left open, each keeping its request id reserved.",
		func(r Reading) uint64 { return r.Pipeline.HeldTrailsLeftOpen }),
	flag("pipeline_hold_journal", "Pipeline.HoldJournal",
		"1 when the plane keeps a durable record of its own holds.",
		func(r Reading) bool { return r.Pipeline.HoldJournal }),
	flag("pipeline_reconcile_incomplete", "Pipeline.ReconcileIncomplete",
		"1 when the last reconciliation stopped at its bound or could not read the journal.",
		func(r Reading) bool { return r.Pipeline.ReconcileIncomplete }),
	level("pipeline_open_executions", "Pipeline.Open",
		"Executions handed out and not yet closed or aborted.",
		func(r Reading) int64 { return int64(r.Pipeline.Open) }),
	level("pipeline_held_requests", "Pipeline.Held",
		"Requests held for an approval that has not expired.",
		func(r Reading) int64 { return int64(r.Pipeline.Held) }),
	flag("pipeline_halted", "Pipeline.Halted",
		"1 when a halt stops material calls: a closing record could not be written and no append has succeeded since, "+
			"or an execution sent bytes that were not authorized. Calls are still blocked for other causes while it reads 0.",
		func(r Reading) bool { return r.Pipeline.Halted }),
	flag("pipeline_halted_mismatch", "Pipeline.MismatchHalted",
		"1 when an execution sent bytes that were not authorized and the mismatch halted the plane, not one run; it stands until restart.",
		func(r Reading) bool { return r.Pipeline.MismatchHalted }),
	flag("pipeline_halted_sink", "Pipeline.SinkHalted",
		"1 when a closing record could not be written and no append has succeeded since.",
		func(r Reading) bool { return r.Pipeline.SinkHalted }),
	count("pipeline_flow_uncomputed_total", "Pipeline.FlowUncomputed",
		"Calls decided with a flow state nobody computed, so a flow rule is undetermined for each.",
		func(r Reading) uint64 { return r.Pipeline.FlowUncomputed }),
	level("pipeline_runs", "Pipeline.Runs",
		"Local runs the pipeline keeps a flow state for in memory.",
		func(r Reading) int64 { return int64(r.Pipeline.Runs) }),
	count("pipeline_run_state_failures_total", "Pipeline.RunStateFailures",
		"Reads and raises of an opened run's root state that failed, each of which blocked its call.",
		func(r Reading) uint64 { return r.Pipeline.RunStateFailures }),
	count("pdp_asks_total", "Pipeline.Asks.Made",
		"Asks of the external decision point, the sum of the six outcomes.",
		func(r Reading) uint64 { return r.Pipeline.Asks.Made }),
	count("pdp_asks_allowed_total", "Pipeline.Asks.Allowed",
		"Asks the decision point answered with an allow.",
		func(r Reading) uint64 { return r.Pipeline.Asks.Allowed }),
	count("pdp_asks_denied_total", "Pipeline.Asks.Denied",
		"Asks the decision point answered with a deny.",
		func(r Reading) uint64 { return r.Pipeline.Asks.Denied }),
	count("pdp_asks_denied_obligations_total", "Pipeline.Asks.DeniedObligations",
		"Asks allowed only with an obligation the plane cannot fulfil, which makes them denials.",
		func(r Reading) uint64 { return r.Pipeline.Asks.DeniedObligations }),
	count("pdp_asks_timed_out_total", "Pipeline.Asks.TimedOut",
		"Asks with no answer within the deadline.",
		func(r Reading) uint64 { return r.Pipeline.Asks.TimedOut }),
	count("pdp_asks_unavailable_total", "Pipeline.Asks.Unavailable",
		"Asks that could not be put, or whose reply was not an answer.",
		func(r Reading) uint64 { return r.Pipeline.Asks.Unavailable }),
	count("pdp_asks_answer_refused_total", "Pipeline.Asks.AnswerRefused",
		"Asks whose reply the plane will not read as a decision.",
		func(r Reading) uint64 { return r.Pipeline.Asks.AnswerRefused }),
	{
		Name: Prefix() + "pdp_ask_wait_seconds_total", Type: Counter, Reads: "Pipeline.Asks.Micros",
		Help: "Time spent waiting on the decision point over every ask, in seconds of the plane's clock.",
		read: func(r Reading) ([]sample, error) {
			return one(seconds(r.Pipeline.Asks.Micros)), nil
		},
	},

	signed("adapter_admitted_total", "Adapter.Admitted",
		"Calls the adapter put to the pipeline.",
		func(r Reading) int64 { return r.Adapter.Admitted }),
	signed("adapter_blocked_total", "Adapter.Blocked",
		"Calls the adapter answered as blocked, including executions it did not send.",
		func(r Reading) int64 { return r.Adapter.Blocked }),
	signed("adapter_sent_total", "Adapter.Sent",
		"Calls the adapter sent upstream.",
		func(r Reading) int64 { return r.Adapter.Sent }),
	signed("adapter_close_failures_total", "Adapter.CloseFailures",
		"Closing or aborting records the pipeline could not write.",
		func(r Reading) int64 { return r.Adapter.CloseFailures }),
	labelled(Counter, "adapter_runs_refused_at_request_total", "cause", "Adapter.RunsRefusedAtRequest",
		"HTTP requests answered 401 before the library read them, because their run token did not resolve, by cause.",
		func(r Reading) ([]sample, error) { return runSamples(r.Adapter.RunsRefusedAtRequest) }),
	labelled(Counter, "adapter_runs_refused_at_message_total", "cause", "Adapter.RunsRefusedAtMessage",
		"Messages refused with -31102, admitting nothing, because their run token did not resolve, by cause.",
		func(r Reading) ([]sample, error) { return runSamples(r.Adapter.RunsRefusedAtMessage) }),
	signed("adapter_refresh_failures_total", "Adapter.RefreshFailures",
		"Tool list reads that failed, each dropping that upstream's entries.",
		func(r Reading) int64 { return r.Adapter.RefreshFailures }),
	signed("adapter_answers_withheld_total", "Adapter.Withheld",
		"Answers to calls and forwarded lists that quoted a credential the plane sends, or could not be scanned, "+
			"shown to the agent as a fixed answer.",
		func(r Reading) int64 { return r.Adapter.Withheld }),
	signed("adapter_sessions_refused_total", "Adapter.SessionsRefused",
		"Sessionless POSTs a stateful listener counted as opens and answered 503 at its cap on live sessions.",
		func(r Reading) int64 { return r.Adapter.SessionsRefused }),
	level("adapter_sessions_live", "Adapter.SessionsLive",
		"Sessions a stateful listener holds; 0 on any other listener.",
		func(r Reading) int64 { return r.Adapter.SessionsLive }),

	count("pause_polls_total", "Pause.Polls",
		"Reads of the pause file, the first included.",
		func(r Reading) uint64 { return r.Pause.Polls }),
	labelled(Counter, "pause_poll_failures_total", "cause", "Pause.Failed",
		"Reads of the pause file whose state was unknown, by cause; a cause the reader does not declare is counted under "+Other+".",
		func(r Reading) ([]sample, error) { return causeSamples(r.Pause.Failed) }),
	count("pause_changes_total", "Pause.Changes",
		"Reads whose state, cause or entries differ from the read before, the first included.",
		func(r Reading) uint64 { return r.Pause.Changes }),
	labelled(Gauge, "pause_state", "state", "PauseState",
		"1 for the pause state a call admitted now is decided under, 0 for the three others.",
		func(r Reading) ([]sample, error) { return stateSamples(r.PauseState) }),
	level("pause_entries", "PauseEntries",
		"Pause entries in force.",
		func(r Reading) int64 { return int64(r.PauseEntries) }),
}

// storeRows are the spool's and the exporter's, which come last.
var storeRows = []Metric{
	flag("spool_broken", "SpoolBroken",
		"1 when the spool reports an error; every other metric reading the spool is then left out.",
		func(r Reading) bool { return r.SpoolBroken }),
	level("spool_segments", "Spool.Segments",
		"Segments of the spool on disk.",
		func(r Reading) int64 { return int64(r.Spool.Segments) }),
	level("spool_bytes", "Spool.Bytes",
		"Bytes of the spool on disk, the segments and the quarantine.",
		func(r Reading) int64 { return r.Spool.Bytes }),
	level("spool_unacknowledged_bytes", "Spool.Unacknowledged",
		"Bytes of the segments the exporter has not had acknowledged.",
		func(r Reading) int64 { return r.Spool.Unacknowledged }),
	level("spool_reserved_bytes", "Spool.Reserved",
		"Bytes of the budget reserved for the closing records of open trails.",
		func(r Reading) int64 { return r.Spool.Reserved }),
	level("spool_open_trails", "Spool.OpenTrails",
		"Trails holding a reservation.",
		func(r Reading) int64 { return int64(r.Spool.OpenTrails) }),
	level("spool_quarantined_records", "Spool.QuarantinedRecords",
		"Records the quarantine holds.",
		func(r Reading) int64 { return int64(r.Spool.QuarantinedRecords) }),
	level("spool_quarantined_bytes", "Spool.QuarantinedBytes",
		"Bytes the quarantine holds.",
		func(r Reading) int64 { return r.Spool.QuarantinedBytes }),
	level("spool_truncated_bytes", "Spool.Truncated",
		"Bytes discarded after a torn write since the spool opened.",
		func(r Reading) int64 { return r.Spool.Truncated }),
	{
		Name: Prefix() + "spool_oldest_segment", Type: Gauge, Reads: "Spool.Oldest.Segment",
		Help: "Sequence number of the segment holding the oldest unacknowledged record.",
		read: func(r Reading) ([]sample, error) { return one(strconv.FormatUint(r.Spool.Oldest.Segment, 10)), nil },
	},
	level("spool_oldest_offset_bytes", "Spool.Oldest.Offset",
		"Byte offset of the oldest unacknowledged record within its segment.",
		func(r Reading) int64 { return r.Spool.Oldest.Offset }),

	count("exporter_acknowledged_records_total", "Exporter.Acknowledged",
		"Records the spool released past: accepted by a collector, or quarantined.",
		func(r Reading) uint64 { return r.Exporter.Acknowledged }),
	count("exporter_quarantined_records_total", "Exporter.Quarantined",
		"Records the exporter put in the spool's quarantine.",
		func(r Reading) uint64 { return r.Exporter.Quarantined }),
	count("exporter_quarantine_held_records_total", "Exporter.QuarantineHeld",
		"Records the quarantine already held when the exporter offered them again.",
		func(r Reading) uint64 { return r.Exporter.QuarantineHeld }),
	count("exporter_partial_rejected_records_total", "Exporter.PartialRejected",
		"Records collectors reported dropped inside requests they otherwise accepted.",
		func(r Reading) uint64 { return r.Exporter.PartialRejected }),
	count("exporter_refused_total", "Exporter.Refused",
		"Answers 400, 413 and 422, which refuse the records themselves.",
		func(r Reading) uint64 { return r.Exporter.Refused }),
	count("exporter_retries_total", "Exporter.Retries",
		"Requests sent again after an answer that neither accepts nor refuses the records.",
		func(r Reading) uint64 { return r.Exporter.Retries }),
	count("exporter_retried_transport_total", "Exporter.RetriedTransport",
		"Retries after no answer: a timeout or a connection failure.",
		func(r Reading) uint64 { return r.Exporter.RetriedTransport }),
	count("exporter_retried_redirect_total", "Exporter.RetriedRedirect",
		"Retries after a 3xx, which is never followed.",
		func(r Reading) uint64 { return r.Exporter.RetriedRedirect }),
	count("exporter_retried_auth_total", "Exporter.RetriedAuth",
		"Retries after a 401, 403 or 407.",
		func(r Reading) uint64 { return r.Exporter.RetriedAuth }),
	count("exporter_retried_throttled_total", "Exporter.RetriedThrottled",
		"Retries after a 408 or 429.",
		func(r Reading) uint64 { return r.Exporter.RetriedThrottled }),
	count("exporter_retried_server_total", "Exporter.RetriedServer",
		"Retries after a 5xx.",
		func(r Reading) uint64 { return r.Exporter.RetriedServer }),
	count("exporter_retried_answer_total", "Exporter.RetriedAnswer",
		"Retries after a 200 or 202 whose body is not the protocol's answer.",
		func(r Reading) uint64 { return r.Exporter.RetriedAnswer }),
	count("exporter_retried_status_total", "Exporter.RetriedStatus",
		"Retries after any other status.",
		func(r Reading) uint64 { return r.Exporter.RetriedStatus }),
	flag("exporter_stopped", "ExporterStopped",
		"1 when the exporter's run ended; the spool then fills to its budget.",
		func(r Reading) bool { return r.ExporterStopped }),
}

// pauseStates is every state a pause state gauge has a sample for.
var pauseStates = []pause.State{pause.Unknown, pause.Disabled, pause.Clear, pause.Paused}

func count(name, reads, help string, v func(Reading) uint64) Metric {
	return Metric{Name: Prefix() + name, Type: Counter, Help: help, Reads: reads,
		read: func(r Reading) ([]sample, error) { return one(strconv.FormatUint(v(r), 10)), nil }}
}

func level(name, reads, help string, v func(Reading) int64) Metric {
	return Metric{Name: Prefix() + name, Type: Gauge, Help: help, Reads: reads,
		read: func(r Reading) ([]sample, error) { return one(strconv.FormatInt(v(r), 10)), nil }}
}

func flag(name, reads, help string, v func(Reading) bool) Metric {
	return level(name, reads, help, func(r Reading) int64 {
		if v(r) {
			return 1
		}
		return 0
	})
}

func labelled(t Type, name, label, reads, help string, read func(Reading) ([]sample, error)) Metric {
	return Metric{Name: Prefix() + name, Type: t, Help: help, Label: label, Reads: reads, read: read}
}

// signed is a counter its seam keeps as a signed number; Render refuses one
// below zero.
func signed(name, reads, help string, v func(Reading) int64) Metric {
	m := level(name, reads, help, v)
	m.Type = Counter
	return m
}

func one(value string) []sample { return []sample{{value: value}} }

// Other is the label value of every count whose code or cause is outside its
// closed set. It is in neither set, so it never stands for a value that is.
const Other = "other"

// blockSamples is one sample per code the reason registry holds, in order,
// and one labelled Other for the rest, so a label carries a documented code
// and never an identifier or a reason, and no block goes uncounted.
func blockSamples(blocks map[string]uint64) ([]sample, error) {
	return closedSamples(blocks, func(code string) bool {
		_, ok := reasons.Lookup(code)
		return ok
	})
}

// runSamples writes the count of every run refusal cause counted at least
// once, in their order, and the sum of any other key last, labelled Other.
func runSamples(counts map[gateway.RunCause]uint64) ([]sample, error) {
	causes := gateway.RunCauses()
	out := make([]sample, 0, len(causes)+1)
	for _, cause := range causes {
		if n := counts[cause]; n > 0 {
			out = append(out, sample{string(cause), strconv.FormatUint(n, 10)})
		}
	}
	others := maps.Clone(counts)
	maps.DeleteFunc(others, func(c gateway.RunCause, _ uint64) bool { return slices.Contains(causes, c) })
	rest, err := closedSamples(others, func(gateway.RunCause) bool { return false })
	if err != nil {
		return nil, err
	}
	return append(out, rest...), nil
}

func causeSamples(failed map[pause.Cause]uint64) ([]sample, error) {
	return closedSamples(failed, func(c pause.Cause) bool { return slices.Contains(pause.Causes(), c) })
}

// closedSamples writes the counts of the keys known holds under their own
// label, in order, and the sum of the others last, labelled Other. A sum past
// a counter's range is refused rather than written wrapped.
func closedSamples[K ~string](counts map[K]uint64, known func(K) bool) ([]sample, error) {
	out := make([]sample, 0, len(counts))
	var other uint64
	var outside bool
	for _, k := range sortedKeys(counts) {
		if known(k) {
			out = append(out, sample{string(k), strconv.FormatUint(counts[k], 10)})
			continue
		}
		sum, carry := bits.Add64(other, counts[k], 0)
		if carry != 0 {
			return nil, fmt.Errorf("the counts labelled %s pass a counter's range", Other)
		}
		other, outside = sum, true
	}
	if outside {
		out = append(out, sample{Other, strconv.FormatUint(other, 10)})
	}
	return out, nil
}

func stateSamples(state pause.State) ([]sample, error) {
	if !slices.Contains(pauseStates, state) {
		return nil, errors.New("a pause state outside the four")
	}
	out := make([]sample, 0, len(pauseStates))
	for _, s := range pauseStates {
		v := "0"
		if s == state {
			v = "1"
		}
		out = append(out, sample{s.String(), v})
	}
	return out, nil
}

// seconds spells a count of microseconds in seconds, exactly: a float would
// round a large count.
func seconds(micros uint64) string {
	s := strconv.FormatUint(micros/1_000_000, 10)
	if frac := micros % 1_000_000; frac != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%06d", frac), "0")
	}
	return s
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
