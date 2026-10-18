---
title: Metrics
summary: Every metric a plane answers on /metrics, with its type, its label, the statistic it reads and what it counts.
type: reference
covers: [internal/metrics/**]
generated: scripts/gen-metrics.go
---

# Metrics

The health listener answers `GET /metrics` in the Prometheus text exposition format,
version 0.0.4, with the content type `text/plain; version=0.0.4; charset=utf-8`.
Every name begins with `guardana_control_`. A counter ends in `_total` and counts
from the plane's start; a gauge is a value now. The flags are the gauges whose meaning
begins "1 when", and read 1 or 0. Times are in seconds and sizes in bytes.

A spool that cannot answer sets `guardana_control_spool_broken` to 1, and every other
metric reading the spool is left out of the text rather than written as zero; the rest
is still answered. A reading the text cannot carry truthfully answers 503 with no body:
a counter below zero, a pause state outside the four, a freshness state outside the
three, or counts outside a label's closed set that sum past a counter's range.

A plane whose listener serves the enforcement API writes the `guardana_control_enforce_`
metrics and leaves out the MCP adapter's `guardana_control_adapter_` ones; any other
plane does the reverse, and `guardana_control_listener_enforce_api` says which.

`guardana_control_pipeline_halted` is not the only thing that stops calls. While it
reads 0, an unknown pause state takes no call at all, which `guardana_control_pause_state`
reports under `state="unknown"`; in every mode but OBSERVE a policy that is not
confirmed blocks every call but a read under `policy.fail_open_read`, which
`guardana_control_policy_freshness`
reports; and a refused evidence append
blocks the call it records, which `guardana_control_pipeline_sink_failures_before_effect_total`
counts. That counter also holds a client's abort whose record was refused; the
aborted call never ran, and the plane does not halt for it.

No label carries an identifier, a digest or a reason: `code` is a code of the reason
registry, or an error code of the enforcement API contract in lower case without its
`ERROR_CODE_` prefix; `cause` is why a read of the pause file was unknown, why a run token did not
resolve, or why a poll of the policy moved nothing; and `state` is one of the four pause
states or the three freshness states. A code or a cause outside its set is counted under
`other`, so no count is dropped. Reads names the statistic: `Pipeline` is the
pipeline's, `Adapter` the MCP adapter's, `Enforce` the enforcement API adapter's,
`Pause` the pause file reader's, `Policy` the
policy refresher's, `Spool` the evidence spool's and `Exporter` the exporter's.

Rendered from the table in `internal/metrics`. Rebuild it with `make docs-gen`; an
edit made here does not survive the next run.

| Metric | Type | Label | Reads | Meaning |
| --- | --- | --- | --- | --- |
| `guardana_control_pipeline_blocks_total` | counter | `code` | `Pipeline.Blocks` | Calls and resumes blocked, expired holds swept and lost holds a reconciliation closed, by the first reason code of the decision each carries; a code outside the reason registry is counted under other. |
| `guardana_control_pipeline_pending_total` | counter |  | `Pipeline.Pending` | Admissions answered with a pending approval, first requests and retries alike. |
| `guardana_control_pipeline_executed_total` | counter |  | `Pipeline.Executed` | Admissions handed to execution. |
| `guardana_control_pipeline_sink_failures_before_effect_total` | counter |  | `Pipeline.SinkFailuresBeforeEffect` | Evidence appends that failed before anything ran. |
| `guardana_control_pipeline_sink_failures_after_effect_total` | counter |  | `Pipeline.SinkFailuresAfterEffect` | Closing records that could not be written; each halted material calls. |
| `guardana_control_pipeline_reads_unrecorded_total` | counter |  | `Pipeline.ReadsUnrecorded` | Reads under allow_reads whose trail the sink refused an event of. |
| `guardana_control_pipeline_mismatches_total` | counter |  | `Pipeline.Mismatches` | Closings whose sent bytes were not the authorized ones. |
| `guardana_control_pipeline_runs_halted` | gauge |  | `Pipeline.RunsHalted` | Opened runs whose material calls are blocked until restart because a caller reported bytes that were not the authorized ones. |
| `guardana_control_pipeline_abandoned_total` | counter |  | `Pipeline.Abandoned` | Executions nobody completed or aborted before they expired, closed with the outcome unknown. |
| `guardana_control_pipeline_sink_failures_abandoned_total` | counter |  | `Pipeline.SinkFailuresAbandoned` | Closing records of abandoned executions that could not be written; none halts material calls. |
| `guardana_control_pipeline_multi_use_refused_total` | counter |  | `Pipeline.MultiUseRefused` | Approvals a store held as multi-use, which the plane left pending. |
| `guardana_control_pipeline_stale_handed_out_total` | counter |  | `Pipeline.StaleHandedOut` | Calls OBSERVE let through whose decision's policy was no longer current at hand-out, which ENFORCE would withhold. |
| `guardana_control_pipeline_unheld_records_total` | counter |  | `Pipeline.UnheldRecords` | Approval records for a request the plane did not hold, each held anew. |
| `guardana_control_pipeline_journal_refusals_total` | counter |  | `Pipeline.JournalRefusals` | Hold journal writes that failed. |
| `guardana_control_pipeline_holds_closed_total` | counter |  | `Pipeline.HoldsClosed` | Trails of holds lost to a restart that a reconciliation closed. |
| `guardana_control_pipeline_holds_unmeasured_total` | counter |  | `Pipeline.HoldsUnmeasured` | Hold journal entries a reconciliation could not settle. |
| `guardana_control_pipeline_held_trails_left_open_total` | counter |  | `Pipeline.HeldTrailsLeftOpen` | Held trails a refused record or journal write left open, each keeping its request id reserved. |
| `guardana_control_pipeline_hold_journal` | gauge |  | `Pipeline.HoldJournal` | 1 when the plane keeps a durable record of its own holds. |
| `guardana_control_pipeline_reconcile_incomplete` | gauge |  | `Pipeline.ReconcileIncomplete` | 1 when the last reconciliation stopped at its bound or could not read the journal. |
| `guardana_control_pipeline_open_executions` | gauge |  | `Pipeline.Open` | Executions handed out and not yet closed or aborted. |
| `guardana_control_pipeline_held_requests` | gauge |  | `Pipeline.Held` | Requests held for an approval that has not expired. |
| `guardana_control_pipeline_halted` | gauge |  | `Pipeline.Halted` | 1 when a halt stops material calls: a closing record could not be written and no append has succeeded since, or an execution sent bytes that were not authorized. Calls are still blocked for other causes while it reads 0. |
| `guardana_control_pipeline_halted_mismatch` | gauge |  | `Pipeline.MismatchHalted` | 1 when an execution sent bytes that were not authorized and the mismatch halted the plane, not one run; it stands until restart. |
| `guardana_control_pipeline_halted_sink` | gauge |  | `Pipeline.SinkHalted` | 1 when a closing record could not be written and no append has succeeded since. |
| `guardana_control_pipeline_flow_uncomputed_total` | counter |  | `Pipeline.FlowUncomputed` | Calls decided with a flow state nobody computed, so a flow rule is undetermined for each. |
| `guardana_control_pipeline_runs` | gauge |  | `Pipeline.Runs` | Local runs the pipeline keeps a flow state for in memory. |
| `guardana_control_pipeline_run_state_failures_total` | counter |  | `Pipeline.RunStateFailures` | Reads and raises of an opened run's root state that failed, each of which blocked its call. |
| `guardana_control_pdp_asks_total` | counter |  | `Pipeline.Asks.Made` | Asks of the external decision point, the sum of the six outcomes. |
| `guardana_control_pdp_asks_allowed_total` | counter |  | `Pipeline.Asks.Allowed` | Asks the decision point answered with an allow. |
| `guardana_control_pdp_asks_denied_total` | counter |  | `Pipeline.Asks.Denied` | Asks the decision point answered with a deny. |
| `guardana_control_pdp_asks_denied_obligations_total` | counter |  | `Pipeline.Asks.DeniedObligations` | Asks allowed only with an obligation the plane cannot fulfil, which makes them denials. |
| `guardana_control_pdp_asks_timed_out_total` | counter |  | `Pipeline.Asks.TimedOut` | Asks with no answer within the deadline. |
| `guardana_control_pdp_asks_unavailable_total` | counter |  | `Pipeline.Asks.Unavailable` | Asks that could not be put, or whose reply was not an answer. |
| `guardana_control_pdp_asks_answer_refused_total` | counter |  | `Pipeline.Asks.AnswerRefused` | Asks whose reply the plane will not read as a decision. |
| `guardana_control_pdp_ask_wait_seconds_total` | counter |  | `Pipeline.Asks.Micros` | Time spent waiting on the decision point over every ask, in seconds of the plane's clock. |
| `guardana_control_adapter_admitted_total` | counter |  | `Adapter.Admitted` | Calls the adapter put to the pipeline. |
| `guardana_control_adapter_blocked_total` | counter |  | `Adapter.Blocked` | Calls the adapter answered as blocked, including executions it did not send. |
| `guardana_control_adapter_sent_total` | counter |  | `Adapter.Sent` | Calls the adapter sent upstream. |
| `guardana_control_adapter_close_failures_total` | counter |  | `Adapter.CloseFailures` | Closing or aborting records the pipeline could not write. |
| `guardana_control_adapter_runs_refused_at_request_total` | counter | `cause` | `Adapter.RunsRefusedAtRequest` | HTTP requests answered 401 before the library read them, because their run token did not resolve, by cause. |
| `guardana_control_adapter_runs_refused_at_message_total` | counter | `cause` | `Adapter.RunsRefusedAtMessage` | Messages refused with -31102, admitting nothing, because their run token did not resolve, by cause. |
| `guardana_control_adapter_refresh_failures_total` | counter |  | `Adapter.RefreshFailures` | Tool list reads that failed, each dropping that upstream's entries. |
| `guardana_control_adapter_answers_withheld_total` | counter |  | `Adapter.Withheld` | Answers to calls and forwarded lists that quoted a credential the plane sends, or could not be scanned, shown to the agent as a fixed answer. |
| `guardana_control_adapter_sessions_refused_total` | counter |  | `Adapter.SessionsRefused` | Sessionless POSTs a stateful listener counted as opens and answered 503 at its cap on live sessions. |
| `guardana_control_adapter_sessions_live` | gauge |  | `Adapter.SessionsLive` | Sessions a stateful listener holds; 0 on any other listener. |
| `guardana_control_pause_polls_total` | counter |  | `Pause.Polls` | Reads of the pause file, the first included. |
| `guardana_control_pause_poll_failures_total` | counter | `cause` | `Pause.Failed` | Reads of the pause file whose state was unknown, by cause; a cause the reader does not declare is counted under other. |
| `guardana_control_pause_changes_total` | counter |  | `Pause.Changes` | Reads whose state, cause or entries differ from the read before, the first included. |
| `guardana_control_pause_state` | gauge | `state` | `PauseState` | 1 for the pause state a call admitted now is decided under, 0 for the three others. |
| `guardana_control_pause_entries` | gauge |  | `PauseEntries` | Pause entries in force. |
| `guardana_control_listener_enforce_api` | gauge |  | `EnforceAPI` | 1 when the plane serves the enforcement API: the metrics of its adapter are written and those of the MCP adapter left out. |
| `guardana_control_enforce_open_handles` | gauge |  | `Enforce.Open` | Executions the enforcement API handed out whose handle is still open. |
| `guardana_control_enforce_executed_total` | counter |  | `Enforce.Executed` | Admits answered EXECUTE. |
| `guardana_control_enforce_blocked_total` | counter |  | `Enforce.Blocked` | Admits answered BLOCK, including executions not handed out because their resource moved. |
| `guardana_control_enforce_pending_total` | counter |  | `Enforce.Pending` | Admits answered PENDING. |
| `guardana_control_enforce_completed_total` | counter |  | `Enforce.Completed` | Executions a client completed. |
| `guardana_control_enforce_aborted_total` | counter |  | `Enforce.Aborted` | Executions a client aborted, and those the adapter aborted because their resource moved. |
| `guardana_control_enforce_abandoned_total` | counter |  | `Enforce.Abandoned` | Executions the adapter abandoned: expired, open at shutdown, or handed to nobody. |
| `guardana_control_enforce_records_failed_total` | counter |  | `Enforce.RecordsFailed` | Abandons and aborts whose closing record could not be written; each leaves its trail open. |
| `guardana_control_enforce_refused_total` | counter | `code` | `Enforce.Refused` | Requests the enforcement API refused, by its error code, refused run tokens included; a code the contract does not declare is counted under other. |
| `guardana_control_enforce_runs_refused_total` | counter | `cause` | `Enforce.RunsRefused` | Requests refused because their run token did not resolve, by cause. |
| `guardana_control_stops_polls_total` | counter |  | `Stops.Polls` | Reads of the stop list, the first included. |
| `guardana_control_stops_poll_failures_total` | counter | `cause` | `Stops.Failed` | Reads of the stop list whose state was unknown, by cause; each blocked every call until a read was whole again; a cause the reader does not declare is counted under other. |
| `guardana_control_stops_active_entries` | gauge |  | `Stops.Active` | Stops active at the clock of the last read of the stop list. |
| `guardana_control_policy_freshness` | gauge | `state` | `PolicyFreshness` | 1 for how the policy a call is decided under stands, confirmed, unconfirmed or expired, 0 for the two others; while it is not confirmed every mode but OBSERVE blocks every material call. |
| `guardana_control_policy_confirmation_seconds_left` | gauge |  | `PolicySecondsLeft` | Whole seconds until the policy's confirmation expires; 0 while it is unconfirmed or expired. |
| `guardana_control_policy_seconds_since_poll` | gauge |  | `PolicySecondsSincePoll` | Whole seconds since the policy's refresher last completed a poll, or since the start before any; it grows past the poll interval while the refresher is stuck. |
| `guardana_control_policy_refresh_refused_total` | counter | `cause` | `Policy.Refused` | Polls that moved nothing because a replacement, a statement or the clock was refused, by cause; a cause the refresher does not declare is counted under other. |
| `guardana_control_policy_awaiting_statement_total` | counter |  | `Policy.AwaitingStatement` | Polls that found a new bundle whose statement still names another. |
| `guardana_control_policy_awaiting_bundle_total` | counter |  | `Policy.AwaitingBundle` | Polls that found a statement naming a bundle not yet on disk. |
| `guardana_control_policy_withdrawals_total` | counter |  | `Policy.Withdrawals` | Confirmations withdrawn because the wall clock stood more than a second below the highest it had read. |
| `guardana_control_spool_broken` | gauge |  | `SpoolBroken` | 1 when the spool reports an error; every other metric reading the spool is then left out. |
| `guardana_control_spool_segments` | gauge |  | `Spool.Segments` | Segments of the spool on disk. |
| `guardana_control_spool_bytes` | gauge |  | `Spool.Bytes` | Bytes of the spool on disk, the segments and the quarantine. |
| `guardana_control_spool_unacknowledged_bytes` | gauge |  | `Spool.Unacknowledged` | Bytes of the segments the exporter has not had acknowledged. |
| `guardana_control_spool_reserved_bytes` | gauge |  | `Spool.Reserved` | Bytes of the budget reserved for the closing records of open trails. |
| `guardana_control_spool_open_trails` | gauge |  | `Spool.OpenTrails` | Trails holding a reservation. |
| `guardana_control_spool_quarantined_records` | gauge |  | `Spool.QuarantinedRecords` | Records the quarantine holds. |
| `guardana_control_spool_quarantined_bytes` | gauge |  | `Spool.QuarantinedBytes` | Bytes the quarantine holds. |
| `guardana_control_spool_truncated_bytes` | gauge |  | `Spool.Truncated` | Bytes discarded after a torn write since the spool opened. |
| `guardana_control_spool_oldest_segment` | gauge |  | `Spool.Oldest.Segment` | Sequence number of the segment holding the oldest unacknowledged record. |
| `guardana_control_spool_oldest_offset_bytes` | gauge |  | `Spool.Oldest.Offset` | Byte offset of the oldest unacknowledged record within its segment. |
| `guardana_control_exporter_acknowledged_records_total` | counter |  | `Exporter.Acknowledged` | Records the spool released past: accepted by a collector, or quarantined. |
| `guardana_control_exporter_quarantined_records_total` | counter |  | `Exporter.Quarantined` | Records the exporter put in the spool's quarantine. |
| `guardana_control_exporter_quarantine_held_records_total` | counter |  | `Exporter.QuarantineHeld` | Records the quarantine already held when the exporter offered them again. |
| `guardana_control_exporter_partial_rejected_records_total` | counter |  | `Exporter.PartialRejected` | Records collectors reported dropped inside requests they otherwise accepted. |
| `guardana_control_exporter_refused_total` | counter |  | `Exporter.Refused` | Answers 400, 413 and 422, which refuse the records themselves. |
| `guardana_control_exporter_retries_total` | counter |  | `Exporter.Retries` | Requests sent again after an answer that neither accepts nor refuses the records. |
| `guardana_control_exporter_retried_transport_total` | counter |  | `Exporter.RetriedTransport` | Retries after no answer: a timeout or a connection failure. |
| `guardana_control_exporter_retried_redirect_total` | counter |  | `Exporter.RetriedRedirect` | Retries after a 3xx, which is never followed. |
| `guardana_control_exporter_retried_auth_total` | counter |  | `Exporter.RetriedAuth` | Retries after a 401, 403 or 407. |
| `guardana_control_exporter_retried_throttled_total` | counter |  | `Exporter.RetriedThrottled` | Retries after a 408 or 429. |
| `guardana_control_exporter_retried_server_total` | counter |  | `Exporter.RetriedServer` | Retries after a 5xx. |
| `guardana_control_exporter_retried_answer_total` | counter |  | `Exporter.RetriedAnswer` | Retries after a 200 or 202 whose body is not the protocol's answer. |
| `guardana_control_exporter_retried_status_total` | counter |  | `Exporter.RetriedStatus` | Retries after any other status. |
| `guardana_control_exporter_stopped` | gauge |  | `ExporterStopped` | 1 when the exporter's run ended; the spool then fills to its budget. |
