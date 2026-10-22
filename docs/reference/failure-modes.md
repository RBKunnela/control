---
title: Failure modes
summary: What a plane does when its collector, spool, decision point, upstream, pause file, stop list, freshness statement or clock fails, or it is killed holding calls.
type: reference
covers: [cmd/guardana-gateway/serve.go, cmd/guardana-gateway/adapter.go, cmd/guardana-gateway/chaos_*_test.go, adapters/mcp/middleware.go, adapters/mcp/answer.go, adapters/authzen/**, adapters/otel/**, internal/spool/**, internal/pause/**, internal/gateway/close.go, internal/gateway/decisionpoint.go, internal/gateway/lapse.go, internal/gateway/resume.go, internal/core/clock.go, internal/core/clock_test.go, internal/gateway/e2e/**, internal/gateway/reconcile.go, internal/policy/policy.go, internal/policywatch/**, internal/policystate/**, internal/reaction/stoplist/**, cmd/guardana-gateway/reaction.go]
---

# Failure modes

Each row says whether the plane blocks the call, its code, what the agent
gets, whether the plane recovers alone, and the test that makes
the failure happen; the sections say what the trail holds. The `chaos_` tests
of `cmd/guardana-gateway/` run the built binary in `ENFORCE` against
listeners, files and a child process that really fail. Nothing here is a
security boundary ([status](../status.md)).

| Failure | The call | Reason code | The agent gets | Recovers by itself | Test |
| --- | --- | --- | --- | --- | --- |
| Collector gone, then back | runs | none | the upstream's answer | yes | `TestACollectorThatIsGoneBlocksNoCallAndGetsEveryRecordBack` |
| Spool full | blocked before its effect | `EVIDENCE_UNAVAILABLE` | a tool result with `isError: true` and the code | yes, once draining frees room; quarantined records count until `quarantine.log` is removed with the plane stopped | `TestAFullSpoolBlocksCallsUntilTheCollectorDrainsIt` |
| Decision point silent | blocked | `PDP_TIMEOUT` | `isError` and the code | yes, each call asks again | `TestAnAskPastTheConfiguredTimeoutIsATimeout`, `TestEveryEffectClassUnderEveryAnswer` |
| Decision point wrong or gone | blocked | `PDP_ANSWER_REFUSED`, `PDP_UNAVAILABLE` | `isError` and the code | yes, each call asks again | `TestAWrongOrAbsentDecisionPointBlocksOnARunningPlane` |
| `stdio` upstream dies mid-call | sent once, never retried | none | a JSON-RPC error | no: restart the plane | `TestAStdioUpstreamThatDiesMidCallIsNeverASuccess` |
| HTTP upstream drops the connection mid-call | sent once, never retried | none | a JSON-RPC error | yes, the next call is sent | `TestAnHTTPUpstreamThatDropsTheCallIsNeverASuccess` |
| Pause file unreadable | blocked | `PAUSE_STATE_UNAVAILABLE` | `isError` and the code | yes, at the first read of a whole file | `TestAPauseFileSpoiledWhileThePlaneRunsBlocksEveryCall` |
| Stop list unknown | blocked | `STOP_STATE_UNAVAILABLE` | `isError` and the code | yes, at a whole read extending the accepted list; shrunk or rewritten, no | `TestAnUnknownStopStateBlocksEveryCall`, `TestHealthAnswersTheStopStateAnd503WhenTheListIsRewritten` |
| No freshness statement current | blocked, a read too unless `policy.fail_open_read` opened it | `POLICY_STALE` | `isError` and the code | yes, at the first poll taking a statement bound to the bundle | `TestAnUnconfirmedPlaneBlocksMaterialCalls`, `TestARenewalConfirmsAgain` |
| Bundle file torn, unsigned, older or another id's | runs on the last good bundle until its statement expires, then blocked | none, then `POLICY_STALE` | the upstream's answer, then `isError` and the code | yes, once the file holds the served bundle or a newer one with its statement | `TestEveryRefusedReplacementMovesNothing` |
| Clock outside 1970 to 9999, or behind the verified time | blocked outside `OBSERVE`, a read too, whatever `policy.fail_open_read` says | `POLICY_STALE` | `isError` and the code | yes, once the clock passes the verified time and, after a step back, a newer statement arrives, or a restart follows `policy state reset`; outside 1970 to 9999, no | `TestAClockOutsideTheUsableRangeIsACauseInTheRequest`, `TestAClockBehindAVerifiedTimeIsACauseInTheRequest`, `TestAClockBehindTheFloorStopsAnUnconfirmedSnapshotsRead` |
| Floor directory or file missing or unreadable at start | none: the plane does not start | none | no listener | no: restore it, or make it again with `policy state init` or `reset` | `TestAStartWithNoFloorIsRefused`, `TestAStartIsRefusedForWhatItCannotRead` |
| Plane killed with calls held | never runs | `APPROVAL_NOT_RESUMED`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED` or `APPROVAL_STATE_UNKNOWN` on the closing record | `APPROVAL_PENDING`, before the kill | at the next start, with a hold journal | `TestAnApproverOutsideThePlaneAnswersAndALostHoldIsClosed`, `TestTheLostHoldCodesTellTheFourAnswersApart` |

`APPROVAL_NOT_RESUMED`, `APPROVAL_REJECTED` and `APPROVAL_EXPIRED` are
`DENY`; every other code in the table, `APPROVAL_STATE_UNKNOWN` included, is
`INDETERMINATE` ([reason codes](reason-codes.md)). A blocked `tools/call` is
a tool result with `isError: true`; a blocked `resources/read` or
`prompts/get`, whose results cannot say `isError`, is a JSON-RPC error with
the adapter's code.

## Collector gone, then back

The exporter resends with a backoff growing to `export.max_backoff`; every record stays in the spool (`/healthz`: `spool.unacknowledged`), and no
call is blocked until the spool is full. Once a collector answers again, every record it accepts
arrives, at least once, so it tells copies apart by `event_id`; one it keeps
refusing goes to the spool's `quarantine.log`.
`TestCollectorOutageBlocksNoDecision` in `internal/gateway/e2e/` holds the
same for a collector answering `503`.

## Spool full

A record that would take the bytes on disk and the reservations past
`evidence.max_bytes` blocks the call before anything runs, a read too unless
`evidence.on_unwritable` is `allow_reads`. The block is not recorded: its
record is the one that failed. A running call writes its closing record into
the room its `ACTION_STARTED` reserved; bytes past it are checked like any
record's (`TestAClosingRecordWritesOnAFullSpool`). Calls run again once the
spool has released what the collector accepted.

## Decision point silent, wrong or gone

The plane asks only when the answer would change a call's decision, so a
failure blocks only calls a veto rule covers, and their trail ends
`ACTION_BLOCKED` with the code. An ask past `pdp.timeout` is
`PDP_TIMEOUT`. An answer that is no plain allow or deny, such as two `decision` members or a
string for a boolean, is `PDP_ANSWER_REFUSED`. Nothing listening, a `500`, or an ask past `pdp.max_in_flight`
is `PDP_UNAVAILABLE`. A well-formed `false` is `PDP_DENY`; a forged `true` is
read as an allow ([threat model](../concepts/threat-model.md)).

## An upstream that dies mid-call

The upstream took the call and no answer came back. The
agent gets a JSON-RPC error, never a result; the call is not sent again, and
its trail ends `ACTION_FAILED` with an `UNKNOWN` result and
`tool_protocol_status: error`, never `ACTION_COMPLETED`.

- A `stdio` upstream that exits during a call is not
  started again: every later call to it is closed that way and answered with an error until
the plane restarts. Other upstreams run.
- An HTTP upstream that closes the connection after reading the call leaves that call's outcome unknown; the next
  call to it is sent and answered.

An upstream that answers nothing within `upstream.call_timeout` is closed
with a `TIMEOUT` result (`TestUpstreamTimeoutIsRecordedAsOne`). A `stdio`
upstream that stops reading its input can hold a call's write, and a call
queued behind it, past that bound; each closes `TIMEOUT` or unknown, never
as not sent.

## Pause file unreadable

At start, a pause file that is missing, garbled, too large, a link, a
directory, or writable by the group or others refuses the start, naming
`pause.file` and the cause (`TestAStartIsRefusedOnEveryUnknownCause`). While
the plane runs, a read every `pause.poll_interval` that meets one of those
causes, or cannot read the file, blocks every call until a read finds a whole
file, and so does a read older than three intervals. `/healthz` answers `503`
with `pause.state: unknown` and the cause
(`TestHealthAnswers503OnEveryUnknownState`), and the trail of each call ends
`ACTION_BLOCKED` with the code.

## Stop list unknown

At start, a stop list the plane cannot serve refuses the start, naming
`reaction.stops` and the cause
(`TestAStopListThatCannotBeServedRefusesTheStart`). While the plane runs, a
read every `reaction.poll_interval` that is not whole, or does not extend the
bytes accepted before, blocks every call until one does. `/healthz` answers
`503` with `stops.state: unknown` and one cause, which `/metrics` counts:
`missing`, `unreadable`, `a link`, `writable by others`, `owned by another
account`, `never read`, `too large`, `malformed`, `another route`, `header
changed`, `shrunk`, `rewritten`, `a stop the route does not permit`, `a line
dated ahead`, `a lift that does not verify`, `clock unusable`, `stale` or
`read ahead`. The trail of each call ends
`ACTION_BLOCKED` with the code. A shrunk or rewritten list stays unknown
until `stops init --carry` copies its unlifted stops to a new list and the
plane restarts ([reaction.md](reaction.md)).

## A policy that is not confirmed

Every poll rereads the bundle and the statement, and logs and counts a
refusal by cause in
`guardana_control_policy_refresh_refused_total`: `bundle_unreadable`,
`bundle_invalid`, `bundle_id`, `bundle_budget`, `rollback`, `serial_reused`,
`statement_missing`, `statement_unreadable`, `statement_invalid`,
`statement_unbound`, `statement_future`, `statement_expired`, `below_floor`,
`clock_behind_floor`, `clock_back`, `withdrawn`, `floor` or `unknown`. A
floor restored below the confirmed statement counts under `floor`. The
bundle in use keeps its confirmation, but a refused bundle file stops
renewals, since each poll pairs statement and file, so the plane turns stale
when the last budget ends. Then each call's `POLICY_DECIDED` carries
`POLICY_STALE` and `policy_freshness` `STALE`, `/healthz` answers
`"status":"degraded"`, and outside `OBSERVE` a call is blocked, a read too
unless `policy.fail_open_read`.

## A clock that cannot be read as now

The kernel judges no expiry and no bundle's age by a reading before 1970,
after 9999-12-31, or behind the
[verified time](../concepts/glossary.md). It decides
`INDETERMINATE` with `POLICY_STALE` alone, and `policy.fail_open_read` opens
no read: a wrong clock is no missing policy. A hop's unsigned `issued_at`
is not compared.

Outside 1970 to 9999 the kernel's decision has no `decided_at`, though the
plane's records carry the reading. The spool refuses a record dated before
year 1 or after 9999, which blocks the call with `EVIDENCE_UNAVAILABLE`
unless `evidence.on_unwritable: allow_reads` lets a read go on unrecorded.

Before handing out an approved or run-bound call, a reading outside 1970
to 9999, or behind one the call took before, the verified time or the
approval's `requested_at`, blocks it as lapsed: `APPROVAL_EXPIRED` or `EVIDENCE_UNAVAILABLE`.

## Plane killed with calls held

A held call's trail stands at `APPROVAL_REQUESTED` while no plane runs, and
an approver can still answer its record. With `approvals.hold_journal_dir`,
the next `run` closes it: the answer, then `ACTION_BLOCKED` with
`APPROVAL_NOT_RESUMED` for an approval, `APPROVAL_REJECTED` for a rejection,
or `APPROVAL_EXPIRED` when nobody answered or the approval expired. A store
that cannot be read, a record lost before its approval expired, and one that
fails its checks (no approver, a state no answer has) give `INDETERMINATE`
`APPROVAL_STATE_UNKNOWN`. So does a crash between journalling a hold and filing its record, followed by a
restart before the expiry, since a record never filed looks like one
deleted. The call never runs; `run` prints `lost holds:` with the count.
What the bounded reconciliation cannot settle stays open: a journal it cannot
read, or one past its bound, sets
`guardana_control_pipeline_reconcile_incomplete` to 1, and each entry it
cannot settle counts in `guardana_control_pipeline_holds_unmeasured_total`.
Without a hold journal the trail is never closed, as `/healthz` says under
`approvals.limits`.
