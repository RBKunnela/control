# ADR-0014: Evidence goes to a local spool first, and the spool decides what blocks

Status: accepted
Date: 2026-09-19

Builds on [ADR-0004](0004-evidence-and-privacy-defaults.md),
[ADR-0007](0007-repository-layout-and-dependency-rule.md) and
[ADR-0013](0013-mcp-interception-approvals-and-modes.md).

Amended by [ADR-0080](0080-evidence-leaves-a-plane-over-a-unix-socket-or-tls.md):
the exporter sends to a unix socket whose peer is `export.collector_uid`, or
over TLS; a plaintext `http` endpoint is refused.

## Context

ADR-0004 puts every record in a local spool first and exports from there, so
that an exporter outage never reaches the request path and the loss an outage
can cause is bounded and visible. `internal/evidence` builds and validates the
records, and it is a guarded tree: it reads no clock and touches no file or
network. So the interface through which evidence is written is declared there,
and the thing that writes disk lives outside it. Invariant 5 says an action with
material effect fails closed when the evidence it needs is unavailable, unless
an explicit risk setting says otherwise; invariant 11 says a non-idempotent
effect is never retried automatically. What "unavailable" means for a spool on
a disk with a budget, before an effect and after one, is what this record
settles.

## Decision

**One interface, declared beside the records.** `internal/evidence.Sink` has
one method: append one event, and return only when the event is durable under
the sink's own policy. An error from it means the event is not durable, and
nothing that returns a decision to an agent may treat that error as a success.
`MemorySink` keeps events in memory for tests; a gateway configured with no sink
refuses to start.

**The spool is our own segmented log, in `internal/spool`.** A record is one
event in the JSONL encoding `internal/evidence` already defines, so a segment is
readable by the reader that already exists, framed with its length and a
CRC32C over the line. Segments are append-only files named by the sequence
number of their first record, rolled at a byte size, and bounded in total by
`max_bytes`. The fsync policy is `every_record` by default; `interval` is an
explicit risk setting that names how many seconds of records a power loss may
cost. A reader holds a cursor, a segment and an offset, and acknowledges what it
has delivered; a segment acknowledged whole is deleted, and bytes not yet
acknowledged are what count against the budget.

**Every record in the spool is evidence, and none is dropped.** When the budget
is reached and no segment can be released, an append fails. What happens next
depends on whether the effect has happened yet. Before it, for
`ACTION_PROPOSED`, `POLICY_DECIDED` and `ACTION_STARTED`, the gateway blocks
the call it was recording, answers the agent with `EVIDENCE_UNAVAILABLE`, and
counts the block, because the one record that could not be written is the
record of that block. After it, for `ACTION_COMPLETED` and `ACTION_FAILED`, a
block is impossible and an error would invite the retry invariant 11 forbids,
so the spool reserves the closing record's bytes when it appends
`ACTION_STARTED`, an allowance named by the request and the execution that
opened it, so a closing record spends only its own trail's reservation and
`MaxOpenTrails` bounds how much of the budget open trails can lock away; it
spends that reservation when the trail closes: a closing record within its
reservation is never refused on the budget, and only the bytes beyond it are
budgeted like any other record. When a closing append does fail, the gateway
delivers the upstream's result, never hiding that an effect happened, counts
the failure, and refuses every further material call until an append succeeds
again. `evidence.on_unwritable: allow_reads` is the explicit risk setting of
invariant 5: under it a read proceeds unrecorded, counted, and a material call
never does. A record with no call behind it, `FINDING_RAISED` or
`POLICY_RELOADED`, has nothing to block; a failed append there is an error its
producer reports and counts. The gateway's own telemetry, counters, health and
spans, never enters the spool; it has a bounded queue of its own and drops with
a counter when that is full. One process at a time owns a spool directory,
because two would interleave their records into one segment: opening a
directory another spool holds is refused.

**A torn write ends the log, it does not corrupt it, and damage is never
mistaken for a tear.** A tear can only be the last thing written: a segment is
synced before the log rolls to the next one, so an unfinished record can sit
only at the end of the last segment or of the quarantine file. There, the
record that does not check is where that file ends; the bytes after it are
discarded and counted, and the next append starts clean. Under `FsyncInterval`
the records since the last tick are not yet on disk, so a power loss can
persist a later one and not an earlier one: there the first record of the last
file that does not check ends it and what follows is a tear too, because
refusing to start would punish a loss the operator's own setting accepted. The
strict rule that follows holds under `FsyncEveryRecord`. A record that does not
check anywhere else, a record that checks after one that does not, an empty
segment before the last, or a sequence number outside the range the log can
name, is damage to evidence the spool reported durable: `Open` refuses with a
corruption error naming the segment and the byte, and changes nothing on disk,
so an operator decides what happens to it. The property that pins the first
half: cut a spool at any byte, reopen it, and every record before the cut
replays intact while nothing after it does. The second half is pinned by a
flipped bit in an earlier segment.

**The exporter drains the spool and never touches the request path.** The
exporter in `adapters/otel` reads from the acknowledged position, sends each
event to an OpenTelemetry collector as one OTLP log record over HTTP in the
protocol's JSON encoding, with the event's identifiers as attributes and the
JSONL line as the body, and acknowledges only what the collector accepted: a
200 or 202 whose body is empty, or is the protocol's own answer read strictly,
every member once, in either spelling but not both, nothing unknown in it and
no count larger than the batch. Anything else is not an answer. One run drains
a reader at a time, and a reader acknowledges only as far as it delivered, so a
second run cannot release what the first is still retrying. The endpoint is
https unless the operator names the risk of a plaintext one, because an
unauthenticated peer's empty 200 would otherwise release evidence and the
collector's credential would travel in the clear. It follows no redirect,
because a redirect would carry the evidence and the operator's credentials to a
host nobody configured, and a 3xx is an answer that did not accept. Everything
else, any other status, a body it cannot read, a timeout, a refused connection,
is retried with backoff and a bound on what is in flight, and a stopped run
begins again where the collector last acknowledged, so a record is never
released because a run ended mid-flight. Records a collector refuses as invalid
are found by halving the batch and are quarantined one by one, as is a record
the encoder cannot encode and a batch the collector says it partly dropped: the
quarantine is a file of the spool's own, framed and checksummed like a segment,
counted in the stats and against the budget, never deleted or rewritten by the
plane, and the cursor passes a record only once it is there. The quarantine
takes no more than the acknowledgement it precedes releases, and holds one copy
of a record, so a run cut short between quarantining and acknowledging cannot
write a second. It is written on the standard library: the request is one JSON
document in the protobuf JSON mapping of `ExportLogsServiceRequest`, and a
golden produced once from the protocol's own generated types, outside this tree
and described beside the golden, pins the encoding. The OpenTelemetry SDK's log
exporter would bring fourteen direct and twelve indirect modules into the
binary that sits in the request path, for batching and retry that are a hundred
lines here. A collector outage fills the spool, up to its budget, and then the
spool's rule above applies; the depth and the oldest unacknowledged record are
in the spool's stats and in the gateway's health answer, so an outage is
visible long before it blocks. The exporter carries no content the record does
not: capture is off by default and the record is metadata (ADR-0004); its
endpoint's credentials never reach a log line.

**A refusal's pointer is kept as canon renders it.** A refusal names where in
the envelope it failed as an RFC 6901 pointer of member names, bounded and cut
as `internal/canon` does it, and evidence keeps that pointer whole: a refusal a
reader cannot locate is worth nothing. A member name is where a value sat, not
the value, so the pointer is metadata. A key a producer supplied in a map is a
name too, and it appears in a pointer; the evidence page says so, so a producer
keeps content out of keys.

## Security / compatibility impact

The spool is the point where "fail closed on unavailable evidence" becomes
concrete: a full disk blocks material calls before their effect with a reason
the agent and the operator both see, never after it, and the only way a read
proceeds without a record is a setting whose name says what it risks. A record
is durable before a decision is answered, so an answer the agent saw is an
answer the evidence holds, at the fsync policy's granularity; a result the
agent saw after an I/O failure is one the gateway counted and stopped the plane
on. The exporter's failure modes are bounded by the budget and cannot reach the
kernel, and it adds no module to the tree. Nothing here changes the wire
contract; `EVIDENCE_UNAVAILABLE` is a registry code (ADR-0013).

## Alternatives considered

- **An embedded store or a write-ahead-log library.** Each adds a dependency
  in the request path, with a format of its own to audit and to keep readable
  when the library moves. The log here is a few hundred lines over a codec the
  tree already has.
- **Dropping evidence when the spool is full.** It turns a full disk into an
  unrecorded action, which is the failure the evidence exists to prevent.
- **Blocking on a closing record too.** The effect has happened; an error for
  it is a lie to the agent and an invitation to retry a non-idempotent call.
- **Exporting from the request path with a timeout.** Every collector hiccup
  then costs latency on the decision, and a timeout that trips is an outage
  shaped like a slow call.
- **The OpenTelemetry SDK's exporter.** Correct and maintained, and a
  dependency tree of that size in the request-path binary is what the
  dependency page exists to keep out when a hundred lines will do. OTLP over
  gRPC, which it would also bring, is `planned` only if a collector that takes
  no HTTP appears.
- **Writing the spool in `internal/evidence`.** It would put file I/O in a
  guarded tree; the interface goes there and the implementation does not.

## Consequences

An operator gives the spool a disk budget and an fsync policy, and watches its
depth. Evidence throughput is bounded by `every_record` fsync on the spool's
disk; the interval policy trades that for a stated loss window. The per-trail
reservation means the budget an operator sets is not all available to opening
records; the stats say how much is reserved. The exporter speaks OTLP over HTTP
in JSON and nothing else.

## Validation

The spool's own tests: the cut-at-any-byte property, over as many cases as the gate's default; a
flipped bit in an
earlier segment refusing `Open` with nothing deleted; the budget at the byte where a reservation
no longer fits; a closing record spending its reservation and its excess budgeted; the fsync
policy and the directory sync observed through the file seam, one sync per roll; acknowledgement
releasing whole segments only, and never past what a reader delivered; a second spool on one
directory refused; a broken spool answering its stats with the error and waking its readers.
The exporter's: nothing acknowledged but the protocol's own answer, with ten bodies that are not
it; no redirect followed, and the second host seeing no request; every other answer retried, per
class; a record the collector refuses three times, one the encoder cannot encode, and a batch the
collector partly dropped, each in the quarantine before the cursor passes it; a stopped run
sending again what it had taken; the request bytes against the golden; headers refused at
construction and credentials absent from every log line.

Shown with the gateway, by the suite beside it: a full spool blocking a
material call with `EVIDENCE_UNAVAILABLE` before its effect and letting a read
through only under the risk setting; a closing record still written while the
budget is reached; a sink that refuses a closing record halting material calls
until an append succeeds; and a collector outage blocking no decision, with
everything delivered when it returns.