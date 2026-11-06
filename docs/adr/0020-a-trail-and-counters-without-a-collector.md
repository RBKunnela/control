# ADR-0020: A plane's trail can land in a local file, and its counters in /metrics

Status: accepted
Date: 2026-09-24

Builds on [ADR-0004](0004-evidence-and-privacy-defaults.md),
[ADR-0014](0014-evidence-spool-and-sinks.md) and
[ADR-0016](0016-approval-providers-and-the-lost-hold.md).

Amended by [ADR-0072](0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md):
`collect` writes a bounded directory of segments bound to one tenant and
project, requires a credential, and `--out` is gone.

Amended when export gained a Unix socket: `collect --listen unix:///path`
listens on a socket as well as on the loopback, and a plane sends to it only
once the socket's peer is `export.collector_uid`
([docs/status.md](../status.md)).

## Context

A plane exports its evidence to an OpenTelemetry collector over OTLP/HTTP, and
`export.endpoint` is required: a plane whose spool nobody drains fills its
budget and then blocks material calls (ADR-0014). The spool is an outbound
queue, not a store: a segment acknowledged whole is deleted, so a healthy plane
holds almost none of its own trail (ADR-0016). A stranger trying the plane for
the first time has no collector, and nothing in this tree reads a trail back or
checks its chain outside the tests. The plane's counters reach `/healthz` as
JSON, which no metrics system scrapes.

## Decision

**The plane is unchanged.** It still requires a collector and exports to it as
ADR-0014 says. What changes is that this repository ships one.

**A collector of its own, as strict as the exporter.** `adapters/otel` gains
the receiving side of the one protocol it speaks: an `ExportLogsServiceRequest`
in the protobuf JSON mapping over HTTP, read strictly: each member once in its
JSON name, nothing unknown, an enum by name or by number, bounded. That is a
deviation from OTLP, whose receivers ignore members they do not know: this
receiver has one sender, and a member it does not know is a sender it does not
know. Every log record's body must be one JSONL line that decodes as exactly
one evidence event; a body holding a line break, or one that is not an event,
refuses the request with 400, which the exporter answers by halving the batch
and quarantining the record it cannot deliver (ADR-0014). A request over the
bound is answered 413. The encoder's golden request, decoded by the receiver,
gives back the golden's events.

**It acknowledges only what is on disk.** The collector appends each accepted
record to one trail file and syncs the file before it answers 200 with an empty
body, which the exporter accepts and OTLP's own encoded answer would only
restate, so the plane never releases a record the file does not hold. A write
or a sync that fails answers 503: the exporter retries, the spool fills, and at
its budget material calls block with `EVIDENCE_UNAVAILABLE`, as ADR-0014
already says. One process writes a trail file, under an exclusive lock; the
file is `0600` in a directory the group and others cannot write, because events
carry tenant and principal identifiers; an existing file is refused when the
group or others can write it. At open, a last line cut by a crash is removed,
when it can be the start of a line the codec writes: nothing unsynced was
acknowledged, so the spool sends it again. The writer
keeps an index of the event ids the file holds, rebuilt at open: a record sent
again after a crash between the sync and the acknowledgement is not written
twice, and an id that arrives with other content refuses the request (400), so
no event id carries two lines. Before each write and after each sync the writer
checks that its path, not followed, still names the regular file it holds, at
the size it left it; a file removed, renamed, replaced, cut or extended under
it, or a link put in its place, fails the writer for good and every later
request is answered 503, so nothing is acknowledged into a file nobody can
reach. Bytes rewritten in place, at the same size, are not detected. Open
refuses, and leaves as it was, a file whose whole lines are not events or
whose tail cannot be the start of one.

**Two commands, experimental.** `guardana-gateway collect --listen <addr> --out
<file>` runs the collector alone, on a loopback address only, since the plane
reaches a plaintext collector only on the loopback and only when the operator
says so (`export.allow_plaintext`). Dev mode runs the same collector in-process
on an ephemeral loopback port. `guardana-gateway trail <file>` reads a trail
file up to its last newline, within a bound per line and on the number of
events, collapses exact duplicates by event id, refuses one id carrying two
different lines as damage, groups the events by tenant, project and request,
runs the chain check on each trail in the order of its links, and prints one
line per trail: its request, its last event, and whether the chain check
passed, failed, could not be made, or the trail is still open. Bytes after the
last newline are a record being written when a collector holds the file, and
damage, exit 1, when none does. It exits 1 when any trail fails. The chain
check proves shape, not integrity, as the contract says, and the line says so.
Both commands live in the gateway's binary: the approver's binary may not link
evidence (ADR-0016).

**`/metrics` beside `/healthz`.** The health listener answers `GET /metrics` in
the Prometheus text exposition format, version 0.0.4, written on the standard
library: every counter and gauge the pipeline's statistics hold, the pause
reader's, the spool's, the exporter's and the adapter's, under a prefix the
product's name derives, each with a line of help taken from the code. A block
code or a pause cause outside its closed set is counted under `other`, so no
count is dropped and no label carries an identifier. A spool that cannot answer
sets a flag and leaves out only the spool's metrics, rather than writing them
as zero. A reading the text cannot carry truthfully, a counter below zero, a
pause state outside the four or counts outside a closed set that sum past a
counter's range, answers 503 for the whole scrape. A reference page
lists them, rendered from the same table and pinned by a test, so a counter
added to the code without a name, or a name the page lacks, fails the gate. No
client library joins the request path's binary.

## Security / compatibility impact

Nothing in the decision path, the spool or the exporter changes, and no rule of
ADR-0014 is relaxed: an acknowledgement still means the record is durable
somewhere else, and a collector that cannot write still makes the plane block
material calls at its budget. The collector listens on the loopback only and
takes no credential. The trail file holds what the evidence holds, metadata by
default (ADR-0004), and is created readable by its owner only; an existing file
keeps the read bits its operator gave it and is refused when the group or
others may write it or another account owns it. `/metrics` carries counts
and states, never an identifier, a digest or a reason; it is served on the
health listener, which binds where the operator configures it.

## Alternatives considered

- **A setting under which nothing is exported and the spool keeps every
  record.** The budget then blocks material calls once it is full, or it has to
  be lifted, which is an unbounded disk; and a reader of a spool another
  process holds would read the live segment's last frame one way while `Open`
  reads it as a tear, which makes the spool the state store ADR-0016 rules out.
- **A file export kind in the plane.** It works with no collector at all, and
  makes a permanent configuration surface in the request path's binary: an
  export interface where one exporter is enough, a conditionally required
  endpoint, and a file with no rotation that a production plane would be asked
  to support.
- **Requiring a third-party collector.** Correct, and the stranger's first run
  then starts with installing and configuring one.
- **A Prometheus client library.** Maintained and correct, and a dependency in
  the request path's binary for a text format of a few dozen lines.

## Consequences

A stranger's first run gets a whole trail from one command, and the demo
exercises the real export path. A served plane may use `collect` where a
collector would otherwise be a first install. Metric names become something a
dashboard depends on; while they are experimental a change is listed in the
changelog.

## Declared limits

- A trail file is never rotated or pruned, and its index grows with it. `trail`
  reads at most 100,000 events and refuses a longer file, which a busy plane
  reaches on its own.
- `collect` takes no credential: any local account that can reach the loopback
  port can write events into the trail, forged chains among them, and enough of
  them to pass `trail`'s bound; none can make one event id carry two lines.
- `collect` listens on the loopback only and writes one file.
- `trail` checks each chain's shape, not its integrity: there is no hash chain
  yet.
- The metric names are experimental until the first release.

## Validation

The exit criteria of the change that brings this record:

- The receiver: a fuzz target; one refusal test each for a body holding a line
  break, a body that is not an event, an unknown member and a request over the
  bound; the encoder's golden decoded back to its events.
- The trail file: a failed sync answers 503 and the exporter's cursor does not
  pass the record; a file cut at every byte of its last line reopens cut back to
  the last newline, and the record the spool sends again appears once; a tail
  that cannot start an evidence line, a one-line settings file among them, is
  refused and left byte for byte.
- The reader: a duplicate collapses, one id with two lines is refused, a
  partial last line is not read, an open trail is reported open.
- End to end: a plane exporting to the collector, one call of each outcome, and
  `trail` passing every chain; the collector stopped, the spool growing and a
  material call blocked at the budget; the collector back, and every record
  arriving once.
- `/metrics`: every field of the statistics appears, checked over the structs
  so a new one cannot be missed; the text parses under a strict reader of the
  format; a broken spool leaves out only its own metrics and sets its flag; a
  code outside the registry is counted under `other`; the rendered page is
  current.
