# ADR-0040: Observations: a record, a source descriptor, a log and one importer

Status: accepted
Date: 2026-10-04

Amends [ADR-0039](0039-many-channels-into-one-core.md): in version 0.1
content is always dropped and a capture setting refused. Builds on ADR-0039,
which accepted the observation as testimony and named its contract, and on
[ADR-0035](0035-a-versioned-evidence-export-and-a-bounded-query.md), whose
export shape it reuses. Applies [ADR-0002](0002-wire-contracts-and-versioning.md)
and [ADR-0004](0004-evidence-and-privacy-defaults.md).

Amended by [ADR-0045](0045-one-run-is-supervised-against-its-procedure.md):
`internal/supervise`, the sixth guarded tree, imports `internal/observe`; the
test below holds the plane's five trees, not every guarded tree, away from
observation code.

Amended by [ADR-0058](0058-a-copy-an-import-never-read-is-doubt-for-the-runs-it-claimed.md):
the reader's table below holds `0.1` and `0.2`. An `ImportReport` naming the
runs its refused copies claimed is `0.2`; every other record stays `0.1`.

## Context

ADR-0039 fixed what an observation says and left its shape open. The first
source is an agent runtime's OpenTelemetry traces under the GenAI semantic
conventions, which are still in development: the last core release that holds
them is 1.41.0, and their own repository has no release yet. A review of the
first proposal found that most of its defaults failed open: a capture switch
would have stored raw prompts under the name of a redaction nothing applies,
one descriptor would have stamped its tenant on every service in a collector's
file, a zero sampling flag read as "sees everything", a zero heartbeat as
"never silent", a source's liveness came from when a file was imported, and a
re-import minted new ids, so no duplicate was ever seen.

## Decision

**A package of its own, outside the v1 promise.** `guardana.control.observe.v1alpha1`
in `api/proto/guardana/control/observe/v1alpha1/` holds `Observation`,
`ImportReport` and `SourceDescriptor`, and imports nothing from v1. `buf.yaml`
ignores exactly that path for breaking changes, and a CI probe proves v1 is
still examined: a field renumbered in v1 fails, the same change in the observe
package passes, and a missing `buf` fails the job. `schema_version` is
`"0.N"`; a reader takes exactly the minors in its table, `0.1` today, and
refuses another minor, another major, an absent or a malformed one, because an
alpha minor promises nothing. An enum number a reader does not know reads as
its restrictive meaning.

**An observation.** `schema_version`, `observation_id`, `tenant_id`,
`project_id`; `source` (`source_id`, the descriptor's SHA-256, `trust`,
`convention` name and version); `event_time`, absent when the source gave
none, never filled with another time; `received_time`, one value per import;
`stage`; `subject` (`kind`: tool, model or agent; `name`, `operation`,
`provider`, `server_address`); `outcome` (the span status as sent: unset, ok
or error; `error_type`); `correlation` (`basis`, `run_id`, `trace_id`,
`span_id`, `parent_span_id`); and `content_attributes_dropped`. No mode,
verdict, decision or content. Zero values mean the least: trust unspecified
is self-reported, basis unspecified is none, stage unspecified is unknown. The
importer always writes explicit values.

**Identity and duplicates.** The key is tenant, project, source id, trace id
and span id. `observation_id` is `obs-` and 32 hex digits of a domain-separated
SHA-256 of the key, so a re-import yields the same id. A key already in the log
with the same content, its receive time and the descriptor's digest aside, is a
duplicate, not appended and counted; with other content it is a conflict, not
appended, counted, and the import exits 1. A span
whose trace or span id is missing, zero or not lowercase hex of 32 and 16
digits cannot be keyed and is refused. Ids are spelled as the MCP adapter
spells an envelope's `trace_id` and `span_id`, so a later join is byte
equality.

**A source descriptor.** A strict JSON document read under the owner checks
the stores use: `schema_version`, `source_id`, `kind` (`otel-genai-traces`),
`trust` (required; `independent` is refused for this kind, whose spans the
agent's own process writes), `convention` (`opentelemetry.gen_ai` `1.41.0`
only), `otlp_version` (`1.11.1` only), `select.service_name` (required, matched
exactly against a resource's `service.name`; spans of any other resource are
not imported and are counted), `sampling` (complete or partial; unspecified
reads as partial), `heartbeat_seconds` (required, from 1 to 604800),
`tenant_id`, `project_id` and an optional `run_attribute`. Every member is
matched exactly; an unknown member, a capture setting among them, is refused.

**No content in 0.1.** ADR-0004's redaction is not built, so nothing could
honour a capture setting. Every content attribute (`gen_ai.input.messages`,
`gen_ai.output.messages`, `gen_ai.system_instructions`,
`gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` and any other
`gen_ai.*` attribute outside the allowlist below) is dropped and counted:
on an observed span in its own count, and wherever else the selected
resource carries one (its attributes, its scopes', links, skipped spans) in
the import's.
Message parts are parsed only to count reasoning: a part whose `type` is
`reasoning` or `thinking` is counted as reasoning, and a value that does not
parse is counted as unparsed, never as zero. Capture returns as an added field
once a redaction exists.

**An allowlist, not a denylist.** The importer copies only these into typed
fields: `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.request.model`,
`gen_ai.provider.name`, `gen_ai.agent.name`, `server.address`, `error.type`,
and the descriptor's `run_attribute`. A copied string over 256 bytes, or
holding a control, format, line or paragraph separator, private-use or
noncharacter code point or U+FFFD, is dropped and counted. A span's name and its status message
are never copied. `execute_tool` is a tool, `invoke_agent` and `create_agent`
an agent, `chat`, `generate_content`, `text_completion` and `embeddings` a
model; any other span is skipped and counted. Stage is failed when the status
is error or `error.type` is set, completed when the span ended otherwise, and
unknown without an end time.

**Correlation.** The basis is `claimed` when the descriptor names a
`run_attribute` and the span's value has the form of an opened run's id
(`run-` and 32 lowercase hex digits); a value of any other form is dropped and
counted, and the basis is `none`. The importer never reads the runs directory:
whether that run exists, and whether its source may speak for it, is the
join's question (`joined`, B15). `bound` needs a run's token inside a span and
is not reachable from this importer.

**What an import leaves.** One `ImportReport` per import, in the same log:
the source id, the descriptor's SHA-256, `received_time`, the input's
first-line digest and bytes read, counts (read, observed, skipped by reason,
duplicate, conflict, other resource, refused, content attributes dropped,
reasoning parts dropped, content left unparsed, run ids dropped) and the
earliest and latest `event_time`. A source was last heard at its newest
`event_time` that is not later than that record's `received_time`; a record
without an event time does not count, and a later one is taken at
`received_time`. The importer never adjusts a time for skew.

**A log and its export.** One JSON Lines file in an owner-only directory with
a lock, each line one record, compact and escaped as the evidence writer
writes its lines. `guardana-control observe import --source <descriptor>
--log <dir> <file>` reads OTLP/JSON `TracesData` lines up to the last newline;
an unknown member, a duplicate member, a duplicate attribute, or more array
elements than one 64th of the line bound refuses that line, counted, exit 1,
so a line costs memory in proportion to its length. `guardana-control observe export [--after <cursor>]
[--limit <n>] [--max-bytes <n>] <file>` writes
`guardana.control.observation-export` version `0.1`: ADR-0035's header,
records of type `observation` and `import_report`, gap, duplicate and
trailer, the same cursor grammar and exit codes, and no filters yet. The
cursor and the line reader move out of `internal/trailfile` into one package
both exports use; the trail file's goldens prove its export unchanged.

**Where the code goes.** `internal/observe`: the version table, the
descriptor's validation, id derivation and the reading of enums, pure, for a
future `internal/supervise` to import. `internal/observelog`: the log and its
export. `internal/ingest/otelgenai`: the importer. A test lists the
dependencies of the five guarded trees, `cmd/guardana-gateway` and
`adapters/...` and fails on anything under the observe package,
`internal/ingest`, `internal/observe` or `internal/observelog`.

## Security / compatibility impact

No v1 contract, digest, reason code or decision path changes; the plane never
reads an observation. Default-deny holds for content: nothing a prompt or a
tool carried is stored. A descriptor is read under owner checks and its trust
is never taken from the data. It is unsigned in 0.1, so no finding may stop a
run on its trust until descriptors are signed under the route key
(ADR-0039).
Self-reported spans can lie; an observation says what a source claimed, and
`claimed` is the strongest basis this importer gives.

## Alternatives considered

- The first proposal: a capture switch, a sampled flag, a random id, a
  runs-directory lookup. Each failed open or gave the importer authority it
  did not need.
- A JSON schema and no typed package: ADR-0039 rejected it; a sensor in
  another language gets nothing to compile against.
- A second buf module for the observe package: two configurations and two
  generate paths kept in step, for what one ignore path gives.
- A copy of the trail file's cursor: two implementations of one public cursor
  grammar drift.

## Consequences

B17's acceptance reads with two changes: content is always dropped and a
capture setting refused in 0.1, and its "unknown run" fixture is a malformed
run id, since the importer does not look runs up. B18 reads descriptors for
trust, sampling and heartbeat, import reports for liveness, and subjects for
paths. Package path, field numbers, enum zero meanings, id derivation, the
key and the export's name are expensive to change once a release carries
them; fields are cheap to add.

## Validation

- The CI probe: v1 renumbered fails `buf breaking`, observe renumbered passes.
- The reach test, and its negative control: the same check finds every
  observation tree in the control's command line, which imports them.
- Descriptor cases: capture, a sampled flag, heartbeat 0, no trust,
  `independent` for this kind, an unpinned convention or OTLP version, and a
  `run_attribute` naming a content key, each refused.
- Importer fixtures: a mixed-service file, a re-import, a conflicting resend,
  a zero id, duplicate attributes, an unset status, a reasoning and a
  `thinking` part, an oversized tool name, a status message, an old file and
  a future time, a sampled source, an event with no time, a malformed run id;
  each with its records and counts.
- The trail file's export goldens byte-identical after the read side moves.
