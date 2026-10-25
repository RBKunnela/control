---
title: Observations
summary: The source descriptor, what an import of OpenTelemetry GenAI spans keeps and drops, the observation log and its export.
type: reference
covers: [internal/observe/**, internal/observelog/**, internal/ingest/**, internal/lineexport/**, cmd/guardana-control/observe.go, api/proto/guardana/control/observe/**]
---

# Observations

An observation is what a source says an agent did: testimony, never a
decision. The plane never reads one, and nothing in it grants or refuses a
call ([ADR-0039](../adr/0039-many-channels-into-one-core.md)). The record is
`guardana.control.observe.v1alpha1`, version `0.1`, outside the v1
compatibility promise ([ADR-0040](../adr/0040-observations-a-record-a-log-and-one-importer.md)).
It is `experimental`; [status.md](../status.md) is the inventory.

## The source descriptor

A JSON file in which the operator describes one source, read under the
same owner checks as the stores. Every member is matched exactly; an unknown member, a
member given twice or `null` is refused, naming the member.

| Member | Required | Value |
| --- | --- | --- |
| `schema_version` | yes | `0.1` |
| `source_id` | yes | 1 to 128 characters of `A-Z a-z 0-9 . _ : -` |
| `kind` | yes | `otel-genai-traces` |
| `trust` | yes | `TRUST_SELF_REPORTED` or `TRUST_PLATFORM`; an agent's own process writes these spans, so `TRUST_INDEPENDENT` is refused |
| `convention` | yes | `{"name": "opentelemetry.gen_ai", "version": "1.41.0"}`; the conventions are still in development, so no other version is read |
| `otlp_version` | yes | `1.11.1` |
| `select.service_name` | yes | the `service.name` of the resource whose spans are this source's; spans of any other resource are not imported |
| `sampling` | no | `SAMPLING_COMPLETE` or `SAMPLING_PARTIAL`; absent or `SAMPLING_UNSPECIFIED` reads as partial, which `guardana-control coverage` prints as `sampled` ([coverage](coverage.md)) |
| `heartbeat_seconds` | yes | 1 to 604800: how long the source may stay silent before its paths are unknown; `guardana-control coverage` reads it ([coverage](coverage.md)) |
| `tenant_id`, `project_id` | yes | as `source_id` |
| `run_attribute` | no | the span attribute that names a run; never a content attribute |

Text values may not hold a control or format character, nor be only
whitespace, nor pass 256 bytes.

## What an import keeps

A span of the selected resource becomes an observation when its
`gen_ai.operation.name` is `execute_tool` (a tool, named by
`gen_ai.tool.name`), `invoke_agent` or `create_agent` (an agent,
`gen_ai.agent.name`), or `chat`, `generate_content`, `text_completion` or
`embeddings` (a model, `gen_ai.request.model`). Any other span is skipped and
counted by reason: `no_operation`, `unmapped_operation`, or one of the two
operations the conventions name that this importer does not map,
`operation:retrieval` and `operation:invoke_workflow`.

Only these are copied: the operation, the name above, `gen_ai.provider.name`,
`server.address`, `error.type` and the run attribute. A copied string longer
than 256 bytes, made only of whitespace, or holding a control, format, line or
paragraph separator, private-use or noncharacter code point or U+FFFD, is dropped and
counted. A span's name and its status message are never copied.

| Field | From the span |
| --- | --- |
| `event_time` | its end time; absent when it has none, never the time it was read |
| `received_time` | the import's own clock reading, the same on every record of one import |
| `stage` | failed when the status is error or `error.type` is present, completed when it ended, unknown otherwise |
| `outcome.status` | the status as sent: unset, ok or error |
| `correlation.trace_id`, `span_id`, `parent_span_id` | the span's ids, lowercase hex as the gateway records a call's trace; a span with no trace or span id, or a zero or upper-case id, or a status code outside 0 to 2, is refused |
| `correlation.basis` | `BASIS_CLAIMED` when the run attribute holds `run-` and 32 lowercase hex digits, the form of a run an operator opened; any other value is dropped and counted, and the basis is `BASIS_NONE`. Whether the run exists is not checked |

## What an import drops

No content is kept in `0.1`: there is no redaction to apply to it, and a
capture setting is refused. Every content attribute (`gen_ai.input.messages`,
`gen_ai.output.messages`, `gen_ai.system_instructions`,
`gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`,
`gen_ai.tool.definitions`, `gen_ai.prompt`, `gen_ai.completion`) and every other `gen_ai.*` attribute outside the
list above is dropped and counted, on a span and on its events, and in the
report wherever else the selected resource carries one; so is
`gen_ai.request.model` on a span that is not a model's. Message parts are
parsed only to count reasoning: a part of type `reasoning` or `thinking` is
counted and nothing of it is kept; a value that is not an array of messages
whose parts each name a type is counted as unparsed, never as none.

## The log

One file, `observations.jsonl`, in a directory of the operator's account that
no other account can reach, held by one writer at a time. Each line holds one
observation or one import report. An observation's id is derived from its
tenant, project, source, trace and span, so importing the same spans again
writes nothing new: a span already in the log with the same content is a
duplicate. One whose content differs, apart from its receive time and the
descriptor's digest, is a conflict: it is not written, and the import exits
1. The observations an import keeps
and its report are appended together and synced, the report last; after a crash
in that append, the next open cuts everything after the last whole report;
a tail no writer of this package leaves is refused, not cut. An append that
would take the file past 1 GiB is refused and writes nothing: the log is then
rotated by hand.

Each import ends with one report: the source, the descriptor's SHA-256, the
receive time, the input's first-line digest and size, every count above, and
the earliest and latest event time. A source was last heard at its newest
event time not later than a report's receive time.

A span the import refused was never written, and of a conflict's two copies
either may be the false one, so each may hide a call of the run it claimed.
The report's `doubted_run_ids` names those runs, ascending, at most 64: a
refused span's, and both copies' of a conflict, save a kept copy that claims
no run, which adds none. A refused span or a
conflict's refused copy that claims no run, a line refused before its spans
are read, or a 65th run sets `every_run_doubted` instead. A report that counts
a refusal or a conflict and names no run, as a `0.1` report does, is read as
doubting every run; [supervision](supervision.md#the-verdict) says what a
doubted run leaves unchecked. A source's doubt is read from its own reports
alone, those naming its source, tenant and project, so another source
importing into the same log directory puts none of its runs in doubt.
`supervise` refuses a `--source` whose tenant or project is not the run's.

A report that carries either member is schema `0.2`; every other report and
every observation is `0.1`, and the reader refuses a `0.2` record with
neither and a `0.1` report with one. A reader of `0.1` alone, such as an
earlier release's, refuses every `0.2` line.

A doubt has no time bound: it holds for as long as the log holds the report,
and a doubt of every run reaches every later run of the source. Only rotating
the log ends it: with no import running, move `observations.jsonl` out of its
directory by hand, and the next import starts a new file. The observations
the old file held go with it; until that import, `supervise` finds the source
never heard.

## Commands

```
guardana-control observe import --source <descriptor> --log <dir> <file>
guardana-control observe export [--after <cursor>] [--limit <n>] [--max-bytes <n>] <file>
```

`import` reads OTLP/JSON trace lines, one `TracesData` object per line as an
OpenTelemetry collector's file exporter writes them, up to the last newline;
the bytes after it are left for the next import, since the exporter may still
be writing them. A line with an unknown member, a member twice, an attribute
twice, a `null`, an enum spelled as a string, nesting deeper than 32 or more
than 262,144 array elements is refused, and every span in it is counted as
refused. A line over 16 MiB is refused. The import reads its whole input into memory. An input over 256 MiB is
refused whole. Exit 0: every span read was imported, skipped or a
duplicate. Exit 1: something was refused or conflicted; the report says
what. Exit 2: the import did not complete, for a usage error, a descriptor or
a log refused, or a write that failed; a write refused only after its sync, or
a log that would not close, can leave the import in the log, and an import of
the same file counts it as duplicates.

`export` writes `guardana.control.observation-export` version `0.1`, in the
evidence export's shape ([ADR-0035](../adr/0035-a-versioned-evidence-export-and-a-bounded-query.md)):
a header, `observation` and `import_report` records, gaps (`malformed`,
`unsupported_version`, `carriage_return`, `conflicting_observation_id`,
`too_long`, `partial_tail`),
duplicates and a trailer with the cursor to resume from, and the same exit
codes. It has no filters. It reads only a file the writer would open: a
regular file of this account, not a link, that the group and others cannot
reach, with no other name. It reads to the last import report, as a writer
keeps the log: what follows is a write still open, or one a crash left that
the next writer cuts, counted in the trailer's `tail_bytes` while a writer
holds the log and a `partial_tail` gap when none does. It reads back from
the end only as far as that report, and `scanned_bytes` leaves those bytes
out. A log over the size bound, or whose lines after that report no writer
leaves, is read to its last newline. Each line after the report is judged
alone, so one that repeats an earlier id with other contents, which no
writer leaves, counts in that gap rather than as a conflict.
