---
title: Privacy
summary: What the plane records about a call, where each record goes and who can read it, how long it stays, and that nothing goes to the project.
type: explanation
covers: [internal/evidence/**, adapters/mcp/translate.go, adapters/mcp/answer.go, adapters/mcp/trace.go, adapters/mcp/adapter.go, internal/gateway/authorize.go, internal/gateway/flow.go, internal/spool/**, adapters/otel/**, internal/trailfile/**, internal/metrics/**, internal/approvals/**, internal/holdjournal/**, internal/pause/**, internal/console/**, adapters/authzen/mapping.go, cmd/guardana-gateway/**, internal/observelog/**, internal/findinglog/**, internal/notify/**, internal/reaction/**]
---

# Privacy

The plane records what a call was about, not what it said. A tool call's
arguments and its result are recorded as hashes; the one piece of argument
text that can enter a record is a resource id the operator told the plane to
read out of them. A resource read's URI and a prompt's name are recorded as
the agent sent them. Nothing turns content capture on in this build, and hidden
model reasoning is never stored
([ADR-0004](../adr/0004-evidence-and-privacy-defaults.md), invariant 9).
What the plane defends against is on the [threat model](threat-model.md)
page.

## What an evidence event holds

Every call the plane can name leaves a trail of events
([evidence](evidence-and-the-spool.md)), with three exceptions: a read the
operator lets run unrecorded when the spool cannot take its events
(`evidence.on_unwritable: allow_reads`), a call refused because its
request id already has an open trail, and a call blocked because the sink
refused its first event. The MCP adapter and the pipeline fill them as below
(`adapters/mcp/translate.go`, `adapters/mcp/answer.go`,
`internal/evidence/event.go`).

Every event carries `event_id`, `kind`, `request_id`, `project_id`,
`tenant_id`, `occurred_at`, `schema_version`, the plane's `enforcement_mode`,
`prev_event_id` and, where the call belongs to a run, `run_id`, an id the
plane mints or, under `runs.dir`, the id of the run the operator opened. `execution_id` is on the events of a call handed to execution.
`prev_event_digest` is left empty.

`ACTION_PROPOSED` carries the envelope:

| Field | What this plane puts there |
| --- | --- |
| `request_id`, `occurred_at`, `project_id`, `tenant_id`, `environment` | an id the plane mints, the clock, and the configuration |
| `principal` | `id`, `type` and `tenant_id` from `listener.principal`, the plane's `tenant_id` when it names none; no end user, since no key wires an authenticator |
| `agent` | `id`, `framework` and `version` from `listener.agent` |
| `action` | `kind` (`tool`, `resource` or `prompt`), `name` (the tool's name, the resource's URI or the prompt's name), `protocol` `mcp`, the effect class, and `provider`, the upstream's name |
| `resource` | the override's `type`, and `id`: the string or number at the override's `resource_from` pointer into the arguments, none for another value, the URI of a `resources/read`, or the name of a `prompts/get`; the upstream's `tenant_id` and `environment`. An action name or resource id refused as over-long is recorded as `overlong:sha256:` and the hex SHA-256 of what was sent |
| `destination` | the override's trust zone, when it names one |
| `arguments` | `canonical_hash` only: a SHA-256 of the canonical arguments |
| `trace_id`, `span_id` | the trace id and the parent id of a version `00` `traceparent` in the request's `_meta`, the client's claim; empty without one |
| `context.tags` | `mcp.client=` with the name and version the client reported, `mcp.protocol_version=`, and the plane's flow tags: whether the run took in untrusted content, and the highest sensitivity it read, or `flow.v1.state=uncomputed` when the plane kept no run state for the call |

Left empty by this plane: `principal.authn_strength`
and `attributes`, `agent.instance_id` and `model_ref`, `delegation`,
`resource.labels`, `destination.host`, `data`, `arguments.redacted_preview`,
`schema_ref` and `redaction_profile`, and every other `context` field.

`POLICY_DECIDED` and `ACTION_BLOCKED` carry a decision: the verdict, the
reason codes, the ids of the rules that matched, the obligations as the
policy wrote them, the action digest, the bundle digest, timings, and, when a
decision point was asked, its identifier.

`APPROVAL_REQUESTED`, `APPROVAL_DECIDED` and `APPROVAL_EXPIRED` carry the
approval: its ids, the action digest, the bundle digest, its state and times,
and on an answer the `approver_id` and the optional `--reason` exactly as the
approver typed them.

`ACTION_STARTED` carries no payload. `ACTION_COMPLETED` and `ACTION_FAILED`
carry the result: its status, when it started and ended, the protocol's own
status (`ok`, `isError`, `input_required` for an upstream that asked for input, `timeout`, `error`, `unhashable` for a result that
cannot be encoded, whose status is then `UNKNOWN`, or a JSON-RPC error code,
each after `withheld:` when the answer quoted a credential the plane sends and
the agent was given a fixed answer instead), a
SHA-256 of the result's JSON encoding when there was one, and the digest of
the bytes that were sent. Neither an error message from the upstream nor any
part of the result is kept (`resultOf` in `adapters/mcp/answer.go`). An
`ACTION_FAILED` for a call that was never sent carries the status `BLOCKED`
and the code that stopped it, and no digest of sent bytes.

This plane writes no `POLICY_RELOADED` and no `FINDING_RAISED`.

A hash is not anonymity. Arguments or a result with few possible values, such as a month or a yes,
can be recovered by hashing each guess and comparing.

## Capture and reasoning

ADR-0004 lets an operator opt in to capturing content. This build has no
setting for it: the MCP adapter builds the arguments message with the hash
alone, the authorized envelope clears any preview
(`internal/gateway/authorize.go`), and the plane clears both previews and
their profiles from every event it hands the sink, whatever an adapter set
(`uncapture` in `internal/gateway/trails.go`). Capture is off, and nothing turns it on.
The collector that `collect` runs clears the same fields from every event it
receives before its trail file holds it, so a previewed event another producer
sends is not kept either (`adapters/otel/receiver.go`).

Hidden model reasoning is never stored at any setting. MCP does not carry it
to the plane, no field of the contract holds it, and no adapter reads it.

## Where records go, and who can read them

| Where | What | Who can read it |
| --- | --- | --- |
| the plane's memory | a held request, its envelope and its decision; without `runs.dir`, the run state of each principal | the plane's process: a held request until its hold ends, a run's state until the plane stops |
| the runs directory, `runs.dir` | each run's record, its tenant, principal, agent, lifetime and the SHA-256 of its token's secret, and each root run's flow state | the operator's account, in a directory only it may write, until the operator removes them |
| the spool, `evidence.dir` | every event, one framed JSON line each, until a collector accepts it or it is moved to `quarantine.log` | the plane's account: new files are `0600`; the directory must be the plane's account's and writable by no one else, and an existing segment or `quarantine.log` is refused when another account owns it or a group or others may write it |
| the collector at `export.endpoint` | every event, as the body of one OTLP log record, with its ids, kind and mode as attributes | whoever runs that collector and wherever it sends them; `https`, or plaintext to a loopback IP literal under `export.allow_plaintext` |
| a trail file written by `collect` | every event the collector accepted, at least once | the account that ran `collect`: a new file is `0600`, and an existing one is refused when another account owns it or a group or others may write it |
| the approvals directory | per held call, the approval record and a projection: principal, agent, tool, upstream, resource type and id, effect class, rule ids, times | the plane's account: records are `0600`, and the directory is refused when another account owns it or others may write it |
| the approvals page and `approvals list` | the projection, and the approval's state, ids, digests, expiry and approver; no arguments, no preview, no trail | the page: whoever holds its session, on `127.0.0.1` ([reference/console](../reference/console.md)); `approvals list`: any account that can read the approvals directory |
| the hold journal, `approvals.hold_journal_dir` | per hold, the trail's ids, the binding, the approval and its expiry; no envelope and no decision | the plane's account: entries are `0600` |
| the floor directory, `policy.state_dir` | per bundle id, the serial, digest and `issuedAt` of the newest freshness statement taken, and the reason and prior value of the last reset | the plane's account: the directory is owner-only and its files `0600` |
| the pause file | each entry's scope and its optional reason | the plane's account, and any account the file's and directory's modes let read it |
| the stop list, `reaction.stops` | per stop the tenant, run id, finding id, procedure, rule and times; per covered finding its id, tenant and run; per lift the run, a line number and its signature | the plane's account, and any account the file's and directory's modes let read it: a new list is `0600`, and the list is refused when another account owns it or its directory, or a group or others may write either |
| the decision point at `pdp.identifier` | the principal, the action, the resource with its id, the destination, the data labels and the ids; never the arguments, their hash or a digest | whoever runs it, and a proxy configured for it ([ADR-0017](../adr/0017-an-external-decision-point-can-veto.md)) |
| `/metrics` and `/healthz` | counts and states; `/healthz` also the mode, the bundle's id, version, digest and serial, its confirmation and expiry times, and the ids of pause entries that match no listed tool; with a route, also the route's id, serial and digest, its floor's serial and digest, the stop list's `list_id`, state and age, and, for each active stop up to 64, its entry id, run id, finding id, rule id and expiry, and the run ids of those stops the runs directory does not hold or cannot read. No metric label carries an identifier, a digest or free text; `pipeline_blocks_total` is labelled with a reason code ([reference/metrics](../reference/metrics.md)) | anyone who reaches `health.address`, which takes no credential |
| the observation log, `observe import --log` | per observation its source and trust, its times, the tool name and server address it names, and its correlation ids; never a prompt, an output or reasoning | the operator's account: the directory is owner-only and the log `0600` |
| the findings log, `supervise --findings` | per finding the tenant, project, procedure, rule, verdict and the ids of the events and observations it cites | the operator's account: the directory is owner-only and the log `0600` |
| notify's state, `notify --state` | the keys delivered and the digest of the findings log's first line | the operator's account: owner-only, files `0600` |
| the program `notify` runs | each alert finding's record, one JSON line on its standard input | that program, and wherever it sends it |
| the plane's log, on stderr | messages with ids such as `request_id`, `execution_id` and an upstream's name, and error text, never an upstream's or a collector's URL past its scheme and host, an upstream's error message, which is logged by its code, nor a transport error's text, which is logged by its type; header values are never printed | wherever the operator sends stderr |

The upstream server receives the authorized arguments, as it would without
the plane. A plane in `OBSERVE` sends the proposed ones.

## How long records stay

| Record | Removed when | What the operator does |
| --- | --- | --- |
| a spool segment | every record in it is accepted by the collector or moved to `quarantine.log` | nothing; `evidence.max_bytes` bounds what waits |
| `quarantine.log` in the spool | never: the plane does not remove it, and its bytes count against the budget | decide what to keep; nothing in this build prunes it |
| the trail file | never: it is not rotated or pruned, and `trail` reads at most 100,000 lines | stop `collect`, move the file, start `collect` again; a file moved under a running collector stops it taking records |
| an approval record and its projection | at a plane's start, once its approval has expired, whether it was consumed or not | nothing removes them while a plane runs; a directory left to grow refuses holds at `approvals.max_records` |
| a hold journal entry | when its trail can take nothing more | nothing |
| a pause entry | when an operator removes it; the file keeps no history | nothing |
| a stop list's line | never: lines are appended, and a lift ends a stop without removing it; a list is refused past 4 MiB or 20 000 lines | start a new list with `stops init --carry`, which keeps every unlifted stop, and restart the plane |
| the collector's copy, the log | as the operator's systems keep them | the operator's retention |
| the observation log and the findings log | never: neither is rotated or pruned, and each is refused past 1 GiB | move the directory aside and start a new one |
| notify's state | never | delete it; `notify --init` on a new state delivers every alert again |
| a `dev` state directory | never: it is left behind when `dev` stops | delete it |

No command finds or deletes the records about one person. A plane without
an authenticator records one configured principal for every call, so a
person's identity enters a record through what the operator configured, what
an approver or an operator typed, or what a call names: a resource id, a URI,
a tool or prompt name, the client's reported name.

## Nothing goes to the project

The binaries connect only to addresses the operator configures: the upstreams,
the collector, the decision point and its proxy, and, for `scenario run`, the
plane it tests. No address of the project or its authors is built into them,
and they send no usage data, crash report or update check.
