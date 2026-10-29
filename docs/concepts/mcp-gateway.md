---
title: The MCP gateway
summary: How a tools/call becomes a decision, an authorized set of bytes and a trail, before the server sees it.
type: explanation
covers: [adapters/mcp/**, adapters/authzen/**, internal/gateway/**, cmd/guardana-gateway/**, internal/spool/**]
---

# The MCP gateway

An agent's call to a Model Context Protocol server is where an agent stops
talking and starts acting. The gateway sits in that gap: it translates the call
into an `ActionEnvelope`, asks the kernel, does what the mode says, sends exactly
the bytes that were authorized, and appends the trail that names the policy
version behind the decision. Two revisions of the protocol are live and they are
different protocols, so the gateway serves both and keys what it can do on the
one that was negotiated.

## One call, end to end

```mermaid
sequenceDiagram
    accTitle: One call, end to end
    accDescr: The listener turns a tools/call into an envelope, the pipeline has the kernel decide and may ask a decision point, the opening events are written before anything runs, the listener sends exactly the authorized bytes, and the trail closes with the executed digest.
    participant Agent
    participant Listener as Listener (adapters/mcp)
    participant Plane as Pipeline (internal/gateway)
    participant Kernel as Kernel (internal/core)
    participant Sink as Spool (internal/spool)
    participant PDP as Decision point (adapters/authzen)
    participant Server as MCP server

    Agent->>Listener: POST tools/call, Mcp-Method and Mcp-Name
    Note over Listener: headers route, the body decides
    Listener->>Plane: Admit(envelope, proposed arguments)
    Plane->>Kernel: Decide(envelope, snapshot)
    Kernel-->>Plane: verdict, rule ids, obligations
    opt the plane has no cause of its own to block the call, and the decision turns on the answer and is not DENY
        Plane->>PDP: ask about the envelope, within pdp.timeout
        PDP-->>Plane: an answer, or silence
        Plane->>Kernel: Decide again with the answer
        Kernel-->>Plane: the decision that is recorded
    end
    Plane->>Plane: apply rewriting obligations, decide the authorized envelope again
    Plane->>Sink: ACTION_PROPOSED, POLICY_DECIDED, ACTION_STARTED
    Sink-->>Plane: appended, on disk under evidence.fsync every_record, closing record reserved
    Plane-->>Listener: Disposition: execute, authorized bytes and digest
    Listener->>Listener: digest the bytes about to go
    Listener->>Server: tools/call with exactly those bytes
    Server-->>Listener: result
    Listener->>Plane: Close(disposition, bytes sent, result)
    Plane->>Sink: ACTION_COMPLETED with the executed digest
    Listener-->>Agent: the upstream's result
```

Sources: `adapters/mcp/middleware.go`, `internal/gateway/admit.go`,
`internal/gateway/decisionpoint.go`, `adapters/authzen/client.go`,
`internal/gateway/close.go`, `internal/spool/append.go`.

A blocked call stops in the pipeline: the disposition says block, the trail
ends with `ACTION_BLOCKED` when the spool takes it, and is otherwise blocked as
`EVIDENCE_UNAVAILABLE`, and the agent gets a tool result with `isError: true`
carrying the reason codes, or a JSON-RPC error carrying them for a resource
read or a prompt. The server is never called. A call the adapter could not
translate is blocked so in every mode, `OBSERVE` included, with the kernel's
code for the refusal. A call the adapter refuses after an allow, such as one
whose bytes the protocol cannot carry, is aborted, and its trail ends with
`ACTION_FAILED`.

## The same call on each revision

The two revisions differ in what reaches the middleware and how. On
`2026-07-28` a stateless listener takes every request on its own: the
protocol version, the client's claim and its capabilities travel in each
request's `_meta`, and the `Mcp-Method` and `Mcp-Name` headers route it. The
library checks those headers against the body before anything of the adapter
runs, and the middleware decides from the body, never from a header.

```mermaid
sequenceDiagram
    accTitle: A call on the stateless revision
    accDescr: On 2026-07-28 the stateless handler checks the routing headers against the body before the adapter runs; the adapter hands the envelope to the pipeline and answers with the result, the reason codes or the pending state.
    participant Agent
    participant Library as Streamable HTTP handler, stateless
    participant Adapter as Middleware (adapters/mcp)
    participant Plane as Pipeline (internal/gateway)
    Agent->>Library: POST tools/call with Mcp-Protocol-Version 2026-07-28, Mcp-Method, Mcp-Name and _meta
    Note over Library: no session and no initialize, and a header that disagrees with the body is -32020 before the adapter runs
    Library->>Adapter: the parsed request
    Note over Adapter: identity from the listener, clientInfo and the revision as run-context tags
    Adapter->>Plane: Admit(envelope, proposed arguments)
    Plane-->>Adapter: disposition
    Adapter-->>Agent: the result, or isError with the reason codes, or the pending state
```

Sources: `adapters/mcp/listener.go`, `adapters/mcp/middleware.go`,
`adapters/mcp/translate.go`.

On `2025-11-25` a stateful listener serves a session: the agent initializes
first, and every later request rides on that session. A `2026-07-28` request
on this listener is answered `-32022` with the versions served, by the
library and before the pipeline is asked anything, so a client renegotiates
instead of losing the connection. `initialize` itself is not the
middleware's: it goes to the library's own handler, like every method the
middleware does not answer. A session idle for `listener.session_idle`,
30 minutes by default, ends, so sessions a client opens and abandons do not
hold the plane's memory; the client initializes again. At most
`listener.max_sessions`, 1024 by default, are live at once, and an open past
them is answered `503`; without authentication the cap bounds memory, not
fairness, since one client that keeps its sessions active can hold every place.

```mermaid
sequenceDiagram
    accTitle: A call on the stateful revision
    accDescr: A stateful listener answers a 2026-07-28 request with -32022; the client initializes on 2025-11-25 and calls on that session, and the adapter hands the envelope to the pipeline as on the other revision.
    participant Agent
    participant Library as Streamable HTTP handler, stateful
    participant Adapter as Middleware (adapters/mcp)
    participant Plane as Pipeline (internal/gateway)
    Agent->>Library: a request on 2026-07-28
    Library-->>Agent: -32022 with the versions served
    Agent->>Library: initialize on 2025-11-25
    Library-->>Agent: the session
    Agent->>Library: POST tools/call on the session
    Library->>Adapter: the parsed request
    Note over Adapter: identity from the listener, the negotiated revision as a run-context tag
    Adapter->>Plane: Admit(envelope, proposed arguments)
    Plane-->>Adapter: disposition
    Adapter-->>Agent: the result, or isError with the reason codes, or the pending state
```

Sources: `adapters/mcp/listener.go`, `adapters/mcp/middleware.go`,
`adapters/mcp/translate.go`.

## Which trace a call belongs to

An agent runtime that traces its work can say which trace a call belongs to:
OpenTelemetry's conventions for MCP put W3C trace context in the request's
`_meta` under the unprefixed key `traceparent`, on every transport. The
adapter copies the trace id and the parent id of a version `00` value into the
envelope's `trace_id` and `span_id`, so a trail can be joined to the
runtime's spans. A value of any other shape, or none, leaves both empty,
which claims no correlation, and never refuses or changes the call. The
digest leaves both out, and nothing that decides, pauses or holds a call
reads them. They are the client's claim: a reader joining on them learns
what the client said, not which run made the call. A held call keeps the
trace of the attempt that was held: the retry that resumes it runs on the
held trail, and its own trace context is not recorded. `tracestate`, `baggage`
and the HTTP `traceparent` header are not read, and no upstream receives the
agent's `_meta`.

## What the manifest holds

The manifest is what the upstream lists plus the operator's classification of
each definition. Nothing else classifies: a tool's own annotations are hints
(invariant 2).

| Field | Comes from | Used for |
| --- | --- | --- |
| `Upstream`, `Tool` | the upstream's `tools/list` | routing, and `action.name` |
| `Fingerprint` | the whole definition through `internal/canon` | pinning the definition an override classified |
| `Effect` | the operator's override | `action.effect`, so materiality and the fail-closed table |
| `ResourceType` | the operator's override | `resource.type` |
| `ResourceFrom` | the operator's override, a bounded JSON pointer | reading `resource.id` out of the arguments: a string as written, a number as its canonical text, so `42.0` and `4.2e1` are `42` and a rule on a numeric id uses that text |
| `TrustZone` | the operator's override | `destination.trust_zone`, which a policy's `destination` constraint and the `deny_external_sink` obligation read. What a tool's results contain is `returns.trust` and `returns.sensitivity`, which the run's flow state reads ([ADR-0021](../adr/0021-a-run-carries-what-it-took-in.md)) |
| `Classified` | whether an override pins this fingerprint | an unclassified call is `ACTION_UNCLASSIFIED` outside `OBSERVE` |

## What the modes do

The kernel is `ENFORCE` only and decides every call the same way in every mode
but `LOCKDOWN`, which builds it with fail-open reads off (ADR-0012). A mode changes what is done with the decision, and it never reaches
an extension: the adapter translates, the sink writes, the policy holder serves a
bundle, and none of them knows the mode.

| Mode | The decision | The call | Built |
| --- | --- | --- | --- |
| `OBSERVE` | recorded | runs, with the proposed bytes, unclassified included when one upstream lists it or only one is configured, unless one of the plane's own causes ([enforcement modes](enforcement-modes.md)) blocks it or the call could not be translated | yes |
| `APPROVE` | recorded | an allowed material call is held for an approval | yes; the `file` provider takes an approver's answer, and the plane refuses to start in `APPROVE` without it |
| `ENFORCE` | recorded | blocked, rewritten, held or run, as decided | yes |
| `LOCKDOWN` | recorded, made for a material call without asking the decision point, with the plane's own `LOCKDOWN` decision on the block | every material call blocked; a read enforced with fail-open reads off | yes |
| `SHADOW`, `WARN` | — | — | refused at start |

A mode the build does not enforce, and a mode needing a capability the adapter
does not declare, are refused when the plane is built, not when a call arrives.

## When the decision point is asked

A bundle that reads `external` needs a decision point, and a decision point
needs a bundle that reads it: the plane refuses to start with either alone
([ADR-0017](../adr/0017-an-external-decision-point-can-veto.md)). The pipeline
decides first without an answer, and asks only when the kernel reports that
its decision turns on the answer and that decision is not already `DENY`,
which no answer changes. It asks once and records the second decision, so a
call no veto rule covers is never sent anywhere.

| Path | Asks |
| --- | --- |
| an admitted call | once, when the answer can change the decision |
| the same call after a rewriting obligation | no: the first answer is reused, since the question carries no arguments |
| the retry that resumes a held request | afresh, so a decision point that now denies blocks the held request |
| `Preview`, which shapes a tool list | never: a listing names no resource, and a governed tool is listed as decided per call |
| a call the plane blocks whatever the answer: a pause, an unreadable pause state, a halt or `LOCKDOWN` on a material call, an unclassified call outside `OBSERVE` | never: `POLICY_DECIDED` carries no `PDP_` code, and a veto rule that reads the answer is undetermined |
| a call whose decision turns on the answer and whose envelope names no resource id | nothing is sent, and the decision carries `PDP_UNAVAILABLE` |

The question carries the call's principal, action, resource and destination,
as mapping version 1 lists them, and never its arguments (invariant 9). The
answer is read strictly where it could allow. An ask past `pdp.timeout` is
`PDP_TIMEOUT`, and one past `pdp.max_in_flight` asks in flight is not sent
and is `PDP_UNAVAILABLE` at once; either blocks in every mode that enforces. The plane names its own causes to block a call before any
question leaves it, and a call with one is never asked about
([ADR-0019](../adr/0019-an-operator-can-pause-calls.md)). Any other call whose
decision turns on the answer is asked about in every mode, `OBSERVE`
included, since the kernel decides the same way in every mode and the mode
acts only on the decision. After the ask the plane takes its pause state and
clock again and names its causes once more, so a pause or a halt that comes
while the ask waits still blocks the call.
`/healthz` counts the asks by outcome and the time spent
waiting on them; `decision_latency_us` stays the kernel's own time.

## What a pending approval looks like on the wire

`REQUIRE_APPROVAL` returns at once. The connection is not held; the request is.

| Method | The answer | Carries |
| --- | --- | --- |
| `tools/call` | a tool result with `isError: true`, which the model reads | `reason_code: APPROVAL_PENDING`, `approval_id`, `action_digest`, `expires_at`, `retry_after`, in `_meta` under the plane's namespace, never as structured content |
| `resources/read`, `prompts/get` | JSON-RPC error `-31101`, because those results have no `isError` | the same structured data in the error's `data` |

A retry that matches the binding, equals the held request on the data labels and
on the run context without the plane's flow tags, comes from the opened run that
holds it, and draws a fresh decision
equal to the held one resumes that request: no second `ACTION_PROPOSED`, the kernel
decides again as a gate, and the approval satisfies the wait and nothing else. A
retry that differs in one of those is a new request with a new hold. A
consumed approval answers `APPROVAL_ALREADY_USED` until it expires, and a
rejected one `APPROVAL_REJECTED`. A retry after the approval expired is held
anew; one whose approval lapses while it resumes answers `APPROVAL_EXPIRED`.
The plane holds at most `approvals.max_held` requests,
`approvals.max_held_per_run` of one opened run, 16 unless set, and keeps at most
`approvals.max_open` executions open; past any bound a call blocks with `EVIDENCE_UNAVAILABLE`.

## What the closing record carries

| Case | Record | Field that says what happened |
| --- | --- | --- |
| The bytes sent were the authorized ones and the result succeeded | `ACTION_COMPLETED` | `executed_action_digest` equals the decision's action digest |
| The result failed upstream | `ACTION_FAILED` | the upstream's status |
| The bytes sent were not the authorized ones | `ACTION_FAILED` | `tool_protocol_status: EXECUTED_ARGS_MISMATCH`, and the plane takes no further material call until it restarts |
| The adapter did not send, because its own check, an obligation, routing or translation refused | `ACTION_FAILED` | the cause's own reason code; the comparison did not run |
| The answer quoted a credential the plane sends | the record its outcome gets; the agent gets a fixed answer | `tool_protocol_status: withheld:` and the status it would have had, the upstream's own hash ([ADR-0042](../adr/0042-an-answer-that-quotes-a-configured-credential-is-withheld.md)) |
| The spool refused the closing record of a call that was sent | the result is delivered anyway | counted, and material calls are refused until an append succeeds |

## An answer that quotes a credential

An answer, a wire error, a listed item or a tool definition that quotes a
credential the plane sends never reaches the agent
([ADR-0042](../adr/0042-an-answer-that-quotes-a-configured-credential-is-withheld.md)).
The plane looks for the credentials of its endpoints, headers and proxies,
and, from 8 bytes, for query values and the variables a command upstream
receives: as written, percent-encoded, JSON-escaped and in base64. It does so
in every mode, before the closing record is written.

| What quoted one | What the agent gets |
| --- | --- |
| a `tools/call` success | a result saying the call ran, its answer was withheld, and calling again repeats its effect; `isError` only when the tool declares an output schema, which no fixed answer meets |
| a `tools/call` result with `isError` | an `isError` result saying the error was withheld |
| a wire error | its code, a fixed message, and `<ns>/answer: withheld` as data |
| a `resources/read` or `prompts/get` result, a forwarded list | `-31103` |
| a tool definition | the tool is never listed, and a call to it is unclassified, which every mode but `OBSERVE` blocks |

It catches an upstream that echoes what it was sent, not one that sets out to
leak: hex, a changed case or a split value pass. `doctor` names each value too
short to scan by its key.

## Why it works this way

- The pipeline is protocol-neutral and the protocol lives in the adapter, so a
  second protocol does not pull the pipeline apart (ADR-0013, ADR-0007).
- The interception is one receiving middleware and registers no tools, so the
  gateway never has to mirror an upstream's registry (ADR-0013).
- Headers route and never decide a verdict: a refusal made from a header cannot
  echo the request id, and the client reads a response without one as a broken
  transport (ADR-0013). Two headers refuse a request before any message is
  read: an `Origin` outside `listener.origins` with `403`, and under
  `runs.dir` a `Run-Token` that does not resolve with `401` (ADR-0034).
- The bytes that go upstream are the bytes that were decided about: with a
  rewriting obligation the kernel is asked again about the authorized envelope,
  so the decision's, the approval's and the executed digests are one action
  digest (ADR-0013, ADR-0005).
- An approval binds to one digest, one bundle and one held request, and is
  consumed once (ADR-0011, ADR-0013).
- A record that cannot be written before the effect blocks the call it was
  recording, and one that cannot be written after it halts material calls
  rather than disappearing (ADR-0014, invariant 5).
- A pending approval never holds the wire: every client times out, and a
  timed-out call becomes a retry the approver never sees (ADR-0013).
- The mode lives in the gateway and never in the kernel, so the same request
  decides the same way whatever the operator set (ADR-0012, ADR-0013).
- The decision point is asked only when its answer can change the decision, so
  a party that governs some calls never sees the others, and its outage
  blocks only the calls a rule routes to it (ADR-0017). A call the plane
  blocks whatever the answer is never sent to it (ADR-0019).

## Where the code lives

| Part | Path |
| --- | --- |
| Listener, upstream client, manifest, translator, answers | `adapters/mcp/` |
| The pipeline: `Admit`, `Close`, `Abort`, `Preview`, the mode table, the approval store, the ask | `internal/gateway/` |
| The client that asks a decision point over AuthZEN | `adapters/authzen/` |
| The kernel's decision | `internal/core/` |
| The evidence records and their chain | `internal/evidence/` |
| The spool on disk and the OTLP export | `internal/spool/`, `adapters/otel/` |
| The command that wires one plane | `cmd/guardana-gateway/` |

Per revision and per transport, what is enforced and what is not, is
[reference/mcp-coverage](../reference/mcp-coverage.md). How to run one is
[guides/run-the-gateway](../guides/run-the-gateway.md).
