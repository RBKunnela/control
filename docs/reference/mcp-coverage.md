---
title: MCP enforcement coverage
summary: Per revision, transport and method, what the gateway enforces today and what it does not.
type: reference
covers: [adapters/mcp/**, internal/gateway/**, cmd/guardana-gateway/**, pkg/contract/effect.go, internal/secretscan/**]
---

# MCP enforcement coverage

What this build does with each Model Context Protocol method, on each
revision and transport. [status.md](../status.md) is the inventory;
[concepts/mcp-gateway](../concepts/mcp-gateway.md) explains the mechanism, and
[ADR-0013](../adr/0013-mcp-interception-approvals-and-modes.md) records the
decisions.

## Revisions and transports

| Listener | Serves | Identity per call comes from | Notes |
| --- | --- | --- | --- |
| `stateless_http` | `2026-07-28`, and older | the listener's configuration | No session; a `2026-07-28` request carries its protocol version and client claim in `_meta` |
| `stateful_http` | `2025-11-25` and older | the listener's configuration | A `2026-07-28` request gets `-32022` and the versions served, so a client renegotiates. Sessions end idle after `listener.session_idle`; past `listener.max_sessions` live, an open gets `503` |
| `stdio` | one agent over a pipe | the listener's configuration | Nothing authenticates a pipe |

No key wires an end user's authenticator: every call is the configured
principal's. `_meta.clientInfo` is a run-context tag no
digest covers. A request with a body gets 30 seconds for it, and 30 seconds
per 64 KiB slice of its answer: a client reading slower is cut, and one reading
a slice every 29 seconds holds a handler throughout.

An upstream is reached over Streamable HTTP (`upstreams[].endpoint`) or as a
child process (`upstreams[].command`).

## Methods

| Method | What the gateway does | Decided |
| --- | --- | --- |
| `tools/list` | Answers from the manifest, without a [withheld](../concepts/mcp-gateway.md#an-answer-that-quotes-a-credential) definition, shaped for the principal, with `cacheScope: private` and the operator's `ttlMs` | under `annotate` or `hide`, one preview per classified tool one upstream serves; a cached list, one naming the bundle and halts in force; nothing recorded |
| `tools/call` | Admits an `ActionEnvelope`; if the mode lets it run, applies the plane's obligations, none under `OBSERVE`, sends the authorized bytes, compacted by the adapter, and closes the trail with those | yes |
| `resources/read` | Translated as a `READ` of the URI. Routed only when one upstream is configured; with several it is `ACTION_UNCLASSIFIED`: nothing says which server holds the URI | yes |
| `prompts/get` | Translated as a `READ` of the prompt, its arguments authorized as a canonical JSON object of strings. Routed as above | yes |
| `resources/list`, `resources/templates/list`, `prompts/list` | Merged from every upstream, bounded, with the gateway's own `_meta` keys stripped and `cacheScope: private`; `-31103` when an item quotes a credential | no: a listing names no action |
| a batch | On `stateful_http`, before `2025-06-18`: each member as if sent alone | each call |
| `tools/call` with no `id` | Dropped by the library | no |
| `notifications/cancelled` | After the send, the upstream's call is cancelled, never resent, and recorded unknown | no |
| everything else | Handled by the library's own server, which registers nothing to forward | no |

## What the gateway cannot do

| Not covered | Why |
| --- | --- |
| Elicitation and multi-round requests (`input_required`) | `planned` ([status.md](../status.md)). A call, read or prompt the upstream answers `input_required` is sent once, recorded failed, and told `-32603` `the upstream asked for input this gateway does not relay` |
| The Tasks extension | `planned` ([status.md](../status.md)) |
| `notifications/tools/list_changed` toward the agent | The library emits it only for its own, empty registry, so the listener declares none; an agent refreshes when `list.ttl` runs out |
| An upstream's own notifications and requests | A changed tool list refreshes the manifest; sampling, roots and progress reach no agent |
| Resuming a hold the plane lost | A hold dies with a restart; its call never runs. With a hold journal the next start closes its trail, with the approver's answer and `APPROVAL_NOT_RESUMED` or as expired, or counts it left open; without one it stays open (ADR-0016) |
| Telling one approver from another | Under `directory`, write access to the approvals directory is the authority and `approver_id` a claim (ADR-0016); under `signed`, a roster operator's key (ADR-0073) |
| A client other than the library's own | Only the MCP project's Python SDK, over HTTP, in `make check-mcp-client` on the [filesystem guide](../guides/connect-an-existing-mcp-setup.md); other clients and stdio are not exercised |
| A tool classified `SPAWN_OR_DELEGATE` | The class needs a delegation chain, which the listener never carries: every such call is refused `REQUIRED_FIELD_ABSENT` before any rule or decision point |
| What a run read outside the gateway | Without `runs.dir`, a run is the listener's principal and starts clean at each restart; on stdio it lasts one connection. The user's prompt, tool descriptions, listed resources and prompts, and tools not behind the gateway are not tracked, and a call carries no data label, so a `flow` rule blocks every untrusted destination after untrusted input. A `resources/read` and a `prompts/get` carry no declared result, so each leaves its run untrusted and unknown from then on (ADR-0021) |

## List shaping under each mode

`list.shaping` only subtracts; anything but `none` is refused at start in a
mode that does not enforce.

| Shaping | `OBSERVE` | `APPROVE`, `ENFORCE`, `LOCKDOWN` |
| --- | --- | --- |
| `none` | the upstream's list without withheld definitions, `_meta` of the gateway's namespace stripped | the same |
| `annotate` | refused at start | each tool carries the verdict a call to it would get, under the gateway's `_meta` key |
| `hide` | refused at start | a tool the preview denies, and every unclassified tool, is omitted |

A preview carries no arguments, so no resource id. A tool whose effect class
needs the id is no verdict at preview and stays listed; one whose only `ALLOW`
reads the id stays listed, marked `DECIDED_PER_CALL` under `annotate`, unless
a rule denies it without its arguments.

## The codes the adapter mints

A `tools/call` answers a block or a pending state as an `isError: true` tool
result, the fields below in its `_meta` under `<ns>/`, with no structured
content for a client to check against the tool's output schema. A `resources/read` and a
`prompts/get` have no `isError`, so there the fields travel as a JSON-RPC
error, outside the protocol's reserved range and the library's private code.

| Code | Means | Data |
| --- | --- | --- |
| `-31100` | the gateway blocked the call | `reason_codes`, `decision_id`, and `refused` with why the envelope could not be built or a handed-out call was not sent |
| `-31101` | an approval is pending | `reason_code: APPROVAL_PENDING`, `approval_id`, `action_digest`, `expires_at`, `retry_after` |
| `-31102` | a [run token](runs.md#what-a-plane-does-with-a-token) was refused; one message for every cause | none |
| `-31103` | an answer was [withheld](../concepts/mcp-gateway.md#an-answer-that-quotes-a-credential) | `<ns>/answer: withheld` |

An upstream's own wire error, and the client library's `-32005` `rejected by
transport`, passes through with its code and message, unless it quotes a
credential the plane sends; any
other failure, a timeout or a broken session, answers `-32603` `the upstream
did not answer`, never the transport's text, which can quote the endpoint. Only `<ns>/answer` (`blocked`,
`pending` or `withheld`, `<ns>` being the product's namespace) in an answer's `_meta` or in
the error's `data` marks an answer the gateway made; the namespace is stripped
from both in everything an upstream sends.

A `tools/call` answer the pipeline decided names its decision's trail with the
strings `<ns>/request_id` and `<ns>/decision_id`:

| Answer | Where the ids travel |
| --- | --- |
| a block, a pending state, the upstream's result | the result's `_meta` |
| an upstream's wire error, `data` an object, `null` or absent; the gateway's own `-32603` | the top level of `data` |
| an upstream's wire error, other `data` | nowhere; the data arrives unchanged |

A retry told to wait again, or run, names the held request's trail; one refused
on its own trail names that. The ids are added after the result is hashed,
so `result_hash` stays the upstream's. Reads, prompts, lists
and undecided answers carry neither.

## Reason codes in the gateway's answers

A kernel decision comes back as written, with codes such as `NO_MATCHING_RULE`;
[reference/reason-codes](reason-codes.md) lists every code; an untranslatable call is the kernel's
block in every mode. The codes below are the enforcement point's own.

| Code | When |
| --- | --- |
| `ACTION_UNCLASSIFIED` | no manifest entry classifies the operation, or a refresh withdrew its classification after admission, which spends an approved retry's approval unrun; blocked outside `OBSERVE` |
| `LOCKDOWN` | a material call under `LOCKDOWN` |
| `PAUSED` | an operator's pause covers the call ([scopes](../concepts/enforcement-modes.md#pausing-calls)); in every mode, reads included, and never in a listing |
| `RUN_STOPPED`, `AGENT_OR_PRINCIPAL_STOPPED` | a stop names the call's run, or its agent or principal, reads included |
| `PAUSE_STATE_UNAVAILABLE`, `STOP_STATE_UNAVAILABLE` | the pause file or stop list is unreadable or untrusted, or its last read is stale or dated ahead; every call is blocked |
| `EVIDENCE_UNAVAILABLE` | a record the decision depends on could not be written, kept or read back: the sink refused an event, a bound on held requests or open executions was reached, or the approval store or the hold journal could not answer, or answered with an approval naming another request, not approved, or outliving the expiry the gateway minted; or, under `runs.dir`, its run ([runs.md](runs.md#what-a-plane-does-with-a-token)) |
| `APPROVAL_PENDING`, `APPROVAL_EXPIRED`, `APPROVAL_REJECTED`, `APPROVAL_ALREADY_USED` | the state of the approval this call waits on |
| `APPROVAL_NOT_RESUMED`, `APPROVAL_STATE_UNKNOWN` | a request this plane lost to a restart was granted, or its answer could not be read or trusted; it never ran |
| `APPROVAL_DIGEST_MISMATCH`, `APPROVAL_BUNDLE_MISMATCH` | an approval a store returned named another action or policy bundle |
| `EXECUTED_ARGS_MISMATCH` | the bytes about to be sent, or the bytes sent, were not the authorized ones |
| `EXECUTION_ABANDONED` | never in an MCP answer |
| `OBLIGATION_NOT_UNDERSTOOD` | a non-advisory obligation the plane cannot apply, whose parameters it cannot read, or whose check the call fails, or a rewrite changed the member `resource_from` reads |
| `INVALID_FIELD_VALUE` | the request id names a trail still open, or the protocol cannot carry the bytes |
| `POLICY_STALE` | the decision's bundle was replaced or stale at hand-out |
| `POLICY_UNAVAILABLE` | a block whose decision names no cause, answered with the kernel's code for an absent policy |
| `REQUIRED_FIELD_ABSENT` | any list on a listener whose authenticator established no end user |
