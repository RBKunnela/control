---
title: Channels
summary: For each way an agent's actions reach the plane, what it sees, what it keeps, what it decides, what it enforces, and the bypasses that remain.
type: reference
covers: [internal/channel/**, adapters/mcp/**, adapters/enforce/**, internal/hookbridge/**, internal/ingest/**, internal/observelog/**, internal/coverage/**]
---

# Channels

One row per channel this project has today. Each is `experimental`; its label
and its limits are on its row of [status.md](../status.md), linked from the
first column. Each detail is on its own page: what a record holds on
[privacy](../concepts/privacy.md), what each declared path got on
[coverage](coverage.md), and the MCP methods on
[MCP enforcement coverage](mcp-coverage.md).

| Channel | Sees | Keeps | Decides | Enforces | Bypasses that remain |
| --- | --- | --- | --- | --- | --- |
| [MCP gateway](../status.md#mcp-gateway) | the `tools/call`, `resources/read` and `prompts/get` a client sends through it, and each upstream's tool list | per call, evidence events: the arguments' and the result's hashes, the resource id an override points to, a resource's URI or a prompt's name, and the decision; never the arguments or the result | each call, from the signed policy, before the server sees it | yes, inline: outside `OBSERVE` a blocked call or a held request never reaches the server, and an allowed one carries only the authorized bytes | a client that reaches a server directly; the caller is the configured principal, not a login; the methods on [what the gateway cannot do](mcp-coverage.md#what-the-gateway-cannot-do) |
| [Enforcement API](../status.md#enforce-receiver) | the calls a tool outside MCP admits, completes and aborts on the plane's Unix socket, built from its run token and the operator's `tools` table | the same evidence events, and a side effect's confirmation the tool reports, at most 1024 bytes | each admitted call, from the same policy | no: the client enforces the answer, and nothing proves it obeyed | a tool that never asks, or ignores the answer; [coverage](coverage.md) counts its tools decided, not enforced |
| [Hook bridge](../status.md#hook-bridge) | the tool calls a coding runtime's hooks report, through `guardana-control hook` and the enforcement API | as the enforcement API; between admit and completion the bridge keeps the execution's handle in its state directory | each call the hooks admit | through the runtime: the bridge answers silence or a block status, so it can only take a call away | what starts no hook, a process a shell command starts, and an agent that reaches the plane's directories from its own account: the [profile's gaps](claude-code-hooks.md#gaps-and-bypasses) |
| [Egress access log](../status.md#observations) | the connections an egress proxy logged: time, host, port, method, status, byte counts, and the caller as the proxy wrote it | those, in the observation log; nothing else of the line, such as a path, query, header or body | nothing | nothing: no plane decides egress | traffic that does not cross the proxy; no connection names a run, and `supervise` refuses such a source; `TRUST_INDEPENDENT` is the operator's word on an unsigned descriptor |
| [Imported traces](../status.md#observations) | the spans the agent's runtime emitted under the OpenTelemetry GenAI conventions 1.41.0: tool, agent and model operations | the span's end time, its trace, span and parent span ids, its status, the operation, the tool, agent or model name, the provider, the server address, the error type and the run attribute; never a prompt, an output or reasoning | nothing | nothing | the agent's own process writes the spans, so what it leaves out is unseen, and the source may not declare `TRUST_INDEPENDENT` |

## Notes

- An observation is testimony. The plane never reads one, and nothing in it
  grants or refuses a call ([observations](observations.md)).
- `guardana-control coverage` joins an observation to a plane's event by trace
  and span id, against a whole evidence export only
  ([coverage-map](../status.md#coverage-map)).
- A call around every channel is seen by none of them. The
  [threat model](../concepts/threat-model.md) says who can make
  such a call.
- Channels not built yet: [more channels](../status.md#more-channels) and
  [host process events](../status.md#host-process-events), both `planned`.
