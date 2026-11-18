---
title: Where it fits
summary: When this project fits an agent's tool calls, when an authorization service, a model gateway or operating-system isolation fits instead, and how they combine.
type: explanation
covers: [adapters/mcp/**, adapters/enforce/**, adapters/authzen/**, internal/core/**, internal/gateway/**, internal/ingest/**, internal/supervise/**, internal/reaction/**]
---

# Where it fits

This project decides an agent's consequential tool calls from structured
policy before their effect, and records each decision with the policy that
made it. It is an alpha and not a security boundary
([status.md](../status.md)). Three other kinds of tool are often weighed
against it: an authorization service, a model gateway and operating-system
isolation. Each answers a different question, and they combine.

## What this project does

| It does | Status |
| --- | --- |
| Decide each MCP tool call, resource read and prompt from a signed policy before it reaches the server, and block, allow or hold it | `experimental`, [mcp-gateway](../status.md#mcp-gateway) |
| Decide in a fixed order with a fail-closed table, so `INDETERMINATE` is never `ALLOW` | `implemented`, [decision-kernel](../status.md#decision-kernel) |
| Let a person approve one exact call under one policy bundle, once | `implemented`, [approval-binding](../status.md#approval-binding) |
| Answer a tool outside MCP that asks before it acts, which then enforces the answer itself | `experimental`, [enforce-receiver](../status.md#enforce-receiver) |
| Import an agent's traces and an egress proxy's access log as observations, which decide nothing | `experimental`, [observations](../status.md#observations) |
| Check one opened run against its procedure, and stop that run's later calls on a confirmed finding where a signed route allows it | `experimental`, [run-supervision](../status.md#run-supervision), [run-stop](../status.md#run-stop) |

## What it does not do

- It does not authenticate a caller: every call on a listener is made by the
  principal its configuration names ([mcp-gateway](../status.md#mcp-gateway)).
- It sees only the calls routed through it. A client that reaches a server
  directly is decided by nothing here ([channels](../reference/channels.md)).
- It cancels nothing already running: a pause or a stop bites later calls
  ([run-stop](../status.md#run-stop)).
- Its evidence trail is not tamper-evident: whoever can write the trail can
  rewrite it ([signed operations](signed-operations.md#what-is-not-signed));
  hash links and signed checkpoints are [backlog B29](../backlog.md).
- It records a call's arguments and result as hashes, keeps no model prompt or
  output, and never stores hidden reasoning ([privacy](privacy.md)).
- It does not isolate processes, route model calls or count their cost.

## An authorization service

An authorization service answers whether a principal may perform an action on
a resource, for applications that ask it. It fits when the decision is your
application's, its users are authenticated, and the application enforces the
answer.

This project fits when the actor is an agent and the action is a tool call
whose arguments, effect class and flow of untrusted input decide it, with an
approval bound to one exact call and a trail of each decision.

Together: a plane can ask an organization's authorization service over
AuthZEN about calls its policy names. The answer can veto a call the policy
allows and never grants one, and a silent service blocks those calls in every
mode that enforces (`experimental`,
[external-pdp](../status.md#external-pdp),
[let a decision point veto](../guides/let-a-decision-point-veto.md)).

## A model gateway

A model gateway sits between code and model providers. It sees prompts and
completions, and routes, limits, budgets or filters them. It fits when the
question is about model traffic: which model, how much, with what content.

This project does not sit on that path. It sees the tool calls an agent
makes, not the model requests behind them, and it keeps none of their text.

Together: a model gateway on model traffic, this plane on tool calls. A
runtime's OpenTelemetry GenAI traces, model operations included, can be
imported as observations (`experimental`,
[observations](../status.md#observations)); they decide nothing.

## Operating-system isolation

Containers, virtual machines, sandboxes, separate accounts and network rules
bound what a process can reach, whatever it decides to do. They fit when the
question is what the agent's process may touch at all.

This project is not a sandbox. A process a shell command starts, a file
written outside a tool call, or a connection that does not cross the plane is
not decided by it; the hook bridge lists such gaps for its runtime
([hook-bridge](../status.md#hook-bridge)).

Together: isolation makes the plane the only path to the servers and hosts
that matter, and the plane decides which calls on that path run. An egress
proxy's log then shows the hosts reached that no declared path names
(`experimental`,
[watch an egress proxy](../guides/watch-an-egress-proxy.md)), and the
gateway image runs in a container
([run in a container](../guides/run-in-a-container.md),
[releases](../status.md#releases), `experimental`).

## Why

- Authority is decided from structured inputs, never by a model or by
  pattern matching alone ([AGENTS.md](../../AGENTS.md), invariants 1 and 2).
- Many channels feed one core, and an observation never decides
  ([ADR-0039](../adr/0039-many-channels-into-one-core.md)).
- An external decision point can veto and never grant
  ([ADR-0017](../adr/0017-an-external-decision-point-can-veto.md)).

## Where the code lives

`internal/core/` decides; `internal/gateway/` runs the pipeline and the modes;
`adapters/mcp/` and `adapters/enforce/` are the MCP gateway and the
enforcement API; `adapters/authzen/` asks a decision point;
`internal/ingest/` imports observations; `internal/supervise/` and
`internal/reaction/` check and stop a run.
