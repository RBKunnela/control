---
title: Control and supervision
summary: The 1.0 goal for connected observation, procedure checks and scoped reactions, with today's alpha and the three API roles kept explicit.
type: explanation
covers: [internal/core/**, internal/gateway/**, internal/observe/**, internal/coverage/**, internal/supervise/**, internal/reaction/**, internal/notify/**, adapters/**, cmd/**, ROADMAP.md]
---

# Control and supervision

Guardana Control is a control and supervision layer for AI agents. The
`planned` 1.0 goal is to observe their actions across connected channels,
compare runs with procedures and permissions, and react within the authority
an operator granted. MCP is the first channel. The
[roadmap](../../ROADMAP.md) owns the delivery order and the 1.0 release bar;
[status](../status.md) is the inventory of what exists. Nothing in the current
alpha is a security boundary.

## Observe the connected paths

The 1.0 target is observation from a proposed action through its known or
uncertain outcome, across the sources the operator connects:

- Enforcement points contribute the proposed action, decision, approval and
  reported result. A gateway that holds the tool connection can refuse a call
  before its effect.
- Custom tools and framework hooks ask the Enforcement API before acting,
  then report completion or abort. A cooperating client has to obey the
  decision; the receiver cannot prove that it did.
- Runtime traces and logs describe steps outside an enforcement point as
  observations. The runtime's own account can omit, sample or forge events.
- Egress proxy access logs and process sources add observations independent
  of an agent's own reporting. Their attribution is only as strong as the
  identity their source establishes.

Each declared path needs a stated basis for what is visible and controllable:
enforced, decided but not enforced, observed, inferred or not covered.
Undeclared paths and unreadable or silent sources remain unknown. A missing
event is never proof that nothing happened. This is what full observation
means in the product target: connected coverage and its gaps are explicit,
including when a run cannot be judged.

An enforcement record and an observation stay separate. The first records
what Control decided; the second records what a source said happened.
Correlating them does not promote the source's trust or turn a trace id into
authenticated identity. Prompt and tool content capture is off by default,
and hidden model reasoning is never stored. Visibility does not require
collecting a transcript.

## Supervise a run against its procedure

The supervisor compares decisions and observations with a versioned
procedure: the expected steps, their order and deadlines, permitted
exceptions, resources and child runs. Findings name their evidence, rule
version and certainty. They can describe a step outside the procedure,
repeated denials, a denied action tried through another tool, skipped work,
an overdue or unfinished run, and continuing after a failure.

The 1.0 target joins this with ongoing observation, finding delivery and
operator review beside the agents. Supervision never changes a policy
verdict, grants permission or treats an uncertain outcome as success.
Review records explain what an operator concluded without changing the
finding's evidence or lifting a stop.

Today supervision is `experimental`: `guardana-control supervise` reads
exports when invoked, checks one opened run or its procedure's tree, writes
findings and can draw a static page. `notify` hands alerts to a named program,
and `findings export` exposes them with a cursor. There is no continuously
running supervisor. The
[observations and supervision model](observations-coverage-and-supervision.md)
explains these existing commands and their limits.

## React within granted authority

The 1.0 target has two points at which a response can act. Before an effect,
a policy can deny a proposed action, attach obligations or hold it for an
expiring, single-use approval of one canonical action digest and policy
bundle. After a finding, a configured route can record it, deliver an alert,
request review or stop later actions where enforcement exists.

| Response | Authority and limit |
| --- | --- |
| Inform | Record a finding and its evidence. This grants nothing. |
| Alert | Deliver the finding to an operator's program, webhook, chat or monitoring system. A notifier has no authority over the decision path. |
| Review | Let an authenticated operator acknowledge and assess a finding within their scope. Closing a review neither approves an action nor lifts a stop. |
| Approval | Let one exact action run once before its approval expires. A similar action or a later attempt needs its own decision. |
| Pause | Refuse proposed calls in the configured scope at enforcement points. Calls already running have passed that point. |
| Stop | Refuse later actions of the named run, agent or principal within a signed, expiring route and the operator's authenticated scope. It affects only connected enforcement paths. |

These are the `planned` 1.0 response scopes, not a claim that all operate in
the alpha. Today approvals, pause, a local notifier and a stop of one opened
run are `experimental`. A stop is written when the operator runs `react` and
reaches the plane when it reads the list. It cannot name a whole tree, agent
or principal. It does not cancel a running operation, kill a process or undo
an effect.

Automatic stopping has a higher evidence bar than notifying. Today only an
eligible deterministic, `CONFIRMED` finding can produce a stop under a signed
route. Observations alone and unknown findings stop nothing. Every scope
needs an explicit authority; a sensor, detector or notifier never grants it.
The default authorization path runs no model.

## Three API roles

| API | Role | Current stage |
| --- | --- | --- |
| AuthZEN authorization evaluation | Consult an organization's external PDP for a veto of configured calls; the signed local policy remains the source of every grant. | `experimental` |
| Enforcement API | Let a custom tool ask before acting, receive authorized argument bytes, and report completion or abort under a run token. | `planned`, specified in ADR-0051 |
| Control plane API | Let authenticated operators read evidence and manage approvals, pause and stop within scoped rights. | `planned` |

An AuthZEN veto is an input to the local decision. It can remove permission
and never add it. A timeout, unavailable PDP or unreadable answer leaves a
governed call indeterminate, which blocks it in an enforcing mode. In
`OBSERVE`, the decision is recorded and the call runs. The external service
receives structured action metadata, not arguments or their hash; it is not
a payload-inspection API. The
[AuthZEN guide](../guides/let-a-decision-point-veto.md) shows the two policy
rules and configuration that enable it.

The Enforcement API is a separate contract. Its operations are `admit`,
`complete` and `abort`; its receiver resolves identity and run rather than
trusting identity fields a client submits. Its first transport is JSON over
HTTP on a local Unix socket. It is cooperative: even in `ENFORCE`, its paths
are decided, not enforced by the receiver. A client can ignore a block or
report bytes it did not send. An uncertain effect is recorded as uncertain
and is never automatically retried.

## From the alpha to 1.0

The alpha already joins an MCP enforcement path, imported runtime traces,
coverage, procedure checks and run-scoped reaction, with the limits above.
It uses configured principals and operator-issued run capabilities rather
than authenticated end users. Its append-only evidence trail is not
tamper-evident. These limits stay visible until their controls are built and
verified.

1.0 needs supported contracts and integrations, declared coverage per channel,
authenticated scopes, exercised recovery and adversarial tests for reactions.
It also needs the external review and compatibility work the roadmap names.
Wider fleet management, new protocol adapters and outcome-cost analysis are
demand-led work, rather than prerequisites hidden in the word "observation".

The decisions behind this model are
[ADR-0039](../adr/0039-many-channels-into-one-core.md),
[ADR-0045](../adr/0045-one-run-is-supervised-against-its-procedure.md),
[ADR-0046](../adr/0046-a-finding-stops-one-run-through-a-signed-route.md) and
[ADR-0051](../adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md).
