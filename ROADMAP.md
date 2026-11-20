# Roadmap

Guardana Control is meant to observe and supervise an organization's AI
agents across connected channels, then react within the operator's authority.
MCP is the first channel. [ADR-0039](docs/adr/0039-many-channels-into-one-core.md)
records the architecture.

Everything here is `planned` but what is named as existing, in
delivery order, without dates. Finished
tasks leave the [backlog](docs/backlog.md);
[status](docs/status.md) is the inventory of what exists.

## The 1.0 target: observation, supervision and authorized reaction

1.0 targets observation from a proposed action through its known or uncertain
outcome. Full observation means connected coverage with gaps and source trust
visible.
[Control and supervision](docs/concepts/control-and-supervision.md) explains
the product model and today's limits.

| Area | Target for 1.0 | Delivery path |
| --- | --- | --- |
| Observe | Join tool and API evidence with runtime, proxy and process observations; show coverage, sampling and silence. | B21, B35, B12 |
| Supervise | Check procedures, permissions, resources, exceptions and child runs; report deviations and uncertain outcomes. | Existing supervision, B12, B26, B28 |
| React | Inform, alert, request review, approve one exact action, pause calls or stop later actions within authenticated run, agent or principal scopes. | Existing controls, B12–B14, B26, B28, B38 |
| Integrate | MCP and custom tools share policy, approvals and evidence; publish each integration's enforcement and bypasses. | Existing hook bridge, B11, B12 |

Signatures exist today on the policy and its freshness, the operator roster,
the answers, pauses, runs, routes and stops a signed plane takes, and the
release archives ([what each signature proves](docs/concepts/signed-operations.md)).
The evidence record is not signed yet (B29); B36's signer and
signature-algorithm ports are where another key store would plug in.

## 1. First value in one project

A new user sees an allow, a block with its reason and an exact-action
approval within ten minutes of downloading the release demo: a target to measure.
Connecting an existing MCP setup ends in a local report with coverage and
identity assumptions stated. Preview, apply and undo are B23; setup never
silently widens authority.

## 2. Integrations without a fork

Attributing egress connections to runs (B21) and a process sensor
independent of the agent (B35) come first. Then the port contracts and a
TypeScript client (B12); continuous supervision (B28) builds on both. A
framework integration (B11) follows, the maintainer's choice. B25, B27, B36,
B37, B40 and B44 go alongside.

## 3. A small team

Authenticated operators hold scoped read, approve, pause and stop rights.
Retention, export and recovery work without a managed service. Finding
review and incident packages (B26) do not change verdicts or lift stops.
Approvals may need several operators (B41). A run is drawn as a graph beside
a rule editor (B39).

## 4. A fleet and wider protocols, when adopters need them

Multiple planes feed a self-hosted inventory with signed distribution and
tenant isolation. HTTP and agent-to-agent adapters preserve authority across
handoffs. Outcome and cost analysis grants nothing. The
[Guardana bridge](docs/adr/0024-control-and-guardana-are-independent.md)
stays optional and off unless configured.

## Release bar for 1.0

Supported coverage and reactions require conformance suites, adversarial
tests, explicit bounds and visible failures. 1.0 also requires migration
policies, a second digest implementation, two integrations qualified against
independently maintained upstreams, evidence integrity, isolation, offline
use, recovery, sustained tail latency and an exercised disclosure process.
Content capture stays off by default; hidden reasoning is never stored.
Feature counts do not meet this bar.

What needs people from outside the project stays `not met` at 1.0, and the
release notes say so: an outside threat-model review, trials with new users
and new approvers' understanding. A model reading a page is a simulation with
zero human participants. The rest is met by the project's own evidence
([ADR-0085](docs/adr/0085-the-1-0-bar-is-met-by-own-evidence-and-what-needs-outside-people-stays-not-met.md)).
Its items are B06, B11, B23, B29 to B34, B38 and B43; the
[backlog](docs/backlog.md#release-bar-for-10) gives each its disposition.
