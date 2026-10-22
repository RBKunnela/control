# Roadmap

Guardana Control is meant to observe and supervise an organization's AI
agents across connected channels, then react within the operator's authority.
MCP is the first channel. [ADR-0039](docs/adr/0039-many-channels-into-one-core.md)
records the architecture.

Everything here is `planned` but what the table names as existing, in
delivery order, without dates. Finished
tasks leave the [backlog](docs/backlog.md);
[status](docs/status.md) is the inventory of what exists.

## The 1.0 target: observation, supervision and authorized reaction

1.0 targets observation from a proposed action through its known or uncertain
outcome. Full observation means connected coverage with gaps and source trust
visible. Undeclared paths remain unknown.
[Control and supervision](docs/concepts/control-and-supervision.md) explains
the complete product model and today's limits.

| Area | Target for 1.0 | Delivery path |
| --- | --- | --- |
| Observe | Join tool and API evidence with runtime, proxy and process observations; show coverage, sampling and silence. | B11, B12, B21 |
| Supervise | Check procedures, permissions, resources, exceptions and child runs; report deviations and uncertain outcomes. | Existing supervision, B12, B26, B28 |
| React | Inform, alert, request review, approve one exact action, pause calls or stop later actions within authenticated run, agent or principal scopes. | Existing controls, B12–B14, B26, B28 |
| Integrate | MCP and custom tools share policy, approvals and evidence; publish each integration's enforcement and bypasses. | Existing hook bridge, B11, B12 |

B28 adds continuous supervision beside agents. Today's commands run when
invoked. Sensors report after effects; enforcement points act before them.
A cooperating API client receives a decision without proving it obeyed.
A stop affects later calls on connected enforcement paths, never an operation
already running. It neither kills a process nor undoes an effect.

## 1. First value in one project

A new user sees an allow, a block with its reason and an exact-action
approval within ten minutes of downloading the release demo: a target to measure.
Connecting an existing MCP setup ends in a local report with coverage and
identity assumptions stated. The report shows the action, policy version,
decision, known or uncertain result and next operator step. Configuration
preview, explicit apply and undo are B23; setup never silently widens authority.

## 2. Integrations without a fork

Choose one framework integration with adopters, then TypeScript and a
second integration. Add proxy and process
sensors. Publish port contracts with language-neutral conformance suites
after two consumers use each. A public Go seam needs its own record.
Tool-definition review and policy comparison (B25, B27) help operators
revalidate changes before rollout.

## 3. A small team

Authenticated operators hold scoped read, approve, pause and stop rights.
Retention, export and recovery work without a managed service. Continuous
supervision and authorized reaction follow bounded exports (B28). Finding
review and incident packages (B26) change no verdict and lift no stop.

## 4. A fleet and wider protocols, when adopters need them

Multiple planes feed a self-hosted inventory with signed distribution and
tenant isolation. HTTP and agent-to-agent adapters preserve authority across
handoffs. Outcome and cost analysis grants nothing. The
[Guardana bridge](docs/adr/0024-control-and-guardana-are-independent.md)
stays optional and off unless configured.

## Release bar for 1.0

Supported coverage and reactions require conformance suites, adversarial
tests, explicit bounds and visible failures. 1.0 also requires compatibility
and migration policies, a second digest implementation passing the goldens,
two independently maintained integrations, external threat-model review,
an exercised disclosure process, isolation tests, tested offline use and
recovery, and reproducible sustained tail-latency benchmarks. Observation
contracts need their own v1 record or an explicit exclusion. An evidence
integrity claim needs hash links and signed checkpoints. Content capture
stays off by default; hidden reasoning is never stored. Feature counts do
not meet this bar.
