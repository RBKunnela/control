# Roadmap

What has to become true, in planned order, without dates.

Guardana Control is meant to supervise an organization's AI agents across
the channels an operator connects. Where an enforcement point sits in an
agent's path, it decides a consequential action before it happens. Elsewhere
it watches what agents and their runtimes report, compares that with their
procedures and permissions, and reports deviations, access attempts and
unfinished work. It stops an agent only where the operator allowed that. MCP
is the first channel, not the only one
([ADR-0039](docs/adr/0039-many-channels-into-one-core.md)).

Everything here is `planned`; a finished item is deleted.
[docs/status.md](docs/status.md) is the inventory of what exists, the
[delivery backlog](docs/backlog.md) gives each step its tasks and acceptance
checks, and [ADR-0026](docs/adr/0026-first-value-and-external-extension-paths.md)
with ADR-0039 records the order.

## 1. First value in one project

Done when a new user sees an allowed call, a blocked call with its reason and
one exact-action approval within ten minutes of downloading the release's demo
archive: a target to measure, not a measured result.

A guide connects an existing MCP client and server, states what it covers and
the identity it assumes, and ends in a local report. No setup step widens
authority silently. Configuration preview, explicit apply and undo are B23.

## 2. Integrations without a fork

Done when a language-neutral enforcement API and a Python client wrap a
custom tool with admission, authorized arguments, completion and abort. They
bind identity and run, consume an approval once and never retry an uncertain
effect. One framework or coding-runtime integration chosen with adopters ships first,
then TypeScript and a second integration. Sensors independent of the agent follow: an
egress proxy's access log, then process events. Sensors, detectors,
reactions and notifiers get published data contracts and conformance suites
any language can run, once two consumers have used each, and every port
states the paths it covers. A Go seam becomes public only after two consumers
use it and its record is accepted.

[Planned requirements](docs/adoption-and-incident-workflows.md) add coding hooks
(B24), tool-definition review (B25) and policy comparison (B27).

## 3. A small team

Done when authenticated principals hold scoped rights to read, approve, pause
and stop; a stop can name an agent or a principal as well as a run; and
evidence and observations can be retained, rotated, exported and recovered,
without a managed service. Cross-project access, forged
identity, approval replay and policy outage have adversarial tests.

Finding review and incident export (B26) cannot change verdicts, approve actions
or lift stops.

## 4. A fleet and wider protocols, when adopters need them

Done when many planes report to one self-hosted control plane that holds the
inventory of agents, tools, sources and procedures, distributes signed policy
and definitions and keeps tenants apart, and when HTTP tool APIs and
agent-to-agent handoffs have adapters that keep authority from growing across
a handoff. Outcomes are judged finished, degraded or unknown, with the cost
per accepted outcome, and no quality judgment influences a verdict.

The [Guardana](https://github.com/guardana/guardana) bridge stays optional and
off unless configured
([ADR-0024](docs/adr/0024-control-and-guardana-are-independent.md)).

## 1.0

1.0 commits to supported contracts and security claims. It requires published
compatibility and migration policies, a second implementation of the action
digest passing the same golden fixtures, two independently maintained
integrations, a conformance suite and a stated coverage for every channel it
claims, an external review of the threat model, an exercised disclosure
process, adversarial isolation tests, tested offline use and recovery, and
reproducible benchmarks of sustained tail latency. The observation contract
is promoted to v1 by its own record, or stated outside the 1.0 promise. A
claim of evidence integrity needs hash links and signed checkpoints. A count
of features alone cannot meet this gate.
