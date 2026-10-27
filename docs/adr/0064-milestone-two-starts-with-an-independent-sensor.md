# ADR-0064: Milestone 2 starts with an independent sensor, and the 1.0 bar is a list of tasks

Status: accepted
Date: 2026-10-27

Amends [ADR-0026](0026-first-value-and-external-extension-paths.md) on the
order inside the integrations milestone and on what counts as an outside
integration for 1.0. Builds on
[ADR-0039](0039-many-channels-into-one-core.md), whose ports it orders.

## Context

The whole-tree audit before 0.15.0 found milestone 2 unmoved since 0.13.0:
0.14.0 shipped audit fixes and no roadmap task. Its order put the
tool-definition review (B25) and the policy comparison (B27) first, though
both depend on nothing and nothing depends on them, while continuous
supervision (B28), which the maintainer put in 1.0, depends on the port
contracts (B12) and the independent sensors (B21). The sensor contract B12
would publish has one producer today, and the source descriptor refuses
`TRUST_INDEPENDENT` for every kind, so B21's proxy cannot be declared at all.

The release bar in `ROADMAP.md` named ten things no backlog task delivered:
evidence integrity, a second digest implementation, the observation contract's
v1 decision, compatibility and migration policies, isolation, offline use,
recovery, sustained performance, an outside review and a disclosure exercise.
It also asked for two independently maintained integrations, which waits on
people outside the project for a time nobody can state.

## Decision

- **Milestone 2's order** is B21, then B12 with the TypeScript client, then
  B28 in milestone 3. B21 makes the descriptor's checks neutral to the
  sensor's kind first. B25 and B27 go beside them and block nothing. B11, a
  framework integration, starts when an adopter picks a framework.
- **The release bar is a list of tasks**, B29 to B34 in `docs/backlog.md`:
  a tamper-evident trail, a maintained second digest implementation, the v1
  decision for the observation and finding contracts with a migration rule
  for every format, isolation, offline and recovery tests, sustained
  performance on a dedicated machine, and an outside review with a disclosure
  exercise. A bar item without a task is a defect of the backlog.
- **The two integrations are maintained here**, each against an independently
  maintained upstream and qualified by the published conformance suite at a
  pinned version: the coding runtime's hooks and the B11 framework. Adoption
  by outside teams stays a target after 1.0, stated as not met.
- **The outside review starts now** through free routes, and 1.0 waits for it.

## Security / compatibility impact

No code changes. Each integration still has to pass the suite against a
release its upstream project maintains, and the review is still done by a
person outside the project. What changes is that the bar can be met by work
the project controls, except the review.

## Alternatives considered

- B25 first, as recommended before the audit: useful to operators, and on no
  path to 1.0.
- B11 first: the framework is the adopters' choice, and the client contract it
  would use already has two consumers.
- Fold the bar's items into B12, B14 and B16: B16 waits on demand, so part of
  the bar would wait on outside signals.
- Ship 1.0 stating that no outside review happened: faster, and a weak signal
  for a security tool.

## Consequences

0.15.0 starts B21 after the audit's fixes. The roadmap, the backlog and the
status page have to agree on the bar's tasks at every release, as they do on
the milestones.

## Validation

The release audit compares `ROADMAP.md`, `docs/backlog.md` and
`docs/status.md` with the tree, as `AGENTS.md` asks of every release; a bar
item with no task, or a delivered task still listed, is a finding of that
audit.
