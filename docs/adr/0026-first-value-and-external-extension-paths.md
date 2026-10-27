# ADR-0026: First value and readable evidence come before the supervisor's breadth

Status: accepted
Date: 2026-09-27

Amended by [ADR-0039](0039-many-channels-into-one-core.md): the supervision
milestone, now the second, is one task under supervision across two channels,
so a sensor of another kind, a coverage map and a run-scoped stop come before
any public SDK; the former second milestone, runs and evidence other tools can
read, is delivered, its consumer in a module of its own.

Amended by [ADR-0064](0064-milestone-two-starts-with-an-independent-sensor.md):
milestone 2 starts with the independent sensors (B21), then the port
contracts (B12); the two integrations of the 1.0 bar are maintained here
against independently maintained upstreams.

Builds on [ADR-0007](0007-repository-layout-and-dependency-rule.md),
[ADR-0009](0009-open-core-boundary.md) and
[ADR-0024](0024-control-and-guardana-are-independent.md). Amends ADR-0007 on
the public packages: only `pkg/contract` exists, and the other three are
reserved names.

## Context

The project is meant to supervise an organization's AI agents. Today there is an
experimental MCP gateway and its demo, run from a checkout. An outside review
found that nobody can yet get value from it without building the repository,
that its extension guide uses `internal/gateway`, which another module cannot
import, and that the public adapter, detector and policy provider packages
ADR-0007 names do not exist. A run is keyed by principal and agent, so two tasks
of one agent share flow state. The evidence is written, but no documented,
bounded way reads it back for another application. The local plans carried
several competing sequences.

## Decision

The delivery order is: first value in one project; runs with an identity of
their own and evidence other tools can read; procedures and a supervisor;
integrations without a fork; a small team; a fleet and wider protocols.
Supervision remains the project's purpose. Run identity and a readable
evidence export come first because the supervisor needs both, and so does
anyone who builds on the project.

`ROADMAP.md` owns the sequence, `docs/backlog.md` owns the planned tasks and
their acceptance checks, and `docs/status.md` owns the inventory. Local session
notes are inputs, not a second schedule.

An integration milestone needs a consumer outside this module. Reports, policy
packs and asynchronous detectors must be useful without a fleet service, a
model key or the Guardana project. Versioned data and process interfaces come
before a public Go interface, which is promoted only through its own
compatibility record after two consumers have used it.

## Security / compatibility impact

This record orders work; it defines no API and changes no authorization. It
promotes no package, changes no v1 contract, allows no plugin loaded at run
time, does not make an external decision point a source of grants, and does not
let an asynchronous finding authorize a call. The invariants and the accepted
records still govern every change.

Run identity, the evidence query and the enforcement API each need their own
record: identity, run ownership, admission handles, approval resumption, exact
authorized bytes, completion, expiry and recovery. A decision returned to a
cooperating caller does not prove the caller enforced it, and telemetry is not
evidence that enforcement covered every action; a consumer of the data must be
able to tell the two apart.

## Alternatives considered

- The supervisor first, as the plan stood on 2026-09-25: builds the stated
  purpose, but on runs that share state and on evidence no other tool can read,
  and in a product nobody can try without a checkout.
- Integrations before the supervisor (the outside review's order): the fastest
  way to adoption, but it postpones the purpose past a team and a fleet's
  prerequisites, and the supervisor's needs would then be met last.
- The fleet first: solves distribution before anyone runs more than one plane.
- Publishing the internal interfaces now: exposes the pipeline, the snapshot
  and the storage before two consumers have shown what a stable surface is.

## Consequences

The packaged demo, run identity and the evidence export move forward; the
supervisor follows them rather than leading. SDKs, detectors as extensions and
the fleet wait for their prerequisites and for use. Authentication, policy
freshness and durable operations remain prerequisites for shared use. Each
milestone ends in a task a user completes, not only in a package or a diagram.

## Validation

New users complete the packaged demo and connect their own MCP server, with the
time, errors and help recorded. A consumer in another module reads the evidence
through published contracts. The supervisor's reports are tested against runs
with missing evidence, duplicates and gaps. Measured results and explicit
unknowns are published before a milestone is called complete.
