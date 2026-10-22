# ADR-0050: Adoption workflows preserve authority and evidence

Status: accepted
Date: 2026-10-09

## Context

The gateway and one supervised run already offer approvals, a classification
bound to a tool definition, findings and a scoped reaction. Connecting a
user's existing setup and investigating the resulting records still require
several manual steps. Easier setup and review are useful only if they preserve
the authority and uncertainty those records express.

## Decision

Add the planned [adoption and incident workflows](../adoption-and-incident-workflows.md)
to the existing milestones, with acceptance checks in backlog B23–B27:
configuration preview and undo; one coding runtime's hooks as an integration
candidate; tool-definition change review; policy comparison and simulation;
and finding review with an incident package.

Setup requires explicit mode, operator-owned classification and an explicit
apply. Hook coverage distinguishes a pre-action enforcement point from a
post-action sensor. Reviewing a changed tool never repins it automatically.
A simulation is offline and cannot activate a policy. Review state is
separate from a finding's evidentiary verdict, notification state and reaction
authority; closing a case has no effect on approvals or stops.

These are delivery requirements, not new runtime semantics or published
contracts. The milestone order in
[ADR-0026](0026-first-value-and-external-extension-paths.md) and
[ADR-0039](0039-many-channels-into-one-core.md) stays in force. Each new format
or adapter design needs an accepted record before its implementation. The
proposed record does not authorize an implementation ahead of those records.

## Security / compatibility impact

No wire field, digest, verdict, mode or authorization path changes. No model
or new dependency enters the request path. Missing inputs stay unknown;
prompt and tool capture stays off by default and hidden reasoning is never
stored. The workflows preserve existing fail-closed and exact-action approval
requirements, including when an external runtime cooperates imperfectly.

## Alternatives considered

- Build a fleet dashboard first: postpones the first user's setup and needs
  identity and retention work before it can safely serve a team.
- Treat a hook installation as coverage of all local actions: obscures disabled
  hooks, subprocesses and paths the runtime never presents for admission.
- Use review disposition as a finding verdict or a learned permission:
  gives case management authority over enforcement.
- Replay metadata as if it held the original arguments: creates determinate
  results from missing inputs.

## Consequences

The first integration is selected from adopter needs rather than a list of
vendor names. Tool-definition review builds on the gateway's existing
fingerprints. Incident handling can start with exported records and an
external consumer before a web UI. Reversible DLP, a vault and model detectors
remain outside this work until a concrete flow requires their own design.

## Validation

The linked requirements page gives adversarial acceptance cases for every task.
Implementation requires the existing full quality gate and applicable
conformance tests. Documentation keeps planned work separate from
[the implementation inventory](../status.md); communication links a capability
to a runnable example and states the covered paths and failure behavior.
