# ADR-0082: A signed document names its plane, and a signed plane serves one tenant

Status: accepted
Date: 2026-11-13

Builds on [ADR-0073](0073-an-approval-counts-only-as-the-plane-judges-it.md),
[ADR-0075](0075-a-signed-plane-takes-a-pause-only-from-an-operators-signature.md),
[ADR-0076](0076-a-signed-plane-takes-a-run-only-from-an-operators-signature.md)
and [ADR-0077](0077-a-signed-plane-takes-a-stop-list-only-from-operators-signatures.md).

## Context

Under `approvals.authority: signed` each operator-signed file a plane takes
is bound to a tenant, a project and the absolute path it was signed for. A
path is not a host: ADR-0075 and ADR-0076 state that planes using one path
on two hosts must differ in tenant or project, or a copy from one to the
other is taken. Nothing in a signed file says which plane it was signed for.

The same plane judged its documents under two tenants. Answers and pauses
were judged under `tenant_id`; runs, the route, the stop list and lifts
under the listener's tenant, `listener.principal.tenant_id` when it is set.
A configuration that set the two apart had one plane judge one part of its
authority for one tenant and the rest for another.

## Decision

- `plane_id` is a configuration key, read only under `signed`: required
  there, with no default, and refused under any other authority. The
  operator chooses it; it is held to the contract's identifier rule. It is
  read from the configuration file alone, which the signed start already
  judges not plane-writable, and a signed start refuses any key the
  environment sets, this one included. `guardana-gateway dev` is the one
  exception: it sets an id of its own through its layer and refuses a demo
  that sets the key.
- The plane's id joins `file` in each signed body a plane takes from an
  operator, the pause file, the route, the stop list header and the lift,
  and in the state backup manifest. Those formats carry it in later changes
  of the same release; this change adds the key and nothing binds to it yet.
- Run records keep their `records/` path binding and take no plane id: a
  run can span planes ([ADR-0044](0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md),
  [ADR-0045](0045-one-run-is-supervised-against-its-procedure.md),
  [ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md),
  [ADR-0068](0068-a-run-belongs-to-one-project.md)).
- A signed plane serves one tenant. A `listener.principal.tenant_id` that is
  set and differs from `tenant_id` is refused at load, naming both keys.
  `directory` and `memory` are unchanged.

## Security / compatibility impact

A signed configuration without `plane_id`, or with two tenants, no longer
loads; the operator adds the key, and sets the listener's tenant to
`tenant_id` or removes it. A document signed for one plane will be refused
by another that shares its path, tenant and project once the formats carry
the id. `doctor` names the plane's id and tenant on its trust line, and the
health answer's `trust` member names the id.

## Alternatives considered

- The id instead of `file`: two configurations sharing an id would take each
  other's files. With both, they still never do.
- An id derived from the host: clones share it, a restore changes it, and it
  sits outside the configuration the start judges.
- A random id the plane mints: one more command, and files no one can read
  for which plane they belong to.
- Judging everything under the listener's tenant: it moves the comparison
  beside the approval binding, which names `tenant_id`.

## Consequences

The plane's account still chooses `--config` at start, so it chooses which
configuration, and so which id, it runs under. Uniqueness across hosts is
the operator's: two planes given one id, one path, tenant and project take
each other's documents, as before. A plane that served a second tenant
through the listener needs a plane of its own for it.

## Validation

`internal/gatewayconfig`: `TestTheSignedAuthorityNeedsEveryKeyItReads`
requires `plane_id` under `signed` and refuses it under `directory`;
`TestThePlaneIDIsAnIdentifier` refuses an id the contract refuses;
`TestASignedPlaneServesOneTenant` refuses a second tenant under `signed` and
takes the same tenant, none, and a second one under `directory`.
`cmd/guardana-gateway`: `TestASignedStartRefusesWhatThePlanesAccountCouldTurn`
refuses `plane_id` from the environment and names the id in the health
answer; `TestASignedPlaneWithTwoTenantsIsRefused` refuses a two-tenant
configuration with a route and stop list in place;
`TestADevPlaneTakesOnlyTheTrustDevLaidOut` and
`TestDevRefusesADemoThatSetsWhatDevOwns` hold a dev plane to its own id.
