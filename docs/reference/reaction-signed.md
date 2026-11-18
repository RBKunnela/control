---
title: Signed reaction
summary: How a signed plane takes its route, stop list header and lifts from roster operators, holds them to a stop list floor, and which commands sign them.
type: reference
covers: [internal/reaction/signed.go, internal/reaction/route2.go, internal/reaction/route3.go, internal/reaction/header2.go, internal/reaction/lift2.go, internal/reaction/lift3.go, internal/reaction/subject.go, internal/reaction/maystop.go, internal/reaction/signedstops/**, internal/policystate/stops.go, cmd/guardana-control/stops_signed.go, cmd/guardana-control/stops_lift.go, cmd/guardana-gateway/reaction_signed.go]
---

# Signed reaction

Under `approvals.authority: signed` an operator of the trust roster signs
each [reaction](reaction.md) document, and no route or lift key exists
([ADR-0077](../adr/0077-a-signed-plane-takes-a-stop-list-only-from-operators-signatures.md)).
[contracts.md](../contracts.md#under-the-signed-authority) gives each format.

| Document | Format | Signed under the act | Level |
| --- | --- | --- | --- |
| Route | `reaction-route/v1alpha3` | `route` | `admin` |
| Stop list header | stop list `3.0`, header `reaction-list-header/3.0` | `stops` | `operate` |
| Lift | `reaction-lift/v1alpha3` | `lift` | `operate` |

Each body is canonical JSON naming its `alg`, its `keyId`, `plane_id`, the
tenant, the project and `file`: the absolute, cleaned path of the route file
or of the stop list, every link on the way to its directory resolved. A
plane refuses a body that names another `plane_id` or none, so a copy of a
signed document to another plane of the same tenant and project is refused
there for its `plane_id` even where the paths are alike, and for its `file`
where they differ. The route names a `project_id` and a `scope` on each
rule, and every stop and covered line of a `3.0` list names the project, the
`scope` and the `subject`. Under scope `run` the subject is the line's
`run_id`; under `agent` or `principal`, below, it is the agent or principal
and `run_id` is the run the finding was about. The header names a `serial` and, after a carry, the `previous`
header's digest; a lift names the digest of the header it lifts from,
`list_head`, and the `scope` and `subject` whose stops it ends, so a lift
made against one list never verifies against a list carried or restored
after it.

A plane reads the route, the header and each lift through its operator ports
and refuses a document no operator with the act's grant over its tenant and
project signed; ports that cannot answer read as `operator ports
unavailable`, never as a refusal or a pass. At every read of the list it
asks its ports again, within one poll interval, about the route, the header
and one lift of each operator who signed one, so revoking any of them,
taking the route's admin grant away, or ports that do not answer in time
make the stop state unknown until they answer again; a route refused then
reads as `a route no operator vouches for`. The stop list floor, which `stops
floor init --tenant --project` makes and `reaction.stops_floor_dir` names, is
kept for the plane's tenant and project. It keeps the highest header serial the
plane took, that header's digest, and the length and SHA-256 of the part of
that list the plane accepted, held to at every read and raised under the
floor's lock each time that part grows. A plane
refuses a list below the floor's serial, one at that serial with another head,
one above it whose `previous` is not the floor's head, and, as a broken chain,
one at that serial shorter than the part the floor holds or beginning with
other bytes. It refuses `reaction.route`, `reaction.stops` or the
directory of either when its own account may write them, and a route file,
stop list or their directory its own account owns; only `dev`, on one
account, reads them. A `v1alpha1` route, `reaction.public_key` and a `1.0`
list are refused. A `reaction-route/v1alpha2` route, a `2.0` list and a
`reaction-lift/v1alpha2` lift, which 0.17 signed without `plane_id`, are
refused at start and at every read, naming `route sign` or `stops init
--carry`, and raise no floor.

`route sign --key`, `stops init --key` and `stops lift --key` take the
operator's key; `route sign` refuses a `v1alpha2` document, naming
`reaction-route/v1alpha3` and `plane_id`, and `stops init`, `stops lift` and `stops list` take
`--roster` and `--root-key` in place of `--public-key`: each judges the route,
the list and its lifts on disk through the roster before it signs, and says
on standard error what it signed. A carry judges every line of the old list
as a plane does; with `--stops-floor`, the plane's floor directory, it also
refuses an old list cut back below the part the plane accepted, and without
it says that the floor was not read. Only the floor's owner reads it: on two
accounts root copies it for the operator
([upgrade a plane](../guides/upgrade-a-plane-from-0-17.md)). `--carry-route` may name a
`v1alpha2` route and `--carry` its `2.0` list: a carry is the one reader of
both, judges them by tenant, project and file, as 0.17 did, and writes a
`3.0` list for the plane the new route names, at the next serial, naming the
old head as `previous`; each carried stop takes scope `run` and its run as
subject. The operator vouches that the old list is this plane's. Each
command judges a route against the plane the route names. `react` takes `--approvals`, the plane's
approvals directory, and will not run as the account that owns it; the
directory is the caller's to name, so this guards against a mistake and does
not keep the plane's account out. The console writes no stop and no lift at
any setting.

`--serial` matters only while the floor holds no serial: once it holds one, a
new list is taken only as a carry naming the floor's head. When the old list
cannot be carried, the plane's account makes a new floor with `stops floor
init` in a new directory and names it in `reaction.stops_floor_dir`, an
operator starts a new list with `stops init --key`, and `react` stops again
what may still stop. A new floor takes any list, so this is the step that
lowers it.

## A stop of an agent or a principal

A route rule may carry scope `agent` or `principal` for `REPEATED_DENIAL`
version `2`, `DENIED_ACTION_RETRIED_ARGUMENTS` version `1` and
`DENIED_ACTION_RETRIED_RESOURCE` version `1`, the rules about what the actor
did, and only with `expires_seconds`. Every reader of a route refuses either
scope on any other rule, and either scope without a lifetime
([ADR-0083](../adr/0083-a-finding-may-stop-an-agent-or-a-principal.md)).

`react` takes the subject from the judged run's record, its `agent_id` or
`principal_id`, and writes nothing for a record that names none. Such a
stop lasts the rule's lifetime from when `react` wrote it, whatever the run's
expiry. A finding is covered only by an active stop of the same scope and
subject that lasts as long, whichever run either was about.

A plane matches such a stop against the agent and principal its listener's
configuration names, within the listener's tenant, never against the
envelope or a run record; a principal stop matches the principal's id
alone, never its type. Every opened run of a plane carries the listener's
identity, so **on one plane a stop of its agent or principal stops the
plane**: every run, a run opened after the stop, and a call with no run, each
`AGENT_OR_PRINCIPAL_STOPPED` (48, `DENY`). The tool listing is not stopped.
A call already handed out, or being handed out, finishes under a stop of any
scope.
A call under a stop of its run and of its agent lists both codes,
`RUN_STOPPED` first. An active stop of either scope whose subject the call
does not name reads as an unknown stop state, `STOP_STATE_UNAVAILABLE`, never
as no stop; a plane with a stop list refuses to start unless its listener
names a tenant, a principal and an agent.

`stops lift` takes exactly one of `--run`, `--agent` and `--principal`, and
the last two only under `signed`. A lift ends the stops of its scope and
subject through its line alone: a lift of a run leaves a stop of its agent
standing, and a lift of the agent ends that one.

`doctor` names each rule that stops an agent or a principal, and each such
stop whose agent, principal or tenant is not the listener's, which matches
no call. `health.socket` lists each stop with its `scope` and `subject` and,
under health schema `3`, names the stops that match no call by entry id in
`unheld_entries` and `unread_entries`.

`doctor` judges the route and the header through the roster file, holds the
header to the stop list floor without raising it, and names who signed each.
`/healthz` gives a `3.0` list's header serial under `stops.signed`; only
`health.socket` names the operators who signed the header and the route.

## Limits

- The plane's own account writes its floor: it can lower or remove the
  floor, or name a new one, and a list the stop writers' account cut back is
  then taken without the stops it dropped. The stop writers' account alone
  cannot cut what the floor holds, and the plane's account alone cannot write
  the list. A stop appended and cut before a plane read it was never
  accepted, and no floor holds it.
- A plane serves a carried list after a restart, as any new list.
