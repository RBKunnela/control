---
title: Signed reaction
summary: How a signed plane takes its route, stop list header and lifts from roster operators, holds them to a stop list floor, and which commands sign them.
type: reference
covers: [internal/reaction/signed.go, internal/reaction/route2.go, internal/reaction/header2.go, internal/reaction/lift2.go, internal/reaction/signedstops/**, internal/policystate/stops.go, cmd/guardana-control/stops_signed.go, cmd/guardana-gateway/reaction_signed.go]
---

# Signed reaction

Under `approvals.authority: signed` an operator of the trust roster signs
each [reaction](reaction.md) document, and no route or lift key exists
([ADR-0077](../adr/0077-a-signed-plane-takes-a-stop-list-only-from-operators-signatures.md)).
[contracts.md](../contracts.md#under-the-signed-authority) gives each format.

| Document | Format | Signed under the act | Level |
| --- | --- | --- | --- |
| Route | `reaction-route/v1alpha2` | `route` | `admin` |
| Stop list header | stop list `2.0`, header `reaction-list-header/2.0` | `stops` | `operate` |
| Lift | `reaction-lift/v1alpha2` | `lift` | `operate` |

Each body is canonical JSON naming its `alg`, its `keyId`, the tenant, the
project and `file`: the absolute, cleaned path of the route file or of the
stop list, every link on the way to its directory resolved. A copy of a
signed document to another plane of the same tenant and project is refused
there for its `file`. The route names a `project_id` and a `scope` of `run`
on each rule, and every stop and covered line of a `2.0` list names the
project. The header names a `serial` and, after a carry, the `previous`
header's digest; a lift names the digest of the header it lifts from,
`list_head`, so a lift made against one list never verifies against a list
carried or restored after it.

A plane reads the route, the header and each lift through its operator ports
and refuses a document no operator with the act's grant over its tenant and
project signed; ports that cannot answer read as `operator ports
unavailable`, never as a refusal or a pass. The stop list floor, which `stops
floor init --tenant --project` makes and `reaction.stops_floor_dir` names, is
kept for the tenant the listener serves (`listener.principal_tenant` when set,
else `tenant_id`) and the project. It keeps the highest header serial the
plane took, that header's digest, and the length and SHA-256 of the part of
that list the plane accepted, raised each time that part grows. A plane
refuses a list below the floor's serial, one at that serial with another head,
one above it whose `previous` is not the floor's head, and, as a broken chain,
one at that serial shorter than the part the floor holds or beginning with
other bytes. It refuses `reaction.route`, `reaction.stops` or the
directory of either when its own account may write them, and a route file,
stop list or their directory its own account owns; only `dev`, on one
account, reads them. A `v1alpha1` route, `reaction.public_key` and a `1.0`
list are refused.

`route sign --key`, `stops init --key` and `stops lift --key` take the
operator's key, and `stops init`, `stops lift` and `stops list` take
`--roster` and `--root-key` in place of `--public-key`: each judges the route,
the list and its lifts on disk through the roster before it signs, and says
on standard error what it signed. A carry judges every line of the old list
as a plane does; with `--stops-floor`, the plane's floor directory, it also
refuses an old list cut back below the part the plane accepted, and without
it says that the floor was not read. `react` takes `--approvals`, the plane's
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

`doctor` judges the route and the header through the roster file, holds the
header to the stop list floor without raising it, and names who signed each.
`/healthz` gives a `2.0` list's header serial under `stops.signed`; only
`health.socket` names the operators who signed the header and the route.

## Limits

- The plane's own account writes its floor: it can lower or remove the
  floor, or name a new one, and a list the stop writers' account cut back is
  then taken without the stops it dropped. The stop writers' account alone
  cannot cut what the floor holds, and the plane's account alone cannot write
  the list. A stop appended and cut before a plane read it was never
  accepted, and no floor holds it.
- A plane serves a carried list after a restart, as any new list.
