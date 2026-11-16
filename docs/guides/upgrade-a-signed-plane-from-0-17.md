---
title: Upgrade a signed plane from 0.17
summary: Sign a 0.17 plane's pause file, route and stop list again for its plane_id, carry its stops and lifts into a new list, and point the plane at it.
type: how-to
covers: [cmd/guardana-control/pause*.go, cmd/guardana-control/route.go, cmd/guardana-control/stops.go, cmd/guardana-control/stops_signed.go, internal/reaction/stopwrite/carry.go]
---

# Upgrade a signed plane from 0.17

## When to use this

A plane under `approvals.authority: signed` ran 0.17. 0.18 names the plane in
every signed document it serves, so it refuses the pause file, the route and
the stop list 0.17 signed, each naming the command that replaces it, and
raises no floor while it does
([ADR-0082](../adr/0082-a-signed-document-names-its-plane-and-a-signed-plane-serves-one-tenant.md)).

## Prerequisites

- The plane is stopped, and `plane_id` is set in its configuration.
- A copy of the pause file is kept aside for a roll back: step 1 signs the
  file again in place.
- An operator of the roster holds `admin` for the route and `operate` for the
  pause file and the stop list in the plane's tenant and project.
- The paths below are examples: `/srv/plane` holds the plane's files and
  `orders-eu-1` is its `plane_id`.

## Steps

```
# 1. The pause file: its entries signed again for this plane at the next serial.
# A version 3 file names no plane: sign only the file this plane read.
guardana-control pause sign --key op.key --roster /etc/guardana/roster.json \
  --root-key /etc/guardana/root.pub --plane-id orders-eu-1 /srv/pause/pause.json

# 2. The route: edit the route document to kind reaction-route/v1alpha3, add
# "plane_id": "orders-eu-1" and raise its serial by one; keep its route_id.
# Sign it at a new path: step 3 reads the old route at its own.
guardana-control route sign --key admin.key --out /srv/plane/route-018.json route.json

# 3. The stop list: carried into a new directory, judged first as 0.17 judged it.
guardana-control stops init --key op.key --route /srv/plane/route-018.json \
  --roster /etc/guardana/roster.json --root-key /etc/guardana/root.pub \
  --carry /srv/plane/stops --carry-route /srv/plane/route.json \
  --stops-floor /srv/plane/stopsfloor /srv/plane/stops-018

# 4. As the plane: a new backup, whose manifest 0.2 names the plane.
guardana-control state backup gateway.yaml /backups/plane-2
```

Then set `reaction.route` to `/srv/plane/route-018.json` and
`reaction.stops` to `/srv/plane/stops-018`, and start the plane. Leave the new
route where step 2 signed it: a signed route names its own file and the new
list's header names that route, so a route moved to the old path is refused.
Keep `route.json` and `stops` for a roll back.

Run `react` with the 0.18 binary, with `--route /srv/plane/route-018.json` and
`--stops /srv/plane/stops-018`. A 0.17 `react` left on the old route and
directory keeps appending to a list the plane no longer reads.

`stops init --carry` is the one command that reads a `reaction-route/v1alpha2`
route and a `2.0` list. It judges every line through the roster, as a 0.17
plane did, and with `--stops-floor` refuses an old list cut back below what
the plane accepted. The old documents name no plane, so the operator vouches
that the list is this plane's. The new `3.0` header takes the next serial and
names the old head as `previous`, which the stop list floor needs to take it.
Each stop no lift ended is carried with scope `run` and its run as subject; a
lifted run's findings are carried as covered.

## Verify

- `stops init` says on standard error `for plane orders-eu-1`, a serial one
  above the old list's, and the old head as `previous head`.
- `doctor` prints `ok reaction` and names who signed the route and the
  header.
- `/healthz` gives the new serial under `stops.signed`, and a run the old list
  stopped is still refused with `RUN_STOPPED`.

The health answer is schema `3` in 0.18. A script that reads `/healthz` or
`health.socket` and checks `"schema"` takes `"3"`. Under `stops`, the
socket's `unheld_runs` and `unread_runs` are now `unheld_entries` and
`unread_entries` and name entry ids, since a stop can name an agent or a
principal; each entry in `entries` names its `scope` and `subject`. The
counts `active`, `unheld` and `unread` are unchanged.

## Roll back

0.17 refuses a `reaction-route/v1alpha3` route, a `3.0` list and a backup
whose manifest names a plane. To go back, stop the plane, point
`reaction.route` and `reaction.stops` at the 0.17 files you kept, copy the
0.17 pause file you kept back to its path, and start 0.17. Three floors hold
what 0.18 took:

- The pause floor holds the serial `pause sign` gave the pause file, so 0.17
  refuses the copy below it. Make a new pause floor with `pause floor init
  --tenant <tenant> --project <project>` in a new directory and name it in
  `pause.floor_dir`.
- The route floor holds the new route's serial, so 0.17 refuses the old
  route below it. Make a new route floor with `policy state init --kind route
  --route-id <route_id>` in a new directory and name it in
  `reaction.floor_dir`, or sign with 0.17's `route sign` a
  `reaction-route/v1alpha2` route at a serial above the new route's, at the
  path `reaction.route` names. A new route needs a new list, since a header
  names its route.
- The stop list floor holds the carried list's serial, so 0.17 refuses the
  old list below it. Make a new floor with `stops floor init` in a new
  directory, name it in `reaction.stops_floor_dir`, and start a new list with
  `stops init --key`.

Run `react` with the 0.17 binary against them; it stops again what may still
stop.
