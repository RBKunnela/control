---
title: Upgrade a plane from 0.17
summary: What every plane meets in 0.18, and how a signed plane signs its pause file, route and stop list again for its plane_id and carries its stops.
type: how-to
covers: [cmd/guardana-control/pause*.go, cmd/guardana-control/route.go, cmd/guardana-control/stops.go, cmd/guardana-control/stops_init.go, cmd/guardana-control/stops_lift.go, cmd/guardana-control/stops_signed.go, internal/reaction/stopwrite/carry.go, internal/policystate/stops.go, internal/recovery/manifest.go, cmd/guardana-gateway/health.go, cmd/guardana-gateway/health_stops.go]
---

# Upgrade a plane from 0.17

## When to use this

A plane ran 0.17 and is to run 0.18. Every plane follows the first part. A
plane under `approvals.authority: signed` also follows the second: 0.18 names
the plane in the signed pause file, route, stop list and lifts, so it
refuses the pause file, the route and the stop list 0.17 signed, each naming
the command that replaces it, and raises no floor while it does
([ADR-0082](../adr/0082-a-signed-document-names-its-plane-and-a-signed-plane-serves-one-tenant.md)).

A 0.17 plane need not run 0.18 on its way to 0.19: take these steps with the
0.19 binaries, leaving `DEADLINE_EXCEEDED`,
`DENIED_ACTION_RETRIED_ARGUMENTS` and `DENIED_ACTION_RETRIED_RESOURCE` out of
the route step 2 signs, then [upgrade a plane from 0.18](upgrade-a-plane-from-0-18.md)
before the plane starts: 0.19 will not start on a route naming those rules or
a configuration block written twice. A signed plane has then taken its route
step.

## Every plane

Under `directory` and `memory` the plane reads the files 0.17 wrote: replace
both binaries and start it. Three things it answers differ.

- The health answer is schema `3`. A script that reads `/healthz` or
  `health.socket` and checks `"schema"` takes `"3"`. Under `stops`, the
  socket's `unheld_runs` and `unread_runs` are now `unheld_entries` and
  `unread_entries` and name entry ids, since a stop can name an agent or a
  principal; each entry in `entries` names its `scope` and `subject`. The
  counts `active`, `unheld` and `unread` are unchanged.
- `state backup` writes manifest `0.2`. Under `directory` it names no plane,
  so 0.17 restores it, and 0.18 restores a `0.1` backup.
- `stops lift` takes exactly one of `--run`, `--agent` and `--principal`, the
  last two only under `signed`, so a 0.17 lift with `--run` runs as before.

To go back under `directory` or `memory`, start the 0.17 binaries on the
same files; a signed plane goes back as its [roll back](#roll-back) says.

## A signed plane

### Prerequisites

- The plane is stopped, `plane_id` is set in its configuration, and
  `listener.principal.tenant_id` is unset or equal to `tenant_id`: a signed
  plane serves one tenant.
- A copy of the pause file is kept aside for a roll back: step 1 signs the
  file again in place.
- An operator of the roster holds `admin` for the route and `operate` for the
  pause file and the stop list in the plane's tenant and project.
- The paths and names below are examples: `/srv/plane` holds the route and
  the stop lists, which the account that signs the route may write and the
  plane's account may not, or the plane refuses to start;
  `/var/lib/guardana/stopsfloor` is the plane's stop list floor;
  `orders-eu-1` is its `plane_id`, `ops` is the stop writers' account, which
  holds an operator's key, and `guardana` is a group of the plane's account
  alone.

### Steps

```
# 1. As the operator: the pause file's entries signed again for this plane at
# the next serial. A version 3 file names no plane: sign only the file this
# plane read.
guardana-control pause sign --key op.key --roster /etc/guardana/roster.json \
  --root-key /etc/guardana/root.pub --plane-id orders-eu-1 /srv/pause/pause.json

# 2. As an admin: edit the route document to kind reaction-route/v1alpha3, add
# "plane_id": "orders-eu-1" and raise its serial by one; keep its route_id.
# Sign it at a new path: step 4 reads the old route at its own.
guardana-control route sign --key admin.key --out /srv/plane/route-018.json route.json

# 3. As root: a copy of the plane's stop list floor for ops, and the new stops
# directory.
cp -Rp /var/lib/guardana/stopsfloor /srv/plane/stopsfloor-copy
chown -R ops /srv/plane/stopsfloor-copy
mkdir /srv/plane/stops-018
chown ops:guardana /srv/plane/stops-018
chmod 2750 /srv/plane/stops-018

# 4. As ops: the stop list carried into the new directory, judged first as
# 0.17 judged it.
guardana-control stops init --key op.key --route /srv/plane/route-018.json \
  --roster /etc/guardana/roster.json --root-key /etc/guardana/root.pub \
  --carry /srv/plane/stops --carry-route /srv/plane/route.json \
  --stops-floor /srv/plane/stopsfloor-copy /srv/plane/stops-018

# 5. As root: the copy is no longer needed.
rm -r /srv/plane/stopsfloor-copy

# 6. In gateway.yaml: set reaction.route to /srv/plane/route-018.json and
# reaction.stops to /srv/plane/stops-018. Then, with the plane still stopped,
# as the plane: a new backup, whose manifest 0.2 names the plane and holds
# the carried list.
guardana-control state backup gateway.yaml /backups/plane-2
```

Then start the plane. Leave the new route where step 2 signed it: a signed
route names its own file and the new list's header names that route, so a
route moved to the old path is refused. Keep `/srv/plane/route.json` and
`/srv/plane/stops` for a roll back.

Run `react` with the 0.18 binary as `ops`, with `--route
/srv/plane/route-018.json` and `--stops /srv/plane/stops-018`. Step 4 takes
the write bits off the old list once every check passed and before it writes
the new one, so a 0.17 `react` left on the old route and directory fails to
write instead of appending to a list the plane no longer reads. Only the old
list's owner may take them, so run step 4 as that account: under any other,
it refuses before it writes anything.

`stops init --carry` is the one command that reads a `reaction-route/v1alpha2`
route and a `2.0` list. It judges every line through the roster, as a 0.17
plane did. Only the floor's owner may read a floor, so step 3 copies the
plane's: with `--stops-floor` the carry refuses an old list cut back below
the part the plane accepted. A floor names its tenant and project, not its
directory, so the check trusts the operator, who chooses the old list and
the floor. The old documents name no plane, so the operator also vouches that
the list is this plane's. The new `3.0` header takes the next serial and names
the old head as `previous`, which the stop list floor needs to take it. Each
stop no lift ended is carried with scope `run` and its run as subject; a
lifted run's findings are carried as covered. A stop the new route does not
grant refuses the carry, naming it; `stops lift` takes no `v1alpha2` route,
so change the route document as the refusal says, sign it again and rerun
step 4.

### Verify

- `stops init` says on standard error `for plane orders-eu-1`, a serial one
  above the old list's, and the old head as `previous head`.
- `doctor` prints `ok reaction` and names who signed the route and the
  header.
- `/healthz` gives the new serial under `stops.signed`, and a run the old list
  stopped is still refused with `RUN_STOPPED`.

### Roll back

0.17 refuses a `reaction-route/v1alpha3` route, a `3.0` list, a backup
whose manifest names a plane and the `plane_id` key. To go back, stop the
plane, remove `plane_id` from its configuration, point `reaction.route` and
`reaction.stops` at the 0.17 files you kept, and copy the 0.17 pause file you
kept back to its path. Three floors hold what 0.18 took; replace each before
you start 0.17:

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

Step 4 left the kept list `/srv/plane/stops/stops.jsonl` without its write
bits. Before 0.17's `react` writes to it, give them back as its owner with
`chmod u+w`, or that `react` fails on every stop.

Then start 0.17, and run `react` with the 0.17 binary against the route and
the new list; it stops again each run that a finding and the route still
stop.
