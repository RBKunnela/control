---
title: Back up and restore a plane
summary: Copy a stopped plane's floors, runs, pause file and stop list, and after a loss raise them back so no floor ends lower, every run is closed and no hold resumes.
type: how-to
covers: [internal/recovery/**, cmd/guardana-control/state.go, internal/policystate/restore.go, internal/policystate/restorestops.go, internal/runs/restore.go, internal/runs/restoresigned.go, internal/pause/merge.go]
---

# Back up and restore a plane

A plane keeps authority state on disk: floors, runs and their taint, a
pause file and a stop list. `state backup` copies it; after a loss,
`state restore` raises what survived to the backup and never lowers anything
([ADR-0078](../adr/0078-a-restore-only-raises.md)). Both are `experimental`;
[status.md](../status.md) is the inventory.

## Prerequisites

- The plane stopped. Both commands take the spool's and the hold journal's
  locks for their whole run and refuse while a plane holds either. On a
  system without a file lock, Windows among them, both refuse.
- The plane's account and environment: the commands read the configuration
  as the plane does, and a restore writes only what that account owns.
- `approvals.authority` set to `directory` or `signed`. Under `memory` there
  is nothing to restore, and both commands refuse.

## Steps

1. Back up into a directory that does not exist yet:

   ```sh
   guardana-control state backup plane.yaml /backups/plane-1
   ```

   It prints `backed up <n> files into /backups/plane-1`, and one line for
   each configured path where nothing stood. The directory is made mode
   `0700`, each copy mode `0600`, and `backup.json` is written last: a
   directory without it is no backup.

2. After a loss, make the spool and the hold journal directories again,
   empty and owned by the plane's account, then restore:

   ```sh
   guardana-control state restore plane.yaml /backups/plane-1
   ```

   It prints what it did per configuration key, the residual below, and
   which signed files to put back. It checks every class before its first
   write, so a refusal leaves the plane's files as they were; a failure
   after that prints what was done before it. Under `signed`, make the
   runs directory's `records/` and `state/` again first: without them the
   restore refuses.

3. Check the plane before it serves:

   ```sh
   guardana-gateway doctor --config plane.yaml
   ```

## What a backup holds

`backup.json`, schema `0.1`, names the authority, tenant, project and time
of the backup, and per file its class, configuration key, absolute source,
path in the backup, SHA-256 and size.
A restore refuses a backup of another tenant, project or authority, a file
whose source is not where the configuration puts it today, a size or hash
that differs, a file the manifest does not list, and a major other than `0`.

Copied, each under its class: `policy.state_dir`, `reaction.floor_dir`,
`runs.dir`, `pause.file` and `reaction.stops`, and under `signed` also
`trust.floor_dir`, `pause.floor_dir` and `reaction.stops_floor_dir`. Never copied: the spool, the hold journal and its ledger,
the approvals store and inbox, the trail, the signer's floors, the bundle
and its statement, the roster, the route and every key.

The manifest is unsigned: its hashes catch corruption, not a rewrite of the
backup and its manifest together, so keep the backup where only the plane's
account and the operator write. A restore copies the files it verified
into an owner-only `state-restore-*` directory under `$TMPDIR` and reads
only that copy, which a killed restore leaves behind.

## What a restore does

- Plane floor, per bundle id either side holds: the higher serial of the
  two, with its digest, stamped issued and latest at the restore time,
  rounded up to the whole second; a plane started within that second
  refuses until it passes. The bundle's own statement, issued before the
  restore, confirms nothing; the next renewal does. Two digests at one
  serial, or a clock behind either floor, refuse before that id is written.
  An id neither side holds a serial for is listed with no file, so the
  start refuses until `policy state reset`.
- Route, roster and pause floors: the higher serial of the two. Stop list
  floor: the higher serial; at one serial and head, the longer accepted
  part when the live list or the backup's copy begins with both parts.
  Two heads at one serial, or two parts no list shows as one history,
  refuse.
- Runs: every run closed at the restore time. Under `directory` each record
  either side holds is written closed, keeping an earlier close; under
  `signed`, `state/<id>.closed` is written for every run either side
  names, so an open record put back later is refused. Each root's taint is
  the join of both sides under its lock, and a state lost beside its
  record, or under `signed` beside its lock file, counts as untrusted with
  an unknown read.
- Pause: under `directory` the union of both files' entries; an id holding
  two different pauses refuses. Under `signed` only its floor is raised.
- Stop list: under `directory`, a surviving list that begins with the
  backup's, or carries it, is kept. With none, the backup's list is carried,
  judged against `reaction.route`, into a list of a new id holding every
  stop no lift ended, where a lift made for the old list does not verify.
  Any other surviving list is two histories, and the restore refuses;
  moving it aside lets the restore carry the backup's and loses the stops
  added to it since. Under `signed` the list is an operator's file, and only
  its floor is raised.

Nothing held resumes: the journal, the ledger and the approvals store are
never written, so a lost hold stays lost and a spent approval stays spent.
A missing floor directory is built under a temporary name and renamed into
place; a restore stopped at any write and run again ends where an unbroken
one does.

## Verify

`doctor` reads each signed file against the raised floors. Under `signed`
the restore never writes an operator's file: the pause file, the stop list
and `records/` among them. Put back the newest signed copy you hold, the
backup's only when you hold none newer; the plane takes it wherever the
raised floor still does. A lower signed pause file blocks every call until
an operator signs a new one.

## Take a stop list back

Under `signed`, a stop list floor put back at the backup's serial takes only
a list whose previous head is the backup's. To reach a list carried twice
since, let the plane take the chain in serial order, or put the newest list
back under a new floor, which takes the first list it reads:

```sh
mv <reaction.stops_floor_dir> <aside>
guardana-control stops floor init --tenant <t> --project <p> <reaction.stops_floor_dir>
```

Under `directory` the backup holds no route, so once `reaction.route` was
replaced, restore with the old route back in its place, then put the
current one back and carry the list the restore wrote into a new directory
that replaces `reaction.stops`:

```sh
guardana-control stops init --carry <reaction.stops> --carry-route <old route> \
  --route <current route> --public-key <route key> <new dir>
```

With the route key replaced too, no carry reaches the current route.

## Limits

- A statement issued before the restore above the restored floor's serial
  still confirms within `policy.max_stale`.
- A run neither the backup nor `records/` names reopens only through an
  operator's signed write.
- An older signed file put back, the backup's among them, brings back a
  grant revoked, a route changed or a pause signed after the backup.
- A stop added after the backup is lost with the list, and one lifted after
  it is back until an operator lifts it again.
- A floor file removed beside its marker is restored from the backup, as
  if its directory were lost.
- A plane started while a restore runs may raise `policy.state_dir` before
  the spool's lock refuses it. It only raises.
- Copying a volume back by hand is unsupported: it lowers floors, reopens
  closed runs, resumes holds and lets spent approvals count again.

## Roll back

A restore only raises, so it has no undo. `policy state reset` lowers a
plane floor, recording why; a new run is opened with `runs open`.
