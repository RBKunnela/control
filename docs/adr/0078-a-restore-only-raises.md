# ADR-0078: A restore only raises

Status: accepted
Date: 2026-11-07

Amends [ADR-0038](0038-a-signed-freshness-statement-and-a-serial-floor.md)
with a floor a restore stamps, and
[ADR-0076](0076-a-signed-plane-takes-a-run-only-from-an-operators-signature.md)
with the closes a restore carries into `state/`. Builds on
[ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md),
[ADR-0073](0073-an-approval-counts-only-as-the-plane-judges-it.md) and
[ADR-0075](0075-a-signed-plane-takes-a-pause-only-from-an-operators-signature.md).

## Context

A plane's authority state lives on disk: floors that keep an older policy,
roster or pause from being taken again, runs and what each took in, and a
pause file. Losing that disk and copying an old volume back lowers every
floor, reopens closed runs, resumes holds and lets a spent approval count
again. Under the signed authority the plane's account cannot write the
operators' files, so a restore that merged them would need an operator's
signature over a union nobody judged.

## Decision

- `guardana-control state backup <config> <dir>` copies, per class, the
  plane floors, the route floors, the runs directory, the pause file and the
  stop list, and under `signed` the roster's, the pause's and the stop
  list's floors, into a new
  owner-only directory with `backup.json` (schema `0.1`) written last. The
  spool, the hold journal and its ledger, the approvals store and inbox, the
  trail, the signer's floors and every key are never copied. A test holds
  every configuration key naming a file to one side or the other.
- `state restore <config> <dir>` runs as the plane's account, holding the
  spool's and the journal's locks for its whole run, and writes only what
  that account owns: floors, runs and, under `directory`, the pause file and
  the stop list. It refuses another tenant, project or authority, a source
  the configuration does not name, a tampered or unlisted file and another
  major. It copies the bytes it verified into an owner-only temporary
  directory and restores only from that copy, and it runs every class's
  check, two histories and a lost signed runs layout among them, before its
  first write.
- The manifest is unsigned. Its hashes catch a corrupted backup, not a
  hostile writer of the backup directory, which only the plane's account
  and the operator may write.
- The locks are the directory locks the spool and the journal take, taken
  without linking either, so the approver's binary still reaches neither
  the gateway nor evidence. Where the system has no file lock, both
  commands refuse.
- Every floor ends at the higher serial of the backup's and the live one. A
  plane floor is stamped with issued and latest at the restore time rounded
  up to the second, a raise in the floor's own order, so no statement issued
  before the restore confirms that serial again. The floor format does not
  change. The stop list floor rises in its own order: the higher serial, and
  at one serial and head the longer accepted part where the live list or
  the backup's copy begins with both parts; anything else is refused.
- Every run closes at the restore time. Under `signed` the restore writes
  `state/<id>.closed` for every run the backup or `records/` names, the
  close ADR-0076 carries, so an open record put back later is refused.
  Taint is joined: untrusted where either side is, the higher read, unknown
  above all. A state lost beside its lock file or its record joins as
  untrusted with an unknown read under both authorities.
- Under `directory` the pause file is the union of both; under `signed`
  only the pause floor is raised, and `doctor` names what an operator puts
  back.
- Under `directory` a surviving stop list is kept when it begins with the
  backup's or carries it; with none, the backup's is carried into a list of
  a new id, so a lift bound to the old list does not verify there; any other
  list is two histories and refused. Under `signed` the list is an
  operator's file, never written, and only its floor is raised.

## Security / compatibility impact

A restore cannot grant authority: it only raises floors, closes runs and
adds pauses, and never writes a hold, an approval or an operator's file. A
statement at a higher serial than the restored floor, issued before the
restore, still confirms within `policy.max_stale`. Under `signed` the floors
are only as strong as the plane's account, and the roster, route, pause and
stop list floors rise only to the backup's serial: an older signed file put
back, the backup's copy among them, brings back a grant revoked, a route
changed or a pause signed after the backup, so an operator puts back the
newest signed file they hold. A stop list floor put back at the backup's
serial takes a later list only when that list names the backup's head as
its previous, so a list carried twice since the backup is refused. The way
back is to let the plane take each list of the chain in serial order, or to
make `reaction.stops_floor_dir` again with `stops floor init` and put back
the newest list, which a floor with no serial takes. Under `directory` the
backup holds no route: after the route is replaced, the restore refuses
the backup's list until the route it was written under stands at
`reaction.route` again, and a list carried under it is then carried into
the current route; with the route key replaced too, the backup's stops are
lost. A raw volume copy stays
unsupported. No wire contract changes; `backup.json` is a new format.

## Alternatives considered

- Union the signed files and have an operator re-sign them: puts a key in
  recovery and asks for a signature over a union nobody judged.
- A floor format `1.1` with a `not_before`: the stamp is already a raise in
  the floor's order, so a new format buys nothing.
- Check once that no lock is held: a plane could start halfway through.

## Consequences

An operator stops the plane, makes the spool and journal directories again
and restores; a lost hold is lost, and an operator decides again. A stop
added or lifted after the backup is lost with the list, and a stop lifted
after it is back until an operator lifts it again.

## Validation

`internal/recovery`'s tests restore after a loss and over surviving state,
refuse each bad backup, a held lock, a backup file changed after its check
and two histories of runs, pauses or stops with the tree unchanged, stop a
restore before each write under each authority and rerun it to the same
tree, and draw random backups per class to show nothing ends lower
(`TestRestoreNeverLowers`).
