# ADR-0075: A signed plane takes a pause only from an operator's signature

Status: accepted
Date: 2026-11-06

Amends [ADR-0019](0019-an-operator-can-pause-calls.md) under the signed
authority of [ADR-0073](0073-an-approval-counts-only-as-the-plane-judges-it.md),
over the roster of [ADR-0071](0071-operators-are-named-by-a-signed-roster.md).

## Context

Under ADR-0019 write access to the pause file is the authority to pause and
to lift. Under `approvals.authority: signed` an approval counts only signed
by a roster operator, so a pause the plane's own account could lift by
rewriting a file would leave the stronger authority one write away. A
signature stops a forged pause; it does not stop an older signed file being
put back, which lifts every pause added since.

## Decision

- Under `signed` the pause file is version `3`: a DSSE envelope of
  `application/vnd.agent-pause+json` (`operators.ActPause`, level `operate`)
  over a canonical body naming the signing key, the plane's tenant and
  project, the pause file it was signed for, as an absolute path with its
  directory's links resolved, a serial and the entries. The plane compares
  that path with its own `pause.file`, so a copy into another plane's file is
  refused. Versions `1` and `2` are refused there,
  and version `3` is refused under every other authority.
- At every read the plane takes the file through the authenticator, its own
  tenant and project, the authorizer and its pause floor in
  `pause.floor_dir`, in that order, and raises the floor to the serial it
  took. A file failing any step is the unknown state of ADR-0019, counted
  under its cause: it blocks every call and never reads as a lift.
- The plane refuses to start when its own account may write the pause file
  or any directory on its path, and refuses at every read a file or
  directory that account owns; only a dev plane, one account, reads its own.
- `pause add` and `pause remove` with `--key` judge the file they start from
  against the roster (`--roster`, `--root-key`) and its binding before they
  sign the whole file at the next serial, so a writer without a roster key
  cannot have its entries signed by the next operator. Without `--key` they
  refuse a signed file. The console holds no key and writes no pause under
  `signed` or into a signed file.

## Security / compatibility impact

Breaking under `signed`: a version `1` or `2` file blocks every call, and the
plane needs `pause.floor_dir`. Nothing changes under `memory` or `directory`.
The floor is the plane's to write, so its own account can still lower it and
replay; the start check and the signature keep everyone else out.

## Alternatives considered

- Signing each entry: a removal is an absence, which no entry signature
  covers, so a lift could not be told from a deletion.
- Keeping the floor in memory only: a restart would take any older file.

## Consequences

Each change rewrites and re-signs the whole file, so two operators writing
at once is refused, not merged. The writer owns the file and its directory,
so only one OS account can write a signed pause file; other operators sign
from it. A writer cannot read the plane's floor: an older file put back is
signed again at a serial the floor refuses. A signed body is held to the authenticator's
16 KiB bound, below the file bound of version `2`.

## Validation

`internal/pause/signedpause` tests each refusal, a replay after a restart and
a fork; `internal/pause` tests the reader, the writer's serial and its refusal
of a file that changed under it; `cmd/guardana-gateway` tests the start
refusal and a plane serving the file end to end.
