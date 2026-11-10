# ADR-0079: A signed plane admits a child only if it saw it before its parent's close

Status: accepted
Date: 2026-11-09

Amends [ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md)
on a child of a closed parent, and
[ADR-0076](0076-a-signed-plane-takes-a-run-only-from-an-operators-signature.md)
with a second marker in `state/`. Builds on
[ADR-0078](0078-a-restore-only-raises.md).

## Context

Under `approvals.authority: signed` the plane judges a run by its own record
and by the close it carried into `state/` (ADR-0076). `runs open --key
--parent P` refuses a closed parent only by reading `records/`, which the
commands read without `state/`. After the plane carried P's close, whoever
may write `records/` can put P's open record back; an operator's command then
signs a child of P, and the plane admits it, since it never looks at the
parent. ADR-0034 keeps a child running when its parent closes, so the plane
has to tell a child opened before the close from one opened after it.

## Decision

- Under `signed`, at every resolve of a run with a parent, after its own
  record is taken and is not refused as replayed, the plane reads
  `state/<id>.seen`. Where it stands, no ancestor is looked at.
- Where it does not, the plane walks up from the parent. At each ancestor
  whose close is carried (`state/<ancestor>.closed` stands, or the plane
  holds the close because `state/` did not take it) the call is refused as
  `closed` with `runs.ErrParentClosed`, naming that ancestor, counted under
  `runs.signed` as `refused_parent_closed`, apart from a replay. The walk
  stops at the root or at an ancestor with a `.seen`, whose descendants
  keep ADR-0034; between the two it reads and judges each ancestor's record
  as any record, so a child refused under a put-back parent cannot vouch
  for a grandchild. A record that does not count, or more than 32
  ancestors with no `.seen`, refuses the call as `unreadable`.
- Otherwise the plane creates an empty `state/<id>.seen`, forced to disk,
  before the call is admitted. A write that fails refuses the call; a marker
  that is not a regular file of the plane's alone refuses it as
  `unreadable`.
- `.closed` keeps its empty format. Nothing changes off `signed`.
- A restore closes every run (ADR-0078), so it neither copies nor needs a
  `.seen`: it accepts one in `state/`, the live one or the backup's, and
  counts none as a run.

## Security / compatibility impact

The plane decides from what it saw itself, never from an operator's signed
time. **Breaking** under `signed`: a child a 0.16 plane admitted has no
`.seen`, so once its parent's close is carried it is refused; the operator
opens it again. ADR-0034's "closing a parent closes none of its children"
now holds for the children the plane admitted before it carried the close.
A child signed before the close whose first call comes after the carry is
refused all the same.

Limits: a close the plane never took leaves no marker, so a child of a
parent whose close the plane has not carried yet is admitted and marked. A
stdio plane resolves its token at the start before it carries the closes it
finds there, so its own child is judged before those closes are carried. The plane's own account can delete a `.closed` or create a `.seen`
(ADR-0076). A child whose first call races the carry of its parent's close
may be admitted: it was signed before the carry, and no lock is taken for
it.

## Alternatives considered

- The signed times, `closed_at <= opened_at`: two operators' clocks skew,
  and a child put back after the close passes by the skew.
- The signed times with a margin: still a clock, and more code.
- The commands read `state/`: a new operator read of the plane's state,
  which ADR-0076 keeps from them.
- A stated limit: leaves a closed parent's children open to whoever writes
  `records/`.

## Consequences

`state/` holds one empty file per child the plane admitted, which a
backup copies. An operator reopens a child refused after an upgrade.

## Validation

`internal/runs` tests the put-back parent with a child signed by the
operator's path, carried at a call and at the start, refused at every
resolve, and a grandchild signed under that child; a grandchild under a
child's carried close and under an admitted child of a closed root; an
ancestor's close or record the plane cannot trust; the walk's bound; a child
admitted before the carry across a restart; a child signed before the close
but first called after it; a held close; a `.seen` write that fails and a
marker that is no regular file of the plane's; an unsigned layout; and a
restore over `.seen`. `internal/recovery` restores a backup holding one.
