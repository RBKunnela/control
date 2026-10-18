# ADR-0038: A signed freshness statement and a serial floor that outlives the process

Status: accepted
Date: 2026-10-02

Amends [ADR-0012](0012-policy-kernel-semantics.md) and
[ADR-0018](0018-keys-and-bundles-on-disk.md). Builds on
[ADR-0010](0010-digest-domain-separation.md),
[ADR-0032](0032-the-enforcement-mode-has-no-default.md) and
[ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md).

Amended by [ADR-0055](0055-a-call-is-handed-out-only-while-its-policy-stands.md): a newer bundle, or a statement
that lapses, also withholds a call decided before it and not yet handed out.

## Context

A plane reads its bundle once, at start. Installing the same bundle again
moves its confirmation to the caller's clock, so "confirmed current" means
"read again", which proves nothing about whether it is still the latest
policy. The staleness budget counts from that reading, so every plane turns
`POLICY_STALE` some minutes after it starts and stays so until it is
restarted. The rule that refuses a lower serial lives in memory: after a
restart any serial ever signed under the pinned key is taken.

A signature proves who wrote a bundle. Freshness needs a second, signed
fact: that the bundle was current at a stated time. Putting that time in the
policy document would give every renewal a new digest and serial, so every
pending approval, bound to the bundle's digest, would fail. Putting it in the
protobuf bundle would add an unsigned field, since the signature covers the
document's canonical bytes alone. And a renewal every few minutes needs its
key online, which ADR-0018 keeps the policy key from being.

## Decision

**A bundle says who wrote a policy; a freshness statement says it was current
at a signed time.** A statement is a DSSE JSON envelope with payload type
`application/vnd.agent-policy-freshness+json` and exactly one signature. It is
signed by the freshness key the plane pins, `policy.freshness_key_id` and
`policy.freshness_public_key`, which is never the bundle's key: the plane's
configuration and `renew` each refuse one key named in both roles.
The envelope is decoded outside the guarded trees; the policy package receives
its payload type, payload and signature as bytes, refuses another payload
type, and verifies over the pre-authentication encoding of the fixed type, so
a statement's signature never verifies as a bundle's or the reverse. `keyid`
selects a pinned key and is never trusted alone. The envelope refuses an
unknown or repeated key and reads standard base64 only. The body is strict JSON,
`{"kind":"agent-policy-freshness/v1alpha1","bundleId","serial","digest","issuedAt"}`:
another kind, an unknown or repeated key, or a file over 4 KiB is refused, and
`issuedAt` has one spelling, `YYYY-MM-DDTHH:MM:SSZ`.

**Statements are ordered, and the floor records the newest.** Statements for
one bundle id are ordered by serial, then by `issuedAt`. The floor holds the
newest accepted statement's bundle id, serial, digest and `issuedAt`, and the
latest `issuedAt` any accepted statement carried; every accepted statement
raises it, a renewal included. A statement at or below the
floor's (serial, `issuedAt`), other than the floor's own, is refused, as is one
that names the floor's serial with another digest. Only a statement-confirmed
install raises the floor.

**A snapshot is confirmed only by a statement.** Its confirmation is the
`issuedAt` of the accepted statement bound to the installed bundle by id,
serial and digest; installing a bundle never moves it. It expires at that time
plus the smaller of the document's `maxStaleSeconds` and `policy.max_stale`. A
snapshot with no accepted statement is unconfirmed: its decisions carry the
zero time as `policy_loaded_at`, and the kernel decides every call that reaches
the freshness check `POLICY_STALE`, as it does for an old confirmation, so
outside `OBSERVE` a material call is blocked and a read runs only under
`policy.fail_open_read`.
The kernel, the reason codes' identifiers and numbers, the wire contract, the
digest and the document format do not change; `POLICY_STALE`'s summary is
widened to name an unconfirmed snapshot.

**The floor lives on disk.** `policy.state_dir` is a directory the operator
owns, `0700`, with a marker, holding one strict-JSON file per bundle id, named
by the hex SHA-256 of the id: `schema_version`, `bundle_id`, `serial`, `digest`,
`issued_at`, `latest_issued_at`, `reset_reason`, `reset_from`, mode `0600`,
replaced whole and synced. A directory serves the planes of one policy
authority, and its marker names its kind, a plane's or a signer's; each side
refuses the other's. `guardana-control policy state init --kind plane|signer
--bundle-id <id> <dir>` creates the directory and marker when absent and that
id's file holding no serial yet, and refuses a file that exists and an id the
directory has held before, so it is never a second way to lower a floor. Only
`guardana-control policy state reset` lowers one, writing the reason and the
prior value into the file. The plane never creates or lowers a floor, and its
binary links no code that does: the floor's store sits outside the guarded trees
behind an interface the policy package declares (invariant 8), and the plane
raises a floor only upward, under an exclusive lock and against the file's value
rather than its memory, before it publishes the snapshot that raised it; a raise
that fails refuses that install, and a floor another plane raised past a renewal
refuses that renewal.

**Start.** The plane refuses to start without `policy.statement_file`,
`policy.state_dir`, the freshness key, a marker and the pinned id's floor file;
`policy.statement_file` has no default and no setting keeps freshness counted
from the start (ADR-0032's rule for the mode). With the floor holding no serial
yet, the bundle on disk is installed, confirmed if a statement is bound to it,
unconfirmed if not. With a floor, a bundle of a lower serial, or of the floor's
serial with another digest, refuses the start naming both; a bundle of a higher
serial is installed only with a statement bound to it, and refuses the start
without one, since the bundle file alone may not choose the policy that governs
fail-open reads; the floor's own bundle starts confirmed by its statement or
unconfirmed. A higher bundle whose statement cannot be accepted yet, dated after
the plane's clock or with the clock behind the floor's latest `issuedAt`,
refuses the start as one without its statement does; the floor's own bundle in
that case starts unconfirmed. An expired statement counts as none here. A start
that is unconfirmed is not refused: the plane runs and, outside `OBSERVE`,
blocks material calls until a statement arrives.

**Refresh.** Every `policy.poll_interval` the plane reads both files again. It
may keep the verdicts that no clock or state changes, the parse, the signature
and the digest, for bytes it has judged; the time, floor and pairing checks run
at every poll. The interval is at least one second and must be shorter than
`policy.max_stale`, and a bundle whose effective budget is not longer than the
interval is refused. A new bundle whose statement still names the old one is
awaiting its statement, and a statement naming a bundle not yet on disk is
awaiting its bundle; each is counted apart and tried again at the next poll, and
the current snapshot stays. An operator deploys the statement before the bundle,
so a plane started in between finds the floor's own bundle without its statement
and starts unconfirmed rather than refused. A torn, unsigned, wrong-key,
wrong-id, lower, same-serial other-digest, future-dated, at-or-below-the-floor
or expired replacement is refused: the last good snapshot stays, the refusal is
logged and counted by cause, and the confirmation does not move.

**The clock.** A clock that reads before the confirmation is stale, as today. A
statement dated after the plane's clock is refused until the clock reaches it.
The plane keeps a mark: the highest offset it has seen between its wall clock
and its monotonic clock, lowered by 100 parts per million of the monotonic
time since it was seen, so ordinary drift passes. While the wall clock stands
more than one second below the mark, in one step or many, the snapshot is
unconfirmed and no statement is accepted, the floor's own included. A clock
set back so extends freshness by at most one poll interval, one second and
that drift, however many statements arrive meanwhile; a clock corrected back
after running ahead leaves the plane stale until the mark comes down to it or
the plane restarts. The kernel stays deterministic: the refresher holds both
readings and only confirms or unconfirms.

**What says so.** `/healthz` carries `policy.freshness`, `confirmed`,
`unconfirmed` or `expired`, with the confirmation and expiry times; a plane
that is not confirmed reports `"status":"degraded"` with HTTP 200, never `ok`
and never the 503 a halted plane gives, since a restart cannot fix it. Halted
wins over degraded, and an unconfirmed snapshot is never one of the problems
that halt a plane. `/metrics` carries the freshness state and the seconds left
before expiry, so an alert can fire before the budget runs out, and the
scenario runner refuses a plane that is not confirmed.
`guardana-gateway doctor` reads the floor without raising it, and its policy
line fails for a missing, expired, future-dated or unbound statement and for a
bundle below or beside the floor.

**Commands.** `guardana-control policy renew --key <freshness key> --bundle
<file> --bundle-public-key <file> --floor <dir> --out <file>` verifies the
bundle under the bundle's key, refuses to vouch for a bundle below its own
floor, a directory `policy state init --kind signer` makes, raises it, and
writes a statement printing `bundle_id`, `serial`, `digest` and `issued_at`.
The bundle it reads must be the authority's own copy, not the one a plane is
served, and its floor directory is a signer's. `renew` is the only command that
writes a statement: `policy sign` writes a bundle and nothing else. `renew`
replaces an output only when it is absent or already holds a freshness
statement, refuses a path holding a key or a bundle, and writes by rename, so a
reader sees the old file or the new.

**Dev.** `dev` initialises the floor in its own state directory through the
`guardana-control` beside it, draws a freshness key apart from its bundle key,
drops the bundle key once the bundle is signed as today, holds only the
freshness key for the session, never writes either, and renews the statement
every third of the budget, or every budget less twice the poll interval when
that is sooner, through the same files. A renewal changes
no digest, so scenarios keep their verdicts and bundle digest.

## Security / compatibility impact

Every plane configuration needs `policy.statement_file`, `policy.state_dir`,
`policy.poll_interval` and the freshness key, and an initialised floor, before
it starts: a configuration from an earlier release is refused with the
missing key named. With a freshness key apart from the bundle key, the policy
key can stay offline and a renewal job holds only a key that can vouch for
bundles the authority signed.

What it does not protect, stated rather than implied: while a floor holds no
serial yet, the bundle on disk chooses the policy that governs fail-open reads,
unconfirmed, until the first statement; a plane restarted with its clock set
back to within the budget of the floor's statement is confirmed by it again,
which only a trusted time source would prevent; a restore of the volume or
machine rolls the floor back with the bundle; a `state_dir` that does not
survive a restart protects nothing; an account that can write the state
directory can lower the floor; a statement dated ahead is a valid confirmation
once its time arrives, so a signer never dates one ahead; a floor's last reset
is logged at every start, and one made while a plane runs only at its next; a
signer whose clock runs ahead of a plane's makes a restart onto a new bundle
fail until the plane's clock catches up. A plane whose renewal stops fails
closed, stale, at the end of its budget; the way to tighten policy at once stays
the pause file (ADR-0019).

## Alternatives considered

- **The times in the policy document.** One file, but every renewal a new
  digest and serial, which ends every pending approval, and `sign` would
  rewrite the author's bytes.
- **A new protobuf wrapper carrying a signed time.** One file, but an addition
  to the frozen contract, a new bundle file format and a re-sign for every
  operator.
- **The bundle's key signs statements.** No new key, but the policy key online
  for every renewal, and a second configuration break when the two separate.
- **Keep freshness counted from the start, behind a risk setting.** It keeps
  the property this record removes.
- **Let the plane create an empty floor.** A removed floor would read as a
  first start, and the rollback it guards against would pass.
- **Refuse to start without a valid statement.** No plane could then run in
  its blocking state while a renewal is fixed.
- **A policy-reload event in the trail.** The evidence contract scopes every
  event to a request; a reload shows in each decision's bundle digest, in logs
  and in counters, and a renewal in `policy_loaded_at`.

## Consequences

ADR-0012's "confirmed current means delivered again" and "per process", and
ADR-0018's rollback across a restart, no longer hold. An operator renews
statements on a schedule shorter than the budget less twice the poll interval,
from wherever the freshness key lives.

## Validation

- Installing the same digest twice leaves the confirmation where it was.
- A statement verifies under its payload type only, and a bundle's signature
  never verifies as a statement's, or the reverse.
- The body: another kind, an unknown or repeated key, another spelling of
  `issuedAt` and an oversized file are each refused.
- A table of every refused replacement: the last good snapshot kept, the
  confirmation unmoved, the counter by cause; an unpaired bundle awaits its
  statement and is installed when it arrives.
- Ordering: a renewal raises the floor's `issuedAt`; a statement for a higher
  serial issued before the floor's is accepted and keeps the latest
  `issuedAt`; one at or below the floor is refused.
- Start: a lower bundle, the floor's serial with another digest, and a higher
  bundle without its statement each refuse the start naming both; a removed
  floor file and an empty volume each refuse it; an unconfirmed start runs and
  blocks material calls.
- `init` refuses an existing floor file, an id the directory has held and a
  directory of the other kind; `reset` records its reason and
  prior value; a raise that fails refuses the install; a crash mid-replace
  leaves the old floor or the new.
- Two planes raising one floor never lower it.
- A wall clock moved back over a second unconfirms the snapshot; under a
  second it does not; a clock earlier than the floor's latest `issuedAt` at
  start leaves the floor's own bundle unconfirmed.
- `/healthz` reports `degraded` and the freshness state; `doctor` fails each
  listed case and leaves the floor's bytes and time unchanged.
- The poll interval and the budget: an interval not shorter than the budget is
  refused at load or at install.
- A statement first seen dated ahead is accepted, its bytes unchanged, once
  the clock reaches its time; a floor raise that failed is tried again.
- Steps of 0.9 s back, repeated past one second in all, unconfirm, and a
  newer statement is not accepted until the clock is back within the mark;
  drift under 100 parts per million unconfirms nothing.
- A plane's floor directory refused by `renew`, and a signer's by a plane.
- `/healthz` stays `halted` when halted and unconfirmed; `/metrics` reports
  the freshness state and the seconds left.
- `renew` refuses a bundle below its floor, one that does not verify, and the
  same key given as the freshness key and the bundle's; so does the plane's
  configuration.
- The plane's binary holds no floor initialiser or lowerer.
- A dev scenario that runs past the budget stays fresh, with the same verdicts
  and bundle digest.
