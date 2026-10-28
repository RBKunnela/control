# ADR-0046: A finding stops one run through a signed route

Status: accepted
Date: 2026-10-06

Builds on [ADR-0019](0019-an-operator-can-pause-calls.md),
[ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md),
[ADR-0038](0038-a-signed-freshness-statement-and-a-serial-floor.md),
[ADR-0039](0039-many-channels-into-one-core.md) and
[ADR-0045](0045-one-run-is-supervised-against-its-procedure.md). Amends
ADR-0019 on the order of the plane's causes, and ADR-0045 on "no finding stops
anything": one can, through this record's route.

Amended by [ADR-0047](0047-a-procedure-states-its-exceptions-resources-and-children.md):
`Eligible` admits an open child of the finding's tenant, still one run's stop;
verifying a route refuses a rule or version that may not stop, so every reader
of a route refuses it.

Amended in 0.11.0 (`REPEATED_DENIAL` version 2): a rule version a later one
superseded, `REPEATED_DENIAL` `1`, is read only in the route a list is carried
from. The carried list keeps its stops at that version, the judge holds each to
the rule's current version under the new route, and no writer appends one, so
an upgrade drops no stop and brings no lifted one back.

Amended by [ADR-0066](0066-each-decision-about-authority-is-a-port.md),
which decides that a finding's source class comes from its detector's signed
descriptor and that a route names the detectors it accepts;
[status.md](../status.md) says how much of it a plane does today.

## Context

ADR-0039 decided that a reaction turns a finding into a stop of one run's later
calls, under a route signed with a key apart from the policy key, and that a
source the plane cannot read or verify blocks every call. ADR-0045 built the
findings: `guardana-control supervise` writes a `FindingRecord` per finding of
one opened run, with a stable id. Milestone 2 ends with "a stop that refuses
that run's next call, no other's" (backlog B19).

The pause file (ADR-0019) blocks calls from a file the plane polls and fails
closed when it cannot read it, but anyone who can write it can lift any pause,
and the plane rereads it whole, so a truncated file lifts silently. A stop
from a finding must not inherit either: what writes stops must not be able to
lift one, and a stop must not vanish because bytes did.

A run has two identities: the one the plane gives an opened run when a token
resolves (ADR-0034), and the one a runtime claims. Only the first can name
what a stop refuses.

## Decision

**Two documents.** The *route* is the operator's signed statement of which
findings may stop a run. The *stop list* holds the stops, each judged against
the route; its lifts are signed under a key the route names.

**The route.** A strict JSON document, `kind` `reaction-route/v1alpha1`: a
`route_id`, a `serial` of at least 1, a `tenant_id`, `scope` `run`, the
`lift_public_key` that signs lifts, and `rules`, each a procedure
(`procedure_id`, `version` and `digest`, as a `FindingRecord` names it), a
supervise `rule_id` and `rule_version`, and an optional `expires_seconds` from
60 to the longest run lifetime; without one a stop lasts as long as its run. A
route with no rule, another scope, or a scope naming agents or principals is
refused. It is signed in a DSSE envelope like the freshness statement's, over
its canonical bytes, with the payload type
`application/vnd.agent-reaction-route+json`, by `guardana-control route sign`,
which refuses a rule id supervise does not have and the three rules that are
never `CONFIRMED` (ADR-0045). The plane names it with `reaction.route` and
`reaction.public_key` and refuses to start when that key or the lift key is the
policy key or the freshness key, or the two are one, comparing keys as points
up to their sign, since one private key signs for a point and its negation. It reads
the route at start only: a route can only allow stops, so a stale one stops too
much and never grants, and needs no freshness statement.

**The route floor.** A third kind of floor in `internal/policystate`, `route`,
in a directory of its own (`reaction.floor_dir`), holding per route id the
highest serial and its digest. The operator makes it with `policy state init
--kind route --route-id`. At start the plane refuses a route below the floor's
serial, or at it with another digest, and, once its list's first read is
served, raises the floor under its lock before it listens, so a start refused
for its list leaves the floor as it was; it never creates one, so a removed
floor refuses the start.
`doctor` reads it and never raises it.

**What may stop.** Two predicates in `internal/reaction`, which holds no
finding type. `Eligible`, the emitter's, takes facts the emitter copies out of
a `FindingRecord` and the runs directory: the finding's source is
`DETERMINISTIC`, its verdict `CONFIRMED`, its run an opened run that is open,
unexpired and no child; zero and unknown values are not eligible.
`Route.Permits`, the emitter's and the plane's, takes a stop's claim: its
tenant is the route's, its procedure and rule a rule of the route, and its
expiry within the rule's. A finding's escalation is not read: the route
decides. No setting widens this: a suspected, indeterminate or model's finding
stops nothing, and a claimed run id never stops a run.

**The stop list.** One JSON Lines file, `stops.jsonl`, in an owner-only
directory (`reaction.stops`), judged as the pause file is and bounded at 4 MiB
and 20 000 lines. Every line names its `kind` and `version`, and every time is
spelled `YYYY-MM-DDTHH:MM:SSZ`. The first line is a header: a random `list_id`
and the route's id, serial and digest. A `stop` line holds an entry id derived
from the finding id under a domain of its own, the tenant, the run id, the
finding id, the procedure and rule, `created_at` and `expires_at`. A `covered`
line holds a finding id the list knows and will not stop again: the emitter
writes one for a finding about a run that has an active stop, and a carried
list one for each finding whose stop ended. A `lift` line names a run and the last line it ends, and carries a
DSSE signature under the lift key, payload type
`application/vnd.agent-reaction-lift+json`, over its kind, version, the
`list_id`, the route digest, the run and that line; it ends every stop of that
run up to that line. Lines are appended, never rewritten. Only
`internal/reaction/stopwrite` writes, under a lock, truncating an unterminated
tail to its last newline before it appends, and refusing a list past its byte
bound rather than cut lines it did not read; the plane links only the reader.

**The emitter adds and never lifts.** `guardana-control react --findings <dir>
--runs <dir> --route <file> --public-key <file> --stops <dir>` verifies the
route, refuses one whose digest is not the header's, reads the findings log as
`notify` does, and appends, for each finding `Eligible` and the route permit
and the list does not name yet, a `covered` line when its run has an active
stop that lasts at least as long as the stop would, so a longer lifetime is
never cut short under a shorter one, and a `stop` otherwise, the writer
choosing under its lock over the list as it stands, so two emitters never
stop one run twice for one lifetime. A finding the list names, in any line,
writes
nothing again, so a lift holds: what an agent does while stopped is covered,
and only a new finding after a lift stops the run again. `expires_at` is its
clock plus the rule's lifetime and never later than the run's expiry rounded
up to the whole second a line spells. At the
list's bound it exits 1 naming each finding it could not write. It holds no
key. `guardana-control stops init --route --public-key [--carry <dir>]` starts
a list, and with `--carry` copies the old list's unlifted stops, expired or
not, since the writer's clock may be one a plane would not trust, and every
other finding id it names as covered, holding the old list's lock until the
new one is written, so a new list only adds. A list a plane refuses at one
line is carried up to that line, and the command names what it left out,
unless a stop or covered line follows it or the line is dated past the
writer's clock. `stops lift --key`, which refuses a lift that ends no stop,
and `stops list` are the operator's.

**What a plane checks.** A plane with a route requires `runs.dir`, a route
tenant equal to the listener's, and a stops directory that is neither inside
nor around any directory the plane or its commands lock or own. A nil stop
source is refused and a plane without a route gets an explicit disabled one. It
reads the list every `reaction.poll_interval` into a snapshot, as it reads the
pause file, with the same four states and age rule, and keeps the length and
SHA-256 of the prefix it accepted, which only grows: a read that does not
extend it, or whose header differs, is unknown. Each line is judged by
`Route.Permits` and the grammar: a duplicate entry id, a `created_at` later
than the plane's clock plus one poll interval, and a `lift` that is unsigned,
under another key, of another list or route, naming a line after itself, or
repeating one already read, each make the state unknown. Unknown blocks every
call `STOP_STATE_UNAVAILABLE` (`INDETERMINATE`, registry 46).

**What a plane does.** An entry is active until a lift ends it or the call's
clock is usable, not behind the call's floor, and at or past `expires_at`; a
clock it cannot trust keeps a stop active. A call whose opened run, as the
plane vouched for it, and tenant equal an active entry's is blocked
`RUN_STOPPED` (`DENY`, registry 45). Both are plane causes, named before the
decision point is asked, in every mode and for every effect class. The order
of ADR-0019 becomes: `PAUSED`, `RUN_STOPPED`, `EXECUTED_ARGS_MISMATCH`,
`LOCKDOWN`, `PAUSE_STATE_UNAVAILABLE`, `STOP_STATE_UNAVAILABLE`,
`EVIDENCE_UNAVAILABLE`, `ACTION_UNCLASSIFIED`. Another run's call, including a
stopped run's child, and the tool listing are not stopped. The stop snapshot is
taken with the pause snapshot, before the clock, and again before each step
that cannot be undone: a stopped retry of a held request is blocked on its own
trail and consumes nothing; a stop read after the approval was consumed closes
the held trail as stopped and the approval is spent; a hold outlives a stop and
resumes after it ends.

**A call already running is not cut.** An execution handed out before the stop
was read finishes and is recorded; the stop bites on the run's next call,
within one poll interval of the line being written. The pages say so.

**What reports it.** `doctor` and `/healthz` show the route's id, serial and
digest, the `list_id`, the state and an unknown state's cause, the snapshot's
age, the active entries (bounded), the list's use of its bounds, and each
active stop that names a run the runs directory does not hold; an unknown state
answers 503, and a list past nine tenths of a bound is degraded. `doctor` also
names a rule whose lifetime ends a stop before its run can end. The plane logs
each entry that becomes active, expires or is lifted, with its finding id;
`/metrics` counts polls, failed polls by cause and active entries. A decision
carries no entry id, as a pause's carries none.

## Security / compatibility impact

No model and no heuristic stops anything (invariant 1); a stop only blocks. An
unreadable, rewritten or unverifiable list blocks every call (invariants 4 and
5). The route key and floor keep a stale or forged route from widening what may
stop. The emitter, and anything else running as the plane's user, can add a
stop the route allows for any opened run of its tenant, and can block every
call by writing a line the route refuses; it cannot lift a stop without the
lift key, which need not be on the plane's host, nor shorten the list while a
plane runs without the plane seeing it. It can rotate the list and restart a
plane, which nothing here tells from an operator doing so; a real separation
needs another account for the list, which belongs with authenticated operators
(B13).

The wire contract does not change. Codes 45 and 46 are a registry change. The
plane gains an optional, all-or-nothing key group, `reaction`, and reaches
`internal/reaction` and its reader, which hold no finding type; it reaches none
of supervise, the findings log, the finding package, the notifier or the stop
writer.

## Alternatives considered

- **Stops written into the pause file.** The emitter would hold the authority
  to lift every pause, and a pause has no run scope.
- **Unsigned lifts and append-only by convention.** Any process of the plane's
  user could lift inside the file.
- **A lift that clears a run for the whole list.** Simplest and cannot
  cascade, but a new bad act after the lift is never stopped.
- **One stop per finding with no covered lines.** A lift would be followed by
  the next finding the stop itself produced, so it would never hold.
- **A list owned by an account of its own that the plane only reads.** The only
  real separation of authority; it needs a second account per deployment and
  breaks the pause file's owner rule. With B13.
- **Signed stop lines, or the route key signing lifts.** Either puts a signing
  key on the account that owns the list.
- **The route floor among the policy floors.** Changes that directory's strict
  marker, so an older plane would refuse it.
- **A stop of the run's tree.** Children share the root's flow state, but the
  milestone asks for one run's calls and no other's.
- **A stop as `runs close`.** The approver's authority, final, with no expiry,
  and the listener's 401 writes no trail.
- **Suspected findings stop when the route says so.** ADR-0039 allows it under
  an explicit risk setting; nothing asks for it yet.

## Consequences

An operator signs a route, makes its floor and a stop list, and runs
`supervise` and `react` while the run is open: a closed run is refused at the
listener anyway, and nothing runs on its own, so the time from finding to stop
is the operator's cadence, plus the export's lag, plus one poll. A plane
configured with a route blocks everything when its list breaks or shrinks,
which is the price of a stop deleting bytes cannot defeat; `stops init
--carry` and a restart repair a broken list without dropping a stop. Changing
the route takes a carried list and a restart. A wall clock that jumps forward
ends stops early. `docs/contracts.md` gains the route, the list's grammar, the
lift's payload and the two codes, and `docs/status.md` the stop.

## Declared limits

- A stop never cuts a call already running, and never a child of the run.
- The list's continuity is checked within one plane's life only.
- A process running as the plane's user can add stops the route allows, and
  rotate the list across a restart.
- The checks read mode bits and owners, not a darwin access control list.

## Validation

- A stop refuses that run's next call, `RUN_STOPPED`, in every mode and for a
  read; another run's call, and a child of the stopped run, run; a local run
  whose id equals the stopped one is not stopped.
- An expired entry stops nothing; a zero, rolled-back or untrusted clock keeps
  it active, and a mutant that judges expiry as an approval's does turns that
  test red.
- After a lift, `react` over the same findings writes nothing, three probes of
  tools outside the procedure while stopped write covered lines and no stop,
  and a new finding after the lift writes one stop.
- A lift under the lift key ends its run's stops through its line; an unsigned
  one, one under another key, one of another list or route, one naming a later
  line, and a repeated one make the state unknown; the emitter writes none.
- N confirmed findings of one run under one rule give one active stop, one
  whose stop would outlast it is a stop of its own, and another run's stop is
  still written; at the bound `react` exits 1 naming each finding.
- Every line `react` writes is accepted by the plane's judge, as a property.
- Every value of the finding's source and verdict, the zero and an unknown
  number included, is eligible only as `DETERMINISTIC` and `CONFIRMED`; a rule
  or procedure digest the route does not list, another tenant, and a closed,
  expired or child run write nothing; `--carry` brings no old finding back.
- A truncated list, an edited earlier line and a changed header while a plane
  runs are unknown, and a failed read does not reset the accepted prefix; a
  torn tail is left out and truncated by the next writer, and a list past its
  byte bound is refused by the writer, never cut.
- A `created_at` past the tolerance, and a far-future one with a legal
  difference, are unknown.
- Bundle, statement, route and lift signatures never verify as one another; a
  route or lift key equal to a policy key, or to each other, refuses the start.
- A removed route floor refuses the start and the plane never creates one;
  `doctor` leaves the floor's bytes and time as they were; a route whose tenant
  is not the listener's, and one whose scope the plane cannot serve, refuse the
  start; a nil stop source is refused.
- A held request and a stopped retry consume nothing; a stop read after the
  consume closes the held trail as stopped; after the stop ends the retry
  resumes once; the listing under a stop equals the listing under none.
- A stop written during the decision point's ask, the store's search or before
  `ACTION_STARTED` blocks that call; one written during the last append does
  not. A counting decision point is never asked about a stopped call.
- A pair table over every two plane causes pins the codes, the verdict and the
  counted code; `internal/core` never emits 45 or 46.
- Supervise over a stopped run raises no `REPEATED_DENIAL` from its blocks.
- The gateway binary's reach test holds none of the stop writer, supervise,
  the findings log, the finding package or the notifier.
- The refund example, on a live plane with two opened runs: after `supervise`
  and `react`, the first run's next call is refused and the second's runs.
