# ADR-0016: An approver outside the plane answers, and a lost hold is closed

Status: accepted
Date: 2026-09-21

Builds on [ADR-0004](0004-evidence-and-privacy-defaults.md),
[ADR-0005](0005-canonical-action-digest.md),
[ADR-0007](0007-repository-layout-and-dependency-rule.md) and
[ADR-0014](0014-evidence-spool-and-sinks.md).
Amends [ADR-0013](0013-mcp-interception-approvals-and-modes.md) on what becomes
of a hold the plane loses and on what may be said of a record it does not hold.

Amended once doctor named it: doctor opens the evidence spool as `run` does,
and that open cuts a torn tail, which doctor's evidence line now names in bytes;
the validation's "doctor writes nothing" holds for the approvals directory and
the hold journal, not for a torn spool tail.

Amended again when inspection was held to change nothing: doctor reads the
spool without opening it, names in bytes the torn tail a start would cut and
leaves it in place, writes no probe file and builds its plane over no spool,
so "doctor writes nothing" holds for the spool too.

Amended by [ADR-0023](0023-a-local-page-answers-through-the-directory.md): both
handles open the directory once and reach every file through it, and judge it
again at every call, not only at `Open`, refusing one that changed since.

Amended by [ADR-0019](0019-an-operator-can-pause-calls.md) and
[ADR-0027](0027-expiry-at-hand-out-and-an-unreadable-lost-hold.md): an
approval consumed before a pause read in the last moment, or found expired at
hand-out, is spent although nothing ran, so an identical call then reads
`APPROVAL_ALREADY_USED`; this narrows the validation below.

Amended by [ADR-0027](0027-expiry-at-hand-out-and-an-unreadable-lost-hold.md): a
lost hold whose answer the store cannot give, or gives in a form the checks
refuse, is closed `INDETERMINATE` with `APPROVAL_STATE_UNKNOWN`, not
`APPROVAL_EXPIRED`.

Amended by [ADR-0066](0066-each-decision-about-authority-is-a-port.md),
which decides that only the plane marks an approval spent, in its own
directory, and that an authenticated approver is recorded as
`authn:<issuer>:<subject>`; [status.md](../status.md) says how much of it a
plane does today.

## Context

ADR-0013 fixed what the gateway does with a pending state and with an approved
one, and left who may approve, and how, to the approval providers: this is that
deferred record. It settles two things at once, because the second is the price
of the first — an approver outside the gateway process, and what becomes of a
hold the plane loses while one is taking their time.

Nothing outside a test can answer. The gateway builds its pipeline with
`gateway.MemoryApprovals`, whose records live in the process that holds them,
so `Answer` has no caller from outside; under the `APPROVE` mode every held
call waits out `approvals.ttl` and is blocked. A mode the plane cannot serve is
a total denial wearing the clothes of a pending one.

A hold does not survive a restart. A plane that dies holding a call leaves that
trail standing at `APPROVAL_REQUESTED` for good: nothing closes it, and nothing
that reads the evidence later can tell an action that was refused from one that
was simply abandoned. The moment an approver outside the process can answer,
the window between the request and the answer stops being milliseconds and
starts being as long as a person takes, so the case stops being rare.

The repair that suggests itself — read the spool back, find the trails standing
at a request for approval — does not work, and the reason is recorded here so
that it is not designed again. `Reader.Ack` calls `release`
(`internal/spool/reader.go`), and `release` deletes every segment that has been
acknowledged whole, the segment being appended to included
(`internal/spool/segment.go`). Against `export.linger` of 100ms and
`approvals.ttl` of 15m (`internal/gatewayconfig/fields.go`), a collector that
answers has taken a hold's `APPROVAL_REQUESTED` off disk within a fraction of a
second — minutes before any crash. Such a scan finds orphans only in a plane
whose exporter was already behind: it is empty exactly when the plane is
healthy. The spool is an outbound queue, not a state store, and ADR-0014 means
it that way.

What authorizes a resumed call stays where ADR-0013 put it: the plane's own
record of the hold — the envelope, the decision, the binding, the expiry and
where the trail stands. A store answers whether an approver said yes, and
nothing more.

## Decision

**The approvals directory answers about one approval id and names nothing
else.** It never supplies a trail, a position in one, an envelope or a digest
to write. A writer of that directory is an approver; it cannot choose what the
plane records or where.

**Write access to the approvals directory is the approval authority.**
`approver_id` on a record is an unauthenticated claim, kept because an operator
reading the evidence wants a name, and worth exactly what the directory's
permissions are worth. Nothing in the plane treats it as an identity. An
authenticated provider would make `approver_id` mean something, and would
replace the directory's permissions as the authority. None exists yet.

**Two openers over one directory, and the compiler keeps them apart.**
`OpenPlane(dir)` has no `Answer` method and takes the plane's exclusive lock.
`OpenApprover(dir)` has `Answer`, takes no plane lock, and reports it to its
caller when the plane lock is free, so that `approvals approve` can tell an
operator that no plane is running to consume what they are about to write.
Where `flock` is unavailable both refuse to open, rather than fall back to a
second locking path that nothing in this repository builds or tests: a lock in
the request path is not a place for a branch that has never run.

**One record, one file, one compare-and-swap by `link`.** A record is written
to a temporary name, fsynced, renamed, and the directory fsynced; a state
transition is a `link` to the next name that fails with `EEXIST` when another
writer won. Nothing in the request path waits on another process's lock.

**The durable record is what the plane reads back; the approver's view is a
projection the plane never trusts.** The record carries `schema_version`, the
binding, the request id, the `Approval` and its resolution — no envelope, no
decision, no trail position. Beside it sits a named projection for a human:
approval and request ids, both digests, principal, agent, action, resource,
effect class, rule ids, requested and expiry. The projection never carries
`redacted_preview`, `delegation[].reason` or any other free text, so a second
human-readable copy does not widen what ADR-0004 and invariant 9 allow to be
stored. `approvals list` prints the digest and says plainly that the readable
fields are not bound to it: `approval.Bind` needs the authorized argument
bytes, and no record holds them.

**The plane keeps its own durable journal of its own holds.** It lives in its
own directory under the plane's exclusive lock, written by no other process:
never inside the spool's directory, which the spool owns and locks, and never
inside the approvals directory, which an approver can write. It is configured
by `approvals.hold_journal_dir`, and `approvals.provider: file` requires it. A
plane without it holds exactly as it does today and carries the declared limit
below, which `doctor` and `/healthz` report rather than leave to be discovered.
The journal is as trusted as the spool and for the same reason: whoever can
write it can already write the evidence.

**Three states and one write order make the journal's word provable.** An entry
is `held`, `resuming` or `closing`. It is recorded after `APPROVAL_REQUESTED`
is appended and before the agent is told pending, and a failure to record
refuses the hold down the existing refusal path. Every append that moves a
trail's chain state past `APPROVAL_REQUESTED` is preceded by a flip out of
`held`, and the entry is forgotten after the trail is closed. So `held` means
the chain state stands at `APPROVAL_REQUESTED` and the trail can still be
closed; `resuming`, `closing` and anything that will not decode mean the plane
cannot say, and their trails are reported and left untouched. That turns a
crash in the middle of a close from an invisible orphan into a counted one.

**A lost hold is closed, never resumed.** The agent's call was answered pending
long ago, so running the effect now serves nobody, and ADR-0013's "a hold does
not survive a restart" stands unchanged. The closings are ordinary events
carrying a reason code. Where an answer is present and passes the same field
checks a live resume makes, the plane appends `APPROVAL_DECIDED` with that
answer, then `ACTION_BLOCKED` carrying `DENY` and `APPROVAL_NOT_RESUMED` when
it was approved, or `APPROVAL_REJECTED` when it was refused. Where there is no
answer, no answer the checks accept, or no store to ask, it appends
`APPROVAL_EXPIRED`, then `ACTION_BLOCKED` carrying `DENY` and
`APPROVAL_EXPIRED`. Both pairs are transitions the evidence chain already
allows from a request for approval (`internal/evidence/chain.go`). The closing
events carry the restarted plane's mode, and say that the call was never run
rather than that this plane enforced anything.

**`APPROVAL_NOT_RESUMED` is registry number 38, `DENY`, emitted by the
reconciliation and never by a live call.** An approval that was granted, whose
request is gone, is neither "nobody answered" nor evidence that could not be
written, and saying either would be a lie an operator acts on.

**`APPROVAL_ALREADY_USED` is said of a record the store reports as spent, and
of nothing else.** Under the file provider "spent" is a file name, which is why
the Security section below states what a writer of that directory can do with
it. Consumption also happens before the checks that can still block, so today's
code can write `APPROVAL_ALREADY_USED` for a call that never executed. Its
registry summary therefore loses "by an earlier execution", which the code
cannot back. `Held` gains a `Resolution` — unspecified, pending, consumed, not
resumed — whose zero value means the store cannot say, so the plane holds anew
and counts. A `bool` would put that case on the unsafe side by accident.

**The plane never consumes a record it does not hold.** A store spends a record
only for the approval id the plane minted and keeps in its own record of the
hold: one filed under the same binding and request id carrying any other
approval id is not the plane's to spend, and is left exactly as it was so the
reconciliation can still resolve it. An empty approval id names no approval and
is refused, never read as any approval will do. The reconciliation resolves an
orphan's record to `not resumed`, so the next identical call is held anew
rather than told that an action ran.

**Reconciliation runs on `serve` and never on `doctor`.** Both commands call
the same `build`, so this is stated as a rule and tested as one: `doctor` opens
the journal read-only and reports what it would close, writing no event and
resolving no record.

**`APPROVE` with `approvals.provider: memory` is refused at start**, as the
mode table refuses a mode the adapter cannot serve.

**Bounds and permissions.** `approvals.max_records`,
`approvals.max_record_bytes` and `approvals.reconcile_max` bound what a
directory can make the plane do. A bound that bites leaves the reconciliation
**unmeasured**: it reports how far it got and does not claim to have seen every
hold. It never reports itself complete on a partial pass, and it never stops
the plane from serving; what it did see reaches `/healthz` and the counters.
`Open` refuses a group- or world-writable directory, records are `0600`, and
`approver_id` and `reason` are bounded and refused for control characters
before they reach an `Approval`.

**Layering.** `internal/approvals` and `internal/holdjournal` import only pure
packages of this module — the generated contract, `internal/core/approval`,
`internal/canon`, `internal/evidence` and `pkg/contract` — and never
`internal/gateway`, no vendor library and nothing that serves.
The seams are gateway interfaces, and the glue is a small file in
`cmd/guardana-gateway`, the way the spool already implements `Sink`. The
approver's binary links neither the pipeline nor evidence.

## Security / compatibility impact

No language model takes part in this path, nothing here matches on keywords,
and `INDETERMINATE` is not collapsed into `ALLOW`: every closing is a `DENY` or
an expiry. The approval binding is untouched — one digest, one bundle, one held
request, consumed once — and the plane still compares the store's answer
against its own record field by field before anything runs.

A directory an attacker can write is an approval authority, which is why this
record says so instead of letting `approver_id` imply an identity. What that
attacker cannot do is choose a trail: the record has no field that names one,
and every event the plane writes is linked from the plane's own record of the
hold.

What they can do is wider than granting, and is stated here rather than left to
be found. A record's resolution is its file name, so one filed under the spent
name is not distinguishable from one the plane spent; the plane then answers a
later call of that action and bundle with a denial naming an approval that was
never used, and writes that denial into the evidence. Two bounds limit it: the
read path refuses a record whose expiry is further from its request than the
plane could have minted, so a forged record cannot outlive a window, and the
bound on records limits how many there can be. Within those bounds, a writer of
the directory can deny a chosen action and can make the evidence misleading.
They cannot make anything run.

The directory may not be group- or world-writable, so the approver this
implementation permits is a process running as the same user as the plane, and
not a second account. "An approver outside the gateway process" is true of a
process and false of a user; an authenticated provider is what would change
that.

The wire contract does not change. `reason_codes` is a repeated string, so
adding code 38 to the registry is a registry change, not a wire change, and the
public Go surface does not change. Code 31's summary changes; its number and
verdict do not.

Every failure here fails closed: a journal that cannot be written refuses the
hold, a store that cannot answer blocks the call, an entry that will not decode
is counted and its trail left alone, and a reconciliation that hits a bound
reports itself unmeasured rather than complete.

## Alternatives considered

- **The approvals directory also naming the trail to close.** An approver would
  then choose the identifiers and the link, so forged records could graft
  events onto live or finished trails, break their chain validation, and drive
  unbounded appends until `evidence.max_bytes` blocks every material call.
- **Reconstructing lost holds from the spool.** Empty exactly when the plane is
  healthy, for the reason given in Context, and it would have cost a new read
  path and an amendment to ADR-0014 for nothing.
- **Pinning the spool's retention to the oldest open hold.** One lost hold then
  holds the whole evidence budget for a TTL and can block every material call.
- **Rehydrating the hold and running it after the restart.** It needs the
  envelope's data labels and run context on disk to compare a retry against,
  which widens what is stored for behaviour no operator asked for, and it runs
  an effect for a call that was answered pending long ago.
- **No journal, and the declared limit alone.** Honest, and cheaper, and it
  leaves every restart under a slow approver with a trail that cannot be told
  apart from an abandoned one. Rejected deliberately, and the cost was weighed:
  a directory of small files written under the plane's own lock adds no
  database, no schema migration and no new dependency, which is the whole of
  what deferring the choice of a storage engine was meant to avoid.
- **A `bool` for consumed.** Its zero value is the safe-looking answer to a
  question the store may not be able to answer.

## Consequences

Once the change this record governs has landed, an approver outside the gateway
answers a held request by writing a file, and the `APPROVE` mode becomes usable
for the first time; `docs/status.md` stays the inventory of what is built. Two
packages and two directories join what an operator has to back up, permission
and monitor, and the second of them is a new durable artefact of the plane;
`doctor` reports both so that neither is invisible.

An approver whose answer arrives after a restart answers again, and the closing
event says why. A hold interrupted in the middle of its close is reported and
counted rather than silently reopened or silently lost.

`APPROVAL_ALREADY_USED` becomes a narrower claim than it is today, which is a
behaviour change in the direction of what the code can prove. Reason code 38
joins the registry and the reference page.

## Declared limits

These are stated here, not discovered later.

- An entry left `resuming` or `closing` by a crash is reported and its trail is
  left open: the plane cannot say what landed. One per interrupted close,
  counted, never guessed.
- A `FINDING_RAISED` on a held trail leaves the chain state at
  `APPROVAL_REQUESTED`, so no flip out of `held` is owed for it, but it does
  change the trail's last event, so the position the journal recorded goes
  stale and a close would link to the wrong event. Nothing writes findings
  today; this is revisited with the detector plane.
- A hold whose journal entry cannot be decoded is counted and its trail left
  alone, and the pass that met it reports itself unmeasured. Counted and
  unmeasured are two different meters: the first is how many such entries were
  seen, the second is that the pass cannot claim to have seen every hold.
- A plane configured without `approvals.hold_journal_dir` does not close a lost
  hold. That is today's behaviour, named rather than hidden.

- A writer of the approvals directory can file a record under the spent name
  and make the plane deny a chosen action and bundle, with evidence naming an
  approval that was never used. The expiry bound and the record bound limit how
  long and how many; nothing makes it impossible, because that directory is the
  approval authority.
- `APPROVAL_ALREADY_USED` is decided by binding, not by request. A record the
  plane no longer holds carries no envelope, deliberately, so a call that
  differs from the spent one only in its data labels or its run context cannot
  be told apart and is blocked with it. Telling them apart would mean keeping
  the envelope on disk, which this record refuses for the same reason it
  refuses to rehydrate a hold.
- The approver is a process, not a second account: the directory may not be
  group- or world-writable, so an approver runs as the same user as the plane.

## Validation

Falsifiable by test, and these are the exit criteria of the change that brings
this record:

- An approval given in one process resumes a held call in another; it is
  consumed once, and the next identical call reads `APPROVAL_ALREADY_USED`. An
  expired approval resumes nothing, and a store that lies on any field runs
  nothing.
- With a collector that accepts everything, so that every segment is
  acknowledged and unlinked, a plane killed while holding a call comes back and
  closes that trail, and `ValidateChain` passes over the exported events. This
  is the case the spool cannot serve.
- No `APPROVAL_ALREADY_USED` is written for an action that did not run, and an
  answer to a hold the plane lost is never spent.
- A hostile approvals record naming a live or finished trail changes no
  evidence.
- `doctor` writes nothing: spool statistics and the approvals listing are
  identical across a run.
- A store double returning only an `Approval` and a `Binding` keeps the whole
  gateway suite green, which is what "the store grants nothing" means in code.
