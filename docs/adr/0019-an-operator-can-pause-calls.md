# ADR-0019: An operator can pause calls, and a pause the plane cannot read blocks

Status: accepted
Date: 2026-09-24

Builds on [ADR-0012](0012-policy-kernel-semantics.md),
[ADR-0013](0013-mcp-interception-approvals-and-modes.md),
[ADR-0014](0014-evidence-spool-and-sinks.md) and
[ADR-0016](0016-approval-providers-and-the-lost-hold.md).
Amends [ADR-0017](0017-an-external-decision-point-can-veto.md): the decision
point is never asked about a call the plane blocks whatever it answers.

Amended by [ADR-0046](0046-a-finding-stops-one-run-through-a-signed-route.md):
a plane with a route also blocks a stopped run's calls `RUN_STOPPED` and every
call `STOP_STATE_UNAVAILABLE` while its stop list is unknown, and the order of
the plane's causes becomes `PAUSED`, `RUN_STOPPED`, `EXECUTED_ARGS_MISMATCH`,
`LOCKDOWN`, `PAUSE_STATE_UNAVAILABLE`, `STOP_STATE_UNAVAILABLE`,
`EVIDENCE_UNAVAILABLE`, `ACTION_UNCLASSIFIED`.

Amended in 0.16: an entry may also name a `run`, by the id its runs directory
gives it, an `agent` or a `principal`. Each is matched only against the
identity the plane vouches for: the opened run the listener resolved from its
token, or every run whose root it names, and the agent and principal the
listener's configuration names, never anything the client sent. In place of
refusing those scopes, `/healthz` and `doctor` say per entry whether it covers
all, some or none of the plane's calls, and name each that covers none. A
tenant is still no scope. The file is version `2`; version `1`, which names
none of the three, is still read.

## Context

The registry holds `PAUSED`, number 24, `DENY`, and nothing emits it. An
operator who sees an agent misuse one tool can stop the plane, which stops
every agent and every read, or change the mode, which takes a restart and has
no scope. Neither is an emergency stop for one tool.

The plane already blocks some calls whatever the policy says: a call nothing
classifies outside `OBSERVE`, a material call while a halt stands, a material
call under `LOCKDOWN`. Those blocks are applied after the kernel decides, and
the kernel's first decision is followed by an ask to the decision point when
its answer could change it. So a call the plane will block anyway can still
send its identity, action, resource and destination to the decision point and
wait for the answer. The backlog recorded that, and an incident in which the
decision point itself is what the operator wants stopped is its worst case.

The listener of this build authenticates nobody. The principal and the agent
of every call are the ones configured for the listener, so a pause by
principal or by agent would be the whole plane or nothing.

## Decision

**Three scopes.** `global`; `provider`, an upstream by its configured name;
and `action`: a kind, a provider and, for a tool, the name the plane routes
by. A resource or a prompt is paused by its provider only: the plane routes
neither by name, so the name is the client's spelling, and an exact match on
it could be sidestepped. A scope
matches a call when every field it names equals the envelope's, and a field the
envelope does not carry matches, as an absent input restricts under ADR-0012:
a call nothing classifies carries no provider, so every entry pauses it. A
scope reads nothing else the client wrote: not `_meta`, not client
information, not the run context, not an argument. Principal, agent and tenant
scopes are refused until a listener authenticates, because an entry that
silently pauses nothing is the unsafe failure of an emergency control. An entry
naming a provider this plane does not configure, or a tool its upstream does
not list, pauses only the calls that carry no provider, and `doctor`,
`/healthz` and a warning in the plane's log name it.

**One file, written one way.** A pause is an entry in one JSON document at
`pause.file`: a `schema_version` and a list of entries, each an `id`, a
`scope`, a `created_at` and a `reason`. It is read strictly: an unknown member,
a duplicate id, an unknown scope, a name on a resource or prompt scope or a
control character in a reason refuses the whole document, and its size and its
entries are bounded. `created_at` and `reason` are for the operator and decide
nothing. Only `internal/pause` writes the file, under an exclusive lock,
through a temporary file, a sync, a rename and a sync of the directory, for
`guardana-control pause init`, `add`, `remove` and `list` and for the dev page.
Removing the last entry writes an empty list; nothing deletes the file. Its
directory may not be, or be inside, the evidence, approvals or hold journal
directory, whose locks would keep a writer out while a plane runs; directories
are compared by identity, so a link or another spelling of one of them is
refused too. Neither the file nor its directory may be a link, both must be
owned by the plane's user and writable by nobody else, and the directory is
judged on the handle the file is then read and written through, so a directory
swapped in after the check is refused. The file opened must be the one judged
no link, so a file swapped in between is refused too.

**A snapshot per decision, taken before the clock.** The plane reads the file
every `pause.poll_interval`, one second by default, into an immutable snapshot.
A call takes the snapshot when it starts, before it reads the clock, so a read
published in between cannot look dated ahead; it takes it again after an ask to
the decision point, which can outlast a snapshot's age, and everything decided
after the ask, the rewrite path's second decision included, uses the second
one. It takes it a last time right before each step that cannot be undone:
before a resume consumes its approval, and before an execution's
`ACTION_STARTED` is written. A state there that covers the call or cannot be
read blocks it. The snapshot is in one of four states: disabled, clear, paused,
or unknown with a cause. Its zero value is unknown, because a snapshot nobody
read is not a clear one. A file that is missing, unreadable, a link, too widely
writable, too large, owned by another user, malformed or of an unknown version
is unknown with that cause, and so is a snapshot older than three poll
intervals, or dated ahead, by the plane's clock, so a reader that stopped
cannot leave an old answer standing. At start the same checks run once and a
failure refuses the start, and the plane reads the file once more right before
it listens, so a slow start never hands the first calls a stale snapshot.
`pause.file` is optional: a plane without it is disabled and says so in
`doctor` and `/healthz`, and the pipeline refuses a missing source, so the
command hands it an explicit disabled one.

**The plane's own causes come before any question leaves the plane.** One pure
function of the call and of the plane's state names every cause the plane has
to block the call whatever the policy says. In order: a pause that covers it
(`PAUSED`, `DENY`), the mismatch halt on a material call
(`EXECUTED_ARGS_MISMATCH`, `DENY`), `LOCKDOWN` on a material call (`LOCKDOWN`,
`DENY`), a pause state that cannot be read (`PAUSE_STATE_UNAVAILABLE`,
`INDETERMINATE`), the evidence halt on a material call (`EVIDENCE_UNAVAILABLE`,
`INDETERMINATE`), and a call nothing classifies outside `OBSERVE`
(`ACTION_UNCLASSIFIED`, `INDETERMINATE`). When it names any cause, the kernel
still decides and `POLICY_DECIDED` records that decision, but the decision
point is not asked: the kernel decides with the answer "not asked", so a veto
rule that reads it is undetermined, and the decision carries no `PDP_` code and
no `pdp_instance`. `ACTION_BLOCKED` carries the plane's decision, which lists
every cause named, in that order; its verdict is `DENY` when any `DENY` cause
applies, and its first code is the one the block counters count. The causes
are named once before the ask. When there are none and the decision point is
asked, they are named once more after it, under the second snapshot; any that
appeared blocks the call, whose `POLICY_DECIDED` then holds the answer. A
pause applies in every mode, `OBSERVE` included, and to every effect class.

**A pause is blocked before the approval path.** A paused retry of a held
request is blocked on a trail of its own: nothing is held anew and no approval
is consumed. A pause read in the last moment, after the approval was consumed
and before the execution is handed out, closes the held trail as paused, and
that approval is spent: until it expires, an identical call reads
`APPROVAL_ALREADY_USED` although nothing ran, since a spent record is all the
store can say. Otherwise the hold outlives the pause. Lifted before its
approval expires, the next retry resumes the held request when its fresh
decision equals the held one, as ADR-0013 requires. A pause closes no hold.

**Nothing already running is cancelled.** An execution handed out before the
pause finishes: `Close` compares and records as always and the result is
delivered. Cancelling it would turn an effect into an unknown one. A pause
bites on every call not yet handed out when the plane read it, at most one
poll interval after the write that set it.

**A listing ignores pauses.** `Preview`, which shapes `tools/list`, skips the
pause: a paused tool stays listed, and a call to it reads `PAUSED`. The halts
still apply there, as before.

**What the evidence says.** `PAUSED` keeps its number and verdict, and its
summary becomes "An operator paused calls in a scope this call falls in, so the
enforcement point blocked it whatever the policy decided." No record has ever
carried code 24, so no earlier record changes meaning.
`PAUSE_STATE_UNAVAILABLE` is registry number 43, `INDETERMINATE`: "The
enforcement point could not read the operator's pause state, so it blocked the
call rather than assume that nothing is paused." A fault is not an operator's
act, and a trail must not say an operator paused a call a fault blocked;
reusing `EVIDENCE_UNAVAILABLE` would make a pause file's fault and the spool's
the same fact. The plane's decision names no entry: `policy_rule_ids` stays
empty, because beside the bundle digest an entry's id would read as a rule of
that bundle, and a bundle may hold a rule with the same id. The plane logs each
change of its snapshot, the entry ids added and removed, at info. Setting or
lifting a pause is not evidence: no event kind carries it.

**What reports it.** `doctor` runs the start checks without taking a lock and
prints the path, the state, the number of entries and every entry that pauses
only calls with no provider, never a reason. `/healthz` gains `pause`: the
state, the entries, whether one is global, the entries that pause only calls
with no provider (`unlisted_only`), the snapshot's age and an unknown state's
cause. An unknown state is a problem and answers 503; an
operator's pause answers 200. The counters count blocks by code, as before, and
the polls, the failed polls by cause and the snapshot changes.

## Security / compatibility impact

A pause the plane cannot read blocks every call as `INDETERMINATE`, and nothing
reads an unknown pause state as clear (invariants 4 and 5). Write access to the
pause file is the authority to pause and to lift a pause, as write access to
the approvals directory is the authority to approve (ADR-0016): any process
that runs as the plane's user can empty the file, a stdio upstream the plane
starts included. The ownership and permission checks keep other accounts out,
not that one, so the pause commands run as the plane's user.

The wire contract does not change. Code 43 is a registry change, as codes 39 to
42 were, and code 24's summary changes. ADR-0017's rule that the ask follows
the kernel in every mode narrows: the plane never asks about a call it blocks
whatever the answer, so under `LOCKDOWN`, a halt or a pause the recorded kernel
decision no longer holds the decision point's answer.

## Alternatives considered

- **One file per pause, created exclusively and unlinked to lift**, as the
  approvals store keeps its records. No lock, but no atomic view across
  entries, a lift leaves no trace, and "missing" becomes a missing directory.
- **Pauses held in the plane and set through the control API.** A restart
  forgets them unless they are written somewhere, which is this record again,
  and the emergency stop would need that API to be up.
- **A missing file read as nothing paused.** Deleting it, or a typo in its
  path, lifts every pause silently.
- **An unreadable file recorded as `PAUSED`.** The trail would say an operator
  paused a call that a fault blocked.
- **Principal, agent and tenant scopes now.** On a listener that authenticates
  nobody each is the whole plane or nothing.
- **The entry's id in `policy_rule_ids`.** It reads as a rule of the bundle the
  decision names. A reserved prefix the policy format refuses would make it
  unambiguous, at the cost of a policy format change; it waits for a reader
  that needs the entry.
- **Keeping the ask for calls the plane blocks**, as ADR-0017 had it. The
  recorded decision stays whole, and a paused call sends its metadata out
  during the incident it was paused for.

## Consequences

An operator stops one tool, one upstream or everything without a restart, from
a command or from the dev page, and lifts it the same way. The plane gains a
reader, an optional key group, `pause.file` and `pause.poll_interval`, and one
more file for the operator to protect. A plane configured with a pause file
blocks everything when that file breaks, which is the price of an emergency
stop that deleting a file cannot defeat. A decision the plane mints may now
list several causes.

## Declared limits

- A pause bites up to one poll interval after it is written, and never on an
  execution already handed out.
- The evidence says that a call was paused, not which entry paused it; the
  plane's log says which entries changed and when.
- Principal, agent and tenant cannot be paused until a listener authenticates.
- A hold outlives a pause and can resume after it is lifted, within its
  approval's lifetime.
- The pause file keeps no history of its own.
- The checks read the mode bits and the owner. On macOS an access control list
  can grant what the mode bits do not show, and the checks do not read it.
- A call a fault left without a provider, an unclassified one, is paused by
  every provider entry and recorded `PAUSED` first, because an absent field
  matches.
- A file holding its most entries refuses one more, a global one included: an
  entry is lifted first.
- A writer's rename that lands between a read's check of the file's name and
  its open makes that read unknown, so calls block until the next poll.

## Validation

The exit criteria of the change that brings this record:

- A pause at each scope blocks exactly its calls, in every mode, reads
  included; `POLICY_DECIDED` holds the kernel's decision and `ACTION_BLOCKED`
  the plane's with `PAUSED`. A provider pause blocks a call nothing classifies
  in `OBSERVE`.
- With a bundle that reads `external`, a paused call makes no call to a
  counting decision point, and its `POLICY_DECIDED` carries no `PDP_` code and
  an empty `pdp_instance`; a mutant that asks first turns the test red. The
  same holds under `LOCKDOWN` and each halt.
- A table over every pair of plane causes pins the listed codes, the verdict
  and the counted code.
- A held request and a paused retry: nothing is consumed; after the lift the
  next retry resumes and executes once.
- One case per unknown cause (missing, `0620`, `0602`, a link, a directory
  `0770`, the byte bound and one byte over, malformed, an unknown version, an
  unknown member, an unknown scope, a resource scope with a name, a snapshot
  three intervals old and one tick older, one dated ahead) blocks
  `INDETERMINATE` with code 43, and `/healthz` answers 503 naming the cause.
- A zero snapshot blocks as unknown, and the pipeline refuses a missing source.
- A source that answers differently on every read gives one state before an
  ask, one after it and one before the execution is handed out, the rewrite
  path deciding under the second; a pause written during the ask, during the
  approval store's search or during an evidence append before `ACTION_STARTED`
  bites that call, one written during that last append does not, and a
  resume it blocks before the consume consumes nothing.
- The file is read once more right before the plane listens, and a start
  slower than three poll intervals leaves the first calls a fresh snapshot.
- A file or directory owned by another user reads unknown; the writer refuses
  a directory another user owns.
- A link or another spelling of a locked directory is refused as the pause
  file's directory.
- An entry naming a provider the configuration lacks, or a tool no upstream
  lists, is named by `doctor`, `/healthz` and the log.
- The entry bound bites before the byte bound, with every field at its most
  expensive encoding.
- `Preview` under a global pause answers what it answers under none.
- The loader refuses a pause file inside each of the three locked directories.
- The codes test holds `PAUSED` and code 43 to the gateway's literals and
  their verdicts, and no rule may name either.
- End to end: `guardana-control pause add` against a running plane blocks the
  next call within one interval, `pause remove` lets the one after through, and
  every trail validates.
