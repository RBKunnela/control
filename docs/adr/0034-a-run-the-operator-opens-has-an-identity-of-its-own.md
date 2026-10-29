# ADR-0034: A run the operator opens has an identity of its own

Status: accepted
Date: 2026-09-30

Amends [ADR-0021](0021-a-run-carries-what-it-took-in.md) on what a run is.

Builds on [ADR-0013](0013-mcp-interception-approvals-and-modes.md),
[ADR-0018](0018-keys-and-bundles-on-disk.md) and
[ADR-0023](0023-a-local-page-answers-through-the-directory.md).

Amended when it was built, three points the text below leaves open. A 401
carries `WWW-Authenticate: Run-Token` and one body whatever the cause. An
approval's binding names no run, so once an approval is consumed the same
action from any run of that principal and agent is refused as already used;
a retry from another run is held anew only while the first hold stands. A
call's run is judged expired once more, by the plane's clock, right before
the call is handed out; a run closed after its call passed the listener is
not seen there, and that call runs.

Amended by [ADR-0068](0068-a-run-belongs-to-one-project.md):
a run record names its project, a plane resolves a token only under its own
`project_id`, and a record of major 1 is refused.

## Context

ADR-0021 keys a run by the listener and the principal and agent it resolves.
With no authenticator, which is every listener in this build, that is one run
per plane: two tasks of one agent share their flow state, and two agents behind
one listener do too. That over-restricts and never washes taint, but a restart
ends every run and so forgets what each took in, and on a stdio listener a
client that starts the plane again starts a clean run while the model keeps its
context.

Every boundary a client draws, a session, a connection, a `_meta` value, is the
client's to redraw, so none can name a run. What the plane can trust is what
someone with authority over it said before the run began: the operator, or an
orchestrator the operator runs, which knows that two tasks are separate and
which task spawned which. State kept in one process's memory cannot serve a run
that two processes serve, a parent and its child behind two stdio planes, or a
reconnect while the old process lingers.

## Decision

**Two kinds of run.** A *local* run is ADR-0021's, unchanged, used whenever the
plane has no runs directory; `doctor` and `/healthz` then say that runs are
local and that a new process starts clean. An *opened* run exists because the
operator opened it, and only a plane configured with `runs.dir` serves one.

**Opening a run is the approver's.** `guardana-control runs open <dir>` mints the
run's id, writes the run's initial state file and then its record, and prints a
token once. `--ttl` is required, bounded and has no default. The record holds
the id; the tenant, principal type and id, and agent it is for; the root run,
resolved at opening when `--parent` names an open run of the same tenant; when
it was opened and when it expires; and the SHA-256 of the token's secret, never
the secret. `runs close` closes a run and `runs list` prints a bounded listing;
closing a parent closes none of its children. The directory follows the
approvals directory's rules: owner and mode are checked, and a record the plane
did not expect is refused, not read. The plane reads records by id and writes
only its roots' state files; it never creates, rewrites or deletes a record,
and the check on the built plane binary covers run-record writers as it covers
approval writers.

**Presenting a run.** The token is `<run id>.<secret>`. On an HTTP listener it
travels in a header of its own, never in `Authorization`, which stays the
authenticator's and the protocol's: who calls and which task are separate. A
stdio plane reads it once from `run --run-token-file`, a file whose owner and
mode are checked as a key's are (ADR-0018), and a token that does not resolve
refuses the start. The plane finds the record by the id and compares the
secret's hash once, in constant time. The record's tenant, principal and agent
must equal what the listener resolved: with an authenticator, the authenticated
principal; without one, the listener's configured identity. A request with no
token, an unknown one, one for another principal or agent, or for a closed or
expired run, judged by the plane's own clock, a zero reading proving nothing
unexpired, is refused at the listener: 401 on HTTP before any protocol message,
a JSON-RPC error on stdio for a run closed while the process serves. It mints
no run, never falls back to the local one, writes no trail, and is counted in
`/metrics` by cause. `_meta`, any other header and the envelope's
`context.run_id` never select a run.

**The root's state file is the truth.** Flow state belongs to a root run: a run
opened with a parent shares its root's state, because data moves between a
parent and the runs it spawned in ways the plane does not see. A call reads its
root's state file once, when it takes its flow. When the call's declared result
would raise the state, the plane reads the file again under an exclusive lock,
joins ADR-0021's way, `untrusted` as an OR and `max_read` as its join so that
writers side by side never lower it, writes, syncs, and only then records
`ACTION_STARTED` and hands the execution out, outside the pipeline's own lock.
A write that fails blocks the execution with `EVIDENCE_UNAVAILABLE` in every
mode, as ADR-0021 blocks a run it cannot name. A root whose state file is
missing or unreadable blocks every call of its runs, since writing the file at
opening means a missing one was removed. The state only rises, so a root writes
it a handful of times in its life. With state durable, dropping a run from
memory washes nothing: memory is a bounded cache and no run is refused for
number.

**A hold belongs to its run.** A retry resumes a held request only from the run
that is held under it; from another run of the same principal and agent it is
held anew. A retry from a closed or expired run is refused before it is
decided, so the hold lapses at its expiry and the sweep closes its trail; the
page may still show it until then. A hold lost to a restart is closed, never
resumed (ADR-0016).

**Evidence.** `Event.run_id` is the opened run's id, and the run-context tags
gain `flow.v1.root=` the root whose state was used. Which run is whose and which
spawned which is in the run records, which an evidence consumer needs beside the
export (ADR-0035). No wire field is added.

## Security / compatibility impact

The token is an operator-issued capability for one run: whoever holds it acts
as that run, under the principal the listener resolved. It is printed once,
stored only as a hash, and never logged or recorded. A plane without
`runs.dir` behaves as today. A plane with it refuses a client that presents no
run, which is the point: a run nobody opened cannot wash its taint by starting
over. Sharing a root's state is sound only while every flow of data between
runs follows a declared parent: two siblings an orchestrator bridges are not
seen, which ADR-0021's lower bound gains as a limit. `docs/contracts.md`'s
sentence on which run the gateway writes, the status row on runs and
ADR-0021's declared limits change with the code that builds this record;
until then they describe local runs, the only kind the plane serves.

## Alternatives considered

- **A run per session or per `_meta` value.** The client draws both, so a new
  session washes the taint (ADR-0021).
- **The token in `Authorization`.** It would take the header the end-user
  authenticator and the protocol's own authorization use, and moving it later
  would break every client.
- **One process owns a root under a lock held for its life.** A stdio child
  could not run beside its parent, and a lingering process would lock out a
  reconnect.
- **Opened runs on HTTP only, with state in memory.** A new stdio process, or a
  restart, would wash the taint.
- **Separate state for a child run.** A child's result reaches its parent
  through the orchestrator, which the plane does not see.
- **A token variable under the product's prefix.** The loader refuses a
  variable naming no key, `dev` refuses them all, and a setting would let the
  token live in a file meant for version control.

## Consequences

An orchestrator that wants two tasks kept apart opens two runs and hands each
agent its token. A plane with runs configured cannot be reached without one.
The runs directory is state the operator backs up with the approvals directory.
A call reads one small file when it starts, and a call that raises its root's
state waits for one synced write.

## Validation

Adversarial tests: no token, a forged one, one for a closed, expired or other
principal's run, a run hint in `_meta` or another header, each refused with no
run minted and no trail; a new session and a new stdio process with the same
token reaching the same state; two runs of one agent whose states stay apart; a
child's read reaching its root; two pipelines on one runs directory, each
seeing the other's taint, the state never lowered; a restart keeping it; a
deleted or unreadable state file blocking; a failed write blocking before
`ACTION_STARTED`; a retry from another run held anew; and the built-binary check
finding no run-record writer in the plane.
