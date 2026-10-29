---
title: Runs
summary: The runs directory, what runs open, close and list print and refuse, and what a plane with runs.dir does with a token.
type: reference
covers: [cmd/guardana-control/runs.go, internal/runs/**, cmd/guardana-gateway/runs.go, adapters/mcp/runs.go]
---

# Runs

A run is one task of an agent, with its own flow state. Without `runs.dir` a
plane keeps one run per principal and agent in memory, up to `flow.max_runs`
(ADR-0021). With it,
every call needs a run the operator opened in that directory, and a run's flow
state is kept on disk
([ADR-0034](../adr/0034-a-run-the-operator-opens-has-an-identity-of-its-own.md)).
It is `experimental`; [status.md](../status.md) is the inventory, and
[contracts.md](../contracts.md#the-runs-directory) gives the file formats.

## The directory

The directory must be the operator's and writable by nobody else: one another
user owns, a group- or world-writable one, one holding a link or a file that is
not the directory's, and one changed since it was opened are refused. A link
to it is followed; what it names is judged. `runs open` makes an empty
directory a runs directory; `runs close`, `runs list` and a plane refuse one.
A record, a state or a lock file another user owns or a group or the world
may write is refused when it is read, and a token naming such a record
resolves as unreadable. A temporary file a crash left while the directory was
being made is ignored.
Write access to it is the authority to open and to close a run, so keep it
beside the approvals directory and back it up with it.

A plane reads a record by its id and writes only a root run's state, under
that root's own lock file, and takes no lock on the directory, so several
planes may share one. The `guardana-gateway` binary holds no code that writes
a record.

## runs open

```
guardana-control runs open --project orders --tenant acme --principal-type service --principal agent-runner --agent orders-assistant --ttl 8h <dir>
```

Every flag but `--parent` is required. `--project` must be the plane's
`project_id`, and `--tenant`, `--principal-type`, `--principal` and `--agent`
what its listener resolves: `listener.principal.tenant_id`, or else
`tenant_id`, `listener.principal.type`, `listener.principal.id` and
`listener.agent.id`. A token presented for any other identity is refused, so
planes of two projects that share a directory and a listener identity never
serve each other's runs. `--ttl` is a duration from `1m` to `720h`, with no
default.

`--parent <run id>` opens the run under an open run of the same project and
tenant. The two then share the parent's root and its flow state, because data
moves between a parent and the runs it spawned in ways the plane does not see.
A child ends no later than its parent: a `--ttl` that would pass the parent's
`expires_at` exits 1 naming both times. Closing a parent closes none of its
children.

It prints four lines:

```
run_id: run-1fc2d3dc0e76763df08dbc2eb4cc6bdb
root: run-1fc2d3dc0e76763df08dbc2eb4cc6bdb
expires_at: 2026-10-01T20:20:27.423572Z
token: run-1fc2d3dc0e76763df08dbc2eb4cc6bdb.<the secret, 43 characters>
```

The token is the run id, a dot and a secret. The directory keeps only the
secret's SHA-256, so this is the token's one copy; a lost token leaves a run
to close and another to open.

## runs close and runs list

`runs close <dir> <run-id>` prints `closed <run-id>`. A closed run, an unknown
one and a malformed id each exit 1. A closed run's token is refused at the
next request or message, and a call that passed the listener before the close
still runs. A plane with a route also stops an open run without closing it:
a stop from a confirmed finding refuses the run's later calls `RUN_STOPPED`
until it expires or is lifted ([reaction.md](reaction.md)).

`runs list <dir>` prints one run a line: its id, `open`, `closed` or `expired`
by this machine's clock, then `root`, `project_id`, `tenant_id`, `principal_type`,
`principal_id`, `agent_id`, `opened_at` and `expires_at`, each followed by its
value. It prints no token and no hash. Past 1000 runs it stops, says so on
stderr and exits 1.

No command repeats a token, or a value given as a run id that is not one.

## What a plane does with a token

| Listener | Where the token comes from | A token that does not resolve |
| --- | --- | --- |
| `stateless_http`, `stateful_http` | the `Run-Token` header of every request, on every method | `401` with `WWW-Authenticate: Run-Token` and one body whatever the cause, before the protocol library reads the request; the origin check and an authenticator answer first |
| `stdio` | `run --run-token-file <file>`, read once at start; the file must be this user's and readable by nobody else | refuses the start |

Every message is judged again, so a run closed or expired while a session or a
process serves it is refused with the JSON-RPC error `-31102`, and nothing is
admitted. `_meta`, any other header and the envelope's `context.run_id` never
select a run. Refusals are counted by cause, `missing`, `malformed`,
`unknown`, `identity`, `closed`, `expired` and `unreadable`, in
[metrics.md](metrics.md) and under `runs` on `/healthz`.

A call reads its root's state once and is decided under it; what its result
brings in is written to the root before `ACTION_STARTED`. A state the plane
cannot read or write, or whose lock another holder keeps too long, blocks the
call in every mode, `OBSERVE` included, with `EVIDENCE_UNAVAILABLE` unless a decision already blocked it. A held call resumes only from the run it was held
under. `ACTION_PROPOSED` names the root in the tag `flow.v1.root=`.

A stateful HTTP session is bound to its principal and agent, not to a run:
each call in it is judged under the token it presents, but a token of another
run of the same principal and agent can read the session's stream or end it by
its id.

`dev` and `scenario run` serve local runs only; `dev` refuses `runs.dir`.

## Runs an earlier release opened

A record from before `project_id` is of `schema_version` `1.0` and names no
project. It is never read as any project's run: its token is refused as
`unreadable`, a stdio plane given it refuses the start saying the record names
no project, `runs list` refuses the directory while it holds one, and
`runs close`, `runs open --parent` and `react`, for a finding that names it,
refuse that run.

Move to a new, empty directory, never into the old one: while one `1.0`
record is left in a directory, `runs list` refuses that whole directory, and
so does `supervise` of every run under a procedure that reads children. Open
each run again there with `runs open --project`, point `runs.dir` at it, and
remove the old directory once no plane names it. No run lives past 720 hours,
so nothing in the old directory outlives that.

A reopened run starts with a clean flow state. An agent that took in
untrusted or confidential data under the old run would carry it into the new
one unmarked, and a flow rule would not see it. End each agent's task and
start a new one under the new run; never hand a new token to an agent in the
middle of a task.
