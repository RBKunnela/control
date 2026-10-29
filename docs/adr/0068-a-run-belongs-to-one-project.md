# ADR-0068: A run belongs to one project

Status: accepted
Date: 2026-10-28

Amends [ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md)
on whose run a token names, and
[ADR-0058](0058-a-copy-an-import-never-read-is-doubt-for-the-runs-it-claimed.md)
on what holds a source when no event of the run was read.

## Context

A run's record named a tenant, a principal and an agent, and a plane resolved
a token for the identity its listener gives. Two planes of different projects
that share a runs directory and a listener identity resolved each other's
runs. A token opened for one project's task then acted as a run of the other,
carried that project's flow state into it, and was recorded under the other
project.

## Decision

A run record carries `project_id`, and its `schema_version` moves from `1.0`
to `2.0`. The record is refused when it is written or read with an empty or
invalid project.

A plane resolves a token under its own `project_id`, never under one the
listener or the caller names. A token for another project's run is refused
as another identity: 401 with cause `identity`, and no trail.

`runs open` needs `--project`, and refuses a parent of another project.

A record of major 1 names no project, so it is refused with its version,
never read as any project's. The way to move is to open each run again: no
run lives past 720 hours.

The runs directory's marker and each root's state stay at `1.0` and name no
project. Planes of several projects may still share one directory, because
each record is bound on its own.

Every reader of a run holds it to its project, as it holds it to its tenant:

- A run tree is read only when every member is of the root's project; a member
  of another is refused, as one of another tenant is.
- `supervise` takes the project from the run's record, refuses a member of the
  tree of another project, and refuses evidence whose events of the run name
  another project and a source of another project, even when no event of the
  run was read.
- `react` never stops a run for a finding of another project, nor for one that
  names no project.
- `doctor` and `/healthz` list a stop of another project's run as unheld, since
  it matches no call of the plane.

Resolving a child's token returns the root its record names without reading
the root's record, for the project as for the tenant. A run's state only
rises, so a record planted under another project's root can raise that
root's state, never lower the root's; the planted run itself reads the
root's state, whatever it is. Whoever can plant that record can also rewrite
the root's record, so a second read on every call would bind nothing such a
writer could not undo. The readers that judge a task as a whole, the tree
reads above, refuse such a member.

## Security / compatibility impact

A token can no longer cross projects. The marker binds no project, so write
access to a shared runs directory is the authority to open a run for every
project that shares it, and every plane serving that directory holds it,
since a plane writes the state of the roots it serves. Every run opened by an earlier release
stops resolving on upgrade, and its agents need new tokens. A stdio plane given
such a token refuses to start. A plane that serves runs over HTTP answers 401
`unreadable` on each call until the token is replaced.

## Alternatives considered

- Bind the runs marker to one project as well. Planes of two projects could
  then not share a directory, and the record's own binding already refuses
  the token.
- Read a `1.0` record as the plane's project. A run opened for one project
  would then be served by whichever plane read it first.
- Take the project from the listener. A listener is configured per plane and
  can be copied between planes, so it proves nothing about the project.

## Consequences

Operators reopen live runs once at upgrade, in a new, empty directory. One
`1.0` record left in a directory makes `runs list` refuse that whole
directory, and so does `supervise` of every run under a procedure that reads
children; `runs close`, `runs open --parent` and `react` refuse the old run
itself. `doctor` does not yet name a `1.0` record in a runs directory; the
plane's refusal does.

A reopened run starts with a clean flow state: no command carries a run's
state into another. An agent that took in untrusted data under the old run
would lose that mark under the new one. Operators end each agent's task and
start a new one under the new run, and never hand a new token to an agent in
the middle of a task.

## Validation

- `internal/runs` keeps a literal `1.0` record and refuses it, and refuses a
  record with an empty project at encode and at decode.
- `cmd/guardana-gateway`'s `TestARunOfAnotherProjectIsRefusedOnASharedDirectory`
  serves two projects' planes from one directory and listener identity and
  expects 401 with no trail.
- `TestARecordOfMajorOneResolvesOnNoPlane` expects a `1.0` record to resolve on
  no plane.
- `internal/runs`'s tree tests plant a member of another project and expect
  `ErrTreeProject` from `Tree` and `Children`.
- `internal/supervise` refuses a tree member of another project, and events or
  a source of another project than the run's record, with or without an event
  read; `supervise` exits 2 on such an
  export and writes no finding.
- `react` writes no stop for a finding of another project, or for a run of
  another project; `Eligible` refuses either, and a finding with no project.
- `doctor` and `/healthz` list a stop of another project's run as unheld.
