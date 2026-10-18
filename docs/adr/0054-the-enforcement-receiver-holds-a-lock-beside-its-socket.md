# ADR-0054: The enforcement receiver holds a lock beside its socket

Status: accepted
Date: 2026-10-17

Amends [ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md),
whose receiver binds the socket this record keeps to one plane.

## Context

A plane that ends without closing its listener leaves its socket file
behind, and the next plane on the same path has to tell that file from one a
live receiver still listens on. Until now it dialled the socket and removed it
only when the connection was refused. On Linux a refusal proves the socket
dead. On macOS it does not: a live receiver whose backlog is full refuses a
connection too, so a second plane started on the same path could remove a
live receiver's socket and take its clients. The first plane would keep
running and receive nothing.

## Decision

The receiver takes an exclusive `flock` on `<socket>.lock`, in the socket's
own directory, before it touches the socket, and holds it until its listener
is closed. The lock file is opened without following a link, created with
mode `0600` whatever the umask leaves, and must be a regular file of one name
that the plane's user owns with mode `0600`. A lock another process
holds refuses the bind with `ErrSocketInUse`, whatever a dial would say. With
the lock held, the dial still runs: a socket something answers on is refused,
and one that refuses a connection is removed, as before. The lock file is
never removed, since a plane that removed it could let two later planes lock
two different files.

On a Unix system without `flock` (Solaris, illumos, AIX) `Listen` refuses
with `ErrPlatform`, as it does on Windows.

## Security / compatibility impact

No authorization, wire or evidence change. A second plane on one socket is
refused on both systems instead of taking the socket over. The kernel drops
the lock when the process dies, so a crashed plane leaves nothing that
refuses the next one. A receiver of an earlier release holds no lock; against
it the dial is the only guard, as before. The directory gains one file,
covered by the same owner-only check as the socket.

## Alternatives considered

- Never remove a refused socket on macOS, and have the operator delete it by
  hand after a crash: safe, but every crash on macOS needs a manual step.
- Keep the dial alone and state the macOS limit: leaves a second plane able
  to take a live plane's clients without either saying so.
- A lock on the socket's directory, with no new file: an operator may keep
  several planes' sockets in one directory, and one plane would then refuse
  the others.
- A PID file: a recycled process id can make a dead plane look alive, and a
  live one dead after a PID namespace change; a kernel lock has neither
  failure.

## Consequences

`Listen` returns a listener whose `Close` releases the lock; `Serve` accepts
it. `CheckSocketDir`, which `doctor` runs, refuses without locking a lock file
`Listen` would refuse. An operator who points two planes at one socket gets a refusal naming the
lock file. The socket's directory holds `<socket>.lock` after the first start.

## Validation

`adapters/enforce/socketlock_unix_test.go`: a held lock keeps a socket that
refuses connections and refuses the bind, and a free lock lets it be
replaced; a listener holds the lock until it is closed, and `Serve` releases
it when it ends; a link, a directory, a second name of another file or a file
others may read at the lock's path is refused; a lock created under umask
`0277` is still `0600`. The first case fails
without the lock, on both systems.
