---
title: Watch a plane without a collector
summary: Run the collector the gateway binary ships, point a plane's export at it, and check each request's trail in the file it writes.
type: how-to
covers: [cmd/guardana-gateway/collect.go, cmd/guardana-gateway/trail.go, adapters/otel/receive.go, adapters/otel/receiver.go, internal/trailfile/**]
---

# Watch a plane without a collector

## When to use this

A plane exports its evidence to an OpenTelemetry collector and will not start
without `export.endpoint`. On a first run, or on a small plane you watch yourself, you may
have no collector. `guardana-gateway collect` is one: it takes what a plane
exports over OTLP/HTTP and appends it, argument and result previews cleared,
to a file of evidence lines, and
`guardana-gateway trail` reads that file back, one line per request. The plane
itself does not change: it exports exactly as it would to any collector. Both
commands are `experimental`; [status.md](../status.md) is the inventory.

## Prerequisites

- A plane you can run ([run-the-gateway.md](run-the-gateway.md)).
- A directory for the trail file that the account running `collect` owns and
  that neither the group nor others may write; a directory or a file another
  account owns is refused.
  Events carry tenant and principal ids, so the file is created mode `0600`.

## Steps

### 1. Start the collector

```sh
guardana-gateway collect --listen 127.0.0.1:4318 --out trail/plane.jsonl
```

It listens on a loopback IP address only, so `0.0.0.0`, another host and
`localhost` are refused, and it prints the URL it listens on and the file it
appends to. It runs until you stop it with Ctrl-C or `SIGTERM`, and waits up to ten
seconds for the requests in flight before it exits. One collect holds a file at a time; a
second one on the same file is refused.

`--out` names a trail file or a path where no file exists yet; a path that
ends in a separator, `.` or `..` names no file and is refused. A file that is
not a trail, such as notes, is refused as damaged and left as it was. A last
line with no newline is what a crash leaves of an append the plane was never
told about, and collect removes it, but only when it can be the start of an
evidence line. Anything else is refused and left as it was, a settings file
of one line among them.

While collect runs, do not remove, rename, replace, truncate or append to the
file, and do not put a link in its place. The collector checks before and after
each append that the path, not followed, still names the file it holds, at the
length it left it. When not, it answers 503 to that request and every later
one, each logged with what changed, until you start it again, and the plane
keeps the records in its spool.

### 2. Point the plane at it

In the plane's configuration:

```yaml
export:
  endpoint: http://127.0.0.1:4318/v1/logs
  allow_plaintext: true
```

`allow_plaintext` is the named risk of an unencrypted endpoint. The collector
asks for no credential, so any account on this machine can reach its loopback
port and send it records; no other machine can. Start the plane with `run` as
usual.

### 3. Read the trail

```sh
guardana-gateway trail trail/plane.jsonl
```

```text
request=req-1 project=orders tenant=acme last=EVENT_KIND_ACTION_COMPLETED ok
request=req-2 project=orders tenant=acme last=EVENT_KIND_APPROVAL_REQUESTED open
trails 2: ok 1, open 1, failed 0, indeterminate 0; lines 7, repeated lines collapsed 0, bytes after the last newline 0
the check proves each chain's shape and not its integrity: a record altered to keep that shape passes it
```

Each line is one request: its last event and the chain check's verdict.
`ok` is a trail whose action closed, `open` one still in flight, held for an
approval, or whose closing record has not arrived yet. `failed` and
`indeterminate` carry the check's reason, and either makes `trail` exit 1, as
does a file that holds no trail. An `open` trail does not: a plane still
serving has trails open. You can run it while the collector writes: it reads
up to the last whole line and counts the bytes after it. When no collect holds
the file, those bytes are a line nobody is writing, and `trail` prints its
report and exits 1 saying the file is damaged. `trail` reads at most 100,000
lines, repeated ones included, and refuses a longer file with exit 1.

## What the collector promises

- **It answers only for what is on disk.** Each request is appended and the
  file synced before the plane is told it was accepted, so the plane releases
  nothing the file does not hold. A request whose write fails is answered 503
  and sent again.
- **Stopping it blocks, it loses nothing.** While the collector is down the
  plane keeps its evidence in its spool, and once the spool reaches
  `evidence.max_bytes` material calls are blocked with `EVIDENCE_UNAVAILABLE`.
  Start the collector again on the same file and everything arrives.
- **A record can arrive twice, and is written once.** A crash between the sync
  and the answer makes the plane send it again. The collector keeps the event
  id of every line in the file and does not write an exact repeat again;
  `trail` still counts a repeat once, and refuses a file in which one event id
  carries two different lines.
- **A request it cannot read is refused**, with 400, 413 when it is too large
  or 415 for a media type or encoding it does not take. The plane splits a 400
  or 413 down to one record and quarantines it instead of retrying it for
  ever; a 415 it sends again. So is a record
  whose event id the file already holds with other content, so the file stays
  one `trail` reads.

## Limits

- The file is never rotated or pruned, and `trail` refuses it once it holds
  more than 100,000 lines, which a busy plane can reach and any local account
  that can reach the port can cause.
- The collector takes no credential: any local user who can reach the
  loopback port can write evidence into the trail, including a chain made up
  to pass the check.
- `trail` checks each chain's shape: its links, its order and its identifiers.
  There is no hash chain, so a record changed to keep that shape passes.
- The collector reads what this repository's exporter sends and nothing more:
  a member OTLP defines that the exporter never writes is refused rather than
  ignored.

Why it is built this way, and what it leaves out, is
[ADR-0020](../adr/0020-a-trail-and-counters-without-a-collector.md).
