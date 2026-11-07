---
title: Watch a plane without a collector
summary: Run the collector the gateway binary ships, point a plane at it with its credential, read each request's trail in the segments it writes, and prune them.
type: how-to
covers: [cmd/guardana-gateway/collect.go, cmd/guardana-gateway/trail.go, cmd/guardana-gateway/segments.go, adapters/otel/receive.go, adapters/otel/receiver.go, internal/trailfile/**, internal/segmentlog/**]
---

# Watch a plane without a collector

## When to use this

A plane exports its evidence to an OpenTelemetry collector and will not start
without `export.endpoint`. On a first run, or on a small plane you watch yourself, you may
have no collector. `guardana-gateway collect` is one: it takes what a plane
exports over OTLP/HTTP and appends it, argument and result previews cleared,
to a directory of trail segments, and `guardana-gateway trail` reads it back,
one line per request.
Both commands are `experimental`; [status.md](../status.md) is the inventory.

## Prerequisites

- A plane you can run ([run-the-gateway.md](run-the-gateway.md)).
- A parent directory that the account running `collect` owns and that neither
  the group nor others may write; the trail directory is created in it mode
  `0700`, and its files mode `0600`, since events carry tenant and principal
  ids.
- A credential: 32 to 512 printable ASCII bytes with no space, in a file only
  this account may read.

## Steps

### 1. Make the credential

```sh
(umask 077 && od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > collector.credential)
```

### 2. Start the collector

```sh
guardana-gateway collect --listen unix:///run/collector/logs.sock --dir trail/plane \
  --tenant acme --project orders --credential-file collector.credential
```

`--listen 127.0.0.1:4318` takes a loopback IP address instead, which `doctor`
warns of: `0.0.0.0`, another host and `localhost` are refused.
It prints where it listens, the directory and the plane's keys. It runs until Ctrl-C or `SIGTERM`, and waits up to
ten seconds for the requests in flight. One collect holds a directory at a
time; a second one is refused.

The directory is bound to the tenant and the project it was first opened
with; opening it for another is refused. A request without the credential is
answered 401 before its body is read. One carrying an event of another tenant
or project is answered 400, and the plane quarantines that record.

Appends go to `live.jsonl`. When the next append would take it past
`--segment-bytes` (64 MiB unless told, and at least the largest request a
plane sends), it is sealed: `segments.json` names
it with its lines, bytes and the digests of its first and last line, and it
is renamed `segment-<n>.jsonl`. A request whose new records would take the
segments not pruned past `--max-bytes` (1 GiB unless told, and at least twice
the segment bound) is answered 503; an exact repeat or a smaller request still
succeeds, and nothing is pruned to make room.

At open, every segment is read and refused unless it holds what the manifest
names it with; so is a name no collect leaves. A last line of `live.jsonl`
with no newline is what a crash leaves, and is removed only when it can be
the start of an evidence line. A seal or a prune a crash stopped part way is
finished by the next collect or prune. Do not change the files while collect runs: a live segment removed,
renamed, cut or extended under it makes it answer 503 until you start it
again, and the plane keeps the records in its spool.

### 3. Point the plane at it

In the plane's configuration:

```yaml
export:
  endpoint: unix:///run/collector/logs.sock
  collector_uid: 1001     # the account collect runs as, which it printed
```

Give it the header through the environment, so the token stays out of
`plane.yaml`, which a plane reads whatever the group and others may read:

```sh
export GUARDANA_CONTROL_EXPORT_HEADERS_AUTHORIZATION="Bearer $(cat collector.credential)"
guardana-gateway run --config plane.yaml
```

Over TCP, `endpoint: http://127.0.0.1:4318/v1/logs` needs
`allow_plaintext: true`, the named risk of an unencrypted endpoint. The header's
value is a credential and is never printed. A plane sending no credential or
another one is answered 401, sends again, and blocks its material calls once
its spool is full; collect logs the first refusal, then a count once a
minute.

### 4. Read the trail

```sh
guardana-gateway trail trail/plane
```

```text
request=req-1 project=orders tenant=acme last=EVENT_KIND_ACTION_COMPLETED ok
request=req-2 project=orders tenant=acme last=EVENT_KIND_APPROVAL_REQUESTED open
trails 2: ok 1, open 1, failed 0, indeterminate 0; lines 7, repeated lines collapsed 0, bytes after the last newline 0; segments pruned 0
the check proves each chain's shape and not its integrity: a record altered to keep that shape passes it
```

Each line is one request: its last event and the chain check's verdict, over
every segment not pruned. `ok` is a trail whose action closed, `open` one
still in flight, held for an approval, or whose closing record has not
arrived. `failed` and `indeterminate` carry the reason, and either makes
`trail` exit 1, as does nothing to read. Bytes after the last newline are a
line being written while a collect holds the directory, and damage, exit 1,
when none does. `trail` reads at most 100,000 lines.

### 5. Read across segments, and prune

```sh
guardana-gateway trail segments trail/plane
guardana-gateway prune --through 3 trail/plane
```

`trail export trail/plane` reads one segment. Its `end_reached` is true only
at the log's end; before it, export again after `next_cursor`, which leads into
the next segment. A cursor of a pruned segment is refused as expired, exit 2.
A segment's file named on its own, `trail export trail/plane/segment-00000002.jsonl`,
directly or through a symbolic link, is refused, exit 2: export the directory, whose header counts the segments
pruned before. `evidence-report -state` follows the log from segment to
segment.

`trail segments` prints the manifest: how many segments are sealed, pruned
and dropped of the 10,000 it names at most, then each segment's state, lines,
bytes, key and dates, and whether a collect holds it. `prune`
removes the sealed segments up to the one named, after writing each one's
tombstone, which keeps its lines, bytes and digests. Stop collect first: a
held directory is refused, and so is a clock before the segment's seal.
The live segment is never pruned.

## What the collector promises

- **It answers only for what is on disk.** Each request is appended and the
  file synced before the plane is told it was accepted. A request whose write
  fails is answered 503 and sent again.
- **Stopping it, or its bound, blocks; neither loses.** The plane keeps its
  evidence in its spool, and once the spool reaches `evidence.max_bytes`
  material calls are blocked with `EVIDENCE_UNAVAILABLE`. Start the collector
  again, or prune, and everything arrives.
- **A record can arrive twice, and is written once.** The collector keeps the
  event id of every line of every segment not pruned and does not write an
  exact repeat again, across a seal and a restart; it refuses one event id
  carrying two different lines.
- **A request it cannot read is refused**, with 400, 413 when too large or 415
  for a media type or encoding it does not take. The plane splits a 400 or 413
  down to one record and quarantines it; a 415 it sends again. A body cut off
  before its end, by a reset connection or a read timeout, is answered 503
  and sent again; one that never arrives in time keeps the plane retrying
  until its spool is full and material calls are blocked.

## Limits

- Anyone who can read the credential file, or the plane's configuration, can
  write evidence into the trail, including a chain made up to pass the check.
- An event sent again after its segment was pruned is written again, and a
  trail whose first events were pruned fails the chain check.
- Over TCP, the plane's next retry sends the token in plaintext to whoever
  binds collect's loopback port first, before collect is up; TCP export is
  removed in 0.17. A socket's peer must be `export.collector_uid`.
- At 10,000 sealed segments a request that needs a seal is answered 503 until
  a prune; past that, each seal drops the oldest tombstone.
- `trail` checks each chain's shape: its links, its order and its identifiers.
  There is no hash chain, so a record changed to keep that shape passes.
- The collector reads what this repository's exporter sends and nothing more:
  a member OTLP defines that the exporter never writes is refused.

Why it is built this way is
[ADR-0020](../adr/0020-a-trail-and-counters-without-a-collector.md) and
[ADR-0072](../adr/0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md).
