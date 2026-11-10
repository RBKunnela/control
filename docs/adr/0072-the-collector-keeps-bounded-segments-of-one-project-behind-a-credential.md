# ADR-0072: The collector keeps bounded segments of one project, behind a credential

Status: accepted
Date: 2026-10-30

Amends [ADR-0020](0020-a-trail-and-counters-without-a-collector.md) on what
`collect` writes and whom it takes it from, and
[ADR-0035](0035-a-versioned-evidence-export-and-a-bounded-query.md) on what a
cursor names in a log of segments. Builds on
[ADR-0014](0014-evidence-spool-and-sinks.md) and
[ADR-0066](0066-each-decision-about-authority-is-a-port.md).

Amends [ADR-0066](0066-each-decision-about-authority-is-a-port.md)
properties 1, 3 and 6 for RecordLog until it has a second kind.

Amended when export gained a Unix socket: on `export.endpoint: unix:///path`
the plane sends only to a peer of `export.collector_uid`, so it authenticates
that collector; over TCP it still does not, and `doctor` warns of every TCP
endpoint ([docs/status.md](../status.md)).

Amended by [ADR-0080](0080-evidence-leaves-a-plane-over-a-unix-socket-or-tls.md):
plaintext TCP is refused, `collect` listens on a unix socket only, and a
collector on another host is reached over TLS.

## Context

`collect` appended everything it received to one file that never rotated, and
its index of event ids grew with it. It took a request from anything that
could reach its loopback port, so any local account could write lines into a
plane's trail, or fill the disk. A file that only grows has no bound to fail
closed on, and no way to drop old evidence that leaves a record of what was
dropped.

## Decision

**Evidence storage is a port, RecordLog,** declared in `internal/segmentlog`:
append whole lines, seal the live segment, prune sealed segments through one
number, locate a segment by its key, and read the manifest. A key is the
SHA-256 of the segment's number and its first line's digest; numbers are never
given twice, so no two segments share one, and a segment keeps its key when it
is sealed. A located segment is Live, Sealed or Pruned, with what the log
knows of it; the zero answer is Unknown, and so is a key no segment the
manifest names has. The kind is closed, and its default is `segments`. No
remote kind exists yet.

**RecordLog is a port in part, and says which part.** Until a second kind
exists it falls short of ADR-0066 in three ways. Its interface is declared beside its one kind, in
`internal/segmentlog`, not by its consumer `internal/trailfile`. The kind is
fixed in code: no configuration key selects it, so none can name an unknown
one. And it has no `/metrics` or `doctor` key, because the collector has
neither; `trail segments` prints its counts. Writes and prunes go through
the port. Reads do not: export, cursors and `trail segments` read the
default kind's files through its own read-only view, so a second kind brings
its reader with it. The change that adds a second kind, or a remote one,
moves the interface to its consumer, adds a read interface and a kind
selector, and gives the port its bounds and diagnostics.

**The default kind is a directory of segments and one manifest,**
`segments.json`, format `guardana.control.segments` version `0.1`. The
manifest names the tenant and the project the log is bound to, and each sealed
or pruned segment by number, with its lines, bytes, the SHA-256 of its first
and last line and when it was sealed and pruned. It is read only in the one
spelling its writer gives it; any other version is refused. One writer holds
the directory under a lock file, and waits up to a quarter of a second for it,
so a reader's probe of the lock does not stop a writer starting. The directory
is refused with any group or other access. An open reads every segment not
pruned whole, and refuses one that does not hold what the manifest names it
with, a segment the manifest does not name, and any name no writer leaves. The
live segment is opened by name through the directory the writer judged and
locked.

**The manifest names at most 10,000 segments.** A seal at that bound drops the
oldest tombstone and counts it in `dropped`, so pruned segments never fill the
manifest; 10,000 sealed segments refuse the next seal until an operator
prunes. A cursor of a dropped segment names a key nothing has, and is refused
as another file, never read as another position.

**A seal names the segment in the manifest, then renames the live file; a
prune writes the tombstone, then unlinks.** A crash between the steps is
completed at the next open: a live file that is the segment the manifest names
sealed is renamed, and a file at a pruned segment's name is unlinked when it
is the one the tombstone names. Anything else is refused.

**The bound refuses and nothing prunes on its own.** `collect --max-bytes`
bounds the bytes of the segments not pruned; an append that would pass it is
answered 503, the plane's spool fills, and a material call is blocked with
`EVIDENCE_UNAVAILABLE` as ADR-0014 says. A live segment holding a line is
sealed before an append would take it past `--segment-bytes`, and before the
bound on the log is asked. `collect` refuses a segment bound below the largest
request a plane sends, and a log bound below twice it, so a full log always
holds a sealed segment to prune. `guardana-gateway prune --through <n> <dir>`
is the operator's act, refused while a collector holds the directory.

**The collector is bound to one tenant and project and requires a
credential.** `collect --tenant --project --credential-file` is required. The
receiver answers 401, before it reads the body, a request whose one
`Authorization` header is not `Bearer` and the credential, compared as SHA-256
digests in constant time; the plane sends it through `export.headers`. The
first refusal is logged, then a count at most once a minute. An append holding
an event of another tenant or project is refused whole as 400, which the plane
quarantines. A body the receiver could not read to its end, cut by a reset
connection or a read timeout, is answered 503 and sent again; one that never
arrives in time fills the spool and blocks material calls.

**The evidence export goes to `1.1`, and keeps its meaning.** An export of a
directory, `trail export <dir>`, reads one segment. Its header's `source` and
its cursors carry the segment's key, and its header's `pruned_before` counts
the segments before it the export cannot read, pruned or their tombstones
dropped; a single file's export carries 0. The member is additive: a reader
of `1.0` takes a higher minor, and a `1.1` reader reads a `1.0` header as 0,
since no released build wrote a directory export. A strict `1.0` reader, as
coverage and `examples/evidence-report` of 0.14.0 are, refuses a `1.1` export
on its new member: it fails loudly and never misreads. A coverage join refuses an
export as whole while `pruned_before` is above 0, so a window a pruned segment
held part of is never taken as checked. With no cursor it is the first
segment not pruned. A file of the directory exported by its path is refused,
since it would count no segment pruned before it. `end_reached`
is the end of the log as the export found it: at the end of a sealed segment
that a later one with a line follows it is false, and the export after that
`next_cursor` reads the next segment from its first line. So a reader that
follows `next_cursor` until `end_reached` reads every retained line once, and
a coverage join takes an export as whole only when it reached the log's end. A
cursor of a pruned segment is refused as expired, exit 2. A segment opened is
read from its descriptor; a live segment opened after a seal the view did not
see is refused as moved and the export starts again, so a seal or a prune
while it is read changes nothing read. `trail <dir>` reads every segment not
pruned, and `trail segments <dir>` prints the manifest, its counts and each
segment's key.

## Security / compatibility impact

`collect --out` is gone, and every collect command line changes once: a plane
sending no credential or another one is answered 401, retries, and blocks its
material calls when its spool is full, as with a collector that is down. A
local account without the credential writes nothing to a trail and cannot
fill its bound. One that can read the credential file, or the plane's
configuration, can; both are the operator's to keep.

**What this does not do: the plane does not authenticate the collector.**
While `collect` is down or restarting, any local account that binds its
loopback port first receives the plane's next retry, the bearer token in
plaintext among it, and can then write to the trail and fill its bound once
the real collector is back. The fix, the collector authenticated to the plane
on a unix socket with a peer-credential check, is planned for 0.16.

The dedup index covers the segments not pruned only: an event sent again
after its segment was pruned is written again. A trail whose first events
were pruned fails the chain check in `trail <dir>`, which sees only its rest.
A trail file of the old shape is still read, and exported as before but for
the header's version and `pruned_before`, 0.

## Alternatives considered

- Pruning the oldest sealed segment at the bound: drops evidence nobody chose
  to drop, and lets anyone who can fill the bound erase what came before.
- Splitting appends across segments to keep each under its bound exactly: a
  request's lines would land in two segments, and a cursor would name half a
  request.
- An unbound `collect --out` beside the segments: leaves the refusal at the
  bound, and the credential, for anyone to step around.
- A credential compared as bytes: `subtle.ConstantTimeCompare` returns early
  on a length that differs, so the length would be learned; digests are of one
  length.

## Consequences

An operator watches `trail segments` and prunes; until then the plane blocks
material calls. The findings and observation logs take the same port in a
later change. The collector has no `/metrics` or `doctor` of its own, so the
port's counts are what `trail segments` prints.

## Validation

- `internal/segmentlog`: a crash before every step of a seal and of a prune,
  and again before every step of the open after it, leaves the log whole or
  not begun, located as what it is; the conformance cases in
  `testdata/ports/record-log/`, each with its negative control, one append
  past the segment bound among them; a manifest in any other spelling, and one
  that disagrees with its files, is refused; `FuzzManifest` holds the one
  spelling; a manifest at its bound drops a tombstone at a seal and refuses
  one at 10,000 sealed segments until a prune; a writer waits out a reader's
  probe of its lock.
- `internal/trailfile`: an event of another project refuses its append; a
  resend across a seal and across a reopen is written once; an export cut at
  every record and resumed writes every event once, across seals; a reader
  following `next_cursor` until `end_reached` reads every line once; a cursor
  of a pruned segment is refused as expired; a live segment sealed between a
  view and its open is refused as moved; two segments beginning with one line
  keep their cursors apart.
- `adapters/otel`: a request without the credential exactly, in every form
  tried, is answered 401 and reaches no sink, and a thousand refusals log one
  line.
- `cmd/guardana-gateway`: `prune` removes the segment it names, says how many
  bytes, and is refused while a collector holds the directory; `collect`
  refuses bounds that could leave a full log with nothing sealed.
- `internal/gateway/e2e`: at the trail's bound a material call is blocked and
  never reaches the upstream, nothing is pruned on its own, the collector back
  without a prune leaves it blocked, and after a prune under the same bound
  the spool drains and the call runs; a plane with another credential writes
  nothing; another project's evidence is quarantined by the plane.
