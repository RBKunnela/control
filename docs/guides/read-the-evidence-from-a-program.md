---
title: Read the evidence from a program
summary: Export a trail file in the versioned format, resume where the last export stopped, and rebuild each call's lifecycle without importing the project's internals.
type: how-to
covers: [internal/lineexport/**, internal/trailfile/export.go, internal/trailfile/export_records.go, internal/trailfile/cursor.go, cmd/guardana-gateway/trail.go, examples/evidence-report/**]
---

# Read the evidence from a program

## When to use this

A plane's evidence lands in a trail file, one event per line, written by
`guardana-gateway collect` ([watch a plane without a
collector](watch-a-plane-without-a-collector.md)). A report, an alert or a
dashboard should read it through the export, which is a
versioned format with a cursor, a record for every line it could not read, and
a trailer that says whether it reached the end
([ADR-0035](../adr/0035-a-versioned-evidence-export-and-a-bounded-query.md)).
[contracts.md](../contracts.md#the-evidence-export) states the format member
by member.

## Prerequisites

- A trail file: the one `collect` writes, or the demo's `<state>/trail.jsonl`
  ([try the demo](../get-started/try-the-demo.md)).
- For steps 3 and 4, a checkout of the repository and Go.

## Steps

### 1. Export the file

```
guardana-gateway trail export trail.jsonl > export.jsonl
echo $?
```

Each line of `export.jsonl` is one JSON object with a `type`: a `header`, one
`event` per event, a `gap` for a line that is not one readable event or reuses
an event id with other content, a `duplicate` for a line repeated exactly, and
a `trailer`. An event record carries the file's line as it is, never encoded
again. It exits 0 with nothing refused and no gap, even if a limit ended it early, 1
for a whole export with a gap or a conflicting id, and 2 when refused, with no
trailer. An export with no trailer was cut short.

### 2. Resume where the last one stopped

The trailer's `next_cursor` names the end of the last line read. Pass it to the
next export:

```
guardana-gateway trail export --after '<next_cursor>' trail.jsonl
```

A cursor is refused when the file's first line or the line it names has
changed, or when its offset is not at the end of a line: another file, or one
restored and rewritten since. A line changed elsewhere is not detected. When the trailer's `end_reached` is false,
more remains: follow `next_cursor` until it is true. `--limit` bounds the
events, gaps and duplicates one export writes (default 1000), `--max-bytes` the
bytes of whole lines it scans.

### 3. Rebuild each call's lifecycle

`examples/evidence-report` reads an export on its standard input with the
generated package `api/gen/go/guardana/control/v1` alone, groups the events by
tenant, project and request, follows each request's `prev_event_id` links and
prints a row per request: the kernel's decision, the block, the hold and how
its approval ended, and how the call ended.

The `block` column is the decision on the request's `ACTION_BLOCKED`, beside
the kernel's, never in its place: `=` when its `decision_id` is the
kernel's, otherwise the block's own verdict and codes, such as `DENY PAUSED`
for a call paused after an allow; `-` when nothing was blocked.

```
go -C examples/evidence-report build -o "$PWD/bin/" .
guardana-gateway trail export trail.jsonl | bin/evidence-report
```

It exits 1 when a request's chain is broken or unfinished, when a call ran
against its decision under an enforcing mode, when a result says the effect
may have happened, or when the export held a gap, was cut, held no request,
or went past 100 000 records or 64 MiB: missing evidence is reported as
unknown or open, never as completed; a timeout or an unknown outcome as
`uncertain`, not `failed`. It reads no effect class, so it cannot
tell whether a material call ran without the approval `APPROVE` asks for, or
under `LOCKDOWN`. Export the whole file or one request: any other filter
exits 1.

### 4. Follow a trail and raise alerts

With `-state DIR` the example follows one trail from export to export. `-init`
makes the directory, mode 0700, with an empty state and alert log;
`-cursor` prints the saved cursor, an empty line before the first export; and
each run reads one export on its standard input:

```
bin/evidence-report -state s -init
after=$(bin/evidence-report -state s -cursor)
guardana-gateway trail export ${after:+--after="$after"} trail.jsonl | bin/evidence-report -state s
```

Run the last two lines for what the trail gained since, again at once
while the totals say the end was not reached. Run one
consumer per directory: a run holds its lock, and another refuses.

It refuses, with status 2 and the state untouched, an export that is empty,
cut, filtered, past those bounds, holds a record it refuses, is of another
file than the one it first read, does not start at the saved cursor or ends behind it, or whose
alerts would overfill the log (export again with a smaller `--limit`); and a
state directory another user owns or may read or write, a state of another
`schema_version` major, lacking a member its version had or holding one
unknown, or an alert log shorter than the state.

It drops an event read before, by tenant, project, event id and the same
line, as a duplicate, among the last 20 000 events. An event holding a value
longer than 64 bytes as JSON writes it, or more than 16 reason codes, is not
kept: it raises `lifecycle_unknown`. It prints the requests that ended in
this export, then totals, where `open` counts those it still follows.

Each new alert is one JSON line appended to `s/alerts.jsonl` and written to
standard error after `evidence-report: alert`. The format is the example's
own, `"v":1` and `experimental`, not a contract:

| `alert` | Raised for |
| --- | --- |
| `evidence_gap` | a gap record, its reason in `note` |
| `conflicting_event` | an event id read before with another line |
| `lifecycle_unknown` | a request called `unknown` |
| `effect_uncertain` | a request called `uncertain` |
| `indeterminate` | an `INDETERMINATE` verdict, the kernel's or a block's |
| `plane_block` | a block with a decision of the plane's own, such as a pause |
| `approval_expired` | an approval nobody answered in time |
| `open_bound` | more than 10 000 open requests: the oldest is dropped, and its later events read as broken |

A policy `DENY` is reported, not alerted. A line holds only the members that
apply: `tenant`, `project`, `request`, `run`, `event`, `offset`, where it was
raised, `cursor`, `occurred_at`, `verdict`, `reasons`, `block`, `note`.
Times are the events'; the program reads no clock. The gap after the file's
last newline is alerted once while it stays there. It exits 0 with no new
alert and 1 with one or more.

The alerts are appended, synced and written to standard error first, then
the rows printed, then the state replaced. Exit 2 leaves `state.json`
unchanged unless only its last sync failed: alerts already appended stay in the log, no later run raises them
again, and the rows may print again.

It prints and keeps only identifiers, kinds, the enforcement mode, the
action's kind, name, provider and protocol, verdicts, reason codes, decision
ids, approval states, result statuses, event times, offsets and cursors:
never a preview, a resource, a host, attributes, a delegation reason or a
finding's text.

## Verify

The export's last line is a `trailer` with `end_reached` true, and both
commands exit 0. Any other status names what is missing: read the trailer's
counts and the report's rows before trusting the rest. Following a trail,
`s/alerts.jsonl` holds every alert raised, each once.

## What it does not see

- A record the plane could not deliver stays in its spool's quarantine and
  never reaches the trail file. Missing from the middle or the end of a trail,
  it shows as a broken link or an unfinished trail; a request whose first
  record was refused does not appear at all.
- Duplicates are found within one export. Across exports, drop an event you
  have seen by tenant, project and event id, and read one id with two
  lines as a gap, as step 4 does within its window.
- The export reads what the file holds, which holds no argument or result
  content ([privacy](../concepts/privacy.md)).
