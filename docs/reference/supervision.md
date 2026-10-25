---
title: Supervision
summary: The procedure document, what guardana-control supervise checks for one opened run, the finding record and its log, and how notify delivers findings.
type: reference
covers: [internal/supervise/**, internal/findinglog/**, internal/notify/**, cmd/guardana-control/supervise*.go, cmd/guardana-control/notify.go, cmd/guardana-control/findings.go, api/proto/guardana/control/finding/**]
---

# Supervision

`guardana-control supervise` checks a run an operator opened against its
procedure, from the plane's evidence and the runtime's reports, and
appends findings to a log.
`guardana-control notify` hands each alert in that log to a program of the
operator's, at least once. Both are `experimental`. Neither decides a call,
and no plane reads what they write
([ADR-0045](../adr/0045-one-run-is-supervised-against-its-procedure.md));
`react` turns a confirmed finding into a stop a plane reads
([reaction.md](reaction.md)). `--view` draws the run
([run-view.md](run-view.md)).

```
guardana-control supervise --procedure <file> --runs <dir> --run <run-id> --findings <dir>
    [--evidence <export>]... [--source <descriptor> --log <dir>]...
    [--view <file> [--view-all]]
guardana-control notify --findings <dir> --state <dir> [--init] [--timeout <duration>]
    -- <program> [<arg>]...
```

## The procedure

A strict JSON document of at most 64 KiB: an unknown or repeated member, a
cycle in the order and an unknown step are refused. Its digest is recorded with
every finding; a procedure id and version the findings log has seen under
another digest is refused.

| Member | Meaning |
| --- | --- |
| `schema_version` | `0.1`, or `0.2`, which requires `bindings`, `exceptions`, `children` and `binds` |
| `procedure_id`, `version` | what the findings name |
| `steps` | each an `id`, the `tool` and `upstream` a plane sees, the names a runtime reports it under (`observed_as`), `required`, and `binds` |
| `order` | each step id and the steps it must follow |
| `allow` | tools the run may also call, each with `tool`, `upstream`, `observed_as` and `binds` |
| `bindings` | at most 64, each a name and its calls' resource type; a `binds` lists at most one |
| `exceptions` | at most 128, each an `id`, the rule it `waives`, a `step`, or for `STEP_OUTSIDE_PROCEDURE` a `tool` and `upstream` the procedure lacks, and one `condition`: `approval: granted`, `step_failed: <step>` or `reason: <code>`, a code on the call's policy decision. Only that rule, on an approval, and the three about steps take one, a skipped step not on an approval |
| `children` | `inherit` or `separate`, below |
| `rules` | for each rule of its schema, a `severity` (`info` to `critical`) and an `escalation` (`inform` or `alert`) |
| `max_denials`, `deadline_seconds` | at least 1; absent, its rule is off |

## What belongs to the run

Only a run opened in a runs directory is supervised; a plane's local run is
refused. Under `0.1` and `inherit` the run must be a root. `inherit` reads
the root's tree, up to 400 runs, and refuses a member of another tenant
or a parent chain that misses the root; every member is judged, and
the tree is closed when every member is. `separate` takes any opened run and
lists its children, not judged. Plane events count when their run is judged
and their tenant the run's. Observations count when their correlation is
claimed, with such a run id, tenant and project; another tenant's or
project's `--source` is refused. Only a tool call is a step, never a
prompt or resource read. An observation joined to a plane event by trace
and span id is that call; a join cut short leaves
`STEP_OUTSIDE_PROCEDURE` and `DENIED_ACTION_RETRIED_AROUND` not checked,
findings kept. Everything else is counted and left out.

The procedure, descriptors and evidence exports must be regular
files of this account that only it can write: a `CONFIRMED` finding rests on
the export being the plane's.

## The rules

| Rule | Fires when |
| --- | --- |
| `REPEATED_DENIAL` | one tool on one upstream is denied by policy `max_denials` times, plane blocks apart; doubtful denials dropped when others suffice |
| `STEP_OUTSIDE_PROCEDURE` | a tool neither a step nor allowed is called, or reported and not joined to a plane call |
| `DEADLINE_EXCEEDED` | events span over `deadline_seconds` (per run under `0.2`, from the tree's first); unchecked within it if one is untimed |
| `REQUIRED_STEP_SKIPPED` | a required step has no instance |
| `STEP_OUT_OF_ORDER` | a step comes before one it must follow |
| `CONTINUED_AFTER_FAILURE` | another step proposed after a step's failure, before its retry, unless it is a step's first instance out of order |
| `RESOURCE_OUTSIDE_RUN` | one binding's calls carry more than one resource; indeterminate for one resource beside an id-less call |
| `DENIED_ACTION_RETRIED_ARGUMENTS` | a denied tool is called again with other arguments |
| `DENIED_ACTION_RETRIED_RESOURCE` | another tool or upstream on a denied call's resource, not a read after a denied non-read |
| `DENIED_ACTION_RETRIED_AROUND` | a source reports the denied tool after the denial, joined to no plane call; not checked with no `--source` or one unread or unheard |
| `EXCEPTION_TAKEN` | an exception waived a finding, at that finding's verdict at most |

An order is untold, its finding `INDETERMINATE`, when a proposal or a failure
has no time, or between two of one instant. A retry continues nothing, though
each denial of it counts toward `REPEATED_DENIAL`; an approved call, no
retry, belongs to the step it held. Every rule orders by the plane's times, never by place in
an export; a retry confirms only when one export holds both.

## The verdict

The weakest of what a finding rests on. Plane events in an unbroken chain can
make it `CONFIRMED`; an observation makes it `SUSPECTED`; a record in doubt,
`INDETERMINATE`. So are a silent source's observations. A request with
conflicting copies or a broken chain leaves no rule checked; an observation
with two contents, or a judged run its source doubts, until the log is rotated
([observations](observations.md#the-log)), leaves `STEP_OUTSIDE_PROCEDURE`
and `DENIED_ACTION_RETRIED_AROUND` not checked.
The step rules rest on something not seen:
`SUSPECTED` at most, `INDETERMINATE` while a `--source` is absent, never
heard or silent, and checked only on a closed run whose exports are whole.
Under `0.2` a finding confirms on its run's own events alone, save the
deadline and a retry by a descendant of the denied run; one that needs
another run's events is `SUSPECTED` at most.

## Output and exit status

After the run's line come, under `0.2`, its children mode and a `tree:` line
per run; a line per step, its requests apart from the observations no plane
call joins; per finding, with its run under `0.2` and the references it left
out; per rule; and `not checked: source <path> absent`, `<id> never heard`
or `<id> silent` for each `--source` not judged against.

| Exit | When |
| --- | --- |
| 0 | no finding, every rule checked or off, a plane event of the run read, every `--source` read and heard in time |
| 1 | otherwise |
| 2 | nothing printed: an input refused, or a log not opened or written (a cut write no reader takes) |

The log is opened, and `findings.jsonl` created, only once every input is
accepted. A failure after the write commits exits 2 and keeps it.

## The finding record and its log

`guardana.control.finding.v1alpha1`, outside the v1 promise. A
`FindingRecord` holds the tenant, project, procedure (id, version, digest),
escalation, references to plane events and observations and a v1
finding with its id, rule, severity, verdict and run. Its id is
`fnd-` and 32 hex digits, a function of the run, the procedure, the rule and
its version, and what it is about, so a rerun finds the same ids. The log,
`findings.jsonl`, is JSON Lines in an owner-only directory. The command writes only when it read an event
of the run, and ends its write with a `SuperviseReport`; a write without one
is never read.

A record is schema `0.2` exactly when it carries a member `0.1` lacks
([ADR-0047](../adr/0047-a-procedure-states-its-exceptions-resources-and-children.md)):

| Member | In `0.2` |
| --- | --- |
| `EventRef.run_id` | the run of each plane event cited |
| `FindingRecord.refs_left_out` | references cut past ten, doubtful ones kept; the verdict weighed all |
| `SuperviseReport.children` | the procedure's `children`, as `CHILDREN_MODE_INHERIT` or `_SEPARATE` |
| `SuperviseReport.run_tree` | each run's id and parent, the supervised run first, each other after its parent |
| `LogHeader` | a new log's first line: `log_id`, `log-` and 32 hex digits of 128 random bits |

A log with no header is read as it is; an empty one gains one when opened.
The reader refuses an unknown schema or a member its schema lacks.

## notify

`notify` hands each `alert` record, in log order, one line on its
standard input, to the program after `--`, without a shell, and kills its
process group at the timeout (30 s by default) and again once the program
exits. A delivery is keyed on the
finding id and verdict and marked in the state only after the program exits
0, so a crash delivers that record again: a receiver drops a key it has
seen. The state is an owner-only directory, locked while in use; `--init`
starts one and is refused over one. The next run retries a failed delivery,
and only a new state repeats a delivered one. Exit 0 when nothing
failed; 1 when a delivery failed, on an interrupt, or when the run stopped
after a program had run (a mark not on disk, a log
changed under it); 2, printing nothing, when the state or the log is refused
before any program ran.

## findings export

```
guardana-control findings export --findings <dir> [--after <cursor>] [--limit <n>]
    [--max-bytes <n>]
```

`findings export` writes the log as JSON Lines in the evidence export's
shape, format `guardana.control.findings-export` `0.1`, unstable as the
records are
([ADR-0048](../adr/0048-one-run-drawn-as-a-page-and-findings-exported-with-a-cursor.md)):
`header`, `finding_record` and `supervise_report` each carrying its log line,
`gap`, `duplicate` and `trailer`. Read as `notify` reads it, under no lock,
the log is exported to the last write a report closes; a write still open is
the trailer's `tail_bytes`, or a gap when no writer holds the log. A cursor
holds only in its own log, known by the header's `log_id` or else by its
first line; the trailer's `identity` says `log_id`, `content` or `none`. Exit
0, 1 for a whole export with a gap, 2 refused or cut short.
