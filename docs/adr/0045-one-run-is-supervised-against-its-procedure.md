# ADR-0045: One run is supervised against its procedure

Status: accepted
Date: 2026-10-05

Builds on [ADR-0039](0039-many-channels-into-one-core.md), which decided the
vocabulary (procedures as versioned documents, a finding record around
finding v1, notifiers apart from reactions, a missing event as unknown), on
[ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md),
[ADR-0035](0035-a-versioned-evidence-export-and-a-bounded-query.md),
[ADR-0040](0040-observations-a-record-a-log-and-one-importer.md) and
[ADR-0044](0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md).
Amends ADR-0039 on where a notifier lives, and ADR-0040's "five guarded
trees", which now reads "the plane's trees".

Amended by [ADR-0046](0046-a-finding-stops-one-run-through-a-signed-route.md):
a finding can stop a run. `guardana-control react` turns a deterministic,
confirmed finding a signed route allows into a stop of its run, which a plane
with that route reads; no plane reads a finding itself.

Amended by [ADR-0047](0047-a-procedure-states-its-exceptions-resources-and-children.md):
a procedure of schema `0.2` states exceptions, resource bindings and how
children are judged; each rule has a version of its own; a run's children can
be supervised with it or on their own.

Amended in 0.11.0 (`REPEATED_DENIAL` version 2): when some of the denials the
rule would cite are in doubt, a broken chain or an event id read with two
contents, it cites only the clean ones and keeps its verdict when at least
`max_denials` are clean; a route naming version 1 is refused but as the
source of a carry, which keeps its stops ([ADR-0046](0046-a-finding-stops-one-run-through-a-signed-route.md)).

Amended by [ADR-0058](0058-a-copy-an-import-never-read-is-doubt-for-the-runs-it-claimed.md):
a run a source's import reports doubt leaves `STEP_OUTSIDE_PROCEDURE` and
`DENIED_ACTION_RETRIED_AROUND` not checked, and a finding citing an
observation of a doubted run is `INDETERMINATE`.

Amended by [ADR-0069](0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md),
which decides that `supervise` refuses, as an input error, a `--source` whose
kind names no run, such as an egress proxy's access log, and one with no kind.

## Context

A plane decides each call on its own. Whether a run as a whole kept to the
procedure it was meant to follow (the steps it took, their order, the steps it
skipped, what it did after a failure, how often it was denied, how long it
took) is a question about many calls, from more than one channel: the plane's
events and what the agent's runtime reports. Backlog B15 asks for it over one
run, with findings that cite their evidence and a local notifier, and with no
verdict changed.

Three things make it easy to get wrong. A run id an agent's runtime reports
is a claim. A missing event is unknown, not proof that a step was skipped. And
a finding id that moves when one more piece of evidence arrives sends the same
alert twice.

## Decision

**One opened run.** `guardana-control supervise --procedure <file> --runs <dir>
--run <run-id> --findings <dir>` reads that run's record (tenant, when it was opened and
closed). Only a run an operator opened is supervised; a plane's local run,
one per listener for the plane's whole life, is refused, and so are a run's
children. The command's inputs are evidence exports (`--evidence`) and source
descriptors with their observation logs (`--source`, `--log`). It reads no
clock and contacts no plane.

**What belongs to the run.** Plane events whose `run_id` and tenant are the
run's. Observations whose correlation basis is `claimed`, with that run id and
tenant and the project the run's plane events name. Everything else is counted
and left out. An observation joined to a plane event, as ADR-0044 joins them,
is that call, not a second one. An observation not joined to a plane call
never stands for a step: a required step only the runtime reports is still
skipped, and the report names the claim.

**The procedure.** A strict JSON document, `schema_version` `0.1`, every
member required: `procedure_id`, `version`, the steps (each an id, the tool
and upstream a plane would see, the names a runtime would report it under,
and whether it is required), the order (each step after the steps it lists),
the tools the run may also call, `max_denials` and `deadline_seconds` (each at
least 1, a rule turned off only by leaving its member out, and the report says
so), and per rule its severity and escalation. A cycle or an unknown step is
refused. The command records the document's digest, and a procedure id and
version it has seen under another digest is refused.

**The rules.** A step instance is one request of a tool call, never a prompt or
a resource read; its outcome is its terminal event, and a held request is open,
never failed.

| Rule | Fires when |
| --- | --- |
| `REPEATED_DENIAL` | one tool's calls are denied `max_denials` times; a denial is the policy's `DENY`, not a block of the plane's own (a pause, an unclassified tool, an approval spent or expired) |
| `STEP_OUTSIDE_PROCEDURE` | a tool that is neither a step nor allowed is called, or reported by a source and not joined to a plane call |
| `DEADLINE_EXCEEDED` | the run's events span more than `deadline_seconds` |
| `REQUIRED_STEP_SKIPPED` | a required step has no instance |
| `STEP_OUT_OF_ORDER` | a step's first instance comes before the steps it must follow |
| `CONTINUED_AFTER_FAILURE` | a different step follows a step whose instance failed |

A retry of the same step is never a finding, an approval is part of the step
it held, and a step out of order is not also a continuation.

**The verdict** is the weakest of what the finding rests on. Plane events in
an unbroken chain can confirm. Any observation caps it at `SUSPECTED`: its
correlation is claimed and its descriptor unsigned. A cited record in doubt (a
conflicting id, a broken chain, a source silent past its heartbeat as of the
run's last plane event) makes it `INDETERMINATE`. The three rules that rest on
something not seen (skipped, out of order, continued) are `SUSPECTED` at most,
and run only when the run is closed and every export is whole; otherwise the
report says "not checked" and why. A deadline across planes is `SUSPECTED`,
since their clocks differ.

**The finding record.** `guardana.control.finding.v1alpha1`, a package of its
own outside the v1 promise, ignored by `buf breaking` as the observation
package is: a `FindingRecord` holds the schema version, tenant, project,
procedure id, version and digest, the escalation (`inform` or `alert`), typed
references (a plane event by event id and request id, an observation by source
id and observation id) and a v1 `Finding` whose source is `DETERMINISTIC`,
whose verdict and severity are set, and whose `evidence_refs`, `request_id`,
`recommended_action` and `framework_mappings` are empty, since the typed
references say it once. A `SuperviseReport` ends each write of the command:
what was read and left out, each rule checked or not and why. A run of the
command that read no event of the run writes nothing and exits 1.

**The finding id** is `fnd-` and 32 hex digits of a length-prefixed SHA-256,
domain `finding-id:1`, over tenant, project, run, procedure id and version,
rule id and version, and the rule's anchor (the tool and upstream, the step,
the failed request, or the observation's name or id where an observation is
what the finding is about). A fifth denial, or an older file read later, keeps
the id. The log keys a record on its id and verdict, so a verdict that changes is
a new record.

**The findings log.** `internal/findinglog`: one JSON Lines file in an
owner-only directory under a lock, written as the observation log is, each
write closed by its `SuperviseReport`, a torn or unclosed tail never read as
written.

**The notifier.** `guardana-control notify --findings <dir> --state <dir>
[--timeout <d>] -- <program> [args]` hands each `alert` finding, in log
order, to the program on its standard input, one JSON line, without a shell,
killing its process group at the timeout. A delivery is keyed `<id>:<verdict>`
and marked in the state, synced, only after the program exits 0, so a crash
repeats at most the one record in flight: delivery is at least once, and a
receiver drops a key it has seen. The state is an owner-only directory with a
marker, a lock, an append-only list of delivered keys and the digest of the
log's first line; a state without its marker is refused unless `--init`,
which delivers everything again. A failure moves on to the next record, and
the command exits 1; the next run retries. The code lives in
`internal/notify`, not `adapters/`, which a plane's import rule covers.

**No verdict changed.** `internal/supervise` is a sixth guarded tree, pure as
the kernel is: what a finding rests on and its id are then a function of the
inputs alone. A test holds that the plane's binary, its five trees and
`adapters/mcp` reach none of supervise, the findings log, the finding package
or the notifier, with the control binary as its negative control. Nothing in
a plane reads a finding, and no finding stops anything here: a stop is B19's.

## Security / compatibility impact

The v1 contracts, the digest and the plane do not change. An evidence export
is read as the procedure is, refused when another account or a group can
write it: a confirmed finding rests on the export being the plane's, which
nothing but the file's owner and mode protects until evidence is signed. A
source the command was asked to read and could not, or that fell silent past
its heartbeat, is never a pass: the command exits 1 and names it. A finding grants
nothing and stops nothing. A source that reports a run id it does not belong
to can raise a `SUSPECTED` finding against that run, never a confirmed one;
another tenant's observation is left out. The notifier runs a program the
operator names, with the finding on its standard input and nothing else of
the plane's.

## Alternatives considered

- **Supervise a plane's local run.** It spans every task of a listener's life.
- **Bind observations by trace id.** No stronger than the claimed run id.
- **A whole export makes a finding confirmed.** A skipped step cites nothing,
  so it would be confirmed by nothing.
- **Any input not whole makes every finding indeterminate.** It would demote
  facts that are present and flood the log.
- **Finding records as Go-only JSON.** A notifier program in another language
  is the reader that needs a typed contract.
- **Generalise the observation log.** One failure domain for two records, and
  observation code within a notifier's reach.
- **References inside the finding id.** The id would move as evidence arrives.
- **The notifier in `adapters/`.** The plane's import rule treats that tree
  as the plane's.

## Consequences

An operator writes a procedure per task, opens a run for each task, exports
each plane's trail and the observations, and runs `supervise` and `notify`
when they want an answer; nothing runs on its own. A runtime that names tools
differently from the plane needs each step's reported names. Findings are as
complete as the inputs, and the report says what was not checked.

## Validation

- A local run id is refused; another tenant's observation and an
  observation without a claimed basis are left out; a claimed observation
  caps a finding at `SUSPECTED`.
- A run that keeps to its procedure gives no finding, and the report names
  each step's requests and every rule checked; a wrong run id is not a pass.
- A skipped step on an open run or with a filtered export is "not checked".
- A pause, a silent decision point and an expired approval are not denials;
  four denials fire at `max_denials` 4 and not at 5.
- A second run of the command gives the same ids; a fifth denial keeps the id;
  an edited procedure under the same version is refused.
- The notifier killed between the program's exit and the mark delivers that
  one record again; a second notifier is refused by the lock; a timeout or an
  exec failure is not marked.
- `buf breaking` passes a renumbered field in the finding package and fails one
  in v1; the layering rule covers six trees.
- The refund example, on a live plane with an opened run: exactly
  `REPEATED_DENIAL` confirmed and `STEP_OUTSIDE_PROCEDURE` suspected, and the
  second gone when the observation names another run.
