---
title: Attempt format
summary: Every member of an attempt manifest and an attempt report, how attempts run counts outcomes at the victim, and what it exits with.
type: reference
covers: [internal/attempts/**, cmd/guardana-gateway/attempts*.go, examples/vulnerable-mcp-agent/attempts/**]
---

# Attempt format

`guardana-gateway attempts run` runs a fixed set of scripted attempts against
the demo's victims and counts what each victim received. The manifest says
what runs; the report says what happened. The reader and the counting are
`internal/attempts`; the decision is
[ADR-0086](../adr/0086-controlled-attempts-are-counted-at-the-victim.md).
Both formats are `experimental`.

## The manifest

One JSON document of kind `attempt-manifest/v1alpha1`, read as strictly as a
[scenario](scenario-format.md): at most 256 KiB, at most 16 containers deep;
a repeated member, an unknown one, `null` anywhere, bytes that are not UTF-8,
an escaped lone surrogate and anything after the document are refused.
`kind` is judged before any other member, wherever it stands. An id is
`[a-z0-9][a-z0-9-]{0,63}`.

| Member | Holds |
| --- | --- |
| `kind` | `attempt-manifest/v1alpha1`. |
| `about` | 1 to 200 bytes, no control characters. |
| `selection` | How the attempts were chosen, 1 to 400 bytes. |
| `repetitions` | 1 to 20. |
| `model` | `no model`, the one value of this kind. |
| `demo` | The demo's configuration, as `dev` takes it. |
| `policy` | The policy document each plane signs at its start. |
| `planes` | 2 to 8 plane configurations; at least one `measured` and one `positive`. |
| `attempts` | 1 to 64 attempts. |
| `effects` | 1 to 64 effects, each named by some attack step. |
| `thresholds` | `attack_observed_max`, a whole number from 0 to 999999999; `legitimate_completed_min`, a share from 0 to 1 with at most four decimals. |

A plane configuration is `id`; `mode`, one of the plane's modes;
`decision_point`, `silent` for a loopback port nothing answers, as
`dev --decision-point=silent` makes, or `none`; and `role`. A `positive`
plane runs in `OBSERVE`, which runs the calls the other modes block or hold.

An attempt is `id`, `scenario`, an
[`agent-scenario/v1alpha1`](scenario-format.md) file, and `steps`: each step
of that scenario labelled exactly once, as `{"step": n, "label": ...}`.
`attack` names 1 to 8 `effects` it aims at, each a call of the tool the step
calls; `legitimate` is work the plane should let through; `operator` is an
approval, a pause or an unpause, which must be so labelled, or a call the
manifest counts apart from legitimate work, as for a pause scenario.

An effect is `id`, `server` and `call`, each 1 to 128 bytes, and `args`: 0
to 16 conditions, each `member`, a JSON pointer of at most 256 bytes, and
exactly one of `equals`, any JSON value, or `contains`, 1 to 1024 bytes the
member's string must hold. Objects compare whatever their member order;
numbers compare as written, so `1` does not equal `1.0`.

**Paths.** Every path is relative to the manifest's directory, written with
`/`, with no empty or `.` segment, no backslash or colon, and `..` only at
the start. The demo may climb at most one directory; every other path lies
under the manifest's directory or under the demo's. The rule is judged on the
path as written; a symbolic link is followed.

## A run

Before any plane starts, `attempts run` refuses a report path that exists, an
existing `--state`, a variable of the product's in its environment, a
manifest the reader refuses, a scenario its labels do not cover, a policy it
cannot sign, a demo configuration a plane could not run, and a
`guardana-control` beside it of another version. Then, for each repetition,
each plane configuration and each attempt, one at a time:

1. It makes `<state>/<n>-<attempt>-<plane>-<repetition>/` with a `journal`
   directory, sets `VICTIM_JOURNAL_DIR` to it, and starts a dev plane there
   with the plane's mode and decision point, its log in `plane.log`.
2. It requires `/healthz` to report that mode and nothing paused, and
   records its policy digest.
3. It sends every call step in order, whatever earlier answers were. A
   `${step[n].output}` whose step did not answer a result leaves the step
   not sent. Operator steps run through `guardana-control`; one that cannot
   run is not run, and later steps still run.
4. It stops the plane, which waits for each victim to exit, and reads
   `<server>.jsonl` of each server. A plane that stopped early, or did not
   stop cleanly, leaves every journal unknown.

## Outcomes

| Outcome | When |
| --- | --- |
| observed | A journal line of the effect's server and call meets every condition. |
| verified absent | On a measured plane, none does; every attack step aiming at it was sent and answered, and no operator's action before it failed to run; the journal is a regular, owner-only file with one name, every line parses and the last is whole; every line of that call is the exact line of a legitimate or operator step of the run; every positive plane observed the effect in every repetition; and no line a legitimate or operator step accounts for meets it, anywhere in the report. |
| absent, not sent | None does, and an attack step aiming at the effect was not sent. Counted apart. |
| unknown | Anything else: an attack sent without an answer, an absence on a positive plane. |

An exact line is the step's tool with the arguments sent, as JSON values.
A legitimate step is `completed` with a result and its exact line, `held`
with a pending answer, `blocked` with a blocked answer, and `unknown`
otherwise: a result without its line, a line without a result, an error, no
answer, not sent. Calls labelled operator are counted the same way, apart;
operator actions are counted as run or not run. The plane's agreement, its
answer against the scenario's, is counted apart and feeds nothing.

## The report

`attempt-report/v1alpha1`, JSON Lines, created new and owner-only, each line
synced before the next.

| Line | Members |
| --- | --- |
| `header` | `kind`, `started`, `platform`; `build`: `commit`, `modified`, `belongs_to_commit`, `go`; `manifest` and `corpus`, each file's `path` and `sha256`; `corpus_sha256`; `binaries`, the sha256 of this binary, `guardana-control` and each victim; `about`, `selection`, `model`, `repetitions`, `planes`, `state`. |
| `attempt` | `attempt`, `scenario`, `plane`, `repetition`, `started`, `not_run`, `policy_digest`, `unfinished`, why the clean-up after the last step failed, which counts as unknown; `steps`, each `sent` or `not_sent`, `answer` or `answer_unknown`, `agreement`, `outcome` and `why`, or for an action `ran` or `not_run`; `effects`, each `at_victim`, `observed`, `absent`, `absent, not sent` or `unknown`, and `why`. |
| `summary` | `complete`, `incomplete`, `exit`, `belongs_to_commit`, `runs`, `policy_digests`, `binaries_after`; `planes`, each with its `effects`, `legitimate`, `operator_calls`, `operator_actions` and `agreement` counts over their own denominators; `attack_observed_max` and `legitimate_completed_min` per measured plane; `thresholds_met`; `unknown`, `absent_not_sent`, `unknown_causes`; `positive_control_failed`, `negative_control_failed`; `scope`. |

The corpus digest is the sha256 of one `<path> <sha256>` line per file, in
byte order of the paths. A build that records no commit, or a modified
tree, belongs to no commit, and the command says so. A binary that changed,
more than one policy digest or an interrupt makes the run incomplete. A file
without its summary line is incomplete.

`scope` names the tools the demo declares and those a sent step exercised,
the planes, the sources (the victim journal only), the channels nobody
observed, the time window, the missing inputs (each run not started, journal
not judged, step not sent, operator action that did not run and failed
clean-up), the dev wiring's limits, the
model, and what was not measured: pause and stops have no positive control,
and no broken copy of the plane's code is run.

## Exits

| Exit | Means |
| --- | --- |
| 0 | Complete, every threshold met on every measured plane, nothing unknown or absent and not sent. |
| 1 | Complete, and a threshold missed or something unknown or absent and not sent. |
| 2 | A usage error, a refused manifest or input, or a run that could not complete. |
