---
title: Scenario format
summary: Every member of an agent-scenario/v1alpha1 document, how scenario run holds a live plane to one, and what it exits with.
type: reference
covers: [internal/scenario/**, cmd/guardana-gateway/scenario*.go, cmd/guardana-gateway/sibling.go]
---

# Scenario format

A scenario is one JSON file of tool calls and operator actions, and for each
call the answer, the decision and the trail a live plane must show.
`guardana-gateway scenario run` holds a running plane to it. The reader is
`internal/scenario`; the decision behind the format is
[ADR-0022](../adr/0022-scenarios-are-data.md). Both are `experimental`.

## The document

The file name is the scenario's id and must match
`[a-z0-9][a-z0-9-]{0,63}.json`. The document is at most 1 MiB, nests at most
64 deep, and is strict JSON: a duplicate member, an unknown member, `null`
anywhere, bytes that are not UTF-8, an escaped lone surrogate and anything
after the document are refused. `kind` is checked before any other member,
wherever it stands. Any change to the format is a new `kind`.

| Member | Required | Holds |
| --- | --- | --- |
| `kind` | yes | `agent-scenario/v1alpha1`, exactly. |
| `about` | yes | 1 to 200 bytes, no control characters. |
| `plane` | yes | `mode`, one of the plane's modes; `bundle.id`; optionally `bundle.digest`, `sha256:` and 64 lower-case hex digits. |
| `run` | no | `fresh`, the default, or `continues`. |
| `steps` | yes | 1 to 256 steps, each an object holding exactly one of `call`, `approve`, `reject`, `pause`, `unpause`. |

At least one call step must expect an event: a scenario whose trails may all
be empty examines nothing. `n` in a step reference counts from zero and
always names an earlier step.

### `call`

| Member | Holds |
| --- | --- |
| `tool` | The tool's name, as the plane routes it. |
| `args` | An object, sent as written, numbers included. |
| `answer` | `kind`: `result`, `error`, `blocked` or `pending`; `codes`: the reason codes of a block, `["APPROVAL_PENDING"]` for a pending answer, `[]` otherwise. |
| `decided` | `"none"`, or `verdict` (`ALLOW`, `DENY`, ...), `codes` and `obligations`, each obligation `type`, `params` (an object) and `advisory`. |
| `trail` | `request`: `new`, or `step[n]` for the held request of the pending call step `n`; `kinds`: the event kinds that request's trail holds, without the `EVENT_KIND_` prefix. |

Every list compares exactly and in order, and holds at most 64 items. A code
must be in the reason registry, an obligation type in the catalogue, and a
kind named, when the file loads.

A string value in `args` may hold `${step[n].output}`, where `n` is an
earlier call step expected to answer `result`. At run time that answer must
hold exactly one text item of at most 64 KiB, or the step cannot run; nothing
is cut. Substitution is one pass, left to right, and the text put in is
never read again. A `${` that is not a well-formed reference is refused, so a
literal `${` cannot be sent, and a reference in a member name is refused.

### Operator steps

| Step | Members |
| --- | --- |
| `approve`, `reject` | `step`, the pending call step to answer, once; `approver`, an identifier of at most 128 bytes; `reason`, optional, at most 1024 bytes. |
| `pause` | `global: true`; or `provider`; or `provider` and `action` (`tool`, `prompt`, `resource`), with `name` for a tool. `reason` is optional, at most 474 bytes, which leaves room for the runner's marker. |
| `unpause` | `step`, an earlier pause step, once. |

These values reach `guardana-control`'s command line, so key text in any of
them is refused when the file loads.

## Running scenarios

```
guardana-gateway scenario run --config <file> --trail <file> [--control <file>] [--timeout <d>] <path>...
```

`--config` is the plane's own configuration, read with the environment as
`run` reads it. The listener, `/healthz`, the
approvals directory and the pause file come from it and nowhere else; the
listener must speak HTTP and `health.address` must be set. `--trail` is the
file the plane's collector writes. Paths run in the order given, a
directory's `*.json` files in name order, and every file is read before the
first one runs. `--timeout`, 10s by default, bounds each wait; a call may take the upstream's
call timeout on top of it.

Before its first step a scenario needs `/healthz` to answer 200 with the
mode and bundle it names, `"freshness":"confirmed"`, nothing paused and no
halt. Then the runner waits
for the spool to drain, notes the requests the trail file already holds, and
connects to the listener as an MCP client. It sends no run token, so a plane
with `runs.dir` refuses it.

For each call step the runner:

1. sends the arguments and reads the answer's kind only from the
   `guardana.control/answer` marker and whether it is a JSON-RPC error, and its
   codes, approval and ids only from the result's `_meta` or the error's
   data;
2. polls `/healthz` until the spool holds nothing unacknowledged, and
   requires the spool's quarantined records and the records the exporter
   reports dropped unchanged since the scenario began;
3. requires the plane to have admitted exactly one call per call step so far;
4. reads the trail file once, finds the trail the answer names, and compares
   every member. `new` is a request neither in the file before the scenario
   nor named by an earlier step; `step[n]` is step `n`'s request. An event
   on any other trail since the last read, one an earlier step judged
   included, differs on `trail.others`.

It also holds each trail to the plane: every event carries the plane's mode,
every `POLICY_DECIDED` the bundle digest `/healthz` reported, and, where the
trail records a decision, the answer's decision id is one of them. A pending
answer's approval id must be the one the trail's last `APPROVAL_REQUESTED`
names, or the step differs on `answer.approval_id` and no operator step
answers it. The first call's
`ACTION_PROPOSED` must carry `flow.v1.untrusted=false` and
`flow.v1.max_read=PUBLIC` unless `run` is `continues`. Where canon can hash
the arguments sent, the trail's first `ACTION_PROPOSED` must carry that hash,
which for `step[n]` is the held call's, or the step differs on `args`. Where
canon cannot, as for an integer past 2^53-1, the proposal must carry no hash,
or the step differs on `args`. The runner prints the principal and agent that first proposal names.

An operator step runs `guardana-control approvals approve|reject` or
`pause add|remove`: the binary named by `--control`, a bare name meaning the
file in the working directory, or the one beside `guardana-gateway`, never
one found on the search path, and only one that reports the same version.
Two builds that both report `dev` pass that check whatever tree they come
from. After a pause or an unpause the runner waits for two more completed
reads of the pause file and the state it wrote. The runner ends each pause
step's reason with a marker drawn for that add, `[scenario <random>]`; the
reader refuses a reason with no room for it under the pause file's bound. A
`pause add` that fails has its entry removed, found through `pause list` as
the one new entry with the step's scope and that marker. When no new entry
or more than one carries both, nothing is removed and the step names every
new entry, since any of them may be an operator's. A scenario ends at the
first step that differs or cannot run, and every pause entry it added is
removed either way, after an interrupt too.

## Output and exits

One line per step, `<id> step[<i>] <kind>: ok`, or one line per member that
differs, `<id> step[<i>].<member>: want <x>, got <y>`; then `<id> passed`,
`<id> failed` or `<id> could not run: <why>`.

| Exit | Means |
| --- | --- |
| 0 | No member of any scenario differed. |
| 1 | A member of some scenario differed. |
| 2 | None differed, and some scenario could not run: no scenario, a file refused, a precondition, an answer naming no trail, a barrier past its bound, another client, a `guardana-control` missing or of another version, a trail file that is not the plane's. A gate treats 2 as a failure. |

## Example

```json
{
  "kind": "agent-scenario/v1alpha1",
  "about": "An update is held, approved, and the retry runs on the held trail.",
  "plane": {"mode": "APPROVE", "bundle": {"id": "scenario-fixture"}},
  "steps": [
    {"call": {
      "tool": "update_order",
      "args": {"id": "ord-10"},
      "answer": {"kind": "pending", "codes": ["APPROVAL_PENDING"]},
      "decided": {"verdict": "ALLOW", "codes": ["RULE_ALLOW"], "obligations": []},
      "trail": {"request": "new", "kinds": ["ACTION_PROPOSED", "POLICY_DECIDED", "APPROVAL_REQUESTED"]}
    }},
    {"approve": {"step": 0, "approver": "alice"}},
    {"call": {
      "tool": "update_order",
      "args": {"id": "ord-10"},
      "answer": {"kind": "result", "codes": []},
      "decided": {"verdict": "ALLOW", "codes": ["RULE_ALLOW"], "obligations": []},
      "trail": {"request": "step[0]", "kinds": ["ACTION_PROPOSED", "POLICY_DECIDED",
        "APPROVAL_REQUESTED", "APPROVAL_DECIDED", "ACTION_STARTED", "ACTION_COMPLETED"]}
    }}
  ]
}
```

The runner needs to be the plane's only client, and a scenario must finish
within the plane's approval lifetime. It trusts the trail file to be the
plane's beyond the ids, the digest and the mode it checks.
