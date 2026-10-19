---
title: Adding a coding runtime's hooks
summary: The profile a coding runtime's hook protocol is described by, what the hook bridge does with it, and what a profile needs before its page may claim anything.
type: extending
covers: [internal/hookbridge/**, cmd/guardana-control/hook.go]
stability: development
---

# Adding a coding runtime's hooks

A coding runtime that starts a command for each tool event can send its tool
calls to a plane through `guardana-control hook`. The command is the same for
every runtime; what differs is a profile, data the bridge reads. The decision
behind this is
[ADR-0056](../adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md);
[status.md](../status.md) says which profiles exist and how far each is
qualified.

## What the bridge does

For an event the profile maps to an admit, the bridge asks the plane's
enforcement API about the call, with the tool's input exactly as the runtime
wrote it. Only an `EXECUTE` of exactly those bytes lets the call run, and the
bridge then exits 0 and prints nothing. Anything else exits with the
profile's block status and one line on standard error, or with 2 when the
flags are wrong or the profile cannot be read. The bridge never
writes a reply that allows, asks, defers or changes a call, so the plane's
decision can only take a call away. A decision that wants the arguments
rewritten, or carries an obligation, is denied: a hook cannot hand the
runtime the authorized bytes.

Between the admit and the completion the bridge keeps the execution's handle
in a directory only its account may enter. For an event the profile maps to
a completion, it takes that handle once and reports the input the runtime
says it ran. The plane compares that input with the authorized one as a
value, by `digest_v1`, and records a difference as `EXECUTED_ARGS_MISMATCH`.

The run token comes from `GUARDANA_CONTROL_RUN_TOKEN` in the hook's
environment, never from the event. The plane's `tools` table must name every
tool the runtime sends; a tool it does not name is refused, and the call
blocked, except on a plane in `OBSERVE`.

## The profile

A profile is one JSON object of kind `hook-profile/v1alpha1`, read strictly:
an unknown member or another version is refused.

| Member | What it says |
| --- | --- |
| `id` | the profile's name, as `--profile` takes it |
| `events` | each event name the runtime sends, and its phase: `admit`, `complete` or `complete-failure` |
| `members` | the top-level members of an event that hold the event name, the tool, its input, the call id, the session id and the interrupt flag |
| `reply` | the strategy, `exit-code` today, with the status that blocks a call and the one that reports a problem |
| `hook_timeout_seconds` | the timeout the runtime is configured to give the hook; the bridge's own deadlines fit inside it |
| `max_event_bytes` | the largest event the bridge reads; a completion's tool response counts |
| `claims` | the runtime and versions tested, the setting that blocks a call on a failed hook, how a pending approval is answered, the tools seen and the known bypasses, each with the ids of the cases that back it |

A profile holds no script. When a runtime needs something data cannot say,
the bridge gets a new strategy, under review, and every profile can use it.

## Adding a runtime

1. Write the profile under `internal/hookbridge/profiles/<id>/`, and record
   the runtime's events as fixtures beside it, with paths and ids scrubbed.
2. Pass the fixture suite, which runs in every CI without the runtime. The
   profile's `cases.json` states, apart from the profile, the statuses the
   runtime blocks and reports a problem on, the hook timeout, the largest
   event, and what each fixture must come to: a refusal, or an admit's
   outcome, the bytes it proposed and the trail it leaves, or a completion's
   closing record. The command's own tests check its exit statuses and
   standard output against the profile's.
3. Qualify the profile against the runtime at a pinned version: a call
   blocked with no effect on a recorder the bridge cannot touch, a pending
   approval resumed, a wanted rewrite denied, the input that ran compared,
   the plane down, the hook timing out, crashing and printing garbage, hooks
   disabled, two concurrent resumes, and two mutant bridges caught, one that
   allows every call and one that reports the authorized input as the one
   that ran. The results go in the profile's `qualification/` directory, in
   files named for the runtime version, each with the date and the commit it
   ran at.
4. Write the profile's page under `docs/reference/`, with the tested
   versions, the settings, a table per event, the bypasses and a line saying
   the page is maintained here and not by the runtime's publisher.

The runtime's name appears in its profile's files and page, and in the path
of a link to that page; nowhere else in the tree.

## What a page may claim

Nothing a hook decides is `enforced`: the runtime, not the plane, runs the
call. A profile is **decided, not enforced** only when the runtime blocks a
call whose hook fails, in settings the user cannot override, the hook command
is an absolute path to a binary the agent cannot replace and names a built-in
profile, and the runtime's shell sandbox keeps the agent out of the plane's
directories, since the hook runs as the agent's account. Otherwise it is
**decided, with failure gaps**, and the page names each gap. The page states
a claim no case backs as unverified.
