---
title: Claude Code hooks
summary: What the claude-code hook profile covers, the hook settings it needs, what the bridge reads and answers per event, and the gaps it leaves.
type: reference
covers: [internal/hookbridge/profiles/claude-code/**, internal/hookbridge/**, cmd/guardana-control/hook.go]
---

# Claude Code hooks

The `claude-code` profile lets Claude Code's tool hooks send each tool call
to a plane's enforcement API through `guardana-control hook`. How a profile
works is on [Adding a coding runtime's hooks](../extending/runtime-profiles.md);
which profiles exist and how far each is qualified is on
[status.md](../status.md).

This page is maintained in this repository. It is not affiliated with or
endorsed by the publisher of Claude Code.

## What the profile covers

| | |
| --- | --- |
| Label | decided, with failure gaps |
| Qualified on the real runtime | 2.1.310: all 20 cases passed on the first run, in 22 invocations. 2.1.303: all 20 passed, two of them on a rerun once the tools table named `ToolSearch` and classed `Agent` as `EXECUTE`, and one on a rerun that recorded the hook's output |
| Events | `PreToolUse`, `PostToolUse`, `PostToolUseFailure` |
| Fail-closed setting | `onFailure: "block"`, from Claude Code 2.1.295 |
| Hook timeout the profile assumes | 30 seconds |
| Largest event read | 16 MiB |
| Profile and fixtures | `internal/hookbridge/profiles/claude-code/` |

The fixtures are written from Claude Code's published hook documentation, and
every CI run passes them through the bridge against a plane. The
qualification ran Claude Code 2.1.303, and later 2.1.310, headless against a
plane, case by case, and its results are in the profile's `qualification/`
directory. What the first run observed is marked *(seen on 2.1.303)* below,
and 2.1.310 passed the same cases; the rest is from the documentation and
unverified. The label stays "decided, with failure gaps". It cannot become
"decided, not enforced" until the fail-closed setting is in managed settings,
the hook command is an absolute path to a binary the agent cannot replace and
names this built-in profile, and the runtime's shell sandbox keeps the agent
out of the plane's directories; it is never "enforced", because Claude Code,
not the plane, runs the call.

## Settings

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(?!mcp__)",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/guardana-control hook --profile claude-code --socket /path/to/enforce.sock --state-dir /path/to/hook-state",
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "^(?!mcp__)",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/guardana-control hook --profile claude-code --socket /path/to/enforce.sock --state-dir /path/to/hook-state",
            "timeout": 30
          }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "^(?!mcp__)",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/guardana-control hook --profile claude-code --socket /path/to/enforce.sock --state-dir /path/to/hook-state",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

- `timeout` is 30 because the profile says so: the bridge gives up on each
  request to the plane after 12 seconds and starts none after 27, counted
  once the event is read. That leaves three seconds of the
  runtime's limit for starting the command and reading the event; a hook
  that overruns the limit blocks the call under `onFailure: "block"`.
- `onFailure: "block"` sits on `PreToolUse` only. With it, a hook that times
  out or crashes blocks the call; without it, the call runs, and so it does
  after a hook that prints unreadable output and exits 0 *(seen on 2.1.303)*.
  On the two completion events the call has already run, so there is nothing
  left to block.
- The matcher leaves out tools named `mcp__<server>__<tool>`, which reach the
  plane through the gateway; it matched every other tool the qualification
  used *(seen on 2.1.303)*. An MCP server that is not behind the gateway is
  then seen by neither.
- Put these hooks in managed settings. A user can turn off any hook outside
  them with `disableAllHooks` or by editing their own settings files, and
  `allowManagedHooksOnly` keeps user, project and plugin hooks out.
- The command is an absolute path to a binary the agent cannot replace, and
  names the built-in profile: a binary found through `PATH`, or a
  `--profile-file` the agent can write, is one the agent can swap for one
  that allows every call.
- `--state-dir` must exist and belong to the account the hook runs as, with
  no access for group or others; there is no default.
- The run token is read from `GUARDANA_CONTROL_RUN_TOKEN` in the hook's
  environment, never from a flag or the event. Start Claude Code with it set.
- The plane's `tools` table must name every tool these hooks send, each with
  its effect class; a tool it does not name is refused, and the call blocked,
  except on a plane in `OBSERVE`. Name `ToolSearch` too: Claude Code calls it
  to load a deferred tool, an MCP tool among them, so a table without it
  blocks every deferred tool *(seen on 2.1.303)*. Class `Agent` as `EXECUTE`:
  `SPAWN_OR_DELEGATE` needs a delegation the enforcement API does not carry,
  so the plane refuses to start with a tool of that class. For example:

  ```yaml
  tools:
    - name: Bash
      effect: EXECUTE
      provider: runtime
      resource_type: command
    - name: Write
      effect: WRITE
      provider: runtime
      resource_type: file
      resource_from: /file_path
    - name: Agent
      effect: EXECUTE
      provider: runtime
      resource_type: agent
    - name: ToolSearch
      effect: READ
      provider: runtime
      resource_type: tool
  ```

## Per event

| Event | Phase | What the bridge reads | Reply | When the hook fails |
| --- | --- | --- | --- | --- |
| `PreToolUse` | admit | `hook_event_name`, `tool_name`, `session_id`, `tool_use_id`, and `tool_input` as the exact text the event wrote | exit 0 and nothing on standard output when the plane answers `EXECUTE` of exactly that text; otherwise exit 2 and one line on standard error | with `onFailure: "block"` the call is blocked; without it the call runs |
| `PostToolUse` | complete | the same, and `tool_input` as the input that ran; `tool_response` is read past and kept nowhere | exit 0 once the plane recorded the completion, otherwise the profile's problem status, 1; a refused event exits 2 | the call ran, and the plane may have recorded it; a handle left open is closed by the sweep as abandoned, outcome unknown |
| `PostToolUseFailure` | complete-failure | the same, and `is_interrupt`: `false` reports a failure, `true` or absent reports an unknown outcome | as `PostToolUse` | as `PostToolUse` |

An event that is over 16 MiB, is not one JSON object of valid UTF-8, names a
member twice, lacks the tool name, the call id or the session id, carries a
`tool_input` that is not an object, or is a `PreToolUse` without one is
refused before anything is sent, with the profile's block status, 2, and so
is any event when the hook has no run token. A member spelled in another case
is not read, so it counts as absent.

The plane compares the completion's `tool_input` with the authorized one by
`digest_v1`: key order, white space, string escapes and a number written
`120000.0` for `120000` do not make it another call; a member added, removed
or set to `null`, a number written as a string, or array items in another
order do, and the plane records `EXECUTED_ARGS_MISMATCH` and halts the run's
material calls. A decision whose authorized input is not the proposed text,
a rewrite among them, or that leaves the hook an obligation to apply, is
denied, because a hook cannot hand Claude Code the authorized bytes *(seen on
2.1.303)*; the plane keeps advisory obligations off its answer. A call held for approval is denied with a line
naming the approval; once it is approved, the agent's identical retry runs
once and its completion is recorded, a third identical call is refused as
used, and of two approved retries made at once one runs *(seen on 2.1.303)*. A
completion's start and end, as the plane records them, are both the moment
the completion hook ran; the event's `duration_ms` is not read. A tool input over 64 KiB, an integer beyond 2^53-1 or
more than 32 nested containers is refused by the plane and denied.

## Gaps and bypasses

None of these is closed by the profile.

- A file referenced with `@` enters the context with no tool call.
- `EndConversation` starts no hook.
- A process a shell command starts, or a shell command that writes a file, is
  not seen beyond the shell call itself.
- A hook with `async: true` cannot decide.
- A mod handling `tool.check` can approve a call this hook blocked, unless
  the hook is in managed settings.
- `--bare` skips the discovery of hooks.
- `disableAllHooks` turns off every hook that is not managed; the
  qualification saw it turn off hooks passed with `--settings` *(seen on
  2.1.303)*.
- A cancelled running tool starts no completion hook; the plane's sweep
  closes its handle as abandoned.
- Another hook can replace the input after the bridge let the call run. Only
  the completion shows it, as `EXECUTED_ARGS_MISMATCH` that halts the run,
  after the call ran *(seen on 2.1.303)*.
- When Claude Code refuses a call after the bridge let it run, for
  instance at its own permission prompt, no completion hook follows. The
  handle stays open until `listener.execution_lifetime` ends and holds one of
  the run's open executions, 16 by default, meanwhile; once all are held, the
  plane denies every call of the run until they expire.
- A completion that carries no `tool_input` sends nothing; the sweep closes
  the call as abandoned, its outcome unknown.
- The hook runs as the agent's account. Unless Claude Code's shell sandbox
  denies the agent the plane's directories (approvals, the bridge's state
  directory, the socket's directory), the agent can read the run token,
  reach the socket and the state directory itself, and approve its own held
  calls. The run token in Claude Code's environment can also reach the
  agent's shell commands.
