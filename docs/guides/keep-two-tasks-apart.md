---
title: Keep two tasks apart
summary: Open a run per task in a runs directory, point a plane at it, and give each agent its token, so what one task took in never decides another's calls.
type: how-to
covers: [cmd/guardana-control/runs.go, cmd/guardana-gateway/runs.go, internal/runs/**, adapters/mcp/runs.go, internal/gatewayconfig/runs.go]
---

# Keep two tasks apart

## When to use this

A plane remembers what each run took in, so a `flow` rule can block a call
that carries untrusted data somewhere it should not go. Without a runs
directory a run is the listener's principal and agent: two tasks of one agent
share what they took in, and a restart, or a new stdio process, forgets it.
When your orchestrator knows that two tasks are separate, open a run for each.
Each task's flow state is then its own, kept on disk, and survives a restart
([ADR-0034](../adr/0034-a-run-the-operator-opens-has-an-identity-of-its-own.md)).
This is `experimental`; [status.md](../status.md) is the inventory.

## Prerequisites

- A plane you can run ([run-the-gateway.md](run-the-gateway.md)) and the
  `guardana-control` binary beside it, run as the same user.
- An orchestrator, or a person, who starts each task and can hand it a token:
  an MCP client that sends an extra HTTP header, or the command that starts a
  stdio plane.

## Steps

### 1. Make the runs directory

```
mkdir -m 700 /var/lib/guardana/runs
```

It must be yours and writable by nobody else, and apart from the spool, the
approvals directory, the hold journal and the pause file's directory. The
first `runs open` makes it a runs directory; a plane refuses it before that.

### 2. Open a run per task

```
guardana-control runs open --tenant acme --principal-type service \
  --principal agent-runner --agent orders-assistant --ttl 8h /var/lib/guardana/runs
```

The identity is your listener's: `tenant_id`, `listener.principal.type`,
`listener.principal.id` and `listener.agent.id`. The command prints `run_id`,
`root`, `expires_at` and `token`; the token is printed this once. A task that
spawns another opens the child with `--parent <run id>`, so the two share what
they take in; the child expires no later than its parent, and closing the
parent leaves it open ([reference/runs.md](../reference/runs.md)).

### 3. Point the plane at it

```yaml
runs:
  dir: /var/lib/guardana/runs
```

Every call then needs a run. Remove `flow.max_runs` if you set it: it bounds
the runs a plane keeps in memory, and this plane keeps none.

### 4. Hand each task its token

Over HTTP, configure the agent's MCP client to send the header on every
request:

```
Run-Token: <token>
```

Over stdio, write the token to a file only you can read, and start the plane
with it:

```
umask 077 && printf '%s\n' '<token>' > task-1.token
guardana-gateway run --config gateway.yaml --run-token-file task-1.token
```

A plane started again with the same token reaches the same state.

### 5. Close a run when its task ends

```
guardana-control runs close /var/lib/guardana/runs <run id>
```

Its token is refused from the next request on. `runs list` shows every run
and whether it is open, closed or expired.

## Verify

- `doctor`'s `runs` line is `ok` and says `opened in /var/lib/guardana/runs`.
- Over HTTP a request with no token, a closed run's or another agent's is
  answered `401`, and `/healthz` counts it under `runs.refused_at_request`;
  over stdio a token refused at start stops the plane, and one whose run is
  closed or expires while it serves is answered `-31102` and counted under
  `runs.refused_at_message`.
- After one task reads something untrusted, a call of another task to an
  untrusted destination is decided as before, and its `ACTION_PROPOSED`
  carries `flow.v1.root=` with its own root.

## Limits

- A token acts as its run until it expires or is closed; keep it as you keep a
  credential. A call already admitted when the run is closed still runs.
- Data two runs exchange outside `--parent`, such as two sibling tasks an
  orchestrator bridges, is not seen.
- `dev` and scenarios serve local runs only.

## Roll back

Remove `runs.dir` and restart. Runs are local again, one per principal and
agent, and start clean; the directory is left as it is.
