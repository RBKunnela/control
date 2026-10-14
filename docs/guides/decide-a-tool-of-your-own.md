---
title: Decide a tool of your own
summary: Serve the enforcement API, classify your tools by name, and have a client ask before each call and report how it ended, under one policy and trail.
type: how-to
covers: [cmd/guardana-gateway/enforce.go, adapters/enforce/**, internal/enforceclient/**, internal/gatewayconfig/enforce.go, clients/python/**]
---

# Decide a tool of your own

## When to use this

Your agent calls a tool that is not an MCP server: a function in its
framework, a script, a service you wrote. A plane serving the enforcement API
lets that tool ask before it acts and report what it did, so one policy, one
approval store and one evidence trail cover it as they cover an MCP call
([ADR-0051](../adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)).

The plane decides; your client enforces. Nothing the plane holds proves the
client obeyed, so these tools are `decided, not enforced` in every mode. This
is `experimental`; [status.md](../status.md) is the inventory.

## Prerequisites

- A plane you can run, with its signed policy
  ([run-the-gateway.md](run-the-gateway.md)).
- A runs directory and one opened run per task
  ([keep-two-tasks-apart.md](keep-two-tasks-apart.md)): every request
  presents a run token.
- A client that keeps the client rules: the Python client below, the Go
  reference in `internal/enforceclient`, or one in another language that
  passes the cases in [testdata/enforce/](../../testdata/enforce/README.md).

## Steps

### 1. Classify each tool

```yaml
listener:
  kind: enforce_api
  socket: /run/guardana/enforce.sock
  execution_lifetime: 2m
  principal:
    id: agent-runner
  agent:
    id: refund-worker
runs:
  dir: /var/lib/guardana/runs
tools:
  - name: refund
    effect: TRANSACT
    provider: payments
    resource_type: order
    resource_from: /order_id
```

The socket's directory must be yours with no permission for group or others,
and its path at most 103 bytes. `execution_lifetime` is how long a client may
take between an `EXECUTE` and its report. `listener.max_open_per_run`, 16 by
default, bounds the executions one run holds open and stays below
`approvals.max_open`. The table takes the keys an MCP override takes but the
fingerprint: nothing binds a name to what the tool does. A tool it does not
name is blocked with `ACTION_UNCLASSIFIED`
([reference/configuration.md](../reference/configuration.md)).

### 2. Check and start

```
guardana-gateway doctor --config gateway.yaml
guardana-gateway run --config gateway.yaml
```

`doctor` prints each tool and says the plane calls no upstream. `run` prints
`listening for tools on` and the socket.

### 3. Ask before the tool acts

The arguments travel as base64, so no JSON library reorders them:

```
curl --unix-socket /run/guardana/enforce.sock -H "Run-Token: $TOKEN" \
  -d '{"tool":"refund","arguments":"eyJvcmRlcl9pZCI6Im9yZC0xIn0="}' \
  http://plane/enforce/v1alpha1/admit
```

The answer's `outcome` is one of three:

- `OUTCOME_EXECUTE`: run the tool with exactly `execution.authorizedArguments`,
  which differ from yours when a rewriting obligation applied. Keep
  `execution.handle`.
- `OUTCOME_BLOCK`: send nothing. Read any outcome you do not know the same way.
- `OUTCOME_PENDING`: an approver decides with
  `guardana-control approvals approve`; send the same tool and arguments again
  after `pending.retryAfter`.

An obligation you do not know is a reason to abort, never to run.

### 4. Report how it ended

Send `complete` to `/enforce/v1alpha1/complete` with the handle, the bytes you
sent and a status: success, failure, timeout, cancelled or unknown. When you
cannot tell whether the effect happened, say timeout or unknown; the trail
keeps it uncertain. Send `abort` only when nothing left: the bytes differ
(`ABORT_CAUSE_ARGUMENTS_DIFFER`), an obligation you cannot apply
(`ABORT_CAUSE_OBLIGATION`), or you gave
up before sending (`ABORT_CAUSE_NOT_SENT`). Never send an action again after a
handle was issued; a new attempt is a new admit, decided anew.

The fields, error codes and the strict JSON mapping are in
[contracts.md](../contracts.md#the-enforcement-api).

### 5. Or let the Python client do steps 3 and 4

`guardana_control.enforce` is `experimental` and has no dependencies; it needs
Python 3.11 or later. Use the client of your plane's release.

No release carries it yet. From a checkout of the repository:

```
pip install ./clients/python
```

```python
from guardana_control.enforce import CallBlocked, CallPending, Client, Result, Status

client = Client(socket="/run/guardana/enforce.sock", token=token, timeout=5.0)

def refund(authorized: bytes) -> Result:
    receipt = payments.refund(authorized)
    return Result(Status.SUCCESS, value=receipt)

try:
    answer = client.call("refund", b'{"order_id":"ord-1"}', refund)
except CallBlocked:
    ...  # the tool did not run
except CallPending as held:
    ...  # ask again after held.answer.held.retry_after
```

`call` runs your function only with the authorized bytes and sends one
`complete` or one `abort`. A function that raises is reported `UNKNOWN`; raise
`NotSent` only when the bytes never left. `call` returns when the tool ran
and the record landed. Everything else raises. Only an `EnforceError` says,
in `answer.ran`, whether the tool was entered; any other exception is the
tool's own, raised again after its run was reported `UNKNOWN`, or a
`TypeError` or `ValueError` for a call misused before anything was sent. When
your function makes a call of its own and lets that call's exception out,
`call` raises a `ToolRaised` from it, whose answer is the outer call's.

## Verify

- `/healthz` has an `enforce` object: `open_handles`, the answers by outcome,
  `abandoned` and the refusals by error code; `runs.refused_at_request` counts
  refused tokens by cause.
- In the trail a blocked call ends `ACTION_BLOCKED` with no `ACTION_STARTED`,
  and a handle nobody completed ends `ACTION_FAILED` with
  `EXECUTION_ABANDONED`.
- `guardana-control coverage` with an `enforce_tool` path in the inventory
  prints it `decided, not enforced`, naming the cooperating client
  ([reference/coverage.md](../reference/coverage.md)).

## Limits

- It is not a security boundary. A client can ignore `BLOCK`, send other bytes
  and report the authorized ones; the plane records what it is told.
- Bytes a client reports that differ from the authorized ones halt that run's
  material calls until restart, and no other run's.
- The socket checks read mode bits, not macOS access control lists, and do not
  cover the directories above the socket's.
- A stop closes every open execution as unknown; a crash leaves them at
  `ACTION_STARTED`.
- An admit answer lost on the way can spend an approval: the retry is held
  anew.

## Roll back

Stop the plane: it closes every open execution before its spool drains. Then
point the listener back at an MCP kind, or remove the plane.
