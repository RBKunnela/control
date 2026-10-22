---
title: Run the gateway
summary: Set up a plane's policy files, start the MCP gateway in OBSERVE, keep its policy confirmed, read its health, classify the tools it sees, and move it to ENFORCE.
type: how-to
covers: [cmd/guardana-gateway/**, adapters/mcp/**, internal/gateway/**, internal/spool/**, adapters/otel/**, internal/policywatch/**]
---

# Run the gateway

## When to use this

You have an agent that speaks the Model Context Protocol (MCP) to servers,
and you want every call decided from policy, enforced before the
server sees it, and recorded. Start in `OBSERVE`, which records every call and
blocks only for the plane's own causes, and move to `ENFORCE` once the tools
are classified.

The gateway is `experimental`; [status.md](../status.md) says what runs and what
does not. Nothing here is a security boundary yet.

## Prerequisites

- `guardana-gateway` from a release archive, or built: `go build ./cmd/guardana-gateway`.
- `guardana-control` where the policy is signed and on the plane's host, and a
  policy document ([write-and-test-a-policy.md](write-and-test-a-policy.md)).
- An OpenTelemetry collector that takes OTLP/HTTP logs in JSON: evidence
  nobody drains fills the spool, and material calls then block.
- To hold calls for a person: two directories the gateway does not create,
  for the approval records and the hold journal, neither the spool's nor
  inside the other.

## Steps

### 1. Make the policy's files

Where the keys live, never the plane's host, make two key pairs, sign the
document, and vouch that the bundle is current:

```
guardana-control policy keygen --out keys          # the bundle key
guardana-control policy keygen --out freshness     # the freshness key, never the bundle's
guardana-control policy sign --key keys/signing.key --out orders.bundle policy.json
guardana-control policy state init --kind signer --bundle-id orders-policy signer-floors
guardana-control policy renew --key freshness/signing.key --bundle orders.bundle \
    --bundle-public-key keys/signing.pub --floor signer-floors --out orders.statement
```

Copy `orders.bundle` and `orders.statement` to the plane's host, beside the
configuration. There, as the plane's user, make the spool and the floor
directory, which keeps the highest serial the plane accepted:

```
mkdir -m 700 spool
guardana-control policy state init --kind plane --bundle-id orders-policy floors
```

`--bundle-id` is the document's `id`. Keep `floors` on a disk that outlives
the plane: a floor made anew takes any older bundle.

### 2. Write a configuration

Every path key resolves against its directory; upstream `args` pass as
written. Every key has an environment variable under `GUARDANA_CONTROL_`, the
key in capitals with underscores for dots, which wins over the file. An unknown key is refused.
[configuration.md](../reference/configuration.md) lists every key. The plane
refuses the file if it, or a directory or link above it, belongs to an
account but its own or root, or another account may write it.

```yaml
mode: OBSERVE
project_id: orders
tenant_id: acme
environment: dev

listener:
  kind: stateless_http          # 2026-07-28; stateful_http serves 2025-11-25
  address: 127.0.0.1:8080
  principal:
    id: agent-runner            # who the calls are made by; see the note below
  agent:
    id: orders-assistant

policy:
  bundle_id: orders-policy      # the plane serves this bundle and no other
  bundle_file: orders.bundle
  key_id: ed25519-<16 hex digits>   # the two lines keygen printed for keys
  public_key: <44 characters of base64>
  statement_file: orders.statement
  state_dir: floors
  freshness_key_id: ed25519-<16 hex digits>   # the two lines keygen printed for freshness
  freshness_public_key: <44 characters of base64>
  poll_interval: 30s            # how often both files are read again

evidence:
  dir: spool

export:
  endpoint: http://127.0.0.1:4318/v1/logs
  allow_plaintext: true         # a plaintext collector is a loopback one, and you say so

upstreams:
  - name: orders
    endpoint: http://127.0.0.1:9000/mcp   # a redirect it answers is not followed; the call fails
  # A server the plane starts gets PATH, HOME, LANG, LC_ALL, TMPDIR and USER
  # of the plane's environment and the variables its env list names, nothing
  # else; a name under GUARDANA_CONTROL_ is refused.
  # - name: files
  #   command: /usr/local/bin/files-mcp
  #   env:
  #     - FILES_ROOT
```

The listener in this build authenticates nobody, so every request on it is
made by the principal configured here ([status.md](../status.md)).

A statement confirms its bundle from its `issuedAt` for the smaller of
`policy.max_stale` and the document's `maxStaleSeconds`. Without one, only
the floor's own bundle, or any while the floor has no serial, starts, with every
call `POLICY_STALE`: outside `OBSERVE` a material call is blocked, and a read
runs only under `policy.fail_open_read`. Rerun `renew` and copy the statement
more often than that budget less twice the poll interval.

### 3. Check the configuration before serving

```
guardana-gateway doctor --config gateway.yaml
```

`doctor` prints every key and its source, credentials excepted, then one
line per check, stopping at the first it cannot make. The `policy` line
fails for a statement missing, expired, dated ahead or naming another bundle,
or a bundle below its floor, which it never raises; like `run`'s first
line, it names `policy.fail_open_read`. An unclassified tool is
printed with its fingerprint for step 5. `doctor` locks the spool, cuts a
torn tail and writes a probe file.

### 4. Run in OBSERVE

```
guardana-gateway run --config gateway.yaml
```

Point the agent at `http://127.0.0.1:8080`, not the server. In `OBSERVE`
calls run as proposed, showing which tools exist.

### 5. Classify the tools

A call to a tool the manifest does not classify is blocked with
`ACTION_UNCLASSIFIED` in every mode but `OBSERVE`, so classify each one the
agent needs. Take the fingerprint from `doctor` and add an override:

```yaml
overrides:
  - upstream: orders
    tool: read_order
    fingerprint: <the fingerprint doctor printed>
    effect: READ                # READ, WRITE, DELETE, EXECUTE, COMMUNICATE, TRANSACT, IDENTITY_OR_ACCESS, CONFIGURE, SPAWN_OR_DELEGATE
    resource_type: order
    resource_from: /id          # where in the arguments the resource id sits
```

The fingerprint covers the whole definition: a tool whose description or
schema changes is unclassified again until you look at it.

### 6. Read the health

```
curl -s http://127.0.0.1:8081/healthz | jq
```

`policy.freshness` is `confirmed`, `unconfirmed` or `expired`, beside its
expiry and the poll counts. A plane whose policy is not
confirmed answers `"status":"degraded"` with `200`; one that takes no
material call, or whose pause state is unknown, answers `503`.

### 7. Move to ENFORCE

Run `doctor` again with `GUARDANA_CONTROL_MODE=ENFORCE`: outside `OBSERVE` an
unclassified tool is not a pass, which shows whether the overrides are
complete. Then change the mode and restart.

| Mode | What the plane does with the kernel's decision |
| --- | --- |
| `OBSERVE` | Records; executes every recordable call one upstream lists, unclassified included, unless one of the plane's own causes blocks it ([enforcement modes](../concepts/enforcement-modes.md)); applies no obligation |
| `APPROVE` | Enforces, and holds an allowed material call for an approval. It needs `approvals.provider: file`: nothing outside the process answers a hold kept in memory |
| `ENFORCE` | Enforces the decision: blocks a `DENY` and an `INDETERMINATE` save a fail-open read, applies the obligations, holds what needs an approval |
| `LOCKDOWN` | Blocks every material call whatever the policy said, recording a decision; enforces a read with fail-open reads off |
| `SHADOW`, `WARN` | Refused at start: declared in the contract, not built |

### 8. Let a person answer a held call

```yaml
approvals:
  provider: file
  dir: /var/lib/guardana/approvals
  hold_journal_dir: /var/lib/guardana/holds
```

An approver answers with the approval commands
([reference/cli.md](../reference/cli.md)). Write access to `approvals.dir` is
the approval authority, and `--approver-id` is a claim, never authenticated. A
hold lost to a restart never runs, and the next start closes its trail from
the journal
([concepts/approvals-and-the-held-call.md](../concepts/approvals-and-the-held-call.md)).

### 9. Set the evidence rules on purpose

| Key | What it costs |
| --- | --- |
| `evidence.max_bytes` | The bytes the spool may hold, its quarantine and the room kept for closing records included. Reached, a material call is blocked before its effect, and an oversized closing record fails after it |
| `evidence.fsync: interval` | A power loss costs the records since the last sync, every `evidence.fsync_interval`, a duration such as `5s` |
| `evidence.on_unwritable: allow_reads` | A read whose trail the spool will not take runs unrecorded and counted, unless it retries a held call. A material call never does |
| `policy.fail_open_read: true` | A read undecided only because the policy is unavailable runs if the rules would allow it and, at hand-out, its bundle is still installed and the clock trusted. Off by default, and forced off under `LOCKDOWN` |

### 10. Pause a tool

As the plane's user, before setting `pause.file` and restarting:

```
mkdir -m 700 /srv/pause
guardana-control pause init /srv/pause/pause.json
```

```yaml
pause:
  file: /srv/pause/pause.json
```

```
guardana-control pause add --action tool --provider orders --name refund /srv/pause/pause.json
```

`refund` is blocked with `PAUSED` until `pause remove`
([more](../concepts/enforcement-modes.md#pausing-calls)).

## Verify

- `doctor` prints `ok policy` and `ok upstreams ... 0 unclassified` in the
  mode you will run.
- A denied call comes back to the agent as a tool result with `isError: true`
  and its `reason_codes`, and the upstream never sees it.
- `/healthz` reports `"freshness":"confirmed"`, `"halted": false` and a spool
  depth that falls as the collector acknowledges records.

## When the plane halts

`"halted": true` and `503` mean the plane takes no material call. The `halt`
object says which rule stopped it:

- `executed_args_mismatch`: something sent bytes that were not the authorized
  ones. It stands until a restart. Read the trail's
  `ACTION_FAILED` record before restarting; it names the digest of what was
  sent.
- `evidence_unwritable`: a closing record could not be written. It lifts when an
  append succeeds: give the spool room or let the collector drain it, and
  watch the depth. The two flags are set apart, so both can read `true`;
  `pipeline.sink_failures_after_effect` counts what happened.

## Roll back

To change the policy, sign it with a higher `serial`, renew for it, and copy
the statement before the bundle: the plane installs the bundle at the poll
that finds both, and refuses to start on a lower serial.

Set `mode: OBSERVE` and restart: the policy blocks nothing and the trail keeps
recording; a pause, a mismatch halt or unwritable evidence can still block a
call. To stop enforcing altogether, point the agent back at the server and
stop the gateway; the spool keeps its records, and the exporter drains them on
the next run from the collector's last acknowledgement.
