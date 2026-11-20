---
title: Check a security-testing agent's calls against a scope you declare
summary: Test the policy (implemented). Check MCP calls through the plane, stop the run after four denials and compare proxy logs with the host list (experimental).
type: how-to
covers: [adapters/mcp/translate.go, internal/policy/match/**, cmd/guardana-control/testcase.go, internal/ingest/egresslog/**, cmd/guardana-control/coverage.go, cmd/guardana-control/supervise.go, cmd/guardana-control/react.go, examples/refund-supervision/**, cmd/guardana-control/approvals.go, cmd/guardana-control/runs.go, cmd/guardana-control/observe.go]
---

# Check a security-testing agent's calls against a scope you declare

## When to use this

Use this guide for an authorized security test, to check calls through the plane and compare outbound hosts with your test scope (both `experimental`).

## Prerequisites

- A Unix-like system, a checkout and the Go toolchain in `go.mod` for the initial build.
- `curl`, `jq` and ports 8080 and 8081 free on 127.0.0.1.
- An MCP client that can send an HTTP header and an egress proxy you control that writes an Envoy-style JSON access log.

Isolate the agent's network. Limit credentials for the agent and its tools to permitted targets. Route their outbound traffic through the proxy. Block their direct access to MCP servers. Prevent them from changing the proxy, its log or the plane's control files.

## Steps

### 1. Define the scope

List the permitted servers, tools, targets and outbound hosts. Mark requests that need approval. Here, permit reads of `ord-1` on `orders` in `dev` and require approval for refunds of that order.

Build and copy the example once from the checkout root. Set `WORK` and `PATH` in every terminal you open. [Supervision setup](supervise-and-stop-a-run.md#1-lay-out-the-example)

```sh
export WORK="$HOME/refund"
go build -o "$WORK/bin/" ./cmd/guardana-gateway ./cmd/guardana-control ./examples/vulnerable-mcp-agent
mkdir -p "$WORK/examples/refund-supervision" "$WORK/keys"
cp examples/refund-supervision/plane.yaml examples/refund-supervision/*.json "$WORK/examples/refund-supervision/"
export PATH="$WORK/bin:$PATH"
```

### 2. Match tools to targets

Change to `$WORK/examples/refund-supervision`. The example allows `update_order` and requires approval for `export_orders`. Replace the entire `rules` array in `policy.json`.

```json
[
  {
    "id": "read-test-order", "effect": "ALLOW",
    "when": {
      "action": {"kind": ["tool"], "provider": ["orders"], "name": ["read_order"], "effect": ["READ"]},
      "resource": {"type": ["order"], "id": ["ord-1"], "environment": ["dev"]}
    }
  },
  {
    "id": "approve-test-refund", "effect": "REQUIRE_APPROVAL",
    "when": {
      "action": {"kind": ["tool"], "provider": ["orders"], "name": ["refund"], "effect": ["TRANSACT"]},
      "resource": {"type": ["order"], "id": ["ord-1"], "environment": ["dev"]}
    }
  }
]
```

Write one rule per permitted tool and target pair. The matcher (`implemented`) requires every constraint in that rule to match. [Policy constraints](../reference/policy-format.md#when)

### 3. Test the policy before signing

In `cases/`, create one file per row by copying and editing `allow-read.json` and `approve-refund.json`. [Case fixtures](../../cmd/guardana-control/testdata/cases)

Put the complete edited policy in each case's `document`. Set the envelope and resource environments to `dev`. Use action kind `tool`, provider `orders` and the tool name below. Keep the refund fixture's argument bytes and hash unchanged. Copy each `ord-1` case to create a matching `ord-2` case. In each new file, change only the resource ID and the expected decision.

| Tool | Resource ID | Expected verdict | Expected action | Expected reason |
| --- | --- | --- | --- | --- |
| `read_order` | `ord-1` | `ALLOW` | `Execute` | `RULE_ALLOW` |
| `read_order` | `ord-2` | `DENY` | `Block` | `NO_MATCHING_RULE` |
| `refund` | `ord-1` | `REQUIRE_APPROVAL` | `AwaitApproval` | `APPROVAL_REQUIRED` |
| `refund` | `ord-2` | `DENY` | `Block` | `NO_MATCHING_RULE` |

Run the policy checks (`implemented`). Continue only if lint exits 0 and all four cases pass. [Write and test a policy](write-and-test-a-policy.md)

```sh
guardana-control policy lint policy.json
guardana-control policy test cases
```

### 4. Configure the plane and open one run

Configure the MCP gateway (`experimental`) in `plane.yaml`. Set `mode` to `ENFORCE` and leave `policy.fail_open_read` as `false`. List servers under `upstreams`. Under `overrides`, pin each tool's fingerprint and map its target argument with `resource_from`. Use `/id` for `read_order` and `refund`. Check that each acts on the resource it names. [Connect an existing MCP setup](connect-an-existing-mcp-setup.md)

Use the policy CLI (`implemented`) to create four keys, sign the tested policy and renew its freshness statement. The policy serial floor and policy refresh on the plane are `experimental`. [Sign the policy](supervise-and-stop-a-run.md#2-sign-the-policy)

```sh
cd "$WORK"
guardana-control policy keygen --out keys/bundle
guardana-control policy keygen --out keys/freshness
guardana-control policy keygen --out keys/route
guardana-control policy keygen --out keys/lift
cd examples/refund-supervision
mkdir -m 700 state trail state/spool state/runs state/approvals state/holds state/stops
guardana-control policy sign --key ../../keys/bundle/signing.key --out state/policy.bundle policy.json
guardana-control policy state init --kind signer --bundle-id refund-supervision ../../keys/signer-floors
guardana-control policy renew --key ../../keys/freshness/signing.key --bundle state/policy.bundle \
    --bundle-public-key ../../keys/bundle/signing.pub --floor ../../keys/signer-floors --out state/policy.statement
guardana-control policy state init --kind plane --bundle-id refund-supervision state/floors
```

In `plane.yaml`, fill in the bundle and freshness key IDs and public keys. Replace `/absolute/path/to/collect.sock` with the full path to `$WORK/examples/refund-supervision/state/collect.sock`. Run `id -u` as the collector account, and set `COLLECTOR_UID_FROM_ID` to that number. Create the credential and replace `COLLECTOR_CREDENTIAL_FROM_FILE` with its contents.

```sh
(umask 077 && od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > state/collector.credential)
```

In `route.json`, replace `LIFT_PUBLIC_KEY_FROM_KEYGEN` with the `keys/lift` public key. For stops (`experimental`), sign the route and initialize its floor and stop list.

```sh
guardana-control route sign --key ../../keys/route/signing.key --out state/route.signed.json route.json
cp ../../keys/route/signing.pub state/route.pub
guardana-control policy state init --kind route --route-id refunds state/routefloor
guardana-control stops init --route state/route.signed.json --public-key state/route.pub state/stops
```

Start the collector (`experimental`) in its own terminal in `$WORK/examples/refund-supervision`.

```sh
guardana-gateway collect --listen "unix://$PWD/state/collect.sock" --dir trail/plane --tenant acme --project refunds \
  --credential-file state/collector.credential
```

Open the run in the original terminal.

```sh
guardana-control runs open --project refunds --tenant acme --principal-type service --principal agent-runner --agent refund-assistant --ttl 1h state/runs
```

`runs open` (`experimental`) prints `run_id`, `root`, `expires_at` and `token` (shown only once). Save `run_id` as `RUN_ID` and `token` as `TOKEN`.

Check the configuration with `doctor` (`experimental`).

```sh
guardana-gateway doctor --config plane.yaml
```

When every check says `ok`, start the plane in another terminal in the example directory.

```sh
guardana-gateway run --config plane.yaml
```

Replace the agent's direct server entries with `http://127.0.0.1:8080/mcp`. Send `Run-Token: <token>` with the value of `TOKEN` on every HTTP request. [Connect the client](connect-an-existing-mcp-setup.md#7-point-the-client-at-the-plane)

### 5. Test the calls

Create the log directories, then direct the proxy log to `egress/envoy.jsonl`.

```sh
mkdir -m 700 egress egress/log
```

Prepare `egress/envoy.descriptor.json` for tenant `acme` and project `refunds`. In `egress/inventory.json`, list permitted hosts as `egress` paths with the proxy as their source. [Proxy setup and file permissions](watch-an-egress-proxy.md)

Start the agent. Have it call `read_order` for `ord-1`, then request a `refund` for that order, as `refund.procedure.json` requires. Save the held request's approval ID as `APPROVAL_ID`.

```sh
guardana-control approvals list state/approvals
```

`approvals list` (`experimental`) shows the state, request ID, expiry, action digest, policy bundle digest and fields the plane recorded when it held the request. Compare the principal, agent, action, upstream, resource, effect class, rule IDs and request time with your plan. The action digest does not bind these readable fields. The listing omits arguments.

If the request matches your plan, approve it using the directory authority (`experimental`).

```sh
guardana-control approvals approve --approver-id supervisor state/approvals "$APPROVAL_ID"
```

Have the agent retry the same refund before approval expires. Approval binding (`implemented`) lets that retry run once for the exact approved action digest and policy bundle digest. [Approval binding](../status.md#approval-binding)

In the same run, have the agent call `read_order` on `orders` once each for `ord-2`, `ord-3`, `ord-4` and `ord-5`.

### 6. Check the run and apply the stop

Wait until every test call appears in the collector's trail (`experimental`).

```sh
guardana-gateway trail trail/plane
```

Export the evidence (`experimental`).

```sh
guardana-gateway trail export trail/plane > plane.export.jsonl
```

Create an owner-only findings directory. Check the run against its procedure with `supervise` (`experimental`).

```sh
mkdir -m 700 findings
guardana-control supervise --procedure refund.procedure.json --runs state/runs \
    --run "$RUN_ID" --findings findings --evidence plane.export.jsonl
```

Apply the signed route (`experimental`) only if supervision confirms repeated denials and the run is still open and unexpired.

```sh
guardana-control react --findings findings --runs state/runs --stops state/stops \
    --route state/route.signed.json --public-key state/route.pub
```

Wait for the stop (`experimental`) to show `"stopped"` on `/healthz`.

```sh
curl -s http://127.0.0.1:8081/healthz | jq .stops.state
```

Then call `read_order` for `ord-1` again in the same run.

### 7. Check the proxy log

Import proxy observations (`experimental`).

```sh
guardana-control observe import --source egress/envoy.descriptor.json --log egress/log egress/envoy.jsonl
```

Compare the observations with the inventory using coverage (`experimental`).

```sh
guardana-control coverage --inventory egress/inventory.json --source egress/envoy.descriptor.json --log egress/log
```

## Verify

- For each of the four refused reads, check the trail. The kernel (`implemented`) returns `DENY` with `NO_MATCHING_RULE`, and the plane (`experimental`) blocks the call.
- With `max_denials` set to 4 in `refund.procedure.json`, `supervise` (`experimental`) reports `finding REPEATED_DENIAL confirmed` and exits 1.
- The stop (`experimental`) refuses the next `ord-1` read with `RUN_STOPPED` (reason code 45). [Stops](../status.md#run-stop)
- If you list only `api.example.com` and the proxy logs `registry.example.org`, coverage (`experimental`) exits 1. Read the source, trust level, heartbeat, connection count and port from the row, as in this example. Treat a refused log line as an unknown connection. [Coverage](../reference/coverage.md)

```text
undeclared egress registry.example.org: observed by egress-envoy: independent (unsigned descriptor), past its heartbeat: last heard 2026-10-04T10:00:02Z, heartbeat 300 s; 1 connection, port 80; no plane decides egress
```

## Roll back

Lift the stop and close the run (`experimental`).

```sh
guardana-control stops lift --route state/route.signed.json --public-key state/route.pub \
    --key ../../keys/lift/signing.key --run "$RUN_ID" state/stops
guardana-control runs close state/runs "$RUN_ID"
```

Press Ctrl-C in the plane and collector terminals. Remove `$WORK` if it was only for this test.

## What this guide does not show

- You maintain the tool policy and host inventory separately. A single signed scope per run is backlog item [B44](../backlog.md).
- Direct MCP calls bypass the plane. Traffic that bypasses the proxy leaves no proxy observation. Egress coverage reports connections after they happen. It cannot block them or identify a run from a host alone.
- A stop cannot cancel a call already running.
- With `approvals.authority: directory`, any process running as the plane's account can approve or reject a held request. The `approver_id` is unverified. With `approvals.authority: signed` (`experimental`), only a roster operator granted `operate` for the request's tenant and project can sign a valid approval. [Set up signed operators](set-up-signed-operators.md)
- Guardana Control cannot detect or stop an agent an attacker runs on the attacker's own machines. [Threat model](../concepts/threat-model.md#an-agent-that-is-wrong-or-steered)
