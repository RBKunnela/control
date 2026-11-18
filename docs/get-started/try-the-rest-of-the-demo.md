---
title: Try the rest of the demo
summary: On the demo's running plane, pause a server, read the counters, run the seven scenarios and make one fail on purpose.
type: tutorial
covers: [examples/vulnerable-mcp-agent/**, cmd/guardana-gateway/dev*.go]
---

# Try the rest of the demo

This starts where [Try the demo](try-the-demo.md) ends: `dev` is running and
`$MCP` holds its `mcp` address. You pause a server, read the plane's
counters, then run the demo's seven scenarios, which describe an agent's
calls as data, and make one fail on purpose.

Everything here is `experimental` ([status.md](../status.md#demo-servers)) and
runs on the loopback only. How `dev` keeps its policy signed and current is
on [reference/dev.md](../reference/dev.md), and how a plane of your own does
it with two keys you keep is on [run the gateway](../guides/run-the-gateway.md).

## 1. Pause the orders server

A dev plane's pause file is signed, so the page shows its pauses and writes
none. Run the `pause_command` dev printed, with `--provider orders` in place
of `--global`:

```
bin/guardana-control pause add --provider orders --key <state>/operator/signing.key \
  --roster <state>/trust/roster.json --root-key <state>/trust/root.pub -- <state>/pause/pause.json
```

It prints the entry's id. Once the plane has read its pause file, which the
demo has it do every half second, the read

```
examples/vulnerable-mcp-agent/call.sh "$MCP" read_order '{"id":"ord-1"}'
```

is blocked with `PAUSED`, although the policy allows it. Run `pause remove`
with the same `--key`, `--roster` and `--root-key`, the file and that id, and
the same call runs again.

## 2. Read the counters

The counters need no collector:

```
curl -s http://127.0.0.1:<port>/metrics | grep -E 'pipeline_(executed|pending|blocks)_total'
```

`guardana_control_pipeline_executed_total` counts the calls the plane ran,
`guardana_control_pipeline_pending_total` the ones it held, and
`guardana_control_pipeline_blocks_total` its blocks by reason code: the read
the pause stopped is under `code="PAUSED"`
([reference/metrics](../reference/metrics.md)).

Stop `dev` with Ctrl-C. It stops every part, gives the exporter a moment to
ship what the spool holds, and says how much it did not. The state directory
stays.

## 3. Run the scenarios

Each scenario is a JSON file of calls and operator steps, and for each call
the answer, the decision and the trail the plane must produce
([reference/scenario-format.md](../reference/scenario-format.md)). With
`--scenario`, `dev` runs each one on a plane of its own:

```
bin/guardana-gateway dev --decision-point=silent --config examples/vulnerable-mcp-agent/demo.yaml --policy examples/vulnerable-mcp-agent/policy.json \
  --scenario examples/vulnerable-mcp-agent/scenarios/allow.json \
  --scenario examples/vulnerable-mcp-agent/scenarios/deny.json \
  --scenario examples/vulnerable-mcp-agent/scenarios/approval.json \
  --scenario examples/vulnerable-mcp-agent/scenarios/digest-invalidation.json \
  --scenario examples/vulnerable-mcp-agent/scenarios/fail-closed.json \
  --scenario examples/vulnerable-mcp-agent/scenarios/pause.json \
  --scenario examples/vulnerable-mcp-agent/scenarios/toxic-flow.json
```

Every step prints `ok`, every scenario `passed`, and `dev` exits 0. What each
one shows:

| Scenario | The plane |
| --- | --- |
| `allow` | runs a read |
| `deny` | blocks a refund with `RULE_DENY` before the orders server sees it |
| `approval` | holds an update, and resumes it once approved |
| `digest-invalidation` | holds anew an approved update retried with other arguments, then resumes the original |
| `fail-closed` | blocks a call to `export_orders` `INDETERMINATE` with `PDP_TIMEOUT` when the decision point never answers |
| `pause` | blocks a read while the orders server is paused, runs it once the pause is lifted |
| `toxic-flow` | after an untrusted page, blocks any mail, since `send_mail`'s destination is declared untrusted. Before an order is read the block is undetermined; after, its reason is `TOXIC_FLOW_SENSITIVE_TO_EXTERNAL` |

In `toxic-flow` the page asks the agent to mail an order away, and no rule
names `fetch_page`: the plane blocks the mail because the page's result is
declared untrusted and the mail's destination is too
([ADR-0021](../adr/0021-a-run-carries-what-it-took-in.md)). To see that the
mail never reached the web server, give the servers a directory for their
journals:

```
journal=$(mktemp -d)
VICTIM_JOURNAL_DIR="$journal" bin/guardana-gateway dev --decision-point=silent --config examples/vulnerable-mcp-agent/demo.yaml --policy examples/vulnerable-mcp-agent/policy.json --scenario examples/vulnerable-mcp-agent/scenarios/toxic-flow.json
cat "$journal/web.jsonl"
```

`web.jsonl` lists the `fetch_page` call and no `send_mail`.

## 4. Make one fail

Check that a scenario fails when the plane does something else. Copy one
with its expected verdict changed; the file's name is the
scenario's id, so keep it:

```
mutant=$(mktemp -d)
sed 's/"verdict": "ALLOW"/"verdict": "DENY"/' examples/vulnerable-mcp-agent/scenarios/allow.json > "$mutant/allow.json"
bin/guardana-gateway dev --decision-point=silent --config examples/vulnerable-mcp-agent/demo.yaml --policy examples/vulnerable-mcp-agent/policy.json --scenario "$mutant/allow.json"
echo $?
```

It prints `allow.json step[0].decided.verdict: want DENY, got ALLOW`, then
`allow.json failed`, and exits 1. An exit of 2 means a scenario could not
run, which is never a pass.

## Next

- [guides/write-and-test-a-policy.md](../guides/write-and-test-a-policy.md) to
  change what the plane decides.
- [guides/run-the-gateway.md](../guides/run-the-gateway.md) to run a plane of
  your own with `run`, which `dev` builds the same way.
