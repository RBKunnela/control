---
title: Try the demo
summary: Start a plane in front of two vulnerable MCP servers, answer a held call, pause a server, read the trail and the counters, and run the demo's scenarios.
type: tutorial
covers: [examples/vulnerable-mcp-agent/**]
---

# Try the demo

You start a plane on your machine: the gateway, placed between an agent and
two MCP servers the agent should not be trusted with. You make the calls an
agent would, answer one that is held for a person, pause a server, and read
what the plane recorded. Then you run the demo's seven scenarios, which
describe an agent's calls as data, and make one fail on purpose.

Everything here is `experimental` ([status.md](../status.md)) and runs on the
loopback only. It is a demo, not a security boundary. What the demo holds is
in [examples/vulnerable-mcp-agent](../../examples/vulnerable-mcp-agent/README.md).

## What you need

- Linux or macOS on amd64 or arm64, `curl` and a browser. No Go, model key
  or collector: `dev` runs its own.

## 1. Get the demo

Each release carries a demo archive per platform, beside the product's. From
[the releases](https://github.com/guardana/control/releases), take
`guardana-control-demo_<version>_<os>_<arch>.tar.gz`, `checksums.txt` and
`checksums.txt.sigstore.json`,
check it as [RELEASING.md](../../RELEASING.md) shows, and extract it:

```
tar -xzf guardana-control-demo_<version>_<os>_<arch>.tar.gz
cd guardana-control-demo_<version>_<os>_<arch>
```

On macOS, fetch the files with `curl -LO`: a browser marks a download as
quarantined, and macOS then refuses to run the binaries, which are not
notarized.

The directory is laid out as the repository is. `bin/` holds three programs:
the gateway, `guardana-control`, the approvals tool, which `dev` needs beside
the gateway, and `vulnerable-mcp-agent`, the two servers the demo's
configuration starts. Every command below runs from this directory.

From a checkout instead, with the Go version its `go.mod` names, build the
same three into `bin/` from the repository's root:

```
go build -o bin/ ./cmd/guardana-gateway ./cmd/guardana-control ./examples/vulnerable-mcp-agent
```

## 2. Start the plane

```
bin/guardana-gateway dev --decision-point=silent --config examples/vulnerable-mcp-agent/demo.yaml --policy examples/vulnerable-mcp-agent/policy.json
```

`dev` lays out a new state directory, signs the policy under a key it drops
once it signed, vouches that the bundle is current under a second key it
keeps only in memory, renewing that statement while it runs, and starts a
collector, the plane and the approvals page
([reference/dev.md](../reference/dev.md)). `--decision-point=silent` gives the
plane a decision point that never answers, on a port `dev` binds itself. The
plane starts both servers as its upstreams. Once it is up it prints one `name: value` line per part,
among them:

```
mcp: http://127.0.0.1:<port>
metrics: http://127.0.0.1:<port>/metrics
page: http://127.0.0.1:<port>/#t=<token>
approvals: <state>/approvals
trail: <state>/trail
trail_command: guardana-gateway trail <state>/trail
```

Leave it running and open a second terminal in the same directory. Put
the `mcp` address in a variable:

```
MCP=http://127.0.0.1:<port>
```

## 3. Make a call

`call.sh` makes one MCP `tools/call`, as an agent does, and prints the
answer.

```
examples/vulnerable-mcp-agent/call.sh "$MCP" read_order '{"id":"ord-1"}'
```

The policy allows reads, so the order comes back. The answer's `_meta` names
the `request_id` and `decision_id` the plane recorded for it.

## 4. Answer a held call

The policy holds every update for a person:

```
examples/vulnerable-mcp-agent/call.sh "$MCP" update_order '{"id":"ord-1","status":"cancelled"}'
```

The answer is marked `pending`, with the text `APPROVAL_PENDING`, an
`approval_id` and when it expires. Nothing reached the orders server.

Open the `page` link in your browser within ten minutes of the start; the
link works once. Under **Held calls** the update waits, with its action
digest and the command that signs an approval of it: a dev plane takes only
an answer an operator signs, and the page holds no key. Run the
`approve_command` dev printed, with the `approval_id`:

```
bin/guardana-control approvals approve --key <state>/operator/signing.key --inbox <state>/inbox -- <state>/approvals <approval_id>
```

Now make the same call again, with the same arguments. It runs, and its
`request_id` is the held one's: the retry resumed the held request. An
approval covers one exact call: the same update with other arguments would
be held as a request of its own.

It prints the action digest it signed; check it is the one the page shows.

## 5. Pause the orders server

On the page, under **Pauses**, choose **every call to one upstream**, type
`orders`, give a reason and press **Pause**. Once the plane has read its pause
file, which the demo has it do every half second, the read

```
examples/vulnerable-mcp-agent/call.sh "$MCP" read_order '{"id":"ord-1"}'
```

is blocked with `PAUSED`, although the policy allows it. Press **Lift this
pause** and the same call runs again.

## 6. Read the trail and the counters

The plane's evidence, the events of each call, went through its spool, a
directory on disk, to the collector, which appends it to the trail. Run
the `trail_command` line, the program under `bin/`:

```
bin/guardana-gateway trail <state>/trail
```

It prints one line per request, the kind of its last event, and whether its
events form an unbroken chain. The counters need no collector:

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

## 7. Run the scenarios

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

## 8. Make one fail

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

## Where next

- [guides/write-and-test-a-policy.md](../guides/write-and-test-a-policy.md) to
  change what the plane decides.
- [guides/run-the-gateway.md](../guides/run-the-gateway.md) to run a plane of
  your own with `run`, which `dev` builds the same way.
