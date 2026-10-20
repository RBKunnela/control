---
title: Supervise and stop a run
summary: Run the refund example by hand on a live plane, supervise the run against its procedure, read its page, and stop it on a confirmed finding.
type: how-to
covers: [examples/refund-supervision/**, cmd/guardana-control/supervise*.go, cmd/guardana-control/react.go, cmd/guardana-control/stops.go, cmd/guardana-control/route.go, cmd/guardana-control/findings.go, cmd/guardana-control/procedure*.go]
---

# Supervise and stop a run

## When to use this

You want to see supervision work end to end before you write a procedure of
your own: a plane decides an agent's calls under an opened run, `supervise`
compares the run with its procedure, and `react` turns a confirmed finding
into a stop that refuses the run's next call and no other run's. This guide
does by hand what [examples/refund-supervision/](../../examples/refund-supervision/)
does under its `0.2` procedure. Every command here is `experimental`
([status.md](../status.md)). How the parts fit is in
[observations-coverage-and-supervision.md](../concepts/observations-coverage-and-supervision.md).

## Prerequisites

- A checkout of this repository on a Unix-like system, and the Go toolchain
  `go.mod` names, used once to build the binaries. Nothing after that needs Go.
- `curl` and `jq`.
- Ports 8080 and 8081 (the plane) and 4318 (the collector) free on
  127.0.0.1. If one is taken, change it in `plane.yaml` and in the commands
  below.

## Steps

### 1. Lay out the example

From the repository root, build the gateway, the control command and the
orders server into a directory of your own, and copy the example's files
below them as the repository lays them out: `plane.yaml` starts the server
from `../../bin/`.

```
export WORK="$HOME/refund"
go build -o "$WORK/bin/" ./cmd/guardana-gateway ./cmd/guardana-control ./examples/vulnerable-mcp-agent
mkdir -p "$WORK/examples/refund-supervision" "$WORK/keys"
cp examples/refund-supervision/plane.yaml examples/refund-supervision/*.json "$WORK/examples/refund-supervision/"
export PATH="$WORK/bin:$PATH"
```

Set `WORK` and `PATH` the same way in every terminal you open below.

### 2. Sign the policy

Make four keys: the policy's, the freshness statement's, the route's and the
lift key, which signs the end of a stop. Here they sit on one machine,
outside the plane's state; in use, keep the private keys off the plane's host.

```
$ cd "$WORK"
$ guardana-control policy keygen --out keys/bundle
key_id: ed25519-640a7a9ba6644930
public_key: btJ7DbxTY7wR79k4SxrHAl0BExSlmABGUQkDnm2e59o=
$ guardana-control policy keygen --out keys/freshness
$ guardana-control policy keygen --out keys/route
$ guardana-control policy keygen --out keys/lift
```

Sign the policy, vouch that it is current, and make the plane's directories,
as [run-the-gateway.md](run-the-gateway.md) explains:

```
cd examples/refund-supervision
mkdir -m 700 state trail state/spool state/runs state/approvals state/holds state/stops
guardana-control policy sign --key ../../keys/bundle/signing.key --out state/policy.bundle policy.json
guardana-control policy state init --kind signer --bundle-id refund-supervision ../../keys/signer-floors
guardana-control policy renew --key ../../keys/freshness/signing.key --bundle state/policy.bundle \
    --bundle-public-key ../../keys/bundle/signing.pub --floor ../../keys/signer-floors --out state/policy.statement
guardana-control policy state init --kind plane --bundle-id refund-supervision state/floors
```

In `plane.yaml`, replace the four `..._FROM_KEYGEN` values with the
`key_id` and `public_key` lines keygen printed for `keys/bundle` and
`keys/freshness`.

### 3. Sign the route and start the stop list

The route names the findings that may stop a run: `REPEATED_DENIAL` under
the `0.1` procedure and `DENIED_ACTION_RETRIED_RESOURCE` under `0.2`, each
bound to its procedure's digest. `plane.yaml` names the route, so the plane
refuses to start until it exists. In `route.json`, replace
`LIFT_PUBLIC_KEY_FROM_KEYGEN` with the `public_key` keygen printed for
`keys/lift`, then:

```
$ guardana-control route sign --key ../../keys/route/signing.key --out state/route.signed.json route.json
route_id: refunds
serial: 1
…
$ cp ../../keys/route/signing.pub state/route.pub
$ guardana-control policy state init --kind route --route-id refunds state/routefloor
$ guardana-control stops init --route state/route.signed.json --public-key state/route.pub state/stops
list_id: lst-d0eda7d074d9ee922e9e326bfde153a1
route_id: refunds
…
```

### 4. Start the collector and the plane

Work in `$WORK/examples/refund-supervision` from here on. Start the collector
in a terminal of its own:

```
guardana-gateway collect --listen 127.0.0.1:4318 --out trail/plane.jsonl
```

Check the configuration; every check line should begin `ok`:

```
$ guardana-gateway doctor --config plane.yaml
…
ok      upstreams     1 upstream(s) answered, 4 tool(s) listed, 4 classified, 0 unclassified
…
```

Then start the plane in another terminal:

```
$ guardana-gateway run --config plane.yaml
…
listening for agents on 127.0.0.1:8080
answering /healthz, /metrics and /brand on 127.0.0.1:8081
```

### 5. Open two runs

Every call needs a run the operator opened ([runs.md](../reference/runs.md)).
Open one for the agent and a second to show that a stop stays in its run:

```
$ guardana-control runs open --tenant acme --principal-type service --principal agent-runner --agent refund-assistant --ttl 1h state/runs
run_id: run-9d9ad942e8427a0e36f6abd3fa8ced08
…
token: run-9d9ad942e8427a0e36f6abd3fa8ced08.2sz2oVvp-yKBaXtfq47Gb133ucR_keAinwKSnlBvQkQ
```

Run it again for the second run. Your ids, tokens and approval id differ
from the ones on this page; use yours.

### 6. Make the agent's calls

Here `curl` stands in for the agent and presents the run's token. Define it
in the terminal you opened the runs in:

```
call() {
  curl -sS http://127.0.0.1:8080 -H "Run-Token: $TOKEN" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H "Mcp-Name: $1" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"'"$1"'","arguments":'"$2"',
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
}
TOKEN=run-9d9ad942e8427a0e36f6abd3fa8ced08.2sz2oVvp-yKBaXtfq47Gb133ucR_keAinwKSnlBvQkQ
```

Read the customer's order, then ask for the customer's export, which the
policy holds for a person:

```
$ call read_order '{"id":"ord-1"}'
event: message
data: {…"text":"order ord-1: 2 items, paid, ships to Jane Roe, 1 Main Street"}],"resultType":"complete"}}
$ call export_orders '{"id":"cus-1"}'
event: message
data: {…"guardana.control/answer":"pending","guardana.control/approval_id":"NJ2LS54YEXMJJDH3LK4GFOUSYM",…"text":"APPROVAL_PENDING"}],"isError":true}}
```

Approve it as a person would, and make the same call again; it runs on the
held request:

```
$ guardana-control approvals approve --approver-id supervisor state/approvals NJ2LS54YEXMJJDH3LK4GFOUSYM
approval NJ2LS54YEXMJJDH3LK4GFOUSYM: approved by supervisor
$ call export_orders '{"id":"cus-1"}'
data: {…"text":"customer cus-1: ord-1, ord-2, ord-3"}],"resultType":"complete"}}
```

Now the agent goes wrong: it is denied a refund of another customer's order
and marks that order refunded instead.

```
$ call refund '{"id":"ord-2","amount":"12.00"}'
data: {…"guardana.control/reason_codes":["RULE_DENY"],…"isError":true}}
$ call update_order '{"id":"ord-2","status":"refunded"}'
data: {…"text":"order ord-2 is now refunded"}],"resultType":"complete"}}
```

### 7. Export the trail

Wait until the collector holds the four calls' trails, then export them:

```
$ guardana-gateway trail trail/plane.jsonl
…
trails 4: ok 4, open 0, failed 0, indeterminate 0; …
$ guardana-gateway trail export trail/plane.jsonl > plane.export.jsonl
```

### 8. Supervise the run and read its page

```
$ mkdir -m 700 findings
$ guardana-control supervise --procedure refund-0.2.procedure.json --runs state/runs \
    --run run-9d9ad942e8427a0e36f6abd3fa8ced08 --findings findings --evidence plane.export.jsonl --view run.html
run run-9d9ad942e8427a0e36f6abd3fa8ced08 tenant acme project refunds procedure refund version 2
…
finding RESOURCE_OUTSIDE_RUN confirmed alert fnd-61fa48842c3a3a5c790cf3226fa121d6 …
finding DENIED_ACTION_RETRIED_RESOURCE confirmed alert fnd-56e33295fb4e204153fa79d1ea12bd3e …
finding EXCEPTION_TAKEN confirmed inform fnd-36927c0a79d5afba83b765f2dc206201 …
…
rule REQUIRED_STEP_SKIPPED not checked: the run is open
…
rule DENIED_ACTION_RETRIED_AROUND not checked: no observation source was read
…
findings log: 3 written, 0 already held
```

It exits 1 because it made findings, which is what this run should produce.
`RESOURCE_OUTSIDE_RUN`: the calls bound to one order reached two, `ord-1` and
`ord-2`. `DENIED_ACTION_RETRIED_RESOURCE`: once the refund of `ord-2` was
denied, another tool updated that order. `EXCEPTION_TAKEN`: the approved
export is an exception the procedure allows, reported for information. The
rules about what is missing wait for the run to close.

Open `run.html` in a browser; it runs no script. It shows the expected steps
with their calls, the three findings with the calls each cites, the four
calls with a mark each (enforced, blocked, exception or approval), and every
rule's state ([run-view.md](../reference/run-view.md)).

### 9. Export the findings

```
$ guardana-control findings export --findings findings > findings.export.jsonl
$ cut -c1-60 findings.export.jsonl
{"type":"header","format":"guardana.control.findings-export"
{"type":"finding_record","offset":85,"cursor":"v1:714ceed807
…
{"type":"supervise_report","offset":2637,"cursor":"v1:714cee
{"type":"trailer","next_cursor":"v1:714ceed807678d837cf64ff2
```

### 10. Stop the run

`react` writes a stop for each new confirmed finding the route allows whose
run is open and unexpired, or a covered line when a stop of that run already
lasts as long ([reaction](../reference/reaction.md) has every rule):

```
$ guardana-control react --findings findings --runs state/runs --stops state/stops \
    --route state/route.signed.json --public-key state/route.pub
stop line 2 run run-9d9ad942e8427a0e36f6abd3fa8ced08 finding fnd-56e33295fb4e204153fa79d1ea12bd3e rule DENIED_ACTION_RETRIED_RESOURCE expires_at 2026-10-08T04:59:58Z
stops 1, covered 0, already named 0, not stopping 2, not written 0
```

The plane reads the list every second:

```
$ curl -s http://127.0.0.1:8081/healthz | jq .stops.state
"stopped"
```

The first run's next call is refused; the second run's call runs:

```
$ call read_order '{"id":"ord-1"}'
data: {…"guardana.control/reason_codes":["RUN_STOPPED"],…"isError":true}}
$ TOKEN=run-ccb6fca62cbadb0bfbea3143ec9d407c.JKKS1krX4V3ePWdUzYJm4JlEurwexvY94LbYDwfloDo
$ call read_order '{"id":"ord-1"}'
data: {…"text":"order ord-1: 2 items, paid, ships to Jane Roe, 1 Main Street"}],"resultType":"complete"}}
```

### 11. Test the procedure

Each of the example's test cases describes a run and every finding
`supervise` must report on it ([test-a-procedure.md](test-a-procedure.md)):

```
$ guardana-control procedure test refund-0.2.cases.json
ok   the refund retried as an update: RESOURCE_OUTSIDE_RUN CONFIRMED, DENIED_ACTION_RETRIED_RESOURCE CONFIRMED
ok   the export approved: EXCEPTION_TAKEN CONFIRMED
ok   the export without an approval: STEP_OUTSIDE_PROCEDURE CONFIRMED
procedure refund version 2: 3 cases, 3 passed, 0 failed
```

## Verify

The refused call's trail shows the plane blocked it before the server saw it,
under a policy that allowed it. Use the request id its answer named:

```
$ guardana-gateway trail export --request SGVSUQB3K4E54GEEGBA2VDBOOP trail/plane.jsonl | grep -o '"kind":"[A-Z_]*"\|"reasonCodes":\[[^]]*\]'
"kind":"EVENT_KIND_ACTION_PROPOSED"
"kind":"EVENT_KIND_POLICY_DECIDED"
"reasonCodes":["RULE_ALLOW"]
"kind":"EVENT_KIND_ACTION_BLOCKED"
"reasonCodes":["RUN_STOPPED"]
```

`stops list --route state/route.signed.json --public-key state/route.pub
state/stops` shows the stop `active`.

## Roll back

Lift the stop with the lift key; the plane reads it within a second, and the
first run's calls run again. `react` never writes a stop for the same finding
again ([reaction.md](../reference/reaction.md)).

```
$ guardana-control stops lift --route state/route.signed.json --public-key state/route.pub \
    --key ../../keys/lift/signing.key --run run-9d9ad942e8427a0e36f6abd3fa8ced08 state/stops
lift line 3 run run-9d9ad942e8427a0e36f6abd3fa8ced08 through line 2
```

Close both runs, stop the plane and the collector with Ctrl-C, and remove
`$WORK`:

```
$ guardana-control runs close state/runs run-9d9ad942e8427a0e36f6abd3fa8ced08
closed run-9d9ad942e8427a0e36f6abd3fa8ced08
$ guardana-control runs close state/runs run-ccb6fca62cbadb0bfbea3143ec9d407c
closed run-ccb6fca62cbadb0bfbea3143ec9d407c
```

## What this guide does not show

The example's tests also import the agent runtime's own spans as
observations, which is how `supervise` suspects an upload the plane never saw.
The tests write those spans themselves; by hand there is no runtime to report
them, so this guide supervises from the plane's trail alone, and
`DENIED_ACTION_RETRIED_AROUND` is not checked. Observations and the coverage
map have their own pages: [observations.md](../reference/observations.md) and
[coverage.md](../reference/coverage.md). The example's README describes its
`0.1` run; `notify` and child runs are in
[supervision.md](../reference/supervision.md).
