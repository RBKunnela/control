---
title: Try the demo
summary: Start a plane in front of two vulnerable MCP servers, watch it allow a read, block a refund and hold an update for your approval, and read the trail.
type: tutorial
covers: [examples/vulnerable-mcp-agent/**]
---

# Try the demo

You start a plane on your machine: the gateway, placed between an agent and
two MCP servers the agent should not be trusted with. You make the calls an
agent would, and the plane allows a read, blocks a refund and holds an update
until you approve it. Then you read what it recorded.

Everything here is `experimental` ([status.md](../status.md#demo-servers)) and
runs on the loopback only. It is a demo, not a security boundary. What the
demo holds is in
[examples/vulnerable-mcp-agent](../../examples/vulnerable-mcp-agent/README.md).

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

`dev` lays out a new state directory, signs the demo's policy, and starts a
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

## 4. Watch a refund be blocked

The policy denies refunds:

```
examples/vulnerable-mcp-agent/call.sh "$MCP" refund '{"id":"ord-1","amount":"500.00"}'
```

The answer is marked `blocked`, with `isError: true` and the text
`RULE_DENY`. The orders server never saw the call.

## 5. Answer a held call

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

## 6. Read the trail

The plane's evidence, the events of each call, went through its spool, a
directory on disk, to the collector, which appends it to the trail. Run
the `trail_command` line, the program under `bin/`:

```
bin/guardana-gateway trail <state>/trail
```

It prints one line per request, the kind of its last event, and whether its
events form an unbroken chain. The read, the refund and the update each
have their line.

## Next

[Try the rest of the demo](try-the-rest-of-the-demo.md) starts from this
running plane: it pauses a server, reads the counters and runs the demo's
scenarios. To stop here, stop `dev` with Ctrl-C; the state directory stays.

- [guides/write-and-test-a-policy.md](../guides/write-and-test-a-policy.md) to
  change what the plane decides.
- [guides/connect-an-existing-mcp-setup.md](../guides/connect-an-existing-mcp-setup.md)
  to put the plane in front of a server you already use.
