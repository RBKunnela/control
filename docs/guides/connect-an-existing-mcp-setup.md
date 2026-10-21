---
title: Connect an existing MCP setup
summary: Put the plane between an MCP client and a server you already use, classify the server's tools, hold its writes for approval, and end in a local report.
type: how-to
covers: [examples/connect-a-filesystem-server/**, cmd/guardana-gateway/profile_test.go, adapters/mcp/answer.go, scripts/check-mcp-client.sh]
---

# Connect an existing MCP setup

## When to use this

Your MCP client already talks to a server, and you want every call it makes
decided, held or blocked before the server sees it, and recorded. This page
puts the plane between them, using the MCP project's reference filesystem
server as the example; the profile under
[examples/connect-a-filesystem-server](../../examples/connect-a-filesystem-server)
was tried end to end with `@modelcontextprotocol/server-filesystem` 2026.8.31
and the MCP inspector's command line as the client. The plane is
`experimental` and nothing here is a security boundary
([status.md](../status.md)).

## Prerequisites

- `guardana-gateway` and `guardana-control` from a release archive, and a
  checkout of this repository for the profile and the policy pack, which the
  archives do not carry.
- Node.js with `npm`, for this server; another server needs whatever it runs on.
- Go 1.27.3 or later, to build the report program.
- A client that connects to a server by URL over Streamable HTTP, protocol
  `2025-11-25` or older. A client that only starts servers as commands can
  start the plane instead (step 7).

## Steps

### 1. Copy the profile and the policy, and install the server

From the checkout's root:

```
cp -R examples/connect-a-filesystem-server ~/files-plane
cp examples/starter-packs/approval-for-writes/policy.json ~/files-plane/
go -C examples/evidence-report build -o ~/files-plane/bin/ .
cd ~/files-plane
npm ci --ignore-scripts
mkdir -m 700 spool approvals holds
```

`npm ci` installs the server at 2026.8.31 from the profile's lockfile, every
package checked against its hash. The configuration starts
`node_modules/.bin/mcp-server-filesystem`, a path it resolves against its own
directory. The plane gives the server only `PATH`,
`HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `USER` and what `env` names.

### 2. Make the keys, sign a policy and vouch for it

```
guardana-control policy keygen --out keys
guardana-control policy keygen --out freshness
guardana-control policy sign --key keys/signing.key --out policy.bundle policy.json
guardana-control policy state init --kind signer --bundle-id starter-approval-for-writes signer-floors
guardana-control policy renew --key freshness/signing.key --bundle policy.bundle \
    --bundle-public-key keys/signing.pub --floor signer-floors --out policy.statement
guardana-control policy state init --kind plane --bundle-id starter-approval-for-writes floors
```

`keys` signs the bundle and `freshness`, a second pair, signs the statement
that says the bundle is current. `floors` is the plane's: it keeps the highest
serial the plane took, so a restart cannot go back to an older bundle.

The approval-for-writes pack, copied in step 1, allows reads, holds every write for a person,
denies deletes in `prod` and a confidential message out after untrusted input
([reference/starter-packs.md](../reference/starter-packs.md)). Keep `keys`,
`freshness`, `signer-floors` and your copy of the bundle off the machine that
runs the plane once you sign for real.

### 3. Fill in the profile

In `plane.yaml`, replace `BUNDLE_KEY_ID_FROM_KEYGEN` and `BUNDLE_PUBLIC_KEY_FROM_KEYGEN`
with the two lines the first `keygen` printed,
`FRESHNESS_KEY_ID_FROM_KEYGEN` and `FRESHNESS_PUBLIC_KEY_FROM_KEYGEN` with
the second's, and the server's one argument with the absolute path of the
directory it may touch. Nothing else needs to change for this server.

### 4. Start a collector

```
guardana-gateway collect --listen 127.0.0.1:4318 --out trail.jsonl
```

The plane writes its evidence to the spool and ships it here; the trail file
is what step 9 reads.

### 5. Check the classification

```
guardana-gateway doctor --config plane.yaml
```

The line to read is `upstreams`: `14 tool(s) listed, 14 classified, 0
unclassified`. Each override pins one tool's definition by its fingerprint and
says what the tool does: `READ` or `WRITE`, the resource it touches and, for most, where in the arguments it
sits. The classification is yours. The server
marks its tools `readOnlyHint`, and the profile agrees with it, but a hint is
the server's claim, never the plane's authority.

A tool no override classifies, or one whose definition changed since its
fingerprint was taken, is printed with its new fingerprint and counted as
unclassified; outside `OBSERVE` a call to it is blocked with
`ACTION_UNCLASSIFIED`. For another server, start with `mode: OBSERVE` and no
overrides, read the fingerprints `doctor` prints, and classify each tool the
agent needs, as [run-the-gateway.md](run-the-gateway.md) shows.

### 6. Run the plane

```
guardana-gateway run --config plane.yaml
```

It listens for agents on `127.0.0.1:8080` and answers `/healthz` and
`/metrics` on `127.0.0.1:8081`. The statement confirms the policy for
`policy.max_stale`, ten minutes unless you set it; rerun the `renew` line
before that, less twice `policy.poll_interval`, or every call is blocked with
`POLICY_STALE` and `/healthz` says `"status":"degraded"`.

### 7. Point the client at the plane

Replace the server's entry in the client's configuration with the plane's
address. Most clients take a block like this one; the key names vary between
clients:

```json
{
  "mcpServers": {
    "files": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

A client that can only start servers as commands starts the plane instead,
with `listener.kind: stdio` and no `listener.address` in the profile:

```json
{
  "mcpServers": {
    "files": {
      "command": "/path/to/guardana-gateway",
      "args": ["run", "--config", "/home/you/files-plane/plane.yaml"]
    }
  }
}
```

Then the plane lives as long as the client's session: a call held for approval
is lost when the session ends, and its last records reach the trail when the
client next starts it.

### 8. Make a read and a write

Ask the agent to read a file and then to write one. The read runs. The write
comes back as an error result marked `pending` with the text
`APPROVAL_PENDING`, and its `approval_id` and `retry_after` in `_meta`:

```
guardana-control approvals list approvals
guardana-control approvals approve --approver-id you approvals <approval_id>
```

The same write, retried with the same arguments, now runs once. Retried again
before that approval expires, it is blocked with `APPROVAL_ALREADY_USED`, and
held anew after; an approval covers one exact call.

### 9. Read the report

```
guardana-gateway trail trail.jsonl
guardana-gateway trail export trail.jsonl | bin/evidence-report
```

`trail` checks that each request's events form an unbroken chain.
`evidence-report`, built in step 1, prints a row per request: the tool, the verdict and codes, whether it was held and how
the approval ended, and how the call ended
([read-the-evidence-from-a-program.md](read-the-evidence-from-a-program.md)).

## What this covers and what it assumes

- Every call is made by the listener's configured principal, `me`, for the
  agent `my-client`: the listener authenticates nobody, so any process on the
  machine that reaches `127.0.0.1:8080` acts as that principal.
- Tool calls are decided. Resources and prompts are decided too but route only
  when one upstream is configured; sampling, roots, elicitation and the
  server's own progress never reach the client
  ([reference/mcp-coverage.md](../reference/mcp-coverage.md)).
- A block or a pending state carries its fields in `_meta` and no structured
  content, which a client would check against the tool's output schema.

## Verify

- `doctor` ends with every check `ok` and `0 unclassified`.
- The read returns the file; the write is `pending` until approved and runs
  once after; the report lists both, the write `approved` and `completed`, and
  exits 0 once nothing is open.
- `make check-mcp-client` runs these steps from a checkout with the MCP
  project's Python SDK as the client, and CI runs it on every pull request.

## Roll back

Point the client's entry back at the server and stop the plane. The spool,
the approvals and the trail stay on disk until you remove them.
