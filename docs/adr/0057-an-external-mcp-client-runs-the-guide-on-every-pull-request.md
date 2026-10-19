# ADR-0057: An MCP client outside the Go SDK runs the guide on every pull request

Status: accepted
Date: 2026-10-18

Amends [ADR-0052](0052-a-change-is-gated-on-its-pull-request.md): besides
`make quality`, a pull request is gated on the job this record adds, run
outside it, once the bootstrap applies the required checks.

## Context

The gateway is tested against clients and servers built from the Go SDK the
gateway itself uses. Nothing in CI showed that a client from another
implementation could connect, list the tools, be held for an approval and
resume, and the guide for connecting an existing MCP setup had been tried by
hand once, with one version of the reference filesystem server. The guide
installed that server by name, with nothing pinning its 103 transitive
packages.

## Decision

`scripts/check-mcp-client.sh`, run by `make check-mcp-client`, runs that guide
end to end with an MCP client this module does not contain:

- the MCP project's Python SDK, `mcp` 1.30.0, whose line speaks protocol
  2025-11-25, the newest the gateway serves, locked with hashes in
  `examples/connect-a-filesystem-server/client/uv.lock`;
- the reference filesystem server 2026.8.31, the version the profile's
  fingerprints were taken from, locked with integrity hashes in that
  example's `package-lock.json` and installed with `npm ci --ignore-scripts`.
  Its date-based versions are deprecated since the package resumed semantic
  versioning at 1.0.0, whose 14 tool definitions all fingerprint differently,
  so moving to it is a classification of the profile anew;
- Node.js 24.19.0, pinned with the digest of the asset CI downloads in
  `scripts/tool-versions.env`;
- a plane, a collector and the report program built from the tree, the
  guide's keys, bundle, statement and floors made as the guide makes them,
  on loopback ports picked free.

It holds the plane to the guide's verify list: `doctor` classifies all 14
tools; the client negotiates 2025-11-25 and lists exactly the tools the
profile classifies; a read returns the file; a write is held pending, shown
pending by `approvals list`, and writes nothing; approved, the same write runs
once; retried, it is refused as used; a write the approver rejects is refused;
and the report holds exactly one row per request, each with the verdict,
block, approval and end the steps made, every request ended, with the trail
one unbroken chain per request. A test holds the script to the guide's text:
the script names each command a code block of the guide runs, with the token
after it and every flag the guide passes.

CI runs it as the job "External MCP client" in `ci.yml`, on every pull
request and on `main`, with no condition and no path filter. It is not part
of `make quality`, which runs on a machine with Go and the pinned tools alone
and needs no network for the servers it starts. It is among the required
checks the bootstrap applies; until a maintainer runs the bootstrap, a red run
of it blocks no merge, and `scripts/github-settings-check.sh`, when run,
reports the drift.

Dependabot opens version updates for the client's lockfile. It cannot
propose one for the server, whose maintained 1.x line sorts below 2026.8.31;
the advisory scans over the lockfile are the server's alarm, and Dependabot's
security updates cover the packages below it.

## Security / compatibility impact

None on the product: the job builds the binaries and runs them, and nothing
it installs ships. The job downloads Node.js, uv, CPython and the locked
packages from their public registries, so while one of them is down the job is
red and every merge waits: the admin bypass is not used past a red check
(ADR-0052). The two lockfiles join the advisory scans that already
run over every tracked lockfile in `make quality` and the security workflow,
so an advisory in a test-only package turns those checks red until it is
bumped.

## Alternatives considered

- Inside `make quality`: every machine running the gate would need Node.js and
  network access to two package registries.
- Nightly only: a change that breaks another implementation's client would
  merge and be found a day later.
- The TypeScript SDK as the client: it would add a Node.js project of ours;
  the Python SDK runs on the uv and CPython the repository already pins.
- The MCP inspector's command line, the guide's client when it was tried by
  hand: it prints for a person, and the check needs answers it can assert on.

## Consequences

Each pull request waits for one more job, a few minutes long. A newer server
release is not taken until someone retakes its fingerprints. A plane that
stops leaves what it did not ship in its spool for its next start, so the
check reads the report while the plane runs, as the guide does.

## Validation

The job itself, on every pull request. `internal/docscheck/mcp_client_test.go`
fails when the guide gains a command the script does not run.
