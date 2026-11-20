<div align="center">

# <img src="site/assets/control/mark.svg" height="30" alt=""> Guardana Control

**Decide what your AI agents run. Check what they did.**

Guardana Control puts your rules between an AI agent and its tools. Each call that goes through it is allowed, blocked or held for a person before it runs.

[![CI](https://github.com/guardana/control/actions/workflows/ci.yml/badge.svg)](https://github.com/guardana/control/actions/workflows/ci.yml)
[![Security](https://github.com/guardana/control/actions/workflows/security.yml/badge.svg)](https://github.com/guardana/control/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/guardana/control/badge)](https://scorecard.dev/viewer/?uri=github.com/guardana/control)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15118/badge)](https://www.bestpractices.dev/projects/15118)
[![Release](https://img.shields.io/github/v/release/guardana/control?sort=semver)](https://github.com/guardana/control/releases)
[![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8.svg)](go.mod)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](docs/status.md)

[Website](https://control.guardana.dev) · [Try the demo](docs/get-started/try-the-demo.md) · [Docs](docs/index.md) · [Status](docs/status.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

## What you can do today

- Put the gateway in front of an MCP server and decide each tool call from a
  signed policy before it runs (`experimental`).
- Hold a risky call for a person. An approval covers one exact call, expires
  and works once (`implemented`).
- Let the authorization service you already run veto calls over AuthZEN. It
  can refuse a call and never widen what your policy allows (`experimental`).
- Let a tool of your own ask before it acts, through the enforcement API or
  a coding agent's hooks. Your client enforces the answer (`experimental`).
- Check a recorded run against its procedure, and stop that run's later calls,
  or under signed authority its agent's or principal's, through a signed route
  (`experimental`).
- Read each decision with the policy version that made it, and see in the
  coverage map which paths nobody observed (`experimental`).

[Status](docs/status.md) is the one inventory of what exists.

## Try the demo

The demo needs no Go and no model key. On Linux or macOS:

1. From the [latest release](https://github.com/guardana/control/releases/latest),
   download `guardana-control-demo_<version>_<os>_<arch>.tar.gz`, check it as
   [RELEASING.md](RELEASING.md) shows, extract it and enter its directory.
2. Start the gateway in front of the demo's two servers:

   ```
   bin/guardana-gateway dev --decision-point=silent \
     --config examples/vulnerable-mcp-agent/demo.yaml \
     --policy examples/vulnerable-mcp-agent/policy.json
   ```

3. In a second terminal, set `MCP` to the `mcp` address it printed and call
   the tools as an agent would:

   ```
   examples/vulnerable-mcp-agent/call.sh "$MCP" read_order '{"id":"ord-1"}'
   examples/vulnerable-mcp-agent/call.sh "$MCP" refund '{"id":"ord-1","amount":"500.00"}'
   examples/vulnerable-mcp-agent/call.sh "$MCP" update_order '{"id":"ord-1","status":"cancelled"}'
   ```

   The read runs, the refund is blocked, and the update waits for a person.
   Approve it with the `approve_command` the gateway printed, then send the same
   call again: it runs once.

[The tutorial](docs/get-started/try-the-demo.md) does the same with the
trail of those calls, and [its follow-up](docs/get-started/try-the-rest-of-the-demo.md)
goes on with a pause, the counters and the demo's scenarios.

## How to use it

```
guardana-gateway run --config <file>
guardana-control policy test <dir>
guardana-control policy sign --key <file> --out <file> <document>
guardana-control supervise --procedure <file> --runs <dir> --run <run-id> --findings <dir>
```

- `run` puts the gateway between your agent and its MCP servers:
  [connect an existing MCP setup](docs/guides/connect-an-existing-mcp-setup.md).
- `policy test` proves what your policy decides, case by case, and
  `policy sign` makes the bundle the gateway loads:
  [write and test a policy](docs/guides/write-and-test-a-policy.md).
- `supervise` compares a recorded run with its procedure:
  [supervise and stop a run](docs/guides/supervise-and-stop-a-run.md).

Each release has archives of both binaries for Linux and macOS on amd64 and
arm64, with a signed `checksums.txt`. With Go 1.27.4 or later:

```bash
go install github.com/guardana/control/cmd/guardana-gateway@latest
go install github.com/guardana/control/cmd/guardana-control@latest
```

## What it is not

It is an AI agent supervision framework in alpha, not a security boundary: do
not deploy it as one. It decides only the calls that go through it. The
caller's identity is configured, not logged in. The evidence trail is checked
for order, not yet for tampering (`planned`, [B29](docs/backlog.md)).
Supervision runs when you start it, and a stop refuses later calls without
undoing what already ran. No model grants authority, and prompt and tool
content capture is off by default.

## Related project: Guardana

[Guardana](https://github.com/guardana/guardana) verifies AI systems before
and after deployment. Control decides and checks what agents do while they
run. The projects are independent.

[Governance](GOVERNANCE.md) · [Decision records](docs/adr/README.md) ·
[Code of conduct](CODE_OF_CONDUCT.md) · [Trademarks](TRADEMARKS.md)

[Star Guardana Control on GitHub](https://github.com/guardana/control) to help others find it.
