---
title: Dependencies
summary: Every direct dependency and pinned tool of the module, why the standard library will not do, its licence and whether it sits in the request path.
type: project
covers: [go.mod, go.sum, scripts/tool-versions.env, clients/python/pyproject.toml, clients/python/uv.lock, clients/python/build-constraints.txt]
---

# Dependencies

A new direct dependency needs an entry on this page in the same change that
adds it, stating the problem it solves, why the standard library will not do,
its licence, a maintenance signal, and whether it sits in the request path. A
dependency in the request path gets a stricter review than one in tooling,
because it joins the set of code that has to be audited before a verdict can
be trusted.

`go.mod` is the source of truth. Where this page and `go.mod` disagree, this
page is wrong.

## In the request path

### `google.golang.org/protobuf` v1.36.12

- Problem it solves: encoding, decoding and validating the wire contracts. The
  generated Go under `api/gen/go/` is built against this runtime, and the JSON
  representation goes through `protojson` with unknown fields rejected, see
  [ADR-0002](adr/0002-wire-contracts-and-versioning.md).
- Why the standard library will not do: `encoding/json` carries no schema, no
  generated types, no breaking-change gate, and no rule for a field the
  receiver does not know. Quietly dropping a field the producer believed was
  security-relevant is the failure the contract exists to prevent.
- Licence: BSD-3-Clause, with a separate patent grant file, both in the module.
- Maintenance signal: it is the reference Go implementation of Protobuf,
  developed in `protocolbuffers/protobuf-go` alongside the format itself.
- Request path: yes. It parses input that has not been authorized yet, so a
  version bump is read rather than merged on a green gate.

### `github.com/modelcontextprotocol/go-sdk` v1.8.0

- Problem it solves: speaking the Model Context Protocol on both sides of the
  gateway, at both live revisions: the Streamable HTTP listener toward the
  agent, stateless for `2026-07-28` and stateful for `2025-11-25` and older,
  the stdio listener, and the client toward each upstream server. The
  receiving middleware it exposes is the one interception point of
  [ADR-0013](adr/0013-mcp-interception-approvals-and-modes.md).
- Why the standard library will not do: the protocol is JSON-RPC over three
  transports with per-revision negotiation, session handling, routing-header
  checks and result shapes that changed between revisions. Reimplementing two
  revisions of that and keeping them in step is what the module's authors do;
  it is the reference Go implementation of the protocol.
- Licence: read from the module's `LICENSE` file. The project is moving from
  MIT to Apache-2.0: contributions whose authors consented are Apache-2.0,
  contributions whose authors have not yet consented stay MIT, and the file
  carries both texts. The Go source files themselves still carry an MIT-style
  header. Both licences are permissive and compatible with this project's.
- Maintenance signal: the module is published from
  `modelcontextprotocol/go-sdk`, the organisation that publishes the protocol;
  v1.8.0 was released on 2026-09-14 as a copy of v1.8.0-pre.2, whose commit is
  dated 2026-09-04, and the module ships a security policy. Nothing else about
  the project's activity was checked.
- Request path: yes. It parses every request from the agent before policy
  runs and every answer from an upstream after an allowed call, so a version
  bump is read rather than merged on a green gate. It is imported by `adapters/mcp` and by
  `cmd/guardana-gateway`, which builds the upstream transports; a test in
  `internal/gateway` refuses the import there.
- What it links: the module pulls eight more into the binary that serves the
  adapter, none of them imported by this repository's own code. Each licence
  below was read in the module cache of the version `go.mod` pins:
  `github.com/google/jsonschema-go` v0.4.3 (MIT), which validates tool schemas;
  `github.com/segmentio/encoding` v0.5.4 (MIT) and `github.com/segmentio/asm`
  v1.1.3 (MIT), its JSON encoder and that encoder's assembly kernels;
  `github.com/yosida95/uritemplate/v3` v3.0.2 (BSD-3-Clause, the text in its
  `LICENSE` file), which expands resource templates; `golang.org/x/oauth2`
  v0.35.0, `golang.org/x/sync` v0.23.0, `golang.org/x/sys` v0.48.0 and
  `golang.org/x/time` v0.15.0 (all BSD-3-Clause), for the bearer-token
  middleware, the transports' concurrency helpers, system calls and its rate
  limiter. They sit in the request path with the module that brings them, and a
  bump to any of them is read the same way.

Beside those, code that ships imports only protobuf; `go list -deps
./adapters/mcp` names the set above and nothing more. The test-only entry and Goldmark, both below, are the only other modules this
repository imports itself. `examples/evidence-report`
is a module of its own that requires this one through a `replace`, so it reaches
protobuf and nothing else, and ships in no binary
([ADR-0037](adr/0037-an-evidence-consumer-in-a-module-of-its-own.md)). There is no database
driver and no logging library in the tree. The dependency rule of
[ADR-0007](adr/0007-repository-layout-and-dependency-rule.md) admits no module
but protobuf, and no standard library package it does not name, into the part
that decides; a new one there means an edit to that rule. The MCP module is
imported outside that part, by the adapter and by the gateway's command.

### `gcr.io/distroless/static-debian12:nonroot`

- Problem it solves: the base of the gateway's container image. It gives the
  binary CA certificates to check its upstreams', decision point's and
  collector's TLS certificates, a `nonroot` user (65532) to run as, `/tmp`,
  and the time zone database. `.goreleaser.yaml` names it by the digest of its
  multi-platform index, read from the registry, so a tag the upstream moves
  cannot change what ships.
- Why not `scratch`: the Go binary needs no C library, but `scratch` holds no
  CA certificates and no user entry, so the image would have to carry and
  refresh both itself.
- Licence: the build definitions in `GoogleContainerTools/distroless` are
  Apache-2.0. The image holds five Debian 12 packages, their licences read from
  each `/usr/share/doc/<package>/copyright` in the image: `base-files` 12.4+deb12u15
  (GPL-2+), `ca-certificates` 20250419~deb12u1 (GPL-2+ and MPL-2.0),
  `media-types` 10.0.0 (public information, no restriction stated), `netbase`
  6.4 (GPL-2) and `tzdata` 2026b-0+deb12u1 (public domain). They are data
  files and are not linked with the gateway; their source is Debian's.
- Maintenance signal: the repository is published by Google's container tools
  organisation, is not archived, and its last commit is dated 2026-09-24. The
  images are rebuilt from Debian's updates, which is why the digest is bumped
  by hand rather than followed.
- Request path: yes. It is the filesystem the gateway runs on, so a digest
  bump is read, as a dependency bump is, rather than merged on a green gate.

## Test-only

Imported by `_test.go` files. `go build ./...` does not link them, so none of
them reaches a released artifact.

### `pgregory.net/rapid` v1.3.0

- Problem it solves: property tests for the canonical JSON serializer and the
  action digest. A canonicalizer is a total function over a very large input
  space, and the inputs that break it are the ones nobody thought to write
  down. `rapid` generates them, and when one fails it shrinks the failure to
  the smallest input that still fails, which is what makes a property failure
  something a person can act on.
- Why the standard library will not do: `testing/quick` generates values but
  does not shrink, so a failure arrives as a random deep tree rather than the
  two-key object that actually breaks the ordering rule. Go's native fuzzing is
  used here too and covers byte inputs; it does not build typed trees of the
  shape the canonicalizer takes.
- Licence: **MPL-2.0**. File-level copyleft: modifying one of its source files
  would keep that file under MPL, while using the library unmodified does not
  affect this project's Apache-2.0 licensing. It is never linked into a
  released artifact.
- Maintenance signal: v1.3.0, published 2026-03-30, read from pkg.go.dev in the
  session that added this entry. Nothing else about the project's activity was
  checked, so this line says less than the entries above it.
- Request path: no.

## Developer tooling

Pinned as `tool` directives in `go.mod`, so they arrive with `go mod download`
at the version the module records. None of them is linked into a shipped
binary and none is in the request path.

| Tool | Module | Used by | Licence |
| --- | --- | --- | --- |
| `protoc-gen-go` | `google.golang.org/protobuf` | `make proto`, `make proto-check` | BSD-3-Clause |
| `goimports` | `golang.org/x/tools` | `make fmt`, `make fmt-check` | BSD-3-Clause |
| `govulncheck` | `golang.org/x/vuln` | `make security`; in binary mode, `scripts/scan-binaries.sh` over every binary of every release archive and the image's binary for each platform, before a release is attested or published | BSD-3-Clause |

Every other module in `go.mod` but Goldmark (below) is marked `// indirect` and arrives through
those three or through the MCP module: `golang.org/x/mod`, `golang.org/x/sync`,
`golang.org/x/sys`, `golang.org/x/telemetry`, `golang.org/x/tools` and
`golang.org/x/vuln` through the tools; `github.com/google/jsonschema-go`,
`github.com/segmentio/asm`, `github.com/segmentio/encoding`,
`github.com/yosida95/uritemplate/v3`, `golang.org/x/oauth2` and
`golang.org/x/time` through the MCP module, and those six are linked into the
gateway with it. No code in this repository imports them.

## Tools that are not Go modules

`golangci-lint`, `buf`, `actionlint`, `zizmor`, `gitleaks`, `osv-scanner`,
`shellcheck`, `syft`, `goreleaser`, `cosign` and `uv` are pinned in
`scripts/tool-versions.env` and checked by `make bootstrap`, which fails on a
version mismatch rather than continuing. The Go compiler is pinned separately,
by the `go` directive in `go.mod`, see
[ADR-0001](adr/0001-language-and-toolchain.md).

All but `goreleaser`, `syft` and `cosign` run targets of the gate. Those three
build a release, in `.github/workflows/release.yml` and in
`make release-snapshot`, and CI checks each download against the digest pinned
beside its version:

- `goreleaser` (MIT) builds the two binaries and the demo's servers for Linux
  and macOS, packs a product archive and a demo archive per platform, writes `checksums.txt`, builds and pushes the
  gateway's image with the `ko` library it links (Apache-2.0), and drafts the
  GitHub release, from `.goreleaser.yaml`. `ko` adds no download of its own;
  what it fetches is the base image above. Doing that by hand in the workflow
  would be a long script that nothing else tests.
- `syft` (Apache-2.0) writes a CycloneDX bill of materials for each archive,
  from the module information Go records in each binary.
- `cosign` (Apache-2.0) signs `checksums.txt` and the image's digest without a
  key, with a certificate for the release workflow's identity, and verifies
  both signatures before the release is published.

None of these is a dependency of the product, and nothing in the tree imports
any of them.

## The Python client

The client under `clients/python/` has no dependency at run time: it imports
the standard library alone, and a test reads its imports
([ADR-0053](adr/0053-a-python-client-of-the-enforcement-api-in-this-repository.md)).
Its checks and its build use these, none of them in a request path:

- `uv` (Apache-2.0 or MIT), pinned by version and digest in
  `scripts/tool-versions.env`, installs the two CPython builds the tests run
  on and the tools below from `clients/python/uv.lock`. The standard library's
  `venv` and `pip` pin neither an interpreter build nor every hash in one
  file. Maintained by Astral, with frequent releases.
- `ruff` (MIT) lints and checks formatting, and `mypy` (MIT) checks types.
  Both are locked with hashes and run only in `make check-python`.
- `flit_core` (BSD-3-Clause) builds the wheel and the source archive. It has no
  dependencies of its own and is pinned by hash in
  `clients/python/build-constraints.txt`. A wheel installs without it.
- CPython (PSF licence), the two versions named in
  `scripts/tool-versions.env`, as uv installs them.

## The website

`site/` holds the website's static files ([ADR-0030](adr/0030-a-static-website-drawn-from-the-repository.md)),
and one Go module renders its documentation pages. No binary or image of the
product contains what this section lists.

### `github.com/yuin/goldmark` v1.8.6

- Problem it solves: rendering the documentation's Markdown into the site's
  pages under `site/docs/`, with the tables, strikethrough and bare links the
  pages use as GitHub shows them
  ([ADR-0031](adr/0031-the-documentation-is-served-on-the-website.md)). The
  renderer in `internal/docscheck/sitedoc/docsite` walks its syntax tree to
  rewrite links, set heading anchors and refuse raw HTML.
- Why the standard library will not do: it has no Markdown parser, and
  CommonMark's block and inline rules are too many to keep by hand beside the
  pages they would have to agree with.
- Licence: MIT, copyright Yusuke Inuzuka, read from the module's `LICENSE`.
  The module has no dependency of its own.
- Maintenance signal: v1.8.6 was published on 2026-09-03, read from the module
  proxy in the session that added this entry. Nothing else about the project's
  activity was checked.
- Request path: no. Only `internal/docscheck` imports it, and `go list -deps`
  over `cmd/`, `pkg/`, `adapters/` and `examples/` does not reach it, so no
  binary or image of the product contains it.

### IBM Plex Sans and IBM Plex Mono

- Problem it solves: the website's type, six WOFF2 files served from the site
  itself, so the page loads nothing from another host.
- Why not the system fonts: the page shares its visual system with Guardana's
  site; the system font stacks stay the fallback in `tokens.css`.
- Licence: SIL Open Font License 1.1, copyright IBM Corp., read from
  `site/assets/brand/v1/fonts/OFL.txt`, which is served beside the fonts as the
  licence asks of every copy.
- Maintenance signal: `IBM/plex` is not archived and was last pushed on
  2026-09-22.
- Request path: no.

### Brand v1, copied from Guardana

- Problem it solves: the colour and type tokens, fonts and marks the two
  projects' sites share, in `site/assets/brand/v1/`.
- Why a copy: Control depends on nothing from Guardana
  ([ADR-0024](adr/0024-control-and-guardana-are-independent.md)). The copy is
  Control's own from the day it was taken; a test pins the digest of its
  `SHA256SUMS`, and a change is a v2 at a new path, never an edit in place.
- Licence: Apache-2.0, as Guardana's repository; the fonts as above. Guardana's
  marks in the copy remain Guardana's.
- Maintenance signal: none needed; nothing follows the original.
- Request path: no.

## GitHub Actions used by the workflows

An action runs inside the workflows that decide whether a change may merge, so
it is a dependency of the release and review path even though it never ships.
Each is pinned to a commit SHA with the version in a trailing comment;
`make check-actions` fails on a reference that is not, and `zizmor` and
`actionlint` read the same files. None of them is in the request path.

| Action | Why it is here | Licence |
| --- | --- | --- |
| `actions/checkout` | Fetches the tree every job works on | MIT |
| `actions/setup-go` | Installs the compiler named by `go-version-file: go.mod` | MIT |
| `bufbuild/buf-action` | Installs the pinned `buf`, with `setup_only`; `make proto-check` and the breaking-change step drive it. It replaced the archived `bufbuild/buf-setup-action` | Apache-2.0 |
| `golangci/golangci-lint-action` | Installs the pinned linter, with `install-only`; `make lint` runs it | MIT |
| `github/codeql-action` | CodeQL static analysis, and the SARIF upload that publishes the supply-chain score to code scanning | MIT |
| `actions/dependency-review-action` | Blocks a pull request that adds a vulnerable dependency | MIT |
| `ossf/scorecard-action` | Scores the repository's own supply-chain settings | Apache-2.0 |
| `actions/upload-artifact` | Keeps the raw supply-chain result that code scanning would trim, and the dry run's release build | MIT |
| `actions/attest-build-provenance` | Records signed build provenance for every release asset and for the image before the release is published | MIT |

Licences were read from each action's repository metadata, not from a scanner.
