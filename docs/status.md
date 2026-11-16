---
title: Implementation status
summary: What exists in this repository today, component by component, the one inventory every other page points to.
type: project
covers: [adapters/**, api/proto/**, cmd/**, internal/**, pkg/**]
---

# Implementation status

What exists in this repository today, component by component. Every other
document points here rather than keeping its own list, so this is the only
inventory in the project and the one that has to be right.

Components are grouped by what they do, one table per group, and each row
gives a stable id, a status and one sentence. The sentence's details link
leads to the paths, tests, records and limits behind it.

The product goal is observation across connected agent paths, supervision
against procedures and reactions within scoped authority. That complete 1.0
target is `planned`; [control and supervision](concepts/control-and-supervision.md)
explains it and [the roadmap](../ROADMAP.md) orders its delivery. The inventory
below describes what the alpha can actually do.

In short:

- What you can do today: put the gateway between an MCP client and its
  servers and decide each tool call from a signed policy, allowing it,
  blocking it or holding it for one approval of that exact call. Each decision
  is recorded with the policy version that made it. An external AuthZEN
  decision point can veto configured calls without granting authority. A tool
  outside MCP can ask a plane serving the enforcement API before it acts and
  enforce the answer itself. You
  can import runtime traces and an egress proxy's access log as observations,
  inspect coverage, and check one
  opened run against its procedure, draw it as a page, hand its findings to a
  program, and stop that run where a signed route allows it.
- The limits: the gateway sees only the calls routed through it, the caller's
  identity comes from its configuration rather than a login, and the evidence
  trail is not tamper-evident. It is not a security boundary.
- What to download: the
  [latest release](https://github.com/guardana/control/releases)'s demo
  archive runs the demo with no Go and no model key, its platform archive holds
  `guardana-gateway` and `guardana-control`, and the image `ghcr.io/guardana/control-gateway` holds the
  gateway. [The tutorial](get-started/try-the-demo.md) starts there.

What the labels mean:

- `implemented`: it exists and a command in this repository exercises it.
- `experimental`: it exists and can still change without a major version.
- `planned`: it is not built. Its details name the path it will take, the
  record that defines it, or say that no path has been chosen yet. A path that
  already holds a package doc and a test holds nothing that decides.

Nothing here is a security boundary. Do not deploy it as one.

## Components

### Decisions

| ID | Component | Status | What it does |
| --- | --- | --- | --- |
| wire-contracts | Wire contracts, frozen at `1.0` | `implemented` | The versioned wire messages for actions, decisions, approvals, bundles, results, findings and evidence events, frozen at `1.0` and checked for breaking changes against the latest release. [details](#wire-contracts) |
| strict-decoding | Bounded validation and strict decoding | `implemented` | Reads an action envelope within fixed bounds and refuses unknown fields and undeclared enum numbers, inside map entries too. [details](#strict-decoding) |
| effect-labels | Effect materiality and sensitivity floors | `implemented` | States how material an action's effect is, the sensitivity floor its data carries and the toxic-flow predicate, which the kernel and the matcher read. [details](#effect-labels) |
| reason-codes | Reason-code registry | `implemented` | The registry of the reason codes a decision can carry, and the reference page generated from it. [details](#reason-codes) |
| decision-kernel | Decision kernel | `implemented` | Decides each action in a fixed order, with a fail-closed table and a delegation check; it runs `ENFORCE` only, and the modes belong to the enforcement point. [details](#decision-kernel) |
| action-digest | Canonical action digest | `implemented` | One digest over an action's canonical form, the value an approval binds to; parity with a second implementation is unproved. [details](#action-digest) |
| policy-cli | Policy command line | `implemented` | Writes keys and lints, tests, explains, signs and renews policies with `policy lint`, `test`, `explain`, `keygen`, `sign`, `renew` and `state`. [details](#policy-cli) |
| starter-packs | Starter policy packs | `experimental` | Two starter policies, read-only and approval-for-writes, each with allow, deny and unknown cases that the tests run. [details](#starter-packs) |
| policy-keys | Policy keys and signed bundle files | `implemented` | The private key, public key and bundle files that `policy keygen` and `policy sign` write and the gateway reads, on Unix-like systems only. [details](#policy-keys) |
| policy-matcher | Policy documents, signed bundles and the matcher | `implemented` | Parses a policy document strictly, signs and verifies its bundle, and evaluates each rule as true, false or unknown, where an unknown allow grants nothing. [details](#policy-matcher) |
| policy-floor | Policy serial floor on disk | `experimental` | Keeps, per bundle, the highest serial accepted, in an owner-only directory, so that an older bundle is refused. [details](#policy-floor) |
| policy-refresh | Policy refresh on a plane | `experimental` | A running plane rereads its bundle and freshness statement, installs a newer bundle only with its statement, and stops confirming its policy when its clock cannot be trusted. [details](#policy-refresh) |
| external-pdp | External policy decision point (PDP) | `experimental` | An external decision point asked over AuthZEN can veto a call the policy allows, and never grants authority of its own. [details](#external-pdp) |
| approval-binding | Approval binding | `implemented` | An approval binds to one exact action digest and one bundle digest, and the gateway spends it once, on the retry of that call. [details](#approval-binding) |
| approval-authority | Approval authority and the lost hold | `experimental` | Who may answer a held call, through a records directory or operator signatures, by command or a local page; a hold journal closes a hold a restart lost. [details](#approval-authority) |
| candidate-policy | Candidate-policy comparison and simulation | `planned` | Comparing a candidate policy with the current one and simulating it; no diff or simulation command is built. [details](#candidate-policy) |

### Integrations

| ID | Component | Status | What it does |
| --- | --- | --- | --- |
| mcp-gateway | Model Context Protocol (MCP) gateway | `experimental` | Decides each tool call, resource read and prompt from a signed policy before it reaches an MCP server; `policy.fail_open_read` lets a read run while the policy is unavailable. [details](#mcp-gateway) |
| credential-echo | Withholding an answer that quotes a credential | `experimental` | Withholds an upstream answer that quotes a credential the plane sends, raw, escaped or in base64; it catches an echo, not an upstream set on leaking. [details](#credential-echo) |
| enforce-client | Enforcement API reference client and conformance cases | `experimental` | A Go client that admits, completes and aborts a tool call over the enforcement API, and the cases and answer vectors a client must pass. [details](#enforce-client) |
| python-client | Python client of the enforcement API | `experimental` | A Python package, `guardana-control`, that admits a tool call, runs the tool with the authorized bytes only and closes the call; it cooperates rather than enforces. [details](#python-client) |
| enforce-receiver | Enforcement API receiver | `experimental` | Lets a tool outside MCP ask the plane over a Unix socket before it acts; the client enforces the answer, so nothing proves it obeyed. [details](#enforce-receiver) |
| hook-bridge | Coding-agent hook integration | `experimental` | Admits a coding agent's tool calls through the enforcement API from the runtime's own hooks, with one built-in runtime profile qualified on two of its releases. [details](#hook-bridge) |
| connect-filesystem | Connect an existing MCP setup | `experimental` | A guide and a profile that put the reference filesystem server's tools behind the gateway under the approval-for-writes pack, which an external client runs on every pull request. [details](#connect-filesystem) |
| mcp-config-preview | Preview, apply and undo an existing MCP configuration | `planned` | Previewing, applying and undoing a change to an existing MCP configuration; no command is built. [details](#mcp-config-preview) |
| tool-definition-review | Tool-definition change review | `planned` | A report and review of changes to an upstream's tool definitions; classification is bound to fingerprints, but no review workflow is built. [details](#tool-definition-review) |
| a2a-adapter | Agent-to-agent (A2A) adapter | `planned` | An adapter for the agent-to-agent protocol; it is not built. [details](#a2a-adapter) |
| framework-clients | Framework SDKs and clients in more languages | `planned` | Clients of the enforcement API in more languages, and framework SDKs, for which no framework is chosen. [details](#framework-clients) |
| more-channels | More notifiers and channels | `planned` | Notifiers beyond the local program, and channels beyond MCP, the enforcement API, its hook bridge and the trace and egress access-log sensors. [details](#more-channels) |

### Evidence

| ID | Component | Status | What it does |
| --- | --- | --- | --- |
| evidence-chain | Evidence event chain, in memory | `implemented` | Builds each call's evidence events into a chain, validates its order and reads and writes it as JSON Lines, reading no clock and touching no file. [details](#evidence-chain) |
| evidence-spool | Evidence spool | `experimental` | The plane's evidence log on disk, checked per record, synced by policy and recovered after a crash, from which records are exported. [details](#evidence-spool) |
| otel-export | OpenTelemetry export | `experimental` | Sends evidence as OpenTelemetry logs over HTTPS or a Unix socket, counting a batch delivered only on the collector's own answer and quarantining what it refuses. [details](#otel-export) |
| trail-collector | Collector and trail segments | `experimental` | A collector of the project's own that takes exported evidence behind a credential and keeps it as bounded segments of one tenant and project, read back as trails. [details](#trail-collector) |
| evidence-export | Evidence export and a bounded query | `experimental` | Writes a trail's events in a versioned JSON Lines format, resumable from a cursor and filtered by request, run, tenant, project and kind, exiting 1 on any gap. [details](#evidence-export) |
| observations | Observations from sensors | `experimental` | Imports OpenTelemetry GenAI traces and an egress proxy's access log as observation records, each source described by a descriptor, and keeps no content. [details](#observations) |
| coverage-map | Coverage map per declared path | `experimental` | Reads plane configurations, evidence exports and observations from files and says, per declared path, whether its calls were enforced, decided but not enforced, observed, unknown or not covered. [details](#coverage-map) |
| host-process-events | Host process events | `planned` | Process events from the host an agent runs on, a second sensor independent of the agent, as [backlog B35](backlog.md) describes. [details](#host-process-events) |

### Supervision and reaction

| ID | Component | Status | What it does |
| --- | --- | --- | --- |
| operator-runs | Runs an operator opens | `experimental` | An operator opens a run with its own token and durable flow state, and a plane with a runs directory admits a call only under a live run's token. [details](#operator-runs) |
| run-supervision | Supervision of a run against its procedure | `experimental` | Checks one opened run, or a root and its tree, against its procedure when an operator asks, reports findings, draws the run as a page and alerts a notifier. [details](#run-supervision) |
| run-stop | Stopping a run through a signed route | `experimental` | A confirmed finding stops one opened run's later calls where a signed route allows it; a call already running is not cut. [details](#run-stop) |
| finding-review | Finding review and an incident package | `planned` | Reviewing findings with a case history and exporting a joined incident package; findings export exists, and neither of these is built. [details](#finding-review) |
| web-ui | Web UI | `planned` | A web interface; no path is chosen, and one run is drawn as a static page by `supervise --view`. [details](#web-ui) |
| graph-api | Graph API | `planned` | A graph API; no path is chosen and no milestone names it. [details](#graph-api) |

### Operations

| ID | Component | Status | What it does |
| --- | --- | --- | --- |
| trust-roster | Trust roster, authentication and authorization ports | `experimental` | Names the operators a plane trusts in a roster signed by a pinned root key, with grants of tenant, project and level, behind authentication and authorization ports. [details](#trust-roster) |
| scenario-runs | Scenarios held against a live plane | `experimental` | Runs a scenario against a running plane as its MCP client and compares each call's answer, decision and trail with what the scenario expects. [details](#scenario-runs) |
| dev-mode | Dev mode | `experimental` | One command, `guardana-gateway dev`, starts a local plane with the demo's signed policy, a collector and the approvals page, in a new state directory. [details](#dev-mode) |
| demo-servers | Demo servers and scenarios | `experimental` | Two vulnerable MCP servers, their plane and seven scenarios, shipped in an archive per platform that runs without Go or a checkout. [details](#demo-servers) |
| backup-restore | Backup and restore of authority state | `experimental` | Backs up a plane's floors, runs, pause file and stop list, and restores them only upward: every floor rises and every run closes. [details](#backup-restore) |
| control-plane-api | Control plane API | `planned` | A control plane API; it is not built. [details](#control-plane-api) |
| storage | Storage | `planned` | A storage layer; it is not built. [details](#storage) |

### Project

| ID | Component | Status | What it does |
| --- | --- | --- | --- |
| go-module | Go module and pinned toolchain | `implemented` | One Go module with a pinned toolchain, and a bootstrap that checks Go and every gate tool against their pinned versions. [details](#go-module) |
| quality-gate | Quality gate | `implemented` | One `make quality` runs the tests, lint, the dependency rule, the secret and dependency scans and the documentation checks; probes show the import and scan checks can fail. [details](#quality-gate) |
| brand-rename | Brand indirection and one-command rename | `implemented` | Code reaches the product's name through one package, a check refuses the name spelled elsewhere, and one script renames the product. [details](#brand-rename) |
| decision-records | Architecture decision records | `implemented` | Each decision that outlives its change is a numbered record of its context, the alternatives rejected and the check that enforces it. [details](#decision-records) |
| continuous-integration | Continuous integration | `implemented` | Every pull request and push to main runs the whole gate on Linux, beside security scans, an external MCP client, a two-account job and nightly race and fuzz runs. [details](#continuous-integration) |
| releases | Releases built, signed and attested from a tag | `experimental` | A version tag, once a maintainer approves, builds signed and attested archives for Linux and macOS, demo archives and a gateway image, and publishes the Python client. [details](#releases) |
| benchmarks | Benchmarks | `implemented` | Measures validation, the digest, a decision at 10, 100 and 1000 rules and one MCP call through the gateway against the same call made directly. [details](#benchmarks) |
| website | Website for `control.guardana.dev` | `experimental` | A static landing page with no script and every documentation page rendered beside it, generated from this repository and deployed from main. [details](#website) |

`make quality` names every check that runs today. Read the `Makefile` for the
exact set rather than a list in prose, which drifts.

## Details

### wire-contracts

`api/proto/guardana/control/v1/` (8 files), generated Go in `api/gen/go/`.
`make proto-check` regenerates and diffs; `buf breaking` runs against the latest
release tag, in CI on every push and pull request and in `make proto-breaking`

### strict-decoding

`pkg/contract/`. Unknown fields and undeclared enum numbers refused on both wire
paths, inside map entries too, which `Decode` reads before the runtime parses
them ([ADR-0002](adr/0002-wire-contracts-and-versioning.md))

### effect-labels

`pkg/contract/effect.go`, `labels.go`; the kernel's tenant rule and fail-closed
table read materiality, the matcher reads the floors

### reason-codes

`internal/policy/reasons/`,
[reference/reason-codes.md](reference/reason-codes.md), which the registry
generates. The kernel and the matcher emit codes as their own literals, each
held to the registry by a test; nothing on the decision path imports the
registry

### decision-kernel

`internal/core/`, `internal/core/delegation/`,
[ADR-0012](adr/0012-policy-kernel-semantics.md). `policy test` and 25 fixtures
under `testdata/policy/fixtures/` exercise every verdict and every cause but the
clock, the external decision point's answers among them, and
`internal/core/clock_test.go` holds the clock step; a 10 000-case determinism
property and `FuzzDecide` run in `make test` and `make fuzz-smoke`. `ENFORCE`
only; the modes are the enforcement point's
([ADR-0013](adr/0013-mcp-interception-approvals-and-modes.md)), and
`internal/gateway/` calls `Decide` on every call it admits, and `Recheck` before
it consumes an approval and before and after it records `ACTION_STARTED`, so a
bundle replaced or stale by then blocks the call with `POLICY_STALE` outside
`OBSERVE`, except a read the fail-closed table opened under that same bundle
([ADR-0055](adr/0055-a-call-is-handed-out-only-while-its-policy-stands.md));
`internal/core/recheck_test.go` holds `Recheck` to a second decision at the
hand-out reading

### action-digest

`internal/canon/`, goldens in `testdata/digest/`,
[ADR-0005](adr/0005-canonical-action-digest.md) and
[ADR-0010](adr/0010-digest-domain-separation.md). Cross-language parity is
unproved until a second implementation exists

### policy-cli

`cmd/guardana-control/`,
[guides/write-and-test-a-policy.md](guides/write-and-test-a-policy.md),
[reference/policy-explain.md](reference/policy-explain.md). `policy lint`,
`policy test`, `policy sign` and `guardana-gateway dev` refuse an obligation
parameter the catalogue does not declare for its type, a missing required one or
a malformed value; `policy explain` and loading a bundle do not check them
([ADR-0061](adr/0061-an-obligations-parameters-are-the-catalogues.md)).
`policy explain` decides a case through the kernel's own evaluation and names
the rules that matched and the inputs a rule lacked
([ADR-0036](adr/0036-policy-explain-reads-the-kernels-own-evaluation.md)).
`policy renew` writes a freshness statement and keeps a serial floor, and
`policy state init` and `reset` make and reset a floor (`experimental`,
[rows below](#policy-floor)).

The same binary holds the `approvals` commands and the `console` page in the
[approval authority row](#approval-authority) below, and the page's loopback
listener is its one server; `policy diff` is `planned`

### starter-packs

`examples/starter-packs/`,
[reference/starter-packs.md](reference/starter-packs.md). Each is a document and
its allow, deny and unknown cases; `cmd/guardana-control`'s tests run every case
and hold each case's document to the pack's

### policy-keys

`internal/policykey/` (the private key file and its reader, the public key line
and its one parser, the derived key id, the bundle file, and the freshness
statement's file, `experimental`), `internal/files/` (create without replacing,
replace, bounded read of a regular file), `internal/keytext/` (the withholding
and quoting both binaries and the approvals page print through, which reads no
key), [ADR-0018](adr/0018-keys-and-bundles-on-disk.md). `policy keygen` and
`policy sign` write them and the gateway parses `policy.public_key` through the
same package.

Unix-like systems only; the approvals store, the hold journal and the spool
carry their own file code

### policy-matcher

`internal/policy/rules/` parses `agent-policy/v1alpha1` strictly,
`internal/policy/bundle/` signs and verifies bundle bytes (Ed25519 over the DSSE
PAE); `internal/policy/match/` evaluates three-valued; `internal/policy/` loads
a bundle into a snapshot and installs it in order;
[ADR-0003](adr/0003-policy-model-and-external-pdp.md),
[ADR-0012](adr/0012-policy-kernel-semantics.md). A holder pinned to the bundle
id it serves refuses every other. On a plane a snapshot is confirmed only by a
freshness statement bound to its bundle and signed under a key apart from the
bundle's, and its serial floor is ordered by serial and then `issuedAt`
(`internal/policy/statement.go`, `floor.go`, `experimental`,
[ADR-0038](adr/0038-a-signed-freshness-statement-and-a-serial-floor.md)); an
unconfirmed snapshot decides `POLICY_STALE`

### policy-floor

`internal/policystate/`. One strict-JSON file per bundle id in an owner-only
directory whose marker names a plane's or a signer's kind; raised under the
directory's lock against the file's value; `Init` and `Reset` are the
operator's, and the gateway binary holds neither
([ADR-0038](adr/0038-a-signed-freshness-statement-and-a-serial-floor.md)). The
commands use it (`policy renew`, `policy state init` and `reset`), and so does
every plane, through `policy.state_dir`. A floor protects only while its
directory outlives the plane, and an account that can write the directory can
lower it

### policy-refresh

`internal/policywatch/`, wired by `cmd/guardana-gateway/planepolicy.go`,
[ADR-0038](adr/0038-a-signed-freshness-statement-and-a-serial-floor.md). At
start judges the floor, the bundle and the statement: a bundle below or beside
the floor, or above it without its statement, refuses the start, and a missing
or expired statement starts the plane unconfirmed. Then reads both files every
`policy.poll_interval`, installs a newer bundle only with its statement, refuses
and counts every bad replacement without moving the confirmation, and withdraws
the confirmation while the wall clock, measured against the monotonic clock, has
fallen back more than a second plus 100 parts per million of the time since its
highest reading, or reads too far from the first reading to judge, and until a
statement issued after that arrives.

A clock reading outside 1970 to 9999, or behind the verified time, the latest
`issuedAt` the plane verified, decides nothing: every call is `POLICY_STALE`,
reads included. `/healthz`, `/metrics` and `doctor` report it. Freshness trusts
the plane's clock at start, and the operator schedules `policy renew`; nothing
in the repository schedules it outside `dev`

### external-pdp

[ADR-0017](adr/0017-an-external-decision-point-can-veto.md). The kernel takes
the answer and the policy format reads it (`internal/core/`,
`internal/policy/`); `adapters/authzen/` asks and reads the answer strictly;
`internal/gateway/` asks only when the answer can change the decision;
`cmd/guardana-gateway` configures it from the `pdp.` keys, checks its published
metadata in `doctor` and counts the asks on `/healthz`. The end-to-end tests
reach a decision point on the loopback over plaintext; TLS is exercised in the
adapter's own tests, against the roots a test hands it, and the command has no
setting for a private certificate authority

### approval-binding

`internal/core/approval/` (`Bind`), golden in `testdata/digest/binding.json`.
`internal/gateway/` holds a request for approval, keeps the record of what it
minted itself, and spends the approval exactly once on the retry, in its own
ledger ([ADR-0013](adr/0013-mcp-interception-approvals-and-modes.md)). An
approver outside the plane answers through the
[approval authority](#approval-authority) below; a hold does not survive a
restart, and a plane that keeps a hold journal closes the trail of one it lost
at its next start, and counts one it cannot close as left open
([ADR-0016](adr/0016-approval-providers-and-the-lost-hold.md))

### approval-authority

- `internal/approvals/` (a directory of records an approver writes and the plane
  reads back, two openers kept apart by the compiler, `0600` records under an
  owner-only directory, each refused when read if another account owns it or a
  group or the world may write it)
- `internal/holdjournal/` (the plane's own durable record of its own holds,
  under its own exclusive lock, refusing a directory another account owns, and
  an entry or marker another account owns or a group or the world may write, and
  beside it the ledger of the approvals the plane spent or gave up on), the
  `HoldJournal` and `Ledger` seams and the reconciliation in
  `internal/gateway/`, `approvals list`, `approve` and `reject` in
  `cmd/guardana-control/`, which sign an answer with `--key` and file it in the
  inbox under `signed` and refuse a claim for a signed hold, a sweep in
  `cmd/guardana-gateway/` that forgets expired records and ledger marks older
  than `approvals.ttl` every quarter of it while the plane serves, and counts a
  sweep that fails in `/healthz`, and `console`, a page on `127.0.0.1` that
  lists, approves, rejects and pauses through the same directory and pause file
  (`internal/console/`, [reference/console.md](reference/console.md),
  [ADR-0023](adr/0023-a-local-page-answers-through-the-directory.md)), the
  `ApprovalAuthority` port of `internal/gateway/` with its `directory` and
  `signed` kinds (`testdata/ports/approval-authority/`), the signed answer
  format `approval-answer/v1alpha1` and the inbox in
  `internal/approvals/inbox/`, the `approvals.authority` keys in
  `internal/gatewayconfig/`, which have no default
- [ADR-0016](adr/0016-approval-providers-and-the-lost-hold.md)
- [ADR-0073](adr/0073-an-approval-counts-only-as-the-plane-judges-it.md)
- [concepts/approvals-and-the-held-call.md](concepts/approvals-and-the-held-call.md)

Only the plane marks an approval spent, in its own store: approvals directory
`2.1` holds what the plane held, under which authority, and what approvers
answered, and no file there reads as spent or given up. Under `directory` and
`memory`, write access to where answers are read is the approval authority and
`approver_id` is an unauthenticated claim, and one that reads as the reserved
`authn:` prefix is refused when it is written and when it is read
([ADR-0066](adr/0066-each-decision-about-authority-is-a-port.md)); under
`signed` an answer counts only signed by a roster operator granted the call's
tenant and project, and the console, which holds no operator key, shows a signed
hold and the command that signs it and answers nothing, and writes no pause
under `signed` or into a signed pause file; a `dev` plane runs `signed` with an
operator key in its own state directory, so its own account approves and pauses;
a `memory` plane keeps no hold journal and does not close a lost hold; a hold
journal restored from a copy older than its approval's spend is read as live, so
the next start closes a hold that ran `APPROVAL_NOT_RESUMED` on a trail already
closed and its chain forks, though nothing runs twice: restore is B14's,
`planned`; the page's printed token and the session it trades for are the only
thing between it and another local account or a web page, and it cannot tell
whether a plane reads its pause file; signed webhook callbacks are `planned`

### candidate-policy

[backlog B27](backlog.md),
[adoption requirements](adoption-and-incident-workflows.md#b27-compare-and-simulate-a-candidate-policy);
`policy explain` and `policy test` exist, but no diff or simulation command is
built

### mcp-gateway

- `internal/gateway/` (the protocol-neutral pipeline: `Admit`, `Close`, `Abort`,
  `Preview`, the mode table with its start-time refusals, the executed-arguments
  digest, the plane-owned hold and its memory approval store; in every mode,
  `OBSERVE` included, it refuses a translation refused for more than nothing
  classifying it, an envelope the kernel refuses whatever the adapter reported,
  a claim that nothing classifies a call over an envelope with an effect class,
  one `contract.ValidateUnclassified` refuses or one whose arguments hash names
  other bytes, an action kind or protocol outside `internal/channel`'s list, a
  resource pointer that is not RFC 6901, and rewritten bytes that name another
  resource than the one decided on; at start it refuses an adapter named after
  no protocol of `internal/channel` or declaring another strength than its
  protocol's,
  [ADR-0067](adr/0067-the-pipeline-refuses-what-an-adapter-could-not-translate.md))
- `internal/channel/` (the action kinds, the protocol names and each protocol's
  enforcement strength, whose zero is none, read by the gateway, both adapters,
  the pause, supervision, coverage and the run view)
- `internal/transportcause/` (the type a transport failure is logged by, never
  its text)
- `internal/adapterkit/` (the resource id a pointer names, the refusal of a call
  nothing classifies, the run token, the trace context and the arguments hash,
  read alike by both adapters)
- `adapters/mcp/` (stateless and stateful HTTP and stdio listeners, one upstream
  client per server, the manifest with fingerprints and the operator's
  overrides, `tools/call`, `tools/list` shaping, `resources/read` and
  `prompts/get`, and the caller's W3C `traceparent` from `_meta` into the
  envelope's `trace_id` and `span_id`, which correlate and decide nothing)
- `cmd/guardana-gateway/` (`run`, `doctor`, `collect`, `trail` and `prune`, a
  `stateful_http` listener that caps live sessions at `listener.max_sessions`
  and counts its refusals in `/metrics`, `GET /healthz`, which answers
  `degraded` while the policy is not confirmed and, under `schema` `3`, counts
  without naming a run or a stop, a `health.socket` that answers it whole only to the
  plane's account and `health.socket_uid`, the peer read by `internal/peercred/`
  on Linux and macOS, `GET /metrics` in the Prometheus text format from
  `internal/metrics`, whose names [reference/metrics.md](reference/metrics.md)
  is rendered from, and `GET /brand`)
- `internal/gatewayconfig/` (the configuration file, its `GUARDANA_CONTROL_*`
  variables and the field table
  [reference/configuration.md](reference/configuration.md) is rendered from;
  with both adapters' `New`, it refuses a tool whose envelope needs an
  environment or a tenant the plane leaves unset)
- `internal/classify/` (a tool's classification as one type, its spelling and
  the one check the configuration and both adapters apply, which refuses a
  classification no envelope could carry,
  [ADR-0059](adr/0059-a-tools-classification-is-one-type-checked-when-it-loads.md))
- `internal/pause/` and `pause init`, `add`, `remove`, `sign`, `list` and
  `floor init` in `cmd/guardana-control/` (the operator's pause file, its strict
  reader, its writer under an exclusive lock, and the poller a plane decides
  every call under, [ADR-0019](adr/0019-an-operator-can-pause-calls.md); under
  `approvals.authority: signed` a pause file `4` an operator signs with `--key`,
  which `internal/pause/signedpause/` judges at every read against the roster,
  the plane's `plane_id`, tenant, project and pause file and the pause floor of
  `internal/policystate/`, refusing a `3` file, which `pause sign` signs again
  as `4` with its entries,
  [ADR-0075](adr/0075-a-signed-plane-takes-a-pause-only-from-an-operators-signature.md)),
  the `reaction` keys (`route`, `public_key`, `floor_dir`, `stops`,
  `stops_floor_dir`, `poll_interval`), under which a plane refuses a stopped
  run's calls ([row below](#run-stop))
- [ADR-0013](adr/0013-mcp-interception-approvals-and-modes.md)
- [guides/run-the-gateway.md](guides/run-the-gateway.md)
- [reference/mcp-coverage.md](reference/mcp-coverage.md)

`OBSERVE`, `APPROVE`, `ENFORCE` and `LOCKDOWN` run and `SHADOW` and `WARN` are
refused at start; no configuration key wires an authenticator, so no call binds
an end user; a run is the listener's principal and agent, one per plane without
an authenticator, unless `runs.dir` serves the runs an operator opens
([row below](#operator-runs)), and a policy's `flow` constraints read what the
run's executions declared they return
([ADR-0021](adr/0021-a-run-carries-what-it-took-in.md)); after untrusted input a
flow rule denies a call to an untrusted destination once a known read reached
its floor, and otherwise, an undeclared result included, leaves it undetermined,
and a mode that enforces blocks either; `APPROVE` needs an approval authority
that can answer, `directory` or `signed`, and is refused at start under
`memory`; a pause bites up to one poll interval after it is written, never on an
execution already running, names a run, an agent or a principal only as the
plane vouches for it, says per entry in `/healthz` and `doctor` whether it
covers all, some or none of the plane's calls, and cannot name a tenant;
elicitation, multi-round requests (an upstream's `input_required`, which ends
the call failed) and the Tasks extension are `planned`

### credential-echo

`internal/secretscan/` (the scan: every key, string and number of an answer, as
written, percent-decoded and JSON-unescaped, for each credential raw,
JSON-escaped and in base64), `internal/gatewayconfig/` (the credentials a
configuration holds), `adapters/mcp/` (the scan before the closing record, the
fixed answers, `-31103`, a tool definition that quotes one never classified or
listed), `doctor` (the values too short to scan),
[ADR-0042](adr/0042-an-answer-that-quotes-a-configured-credential-is-withheld.md),
[reference/mcp-coverage.md](reference/mcp-coverage.md). Catches an echo, not an
upstream that sets out to leak; an endpoint's path and a command's arguments are
not scanned, and no setting exempts a value that appears in normal answers

### enforce-client

`internal/enforceclient/` (a Go client of `admit`, `complete` and `abort` over a
Unix socket, and `Admit`, `Complete` and `Abort`, which hold every client rule,
and `Call`, which runs a tool between them, all under the client rules of
[ADR-0051](adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)),
`testdata/enforce/` (the client cases, each with a negative control: a client
that breaks its rule must fail it, and the answer vectors: a status and a body
with the reading or the refusal a client must give, where a `may_refuse` vector
lets a client other than the Go reference refuse what the reference reads).

`go test ./internal/enforceclient/` runs every case and vector against a
receiver that answers from the files; the receiver in `adapters/enforce/`
([row below](#enforce-receiver)) runs the same contract

### python-client

`clients/python/` (`guardana_control.enforce`, a project of its own outside the
Go module: one synchronous call that admits, runs the tool only with the
authorized bytes and closes with one `complete` or one `abort`; the standard
library alone; answers read in the form the receiver writes, from a field table
`scripts/gen-pyschema.go` generates from the descriptors),
[ADR-0053](adr/0053-a-python-client-of-the-enforcement-api-in-this-repository.md),
[guides/decide-a-tool-of-your-own.md](guides/decide-a-tool-of-your-own.md).
`make check-python` runs every client case, every negative control and every
answer vector of `testdata/enforce/` on the two CPython versions pinned in
`scripts/tool-versions.env`, drives a real plane once, and builds and imports
the wheel.

It cooperates: a plane reports its calls `decided, not enforced`. No `asyncio`
entry point. The release workflow uploads the wheel and source archive to PyPI
by trusted publishing, and its dry run to TestPyPI;
`pip install guardana-control` installs it

### enforce-receiver

- `adapters/enforce/` (`admit`, `complete` and `abort` on a Unix socket created
  `0600` in a directory only the plane's account may enter, both checked again
  after the bind, with a lock beside it that refuses a second plane on the
  socket while the first listens,
  [ADR-0054](adr/0054-the-enforcement-receiver-holds-a-lock-beside-its-socket.md);
  each envelope built from the run token and the operator's table of tools,
  never from what the client says about the call; single-use 128-bit handles
  that expire and are abandoned by a sweep; a bound on the executions one run
  holds open; a rewrite that moves the decided resource, and in every mode a
  call whose envelope the contract refuses for anything but an unnamed tool,
  aborted and answered `BLOCK`)
- `internal/adapterkit/` and `internal/classify/` (shared with `adapters/mcp/`)
- `testdata/enforce/receiver/` (the receiver cases, each with a negative
  control)
- [ADR-0051](adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)

`go test ./adapters/enforce/` runs every receiver case against the adapter in
front of an in-process plane. `guardana-gateway run` serves it under
`listener.kind: enforce_api` with the operator's `tools` table, sweeps expired
handles beside the plane's other readers, abandons every open execution when it
stops, before the spool drains, and counts its handles and refusals under
`enforce` in `/healthz`; `doctor` checks such a plane without reaching an
upstream; an end-to-end test in `cmd/guardana-gateway/` drives a cooperating and
a defecting client under one policy,
[guides/decide-a-tool-of-your-own.md](guides/decide-a-tool-of-your-own.md).

It declares `Cooperative`: the client sends the bytes, so nothing proves it
obeyed. The socket checks read mode bits, not darwin access control lists, and
cover the socket's directory, not the directories above it: an account that may
write one of those can move the socket's directory aside

### hook-bridge

`internal/hookbridge/` and `guardana-control hook`
([ADR-0056](adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md),
[extending/runtime-profiles.md](extending/runtime-profiles.md)): a runtime's
tool hooks admit each call through the enforcement API and report it by value;
the admit only restricts (silence or a block status), authorized bytes other
than the proposed ones or an obligation left for the bridge to apply are denied,
a held call is denied with its approval named. One built-in profile,
[for one runtime](reference/claude-code-hooks.md), decided with failure gaps:
its fixtures are written from the runtime's documentation and run through the
bridge against a plane in `make test`; it is qualified on two releases of that
runtime, 20 cases run headless against a plane with the results beside the
profile, and its gaps are on its page

### connect-filesystem

`examples/connect-a-filesystem-server/`,
[guides/connect-an-existing-mcp-setup.md](guides/connect-an-existing-mcp-setup.md).
The profile classifies the 14 tools of `@modelcontextprotocol/server-filesystem`
2026.8.31 under the approval-for-writes pack; a run by hand takes it end to end,
over HTTP and over stdio, with the MCP inspector's command line as the client. A
test loads it; its fingerprints match the tool definitions that version lists,
and a definition another version changes is unclassified.
`make check-mcp-client`, the CI job "External MCP client"
([ADR-0057](adr/0057-an-external-mcp-client-runs-the-guide-on-every-pull-request.md)),
runs the guide with that version from the example's lockfile and the MCP
project's Python SDK 1.30.0 over HTTP: 14 tools classified, a read, a write
held, approved and run once, a reuse and a rejection refused, the report read;
over stdio it runs in no test.

The three-user trial `docs/backlog.md` asks of B06 has not run

### mcp-config-preview

[backlog B23](backlog.md),
[adoption requirements](adoption-and-incident-workflows.md#b23-preview-an-existing-mcp-setup);
no command built

### tool-definition-review

[backlog B25](backlog.md),
[adoption requirements](adoption-and-incident-workflows.md#b25-review-tool-definition-changes);
the gateway already binds classification to fingerprints, but no change report
or review workflow is built

### a2a-adapter

`adapters/`

### framework-clients

a client in another language under `clients/`, as
[ADR-0053](adr/0053-a-python-client-of-the-enforcement-api-in-this-repository.md)
lays out; framework SDKs: none chosen, [ROADMAP.md](../ROADMAP.md)

### more-channels

notifiers `internal/notify/`, channels `adapters/`,
[ADR-0039](adr/0039-many-channels-into-one-core.md),
[ADR-0045](adr/0045-one-run-is-supervised-against-its-procedure.md)

### evidence-chain

`internal/evidence/`, with the order check and the quoting rule in
`internal/trailchain/`. Builder, chain validation and a JSONL codec. A `Sink`
seam and a memory sink for tests; the package itself reads no clock and touches
no file, and the spool that writes disk implements the seam from
`internal/spool/`

### evidence-spool

`internal/spool/` (segmented log with CRC32C per record, fsync policy, a budget
with a reservation per open trail, a quarantine for what a collector refuses, an
exclusive directory lock on a directory only the plane's account owns and
writes, segments opened for append without following a link and refused when
another account owns them or the group or others may write them, recovery that
cuts a torn tail and refuses damage before it; under interval fsync it cuts the
last segment at its first record that does not check), the `Sink` seam in
`internal/evidence/` with a memory sink for tests,
[ADR-0014](adr/0014-evidence-spool-and-sinks.md).

Its own tests and a crash-safety property cover it, and `cmd/guardana-gateway`
wires it as the plane's sink. `spool.Inspect` reads a spool without changing it,
reporting a torn tail and a holder; `doctor` alone reads through it and writes
no probe, and every command the two binaries mark as inspecting is tested over a
crash-damaged tree, alone and beside live writers, to leave bytes, modes,
modification times, link counts and owners as they were.

`guardana-gateway spool drain` moves the quarantine into a new owner-only file,
synced before the quarantine is emptied, and is refused while a plane holds the
spool

### otel-export

`adapters/otel/`, OTLP logs over HTTP in the protocol's JSON encoding on the
standard library, pinned by a golden in `testdata/otlp/`,
[ADR-0014](adr/0014-evidence-spool-and-sinks.md),
[ADR-0080](adr/0080-evidence-leaves-a-plane-over-a-unix-socket-or-tls.md). It
acknowledges only the protocol's own answer read strictly, follows no redirect,
refuses a plaintext `http` endpoint, writes to a `unix:///path` endpoint only
once the socket's peer is `export.collector_uid`, retries everything else,
quarantines what a collector refuses, and drains one run at a time;
`cmd/guardana-gateway` runs it

### trail-collector

- `adapters/otel/` also reads what the exporter sends, strictly, answers only
  after the records are synced, and refuses 401 a request without the
  collector's bearer credential
- `internal/segmentlog/` keeps a directory of segments bound to one tenant and
  project, sealed at a byte bound, refused past a log bound, pruned only by an
  operator with a tombstone first, and completed or refused after a crash
- `internal/trailfile/` writes each live segment under an exclusive lock,
  refuses another project's event, cuts a torn last line at open, and reads a
  file or every segment back with each trail's chain checked;
  `guardana-gateway collect` (a unix socket, `--tenant`, `--project`,
  `--credential-file`), `trail`, `trail segments` and `prune`
- [guides/watch-a-plane-without-a-collector.md](guides/watch-a-plane-without-a-collector.md)
- [ADR-0020](adr/0020-a-trail-and-counters-without-a-collector.md)
- [ADR-0072](adr/0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md)

A trail is at least once, its check proves each chain's shape, not its
integrity, and the token goes only to a socket peer of `export.collector_uid`,
or over `https` to whoever holds a certificate the system trusts for the
collector's name

### evidence-export

`internal/trailfile/` (`Export`), `internal/lineexport/` (the cursor and the
read side a JSON Lines export shares), `guardana-gateway trail export`,
[ADR-0035](adr/0035-a-versioned-evidence-export-and-a-bounded-query.md),
[guides/read-the-evidence-from-a-program.md](guides/read-the-evidence-from-a-program.md).
Writes the events of a trail file, or of one segment at a time with
`end_reached` at the log's end, to standard output in the versioned format `1.1`
of [contracts.md](contracts.md#the-evidence-export), whose header counts the
segments pruned before the one exported, which coverage refuses as whole: a
header, each event's line as the file holds it, a record for every line it
cannot read or that repeats an event id, and a trailer; resumes after a cursor
checked against the file's content; filters by request, run, tenant, project and
kind; exits 1 on any gap.

Each event's schema major is checked where evidence is read for a verdict, and
the collector refuses an event of another major. `examples/evidence-report`, a
Go module of its own
([ADR-0037](adr/0037-an-evidence-consumer-in-a-module-of-its-own.md)), rebuilds
each call's lifecycle from an export with the generated contract package alone,
shows the plane's own block beside the kernel's decision, with `-state DIR`
follows a trail export after export, onto each next segment and raises local
alerts that a repeated delivery, a gap or its own outage neither loses nor
repeats, reports a broken chain as unknown and an unfinished one as open, and a
run that timed out or whose outcome is unknown as uncertain, exiting 1 on any of
them

### observations

- `internal/observe/` (the version table, the table of source kinds and their
  neutral checks, the observation and connection ids and the line codec)
- `internal/ingest/` (the one descriptor reader and the importer of each kind)
- `internal/observelog/` (the log under one writer's lock and its export)
- `internal/ingest/otelgenai/` (OTLP/JSON trace lines under the GenAI
  conventions 1.41.0)
- `internal/ingest/egresslog/` (an egress proxy's JSON access log under the
  descriptor's mapping, a host or a CONNECT authority, with Envoy and Squid
  fixtures)
- `internal/netname/` (the one spelling of a host and a caller address),
  `guardana-control observe import` and `observe export`
- [reference/observations.md](reference/observations.md)
- [reference/egress-access-log.md](reference/egress-access-log.md)
- [guides/watch-an-egress-proxy.md](guides/watch-an-egress-proxy.md)
- [ADR-0039](adr/0039-many-channels-into-one-core.md)
- [ADR-0040](adr/0040-observations-a-record-a-log-and-one-importer.md)
- [ADR-0058](adr/0058-a-copy-an-import-never-read-is-doubt-for-the-runs-it-claimed.md)
- [ADR-0069](adr/0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md)

The record is `guardana.control.observe.v1alpha1`, version `0.1`, `0.2` for an
import report naming the runs its refused copies claimed, or `0.3` for a
connection, refusals by reason or a record naming its source's kind, and the
descriptor `0.1`, or `0.2` for an egress source, outside the v1 promise; an
egress source may declare `TRUST_INDEPENDENT` on an unsigned descriptor, the
operator's word that the agent cannot write the log; no connection names a run,
and `supervise` refuses such a source; `buf breaking` ignores that package and
`scripts/proto-breaking-probe.sh` shows v1 still compared.

No content is kept and a capture setting is refused; the plane never reads an
observation; `guardana-control coverage` joins one to a plane event by trace and
span id against a whole evidence export ([row below](#coverage-map))

### coverage-map

`internal/coverage/` (the inventory, the evidence export reader, one state per
declared path, the join), `coverage` in `cmd/guardana-control/`,
`observelog.ReadFile`, [reference/coverage.md](reference/coverage.md),
[ADR-0041](adr/0041-coverage-per-declared-path.md),
[ADR-0044](adr/0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md).
It reads files and contacts no plane: a configuration is not proof a plane runs
it, and a classification is the override, not the live definition. A tool an
enforcement API plane classifies (`enforce_tool`) is decided, not enforced, in
every mode, since a cooperating client enforces the decision. A call around the
plane is shown only against a whole, unfiltered evidence export; "inferred" has
no source yet.

An egress path is observed by an egress source's connection to its host, and no
plane decides egress; a host an egress source reached that no path declares is a
row of its own, at most 256 printed in host order, which an agent can game, and
so is each egress source whose import refused a line; either makes the exit 1
([ADR-0069](adr/0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md))

### host-process-events

none chosen

### operator-runs

- `internal/runs/` (the runs directory: a record per run, a state and a lock
  file per root run, two openers kept apart by the compiler), `runs open`,
  `close`, `list` and `prune` in `cmd/guardana-control/` (`prune` removes whole
  trees whose every run expired, after copying them into a new owner-only
  archive, leaves a tree whose root is live, and names each expired tree it
  keeps: one with a run that has not expired, a held state lock or a file it
  cannot read), `runs.dir` and `run --run-token-file` in
  `cmd/guardana-gateway/`, the `Run-Token` check in `adapters/mcp/`
- [ADR-0034](adr/0034-a-run-the-operator-opens-has-an-identity-of-its-own.md)
- [ADR-0068](adr/0068-a-run-belongs-to-one-project.md)
- [guides/keep-two-tasks-apart.md](guides/keep-two-tasks-apart.md)

A plane with `runs.dir` admits a call only under a token that resolves for the
plane's `project_id` and the listener's principal and agent, judged on every
request and every message; a run record is `2.0` and names its project, and one
of `1.0` is refused; a run tree, `supervise`, `react` and `doctor` hold a run to
its record's project ([ADR-0068](adr/0068-a-run-belongs-to-one-project.md)); a
call reads its root's state once and raises it before `ACTION_STARTED`, and a
state it cannot read or raise blocks the call; a hold resumes only from its own
run.

Write access to the runs directory is the authority to open a run, for every
project that shares it, except under `approvals.authority: signed`, where the
directory holds `records/` the plane only reads and `state/` it writes, and a
run counts only from a `3.0` record an operator granted `operate` signed with
`--key` for that `records/` and its tenant and project, judged by
`internal/runs/signedruns/` at every call, with each close the plane takes
carried into `state/` so the open record put back is refused
([ADR-0076](adr/0076-a-signed-plane-takes-a-run-only-from-an-operators-signature.md)),
and a child the plane never admitted is refused once an ancestor's close is
carried
([ADR-0079](adr/0079-a-signed-plane-admits-a-child-only-if-it-saw-it-before-its-parents-close.md));
a token acts as its run until it expires or is closed; a run closed after its
call passed the listener still runs that call; `dev` and scenarios serve local
runs only

### run-supervision

- `internal/supervise/` (a guarded tree: procedure schemas `0.1` and `0.2`, the
  second with resource bindings, named exceptions and a children mode, `inherit`
  judging a root and its tree or `separate` one run; what belongs to the run;
  one table of the rules, six under `0.1` and eleven under `0.2`, which adds
  `RESOURCE_OUTSIDE_RUN`, `DENIED_ACTION_RETRIED_ARGUMENTS`, `_RESOURCE` and
  `_AROUND`, and `EXCEPTION_TAKEN`; the verdict, the finding id)
- `internal/findinglog/` (the log, and its export with a cursor)
- `internal/notify/`, `supervise`, `notify`, `findings export`, `procedure lint`
  and `procedure test` in `cmd/guardana-control/`
- `testdata/procedure/`, the contract `guardana.control.finding.v1alpha1`
- `examples/refund-supervision/`
- `internal/runview/` (one run as a static page, `supervise --view`)
- [reference/supervision.md](reference/supervision.md)
- [reference/run-view.md](reference/run-view.md)
- [guides/test-a-procedure.md](guides/test-a-procedure.md)
- [guides/supervise-and-stop-a-run.md](guides/supervise-and-stop-a-run.md)
- [ADR-0045](adr/0045-one-run-is-supervised-against-its-procedure.md)
- [ADR-0047](adr/0047-a-procedure-states-its-exceptions-resources-and-children.md)
- [ADR-0048](adr/0048-one-run-drawn-as-a-page-and-findings-exported-with-a-cursor.md)
- [ADR-0058](adr/0058-a-copy-an-import-never-read-is-doubt-for-the-runs-it-claimed.md)

It reads exports and logs when an operator runs it; nothing in a plane reads a
finding, and `react` turns a confirmed one into a stop of the run it names, a
root or a child ([row below](#run-stop)). A finding resting on what a runtime
reported is suspected at most; a skipped step is never confirmed; the report
names each source not read, never heard or silent

### run-stop

- `internal/reaction/` (the route, the six rules a route may name and the
  three of them that may stop an agent or a principal, the stop list's grammar
  and judge, the snapshot a plane decides under and its matcher of a run, an
  agent and a principal)
- `internal/reaction/stoplist/` (the reader a plane polls)
- `internal/reaction/stopwrite/` (the writer, which the gateway binary does not
  link)
- `internal/reaction/signedstops/` (under `approvals.authority: signed`, the
  roster operators a plane takes a `v1alpha3` route, a stop list `3.0` header
  and a `v1alpha3` lift from, each bound to the plane's `plane_id` and files,
  and the stop list floor,
  [ADR-0077](adr/0077-a-signed-plane-takes-a-stop-list-only-from-operators-signatures.md)),
  the `route` and `stops` kinds of `internal/policystate/`, `route sign`,
  `stops init`, `lift`, `list` and `floor init` and `react` in
  `cmd/guardana-control/`, the `reaction` keys, `doctor`, `/healthz` and
  `/metrics` in `cmd/guardana-gateway/`
- `examples/refund-supervision/`
- [reference/reaction.md](reference/reaction.md)
- [ADR-0046](adr/0046-a-finding-stops-one-run-through-a-signed-route.md)
- [ADR-0083](adr/0083-a-finding-may-stop-an-agent-or-a-principal.md)

A plane with a route refuses a stopped run's later calls `RUN_STOPPED` and no
other run's, and every call `STOP_STATE_UNAVAILABLE` while it cannot read or
trust the list. A call already running is not cut, a stopped run's children are
not stopped, a process of the plane's account can add stops the route allows and
start a new list across a restart, except under `signed`, where the stops
directory and the route are refused when that account may write them and every
list chains to the floor and extends the part of it the plane accepted, a floor
that account can still lower, after which a list the stop writers cut back is
taken; `react`'s own lines are signed by no operator, and the checks read mode
bits, not darwin access control lists

Under `signed` a route may stop the agent or principal of the finding's run
instead, for `REPEATED_DENIAL` and the two retry rules and for the rule's
lifetime; matched against the listener's configured identity, such a stop
refuses every call of the plane `AGENT_OR_PRINCIPAL_STOPPED`, runless calls and
later runs included, and only a lift of that agent or principal ends it.

### finding-review

[backlog B26](backlog.md),
[adoption requirements](adoption-and-incident-workflows.md#b26-review-findings-and-export-an-incident-package);
findings export exists, but no case review history or joined incident package is
built

### web-ui

no path chosen yet; one run's static page is `supervise --view`
([row above](#run-supervision))

### graph-api

no path chosen yet, and no milestone names it

### trust-roster

- `internal/trust/` (the `Roster` port and its `file` kind: one DSSE envelope of
  `trust-roster/v1alpha1` signed by a pinned root, operator keys with grants of
  tenant, project and level, an expiry of at most 7 days, a serial that only
  climbs, held by the `authority` floor of `internal/policystate/`)
- `internal/operators/` (the `Authenticator` and `Authorizer` ports and their
  `roster` kinds, a veto that only denies, a timeout and a bound on calls in
  flight), `operators roster sign` and `operators floor init` in
  `cmd/guardana-control/`, the conformance cases in `testdata/ports/` listed in
  `scripts/ports.txt`, which a test holds to the tree
- [ADR-0066](adr/0066-each-decision-about-authority-is-a-port.md)
- [ADR-0071](adr/0071-operators-are-named-by-a-signed-roster.md)

A plane reads a roster only under `approvals.authority: signed`, where it needs
a `plane_id`, serves one tenant
([ADR-0082](adr/0082-a-signed-document-names-its-plane-and-a-signed-plane-serves-one-tenant.md)),
and `doctor` and `/healthz` report `trust`, naming that id,
`operators.authenticator` and `operators.authorizer`; the plane refuses to start
when its account may write the roster file, so that account cannot put an older
roster in place; it still raises the roster's floor, so it can withhold a newer
roster within the held one's lifetime; a `read` grant parses and grants nothing
yet, which `doctor` says;
[contracts.md](contracts.md#signed-files-and-their-project-checks) lists each
signed file a plane takes with its project check

### scenario-runs

`internal/scenario/` reads `agent-scenario/v1alpha1` strictly;
`guardana-gateway scenario run` (`cmd/guardana-gateway/`) calls a running plane
as an MCP client, waits for its spool to drain, reads the trail its collector
writes and compares each call's answer, decision and trail, and answers
approvals and pauses through the `guardana-control` beside it;
[reference/scenario-format.md](reference/scenario-format.md),
[ADR-0022](adr/0022-scenarios-are-data.md). It must be the plane's only client,
a scenario must finish within the approval lifetime, and it trusts the trail
beyond the ids, the bundle digest and the mode it checks

### dev-mode

`guardana-gateway dev` (`cmd/guardana-gateway/dev*.go`) lays out a new state
directory, signs the demo's document under a key it clears once signed, writes
and renews the bundle's freshness statement under a second key held only in its
memory, makes the plane's floor directory through `guardana-control`, runs the
collector on a unix socket and the plane on loopback ports it bound, both in its
own process, and runs `guardana-control console` beside them; `--scenario` runs
each scenario on a plane of its own.

`internal/loopback/` is the one rule for a loopback IP literal;
[reference/dev.md](reference/dev.md),
[ADR-0023](adr/0023-a-local-page-answers-through-the-directory.md). It renews
the statement every third of the staleness budget, or sooner when the poll
interval asks, so a scenario that runs past the budget keeps its verdicts; a
renewal that fails leaves the plane deciding `POLICY_STALE` once the budget has
passed

### demo-servers

`examples/vulnerable-mcp-agent/`,
[get-started/try-the-demo.md](get-started/try-the-demo.md),
[ADR-0033](adr/0033-a-demo-archive-a-release-user-runs-without-go.md). One
binary serves the orders or the web server over standard input and output;
`demo.yaml` and `policy.json` are what `dev` takes, and
`dev --decision-point=silent` gives the plane a decision point on a port it
binds and never answers, so demos run side by side. Each release carries a demo
archive per platform that runs without Go or a checkout, and
`scripts/check-demo-archive.sh` runs every scenario from the linux/amd64 one,
refusing an archive built from another commit or version, before a release is
published.

Its test builds the binaries, runs each scenario on its own plane through `dev`,
reads what each server received, and fails one mutant of each scenario on the
member it changed

### backup-restore

`internal/recovery/`, `state backup` and `state restore` in
`cmd/guardana-control/`,
[guides/back-up-and-restore-a-plane.md](guides/back-up-and-restore-a-plane.md),
[ADR-0078](adr/0078-a-restore-only-raises.md). A backup copies the floors, the
runs, the pause file and the stop list under a manifest `0.2`, which under
`signed` names the plane a restore must be, never the spool, the hold journal,
the approvals store or a key; a restore reads only the bytes it verified, holds
the spool's and the journal's locks, checks every class before it writes, raises
every floor to the higher of the two, stamps a plane floor at the restore time,
closes every run and joins taint.

Under `directory` it carries the backup's stop list into a new list where none
survived and refuses two histories; under `signed` it writes no operator file
and raises the stop list floor. After the route was replaced, the restore
refuses the backup's stop list, and a signed stop list floor put back at the
backup's serial refuses a list carried twice since, each until an operator takes
the guide's way back.

The manifest is unsigned: its hashes catch corruption, not a hostile writer of
the backup; a signed restore of a `0.1` manifest, which names no plane, says
`plane not checked`. A raw volume restore is unsupported.

### control-plane-api

`internal/controlapi/`, [ADR-0009](adr/0009-open-core-boundary.md)

### storage

`internal/storage/`

### go-module

`go.mod` (`go 1.27.4`), `scripts/bootstrap.sh`

### quality-gate

`Makefile`, `.golangci.yml`, `internal/testreport/` (the test reporter
`make test` and `make test-race` read; it refuses a package with no test files
outside `api/gen/` and a skipped test `scripts/expected-skips.txt` does not name
([ADR-0063](adr/0063-a-skipped-test-fails-the-gate-unless-the-repository-expects-it.md)),
and it reads what the test binary prints, so a test that prints its own pass and
exits 0 hides the tests after it, which only review catches), `scripts/`,
`internal/docscheck/`, `internal/core/layering_test.go`. The dependency rule is
an allowlist over six trees, all examined, and every package of this module they
reach is held to the same refusals by name; no non-test file under `adapters/`
may import the reason-code registry, whatever its build constraints, or compose
or hold a v1 `Decision` by value (one made by reflection is out of a source
check's reach); `make check-imports-probe` plants a violation in each and fails
unless every mechanism refuses it.

The secret and dependency scan fails unless the dependency scanner read every
`go.mod`, `uv.lock` and `package-lock.json` the repository holds, and
`make scan-repo-files-probe` fails unless it refuses a planted secret, a
lockfile left unread and a missing scanner. The documentation check judges every
page's frontmatter, type, `covers`, budget and diagrams and pins every rendered
page and block to its generator
([ADR-0015](adr/0015-documentation-structure-and-checks.md)); `make docs-impact`
names the pages a change makes suspect

### brand-rename

`internal/brand/`, `scripts/check-brand.sh`, `scripts/rename-product.sh`

### decision-records

`docs/adr/`

### continuous-integration

`.github/workflows/`: `ci.yml` runs `make quality` on Linux for every push to
`main` and every pull request, its quality job also checking every action pin
against the commit its version tag names in that action's repository
(`scripts/pin-actions.sh --check`, failing when GitHub cannot answer),
`make check-mcp-client` beside it
([ADR-0057](adr/0057-an-external-mcp-client-runs-the-guide-on-every-pull-request.md)),
and the job "Two accounts", which runs the tests `scripts/expected-runs.txt`
names as root beside two accounts it makes, the health socket's peers, the
export socket's collector, a signed start's placement and an operator's signed
runs directory under real ownership among them, and fails unless each of them
passed, a required check as `scripts/lib/github-settings.sh` declares it once
the maintainer applies those settings
([ADR-0081](adr/0081-tests-that-need-a-second-account-run-in-a-required-job.md));
`security.yml` runs CodeQL and the vulnerability, advisory and secret scans,
`pull-request.yml` checks a pull request's title and sign-offs,
`workflow-lint.yml` checks the workflows, `scorecard.yml` scores the
repository's supply chain, and `nightly.yml` runs the race tests with every
processor busy on Linux and macOS each night (`scripts/test-race-loaded.sh`) and
fuzzes every fuzz target on Linux (`make fuzz-smoke`), opening an issue when a
night is red.

Every workflow's steps start in a bash that ignores the startup files, options
and functions an earlier step can set through `$GITHUB_ENV`; a bash script a
step starts still reads them, and `make quality` refuses them
([ADR-0062](adr/0062-the-gate-is-guarded-at-its-entry-points-and-fuzzed-at-night.md))

### releases

`.goreleaser.yaml`, `.github/workflows/release.yml`,
[RELEASING.md](../RELEASING.md),
[ADR-0025](adr/0025-public-repository-merges-and-releases.md). The release job
runs in the `release` environment, and the job that uploads the Python client to
PyPI in `pypi`, the one environment the index trusts; each admits only `v*` tags
and waits for a maintainer's approval. The dry run's upload to TestPyPI runs in
`testpypi`, which admits only `main`. Archives for Linux and macOS on amd64 and
arm64 with both binaries, a demo archive per platform beside each, a CycloneDX
bill of materials per archive, each one checked present, `checksums.txt` signed
without a stored key, and a build provenance attestation for every archive, all
verified by the workflow before it publishes.

Every binary of every archive and the image's binary for each platform are
scanned with `govulncheck` in binary mode before anything is attested; a finding
stops the release (`scripts/scan-binaries.sh`). The release job refuses a commit
that is not main's head, that lacks a successful CI and Security push run on
main, or that main's newest CodeQL analysis is not of, and refuses while main
has an open CodeQL alert of severity high or critical
(`scripts/check-gate-runs.sh`).

Also an OCI image of the gateway, `ghcr.io/guardana/control-gateway`, for
linux/amd64 and linux/arm64 on a distroless nonroot base, signed and attested by
digest the same way, its digest named in the release notes
([guides/run-in-a-container.md](guides/run-in-a-container.md))

### benchmarks

`bench/`: envelope validation, the digest, `Decide` at 10, 100 and 1000 rules
and with obligations, and one MCP tool call through the gateway against the same
call made directly, with guard tests in `make test`. `scripts/bench.sh` keeps a
run in the ignored `bench/results/local/`; `--publish` writes a tracked
`bench/results/<stamp>-<os>-<arch>.txt` that names the machine

### website

`site/`, `wrangler.json`, `internal/docscheck/sitedoc/`,
[ADR-0030](adr/0030-a-static-website-drawn-from-the-repository.md). One static
landing page with no script, drawing its own illustrations, each of its labels
tied to a row here or a task of the backlog, and every documentation page,
record, the roadmap and the changelog rendered under `/docs/`
([ADR-0031](adr/0031-the-documentation-is-served-on-the-website.md)) with
`llms.txt` beside them, all in one header, footer and set of tokens with a light
and a dark theme a checkbox switches without script
([ADR-0084](adr/0084-the-site-is-redrawn-in-one-system.md)), all written by
`make docs-gen` and compared in `make docs-check`; served at
https://control.guardana.dev, deployed from `main` on every push.

The pages name the release `docs/docs.json` sets once it is published, and link
its documentation at the tag
([ADR-0049](adr/0049-the-site-names-the-published-release.md))

## What it supervises today

The project means to supervise an organization's AI agents
([ROADMAP.md](../ROADMAP.md)). Against that aim, the components above add up to
this:

| Aim | Today |
| --- | --- |
| Setup for common agent stacks, a proxy for the rest | An MCP proxy; the enforcement API for a tool outside MCP, with a Go and a Python client, which cooperates; one coding runtime's hooks through `guardana-control hook`; no framework integration and no proxy for other tool APIs |
| Oversight of what agents do and the data they reach | Each tool call, resource read and prompt through one plane is decided, and none runs before its record is written unless the operator let a read run unrecorded; the plane does not see a call that bypasses it, which an imported trace records as testimony and an egress proxy's log as a connection; `guardana-control coverage` reads the planes' configurations and exports beside it and names a call around the plane, from files, with no plane contacted |
| Procedures, and deviations from them | Policy per call and one flow rule; `guardana-control supervise` checks one opened run, or a root and its whole tree, against a procedure after the fact, and reports an exception the procedure allows when one is taken; `procedure lint` reads a procedure as `supervise` would and `procedure test` runs it against cases |
| Attempts to gain access | Each refusal the pipeline decides is counted in `/metrics`, and recorded with its reason codes unless the call's identifiers name no trail, its request id already has an open trail, or the sink refuses one of its events; a request the listener refuses for its origin or its run token is not recorded, and only run token refusals are counted; within one run, `supervise` reports repeated denials of a tool and, under a `0.2` procedure, a denied action retried with other arguments, through another tool or upstream on the same resource, or around the plane as a source reports it, and the calls of one resource binding that reach more than one resource |
| Quality: finished, not degraded, nothing skipped | A result's status and hash; within one run, `supervise` reports a skipped step, an order broken and a run that carried on after a failure |
| Running beside the agents, reporting deviations | The plane writes evidence to a spool for export; `supervise` reads an export when an operator runs it, `notify` hands its alerts to a program, and `findings export` writes the findings out for a program that resumes from a cursor; nothing runs on its own |
| Stopping an agent | A pause of every call, of one upstream, of one tool, of one opened run or every run under a root, of one agent or of one principal, for calls not yet running; a stop of one opened run's later calls, a root's or a child's, from a confirmed finding a signed route allows, when the operator runs `react`; a stop not of a whole tree, nor of one agent or principal |
| A run drawn as a graph | A static page per run from `supervise --view`: the expected steps beside the calls observed, each marked by shape and line as well as colour; a table, not a graph, and not live |

## Open source, and what may be commercial

Required by [ADR-0009](adr/0009-open-core-boundary.md). A security capability is
never withheld from the open build, whatever its status above.

| Part | Licensing |
| --- | --- |
| Enforcement kernel | Open, permanently |
| Policy matcher | Open, permanently |
| Adapters | Open, permanently |
| Approvals | Open, permanently |
| Evidence | Open, permanently |
| Detectors | Open, permanently |
| Control API | Open, permanently |
| Self-hosted deployment | Open, permanently |
| Managed hosting | May be commercial |
| Curated policy and detector packs | May be commercial |

This page is updated in the same change as the work it describes.
