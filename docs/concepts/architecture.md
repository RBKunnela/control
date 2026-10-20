---
title: Architecture
summary: The system in context, its containers, the request path from a proposed action to a decision and its evidence, the dependency rule, and where it is going.
type: explanation
covers: [cmd/guardana-gateway/**, cmd/guardana-control/**, adapters/**, internal/gateway/**, internal/approvals/**, internal/holdjournal/**, internal/spool/**, internal/core/**, internal/policy/**, internal/canon/**, internal/evidence/**, internal/observe/**, internal/observelog/**, internal/ingest/**, internal/scenario/**, pkg/**, scripts/lib/dependency-rule.sh, ROADMAP.md]
---

# Architecture

Control has two paths: an enforcement point decides before an effect, and
observation and supervision examine what connected sources report. The
`planned` 1.0 target joins them with continuous observation and reactions
within scoped authority; [control and supervision](control-and-supervision.md)
explains that product model. This page starts with today's request path.
The gateway that decides and enforces is `experimental`, and nothing here is a security boundary yet.
What exists, component by component, is in [status.md](../status.md), and
that page is the only inventory.

## The system in context

One process sits between an agent and the servers it calls. Everything else
is outside it and talks to it over a protocol it does not own.

```mermaid
flowchart LR
    accTitle: The system in context
    accDescr: The agent's tool calls pass through the gateway process, which reads a signed bundle and the statement that keeps it current, sends held calls to an approver, asks a decision point that can only veto, forwards the calls it lets through and exports evidence to a collector.
    OP[Operator]
    AG["Agent, an MCP client"]
    APR[Approver]
    GW["Gateway process"]
    SRV["MCP servers, the tools"]
    BUNDLE["Signed policy bundle and its freshness statement"]
    COL["OpenTelemetry collector"]
    PDP["Decision point, the organization's own, over AuthZEN"]
    OP -->|configuration, bundle, mode| GW
    AG -->|tools/call| GW
    GW -->|the calls it lets through| SRV
    GW -->|held call, as a record in the directory of file approvals| APR
    APR -->|approval for one digest| GW
    BUNDLE -->|verified, read again each poll| GW
    GW -->|evidence, OTLP logs| COL
    GW -->|a call a veto rule routes there| PDP
    PDP -->|an answer that can only veto| GW
```

Sources: `cmd/guardana-gateway/serve.go`, `cmd/guardana-gateway/planepolicy.go`, `adapters/mcp/listener.go`,
`internal/gateway/approvals.go`, `adapters/otel/exporter.go`,
`adapters/authzen/client.go`.

The gateway is the only component this project adds to the request path.
Guardana, a separate verifier project, is not part of this system: the gateway
neither calls it nor needs it
([ADR-0024](../adr/0024-control-and-guardana-are-independent.md)).

## The containers

Two binaries. `guardana-gateway` runs the plane; `guardana-control` is the
author's tool for a policy document and its key, the operator's for a held
call, a pause and an opened run, and the reader of files after the fact:
`observe`, `coverage`, `supervise` and `notify`. The one thing it serves is the
local approvals page.

```mermaid
flowchart TB
    accTitle: The containers
    accDescr: Inside guardana-gateway the MCP adapter hands calls to the pipeline, which asks the decision kernel, records evidence through the spool and its exporter, and keeps holds in the approval store; guardana-control lints policy and answers approvals through the approvals directory.
    subgraph CLI["guardana-control"]
        LINT["policy lint, policy test"]
        APPR["approvals list, approve, reject"]
    end
    subgraph PLANE["guardana-gateway"]
        MCP["MCP adapter"]
        PIPE["Pipeline: admit, hold, close"]
        CORE["Decision kernel"]
        POL["Policy snapshot and matcher"]
        CANON["Canonical action digest"]
        EV["Evidence chain"]
        SPOOL["Spool on disk"]
        OTEL["OTLP exporter"]
        HOLD["Approval store, hold journal"]
    end
    AG[Agent] --> MCP
    MCP --> PIPE
    PIPE --> CORE
    CORE --> POL
    CORE --> CANON
    PIPE --> EV
    PIPE --> HOLD
    EV --> SPOOL
    SPOOL --> OTEL
    MCP --> SRV["MCP server"]
    OTEL --> COL[Collector]
    LINT --> POL
    APPR --> DIR[("Approvals directory")]
    HOLD --> DIR
```

Sources: `cmd/guardana-gateway/build.go`, `cmd/guardana-control/main.go`,
`adapters/mcp/pipeline.go`, `internal/gateway/pipeline.go`,
`internal/core/decide.go`, `internal/policy/load.go`,
`internal/canon/digest.go`, `internal/evidence/chain.go`,
`internal/spool/append.go`, `adapters/otel/exporter.go`,
`internal/approvals/plane.go`, `internal/holdjournal/journal.go`,
`cmd/guardana-control/approvals.go`.

| Container | Path | Does |
| --- | --- | --- |
| MCP adapter | `adapters/mcp/` | Listens toward the agent, speaks to each upstream server, translates a call into an envelope and shapes every answer the agent sees. |
| Pipeline | `internal/gateway/` | Protocol-neutral: admits an envelope, asks the kernel and, when the decision turns on it, the external decision point, applies the enforcement mode, holds a call for approval, writes the trail. |
| Decision kernel | `internal/core/` | The fixed order of checks, the fail-closed table and the delegation check; `Decide` once per admitted call, again with the external decision point's answer when the decision turns on it, and again when a rewriting obligation changes the arguments. |
| Policy | `internal/policy/` | Parses a document, verifies a bundle's signature and a freshness statement's, holds one snapshot and its serial floor, and matches three-valued. |
| Policy refresh | `internal/policywatch/`, `internal/policystate/` | Reads the bundle and the statement again every poll, installs a newer bundle only with its statement, and keeps the serial floor on disk. |
| Canonical digest | `internal/canon/` | The one digest an approval binds to. |
| Evidence chain | `internal/evidence/` | The event chain in memory and the `Sink` seam the spool implements. |
| Spool | `internal/spool/` | The segmented log on disk with a budget, a quarantine and recovery. |
| AuthZEN client | `adapters/authzen/` | Asks the organization's decision point about one call whose decision turns on its answer, and reads the answer strictly; the answer can only veto. |
| OTLP exporter | `adapters/otel/` | Drains the spool to a collector and acknowledges only the protocol's own answer. |
| Approval store | `internal/approvals/` | Reads and checks the records in the directory an approver answers in; the pipeline compares an answer with its own record of the hold. |
| Hold journal | `internal/holdjournal/` | The plane's own durable record of its holds, so the next start closes the trail of one it lost, or counts it left open. |
| Commands | `cmd/guardana-control/` | The `policy`, `approvals`, `pause` and `runs` commands and the `console` page, without a plane; `observe`, `coverage`, `supervise` and `notify` read files after the fact. |

## The request path

An adapter receives a proposed action from an agent and normalises it into an
`ActionEnvelope`: the project, tenant and environment it belongs to; the
principal, the agent and the delegation chain; the action, which carries its
own effect class; the resource and the destination; the argument hash together
with the data labels that say whether those arguments hold secrets; the run
context; and the correlation identifiers that tie the sequence together. The
core validates the envelope and classifies the action by effect. A policy
snapshot is evaluated against it and produces a `Decision`: reason codes,
obligations, the digest of the policy bundle that decided, and one of five
verdicts: `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `ALLOW_WITH_OBLIGATIONS` and
`INDETERMINATE`, spelled `VERDICT_ALLOW` and so on in the wire contract. The
pipeline in `internal/gateway/` applies the enforcement mode and holds a call
that needs an approval; the adapter enforces what the pipeline hands back.
The pipeline records every step on the call's trail, and a call it cannot
record before the effect is blocked, unless it is a read the operator let run
unrecorded.

```mermaid
sequenceDiagram
    accTitle: The request path
    accDescr: The adapter hands a proposed action to the pipeline, whose kernel evaluates the policy snapshot and may take a decision point's answer; the pipeline records the proposal and the decision, then a denied or undetermined call is refused and its block recorded, a call that needs approval is recorded as requested and held until an identical retry consumes it, and a call that runs is recorded as started before the tool is called and as completed or failed once the adapter hands back its result.
    participant Agent
    participant Adapter
    participant Pipeline
    participant Core
    participant Policy
    participant PDP as Decision point
    participant Store
    participant Approver
    participant Tool
    participant Evidence
    Agent->>Adapter: proposed action
    Adapter->>Pipeline: ActionEnvelope and the proposed arguments
    Pipeline->>Core: Decide
    Core->>Core: validate, classify effect, compute action digest
    Core->>Policy: evaluate against the policy snapshot
    Policy-->>Core: verdict, reason codes, obligations, bundle digest
    Core-->>Pipeline: decision
    opt the decision turns on the decision point's answer and is not DENY
        Pipeline->>PDP: ask, with a deadline
        PDP-->>Pipeline: an answer, or silence
        Pipeline->>Core: Decide again with the answer
        Core-->>Pipeline: decision
    end
    alt DENY or INDETERMINATE, where the mode enforces it
        Pipeline->>Evidence: ACTION_PROPOSED, POLICY_DECIDED, ACTION_BLOCKED
        Pipeline-->>Adapter: blocked
        Adapter-->>Agent: refusal carrying the reason codes
    else REQUIRE_APPROVAL
        Pipeline->>Evidence: ACTION_PROPOSED, POLICY_DECIDED, APPROVAL_REQUESTED
        Pipeline->>Store: hold this request under its binding, with an expiry
        Pipeline-->>Adapter: pending, with the approval id
        Adapter-->>Agent: pending
        Approver->>Store: approve or reject the held request
        Agent->>Adapter: the same action again
        Adapter->>Pipeline: ActionEnvelope and the proposed arguments
        Pipeline->>Store: the requests still held under this binding
        Store-->>Pipeline: what it holds under the binding, and whether it was approved
        Pipeline->>Store: consume the approval, once
        Pipeline->>Evidence: APPROVAL_DECIDED, ACTION_STARTED, on the held request's trail
        Pipeline-->>Adapter: allow the held request only
        Adapter->>Tool: call
        Tool-->>Adapter: result
    else ALLOW or ALLOW_WITH_OBLIGATIONS
        Pipeline->>Evidence: ACTION_PROPOSED, POLICY_DECIDED, ACTION_STARTED
        Pipeline-->>Adapter: allow, with obligations to enforce
        Adapter->>Tool: call
        Tool-->>Adapter: result
    end
    opt the call ran
        Adapter->>Pipeline: Close, with the result
        Pipeline->>Evidence: ACTION_COMPLETED or ACTION_FAILED
    end
```

Sources: `internal/gateway/admit.go`, `internal/gateway/approve.go`,
`internal/gateway/resume.go`, `internal/gateway/approvals.go`,
`internal/gateway/close.go`,
`internal/core/decide.go`, `internal/core/failclosed.go`,
`internal/evidence/chain.go`.

Four properties the branches carry:

- `INDETERMINATE` is not a quiet allow. A fail-closed table decides what it
  enforces for each effect class, see [ADR-0003](../adr/0003-policy-model-and-external-pdp.md).
- An approval binds one canonical action digest together with the policy bundle
  digest, and it expires, see [ADR-0005](../adr/0005-canonical-action-digest.md).
  A retry that equals the held request resumes it once; a similar action, a
  later one or a run after it is a different action.
- An external decision point can only veto: its answer is an input a `DENY`
  rule reads, and its silence blocks, see
  [ADR-0017](../adr/0017-an-external-decision-point-can-veto.md).
- The blocked branch produces evidence too, naming the policy version that
  decided it, or that none was available, see
  [ADR-0004](../adr/0004-evidence-and-privacy-defaults.md). A block the
  plane cannot record is counted, not recorded: the call's identifiers name no
  trail, its request id already has an open trail, or the sink refuses one of
  its events.

## Layers and the dependency rule

From the outside in:

- Adapters (`adapters/`) speak one protocol or framework and translate. They
  carry no policy meaning.
- The public Go surface is `pkg/contract`. `pkg/adapter`, `pkg/detector` and
  `pkg/policyprovider` are reserved names for what an out-of-tree adapter,
  detector or policy provider would compile against; none exists yet. Adding
  to the surface is a compatibility decision and needs its own record
  ([ADR-0026](../adr/0026-first-value-and-external-extension-paths.md)), and
  data contracts with conformance suites come first
  ([ADR-0039](../adr/0039-many-channels-into-one-core.md)).
- The core (`internal/core`, `internal/policy`) validates, classifies, matches
  and decides.
- Everything the decision does not need sits outside it: storage, the control
  API, the gateway, ingest.

The dependency rule is an allowlist, `implemented` in the gate. A package in
`internal/core`, `internal/policy`, `internal/canon`, `internal/evidence`,
`pkg/contract` or `internal/supervise` may import packages of this module outside `adapters/`,
`internal/storage`, `internal/controlapi`, `internal/gateway` and
`internal/ingest`; packages of `google.golang.org/protobuf`; and a named set of
standard library packages that holds no network, file, process, system call,
randomness, `unsafe` or plugin package; the functions in it that read the
clock, standard input, the zone database or the system's randomness are
refused by name where a name reveals the read; the local zone behind
`time.Unix(...).Format` is not. A package in those trees builds from the same
Go files on every platform: a file build constraints leave out on the machine
the gate runs on, and any source that is not plain Go, is refused. Every
package of this module those trees reach is held to the same list and the
same refusals by name, generated code excepted. The rule runs one way: an adapter may import the core, and core
that needs adapter behaviour declares an interface for the adapter to
implement.

The rule sandboxes nothing. Adapter and core run in one process, so a
compromised adapter dependency can still affect the program, and each allowed
package is trusted whole. What the rule buys is that the set of code able to
influence a verdict stays small enough for one person to read, and that no new
module or standard library package enters that set without an edit to the rule
itself, which the gate checks. See
[ADR-0007](../adr/0007-repository-layout-and-dependency-rule.md).

## Connected channels towards 1.0

This section is `planned`, in the order [ROADMAP.md](../../ROADMAP.md) gives,
and [ADR-0039](../adr/0039-many-channels-into-one-core.md) records its shape;
the enforcement API, the observation log and its importer, the coverage map,
supervision of one run, a local notifier and a stop of one run from a finding
are built
([status.md](../status.md)). The
request path above stays how a plane stops a call. MCP is the first channel
of several, and every channel or extension will be one of five ports, and say
which.

```mermaid
flowchart TB
    accTitle: Where it is going
    accDescr: A planned shape. Agents act through enforcement points, the MCP gateway and framework hooks over one enforcement API, which decide before the effect and record evidence. Sensors bring in what runtimes, proxies and processes report afterwards, as observations. Detectors in the supervisor read both, map coverage and raise findings. Notifiers deliver findings; a reaction stops one run at the enforcement points where the operator allowed it.
    AG[Agents]
    subgraph EP[Enforcement points]
        MCP["MCP gateway: policy, approvals, pause"]
        HK[Framework hooks over one API]
    end
    subgraph SN[Sensors]
        TR[Runtime traces and logs]
        PX[Proxy access logs]
        PR[Process events]
    end
    TL[Tools and APIs]
    EV[(Evidence)]
    OB[(Observations)]
    SV["Supervisor: procedures, detectors, coverage map"]
    subgraph OUT[Notifiers and views]
        AL["Alerts: webhooks, chat"]
        EX["OpenTelemetry, metrics, SIEM"]
        GR[Run graph and console]
    end
    RE["Reaction: stop one run where allowed"]
    AG --> MCP
    AG --> HK
    MCP -->|allowed calls| TL
    HK --> TL
    AG -.-> TR
    AG -.-> PX
    AG -.-> PR
    MCP --> EV
    HK --> EV
    TR --> OB
    PX --> OB
    PR --> OB
    EV --> SV
    OB --> SV
    SV --> AL
    SV --> EX
    SV --> GR
    SV -.-> RE
```

Sources: `ROADMAP.md`, `internal/gateway/pause.go`, `adapters/authzen/client.go`.

- **Enforcement points** see a proposed action before its effect and may block
  it, hold it for an approval or attach obligations. The MCP gateway is one.
  A plane serving the enforcement API decides for a cooperating client, which
  enforces the answer itself. A coding runtime's tool hooks reach it through
  `guardana-control hook`, which can only take a call away; a framework's
  hooks over it are planned.
- **Sensors** see an effect after it happened, or an indirect sign of it:
  the traces and logs an agent's runtime writes, a proxy's access log, process
  events. They report and never decide. An observation names its source and
  how far that source is trusted; the agent's own account can omit or forge
  events, and a proxy attributes a connection only as well as it knows its
  caller. As everywhere in the project, hidden model reasoning is never
  stored.
- **The supervisor** reads the evidence and the observations beside the
  request path, compares each run with the procedure it follows, and raises
  findings that cite what they rest on. It maps each declared path as
  enforced, decided but not enforced, observed, inferred or not covered, and
  what nobody declared as unknown; a missing event is unknown, never proof
  that nothing happened. It runs beside the decision path and never changes a verdict.
- **Notifiers and reactions.** A notifier delivers findings to the tools an
  operator already watches. A reaction is a separate, signed route: it stops
  one run's later calls at the enforcement points, for a scope and an expiry,
  and only from a finding the operator allowed to stop anything. Like a
  pause, a stop applies after the kernel decides, and it never cuts a call
  already running.
- **Extensions** are separate programs speaking versioned data contracts, and
  definitions (policies, scenarios, procedures, and later detector rules and
  routes) are documents a team writes and tests. An external decision point
  can already veto over AuthZEN (`experimental`).
  [extending/adapters.md](../extending/adapters.md) is the first guide.

## What is deliberately not here

- No language model in the decision path. A model may suggest, summarise or
  annotate; it never grants authority.
- No detector that can change a verdict. A detector reports, the policy
  decides.
- No adapter that decides policy. An adapter translates and enforces what it
  is told.
- No regular expressions and no scripting in the matcher, so a rule can be read
  and audited by someone who did not write it.

## Where things live

| Path | Holds | Status |
| --- | --- | --- |
| `api/proto/guardana/control/v1/` | Protobuf contracts, the source of truth, frozen at `1.0` | `implemented` |
| `api/gen/go/` | Generated Go, committed so a consumer needs no plugin chain | `implemented` |
| `testdata/contracts/` | Fixtures the round-trip tests read | `implemented` |
| `internal/contract/` | The round-trip tests over those fixtures | `implemented` |
| `pkg/contract/` | Bounded validation and strict decoding of the contracts | `implemented` |
| `internal/canon/` | The canonical action digest an approval binds to | `implemented` |
| `internal/evidence/` | The evidence event chain, in memory | `implemented` |
| `internal/policy/reasons/` | The reason-code registry | `implemented` |
| `internal/core/` | The decision kernel, [ADR-0012](../adr/0012-policy-kernel-semantics.md) | `implemented` |
| `internal/gateway/` | The protocol-neutral enforcement pipeline, [ADR-0013](../adr/0013-mcp-interception-approvals-and-modes.md) | `experimental` |
| `internal/spool/` | The evidence spool on disk, [ADR-0014](../adr/0014-evidence-spool-and-sinks.md) | `experimental` |
| `internal/gatewayconfig/` | The gateway's configuration: its fields, the file reader and the loader | `experimental` |
| `internal/brand/` | The product name every other package reads | `implemented` |
| `internal/approvals/`, `internal/holdjournal/` | The file approval provider and the plane's hold journal, [ADR-0016](../adr/0016-approval-providers-and-the-lost-hold.md) | `experimental` |
| `cmd/guardana-control/` | The `policy` commands | `implemented` |
| `cmd/guardana-control/` | The `approvals`, `pause`, `runs`, `observe`, `coverage`, `supervise` and `notify` commands and the `console` page | `experimental` |
| `cmd/guardana-gateway/` | The plane: `run`, `doctor`, `collect`, `trail`, `scenario` and `dev` | `experimental` |
| `Makefile`, `scripts/`, `.golangci.yml` | The one quality gate | `implemented` |
| `internal/docscheck/` | The documentation gate, run by `make docs-check` | `implemented` |
| `internal/`, everything else | What is not intentionally public | as [status.md](../status.md) labels each component |
| `pkg/`, the other three packages | The rest of the public Go surface | `planned` |
| `adapters/mcp/`, `adapters/otel/`, `adapters/authzen/` | The MCP adapter, the OTLP exporter and collector, and the AuthZEN client | `experimental` |
| `adapters/`, the rest | Other protocol and framework adapters | `planned` |
| `internal/ingest/`, `internal/coverage/` | The importer of observations and the coverage map, [ADR-0040](../adr/0040-observations-a-record-a-log-and-one-importer.md), [ADR-0044](../adr/0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md) | `experimental` |
| `internal/supervise/`, `internal/findinglog/`, `internal/notify/` | One run checked against its procedure, the findings log and the notifier, [ADR-0045](../adr/0045-one-run-is-supervised-against-its-procedure.md) | `experimental` |

Per component, including what is planned elsewhere, see [status.md](../status.md).
