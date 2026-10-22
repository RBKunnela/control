---
title: Writing an adapter
summary: The internal seam a protocol adapter implements, the capabilities it declares, and the conformance each one owes.
type: extending
covers: [internal/gateway/adapter.go, internal/gateway/mode.go, internal/adapterkit/**, adapters/mcp/**, adapters/enforce/**]
stability: development
---

# Writing an adapter

An adapter translates one protocol into the envelope the kernel decides about,
and turns the plane's answer back into something that protocol can say. It holds
no policy meaning: what a call means lives in the envelope it builds and in the
policy (invariant 7). The MCP adapter in `adapters/mcp/` is the worked example.

The second adapter, `adapters/enforce/`, serves the enforcement API of
[ADR-0051](../adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)
to a tool outside MCP, on a Unix socket; the gateway serves it under
`listener.kind: enforce_api`
([guides/decide-a-tool-of-your-own.md](../guides/decide-a-tool-of-your-own.md)). It builds each envelope from the run token and
the operator's table of tools, never from what the client says about the
call, and declares `Cooperative`: the client sends the bytes, so nothing the
plane holds proves it obeyed. It applies no obligation of its own, aborts an
execution whose rewritten bytes name another resource than the one decided
on, or whose envelope the contract refused for more than an unnamed tool, in
every mode, closes what a client reports with `CloseReported`, and closes with
`Abandon` every execution nobody completed or aborted before its handle
expired. Its receiver cases are files in
[testdata/enforce/](../../testdata/enforce/README.md).

Both adapters read a call's resource id, the resource rewritten bytes name
and the run token through `internal/adapterkit`, so one call is never read
two ways: a spelling one adapter normalised and the other did not would slip
past a rule the first one enforces.

An adapter is the enforcement point among the five ports of
[ADR-0039](../adr/0039-many-channels-into-one-core.md): it sees a call before
its effect. Sensors, detectors, reactions and notifiers run as separate
programs speaking versioned data contracts, never as code compiled into the
plane ([status.md](../status.md) says which exist). Their contracts are on
other pages: a tool's client in
[decide a tool of your own](../guides/decide-a-tool-of-your-own.md), an
evidence consumer in
[read the evidence from a program](../guides/read-the-evidence-from-a-program.md),
a decision point in
[what the decision point sees](../guides/let-a-decision-point-veto.md#what-the-decision-point-sees),
a notifier in [notify](../reference/supervision.md#notify), and a trace
source in [the source descriptor](../reference/observations.md#the-source-descriptor).

## The seam

The seam is internal, in `internal/gateway`:

```go
type Adapter interface {
    Name() string                 // the protocol's name, for evidence and health
    Capabilities() Capabilities   // fixed for the adapter's lifetime
}
```

It is deliberately not `pkg/adapter`. Two adapters in this tree use it, and
[ADR-0009](../adr/0009-open-core-boundary.md) says a pluggable seam stays
internal until its own decision promotes it; until then its shape may change
with a minor release. That is what `stability: development` means here. An adapter is
therefore written inside this repository: Go refuses to let another module
import `internal/`, and an integration built elsewhere speaks the enforcement
API instead.

There is no declared API version. An adapter is compiled into the binary, so the
compiler is the check that fails loudly, and
[ADR-0007](../adr/0007-repository-layout-and-dependency-rule.md) forbids the
run-time loading that would give a version string something to guard.

## What the adapter asks the plane

The pipeline is the whole of what an adapter needs, and it answers rather than
failing:

| Call | Means |
| --- | --- |
| `Admit(ctx, Admission) Disposition` | decide one proposed action. There is no error return: whatever the plane cannot do is a block that names its cause, and the zero `Disposition` blocks |
| `Close(ctx, disposition, sent, result) error` | the call ran; here are the bytes that went and what came back. An error means the record is not durable, or that the bytes sent were not the authorized ones (`ErrExecutedArgsMismatch`), which the record says; `ErrNothingSent` for nil bytes, after the execution is aborted; `ErrNotMinted` for a disposition this plane did not mint or closed already |
| `CloseReported(ctx, disposition, sent, result) error` | `Close` for bytes a cooperating caller reports it sent. A mismatch halts the material calls of that execution's opened run only, until restart; with no opened run, past `MaxRuns` halted runs, or through an adapter that is not cooperative, it halts the plane as `Close` does |
| `Abort(ctx, disposition, cause) error` | the call did not go, and the cause says why: the adapter's own pre-send check, an obligation it applies, a call it cannot route, a call its protocol cannot express |
| `Abandon(ctx, disposition) error` | nobody closed or aborted the execution before it expired. It is closed as `ACTION_FAILED` with status `UNKNOWN` and `EXECUTION_ABANDONED`, since nobody knows whether the call ran, and halts nothing; `ErrNotMinted` for an execution that is not open |
| `Preview(ctx, Admission) *Decision` | the decision a listing shows: the kernel's, the mode's and the halts', without pauses, stops, run flow or the decision point. It records and holds nothing, and is what shaping a listing asks |

An adapter that has an execution open closes or aborts it. An execution left
open holds one of the plane's `MaxOpen` slots until the adapter abandons it or
the process ends; the enforcement API abandons each execution whose handle
expired.

## The capabilities, and what the plane does with each

| Capability | The plane's use of it |
| --- | --- |
| `ObserveRequest` | Needed by every mode: without seeing the call there is nothing to decide |
| `ObserveResult` | Needed by every mode: a trail with no closing record is an action nobody knows the end of |
| `Enforcement` | How far the adapter keeps a call from its effect: `None` (the zero value) cannot; `Cooperative` hands the decision to a caller that enforces it, so the plane decides and records and nothing proves the caller obeyed; `Inline` holds the path to the effect, as the MCP adapter holds the upstream connection. `APPROVE`, `ENFORCE` and `LOCKDOWN` need at least `Cooperative`, and a value outside the three is refused at start |
| `Authenticates` | The adapter's listener establishes an end user before a call is translated |
| `BindEndUser` | The adapter carries that identity into the envelope's principal. Declared without `Authenticates`, it is refused at start: without authentication there is no user, only a claim |
| `PresentsRuns` | The adapter resolves a run token on every call and hands the run in. Declared exactly when the plane has a runs directory, or the plane is refused at start (ADR-0034) |
| `SeeDelegation` | The adapter can read a delegation chain out of the call |
| `SeeResourceIDs` | The adapter can name the resource a call touches |
| `Obligations` | The obligation types the adapter applies itself, by name from the catalogue. The plane's own rewriting types plus these are the kernel's applicable set; an obligation outside the union is a `DENY` with `OBLIGATION_NOT_UNDERSTOOD` |

A capability is a promise to the plane, so the plane checks it at start and never
per call: the mode table maps every declared enforcement mode to what it needs,
`UNSPECIFIED` is refused as configuration, and a mode the adapter cannot serve
stops the plane from being built. A refusal at start is the alternative to an
adapter that observes while the operator believes it enforces.

## Lifecycle

1. **Configure.** The adapter's own `New` refuses everything it can refuse
   before anything runs: a transport it does not serve, an identity that claims
   what only a credential may say, two upstreams with one name, an incomplete
   classification.
2. **Build the plane.** `gateway.New` takes the adapter, reads its capabilities, checks them against the mode and builds the kernel with the applicable
   obligations derived from them.
3. **Start.** The adapter connects what it talks to and reads what it needs to
   classify calls. An upstream it cannot reach fails the start rather than
   serving without it.
4. **Serve.** Per call: translate, `Admit`, apply what the disposition says,
   send, `Close` or `Abort`.
5. **Close.** Disconnect, and let the plane's own seams close after it.

## Applying an obligation

An adapter applies only the obligation types it declared, and each one it
declares needs a conformance test. The MCP adapter's four, with the parameters it
reads:

| Type | Parameters | What it does to a call |
| --- | --- | --- |
| `read_only` | none | refuses a call whose effect is material |
| `restrict_resources` | `ids` (comma-separated exact ids), `prefix` (a literal prefix) | refuses a call whose resource id matches neither; ids compare as text and are never resolved as paths; under `prefix`, counted from the segment the prefix ends in, it also refuses what a resolver could read as leaving the prefix: a `%`, a `;`, a `?` or `#`, a backslash, a byte outside printable ASCII, a segment of only dots and spaces (`.`, `..`, `...`, `.. `) and an empty segment other than a trailing one; end a prefix with `/`, since `/srv/data` also matches `/srv/database`; with neither parameter, nothing matches |
| `shorten_timeout` | `ms` (a positive integer) | bounds this call by the shortest timeout the obligations ask for |
| `deny_external_sink` | none | refuses a call whose destination trust zone is untrusted |

An obligation the adapter cannot satisfy, including one carrying a parameter
its type does not read, is skipped when it is marked advisory and the call
proceeds, and nothing records the skip; a non-advisory one stops it,
and the closing record says the obligation refused it. A rewrite that changes
the member a tool's `resource_from` reads is aborted, not sent. The plane applies the rewriting types (`redact_fields`,
`cap_amount`) itself, before the decision that is recorded, because they change
the bytes the digest covers.

## The bytes are not the adapter's to choose

`Disposition.AuthorizedArgs` are the bytes to send and `AuthorizedDigest` is
their `ArgumentsHashV1`. An adapter digests what it is about to send, compares,
and aborts rather than sending on a mismatch. After the call it hands `Close` the
bytes it sent, and the plane digests them again against its own record. An
adapter that sends anything else is the failure this check exists to catch, and
it stops the plane for material calls until it restarts. Bytes a caller only
reports go to `CloseReported`, which stops that caller's run instead: a report
proves nothing about what the caller sent, and a plane-wide halt would let one
caller stop every run.

## Conformance

A declared capability that no test exercises is a documented capability that does
not exist, so each one is exercised against an in-process server of the
protocol, in the adapter's own package:

| Declared | What the test has to show |
| --- | --- |
| `ObserveRequest` | the envelope the plane was asked about carries what the call said |
| `ObserveResult` | the closing record carries the upstream's outcome |
| `Enforcement` | `Inline`: the upstream is never called for a blocked call. `Cooperative`: a blocked call is answered as a block, and what the caller does about it is its own |
| `Authenticates`, `BindEndUser` | the principal is the credential's user, and a request with no user is refused |
| `SeeDelegation` | the chain in the call reaches the envelope |
| `SeeResourceIDs` | the resource id in the envelope is the one the call names |
| `PresentsRuns` | a call carrying an opened run's token is decided under that run, and a refused token never reaches the plane |
| each obligation type | a call the obligation refuses does not reach the upstream, and one it permits does |

Beyond the capabilities, an adapter that is worth trusting also has an
adversarial test per answer it makes itself: an upstream that tries to answer in
the gateway's name, a result larger than its bound, a call that cannot be routed.

## A minimal adapter

```go
type Echo struct{}

func (Echo) Name() string { return "echo" }

func (Echo) Capabilities() gateway.Capabilities {
    return gateway.Capabilities{ObserveRequest: true, ObserveResult: true, Enforcement: gateway.EnforcementInline}
}

func (e Echo) Handle(ctx context.Context, p *gateway.Pipeline, in Request) Response {
    d := p.Admit(ctx, gateway.Admission{Envelope: translate(in), Arguments: in.Body})
    if d.Action != core.Execute && d.Action != core.ExecuteWithObligations {
        return refusal(d) // a block, or a pending state, as this protocol says it
    }
    sent := d.AuthorizedArgs
    result, err := send(ctx, sent)
    if err := p.Close(ctx, d, sent, resultOf(result, err)); err != nil {
        // the record is not durable: deliver the result, count it, and let the
        // plane stop taking material calls
    }
    return response(result)
}
```

What the plane does with this adapter, and what an operator configures, is
[guides/run-the-gateway](../guides/run-the-gateway.md);
[concepts/mcp-gateway](../concepts/mcp-gateway.md) is the mechanism it plugs into.
