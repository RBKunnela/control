---
title: Writing an adapter
summary: The internal seam a protocol adapter implements, the capabilities it declares, and the conformance each one owes.
type: extending
covers: [internal/gateway/adapter.go, internal/gateway/mode.go, adapters/mcp/**]
stability: development
---

# Writing an adapter

An adapter translates one protocol into the envelope the kernel decides about,
and turns the plane's answer back into something that protocol can say. It holds
no policy meaning: what a call means lives in the envelope it builds and in the
policy (invariant 7). The MCP adapter in `adapters/mcp/` is the worked example
and the only one today.

An adapter is the enforcement point among the five ports of
[ADR-0039](../adr/0039-many-channels-into-one-core.md): it sees a call before
its effect. Sensors, detectors, reactions and notifiers run as separate
programs speaking versioned data contracts, never as code compiled into the
plane ([status.md](../status.md) says which exist), so this guide does not
cover them.

## The seam

The seam is internal, in `internal/gateway`:

```go
type Adapter interface {
    Name() string                 // the protocol's name, for evidence and health
    Capabilities() Capabilities   // fixed for the adapter's lifetime
}
```

It is deliberately not `pkg/adapter`. A public package with one consumer in the
tree is a compatibility promise made to nobody, and
[ADR-0009](../adr/0009-open-core-boundary.md) says a pluggable seam stays
internal until its own decision promotes it. The second adapter is what shows
what the two have in common; until then the shape may change with a minor
release. That is what `stability: development` means here. An adapter is
therefore written inside this repository: Go refuses to let another module
import `internal/`, and an integration built elsewhere waits for the planned
enforcement API ([backlog](../backlog.md), B10).

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
| `Abort(ctx, disposition, cause) error` | the call did not go, and the cause says why: the adapter's own pre-send check, an obligation it applies, a call it cannot route, a call its protocol cannot express |
| `Preview(ctx, Admission) *Decision` | what a call would be decided, recording and holding nothing. It is what shaping a listing asks |

An adapter that has an execution open closes or aborts it. An execution left
open holds one of the plane's `MaxOpen` slots until the process ends.

## The capabilities, and what the plane does with each

| Capability | The plane's use of it |
| --- | --- |
| `ObserveRequest` | Needed by every mode: without seeing the call there is nothing to decide |
| `ObserveResult` | Needed by every mode: a trail with no closing record is an action nobody knows the end of |
| `Block` | Needed by `APPROVE`, `ENFORCE` and `LOCKDOWN`. An adapter without it never runs under a mode that enforces |
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
it stops the plane for material calls until it restarts.

## Conformance

A declared capability that no test exercises is a documented capability that does
not exist, so each one is exercised against an in-process server of the
protocol, in the adapter's own package:

| Declared | What the test has to show |
| --- | --- |
| `ObserveRequest` | the envelope the plane was asked about carries what the call said |
| `ObserveResult` | the closing record carries the upstream's outcome |
| `Block` | the upstream is never called for a blocked call |
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
    return gateway.Capabilities{ObserveRequest: true, ObserveResult: true, Block: true}
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
