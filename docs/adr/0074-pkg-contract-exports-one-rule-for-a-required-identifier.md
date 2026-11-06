# ADR-0074: pkg/contract exports one rule for a required identifier

Status: accepted
Date: 2026-11-06

Adds one function to `pkg/contract`, whose surface
[ADR-0007](0007-repository-layout-and-dependency-rule.md) makes a
compatibility promise, as [ADR-0060](0060-pkg-contract-exports-what-each-effect-class-requires.md)
did. The rule it applies is [ADR-0011](0011-contract-corrections-before-publication.md)'s.

## Context

`CheckIdentifier` checks what a string holds, not whether there is one: `""`
passes, and the bound on its length is `Validate`'s, not its own. Every
caller that requires an identifier outside an envelope added both: the
policy reader's ids, the kernel's decision point and request id, a
classification's strings, an obligation's identifiers and resource prefix, a
procedure's identifiers. Seven copies of one rule agree today and drift on the first change, which is
how the gateway's configuration came to load a `tenant_id` with a trailing
space that the contract refused at the first call.

## Decision

`contract.CheckID(s)` refuses `""` as `ErrMissingField`, a string longer than
`MaxStringBytes` bytes as `ErrTooLarge`, and anything else as
`CheckIdentifier` does. The refusal is a `*ValidationError` with no field and
never repeats the string. `CheckIdentifier` keeps its meaning, so a walk over
optional fields still passes an empty one.

Each former copy calls it and keeps its own error vocabulary. The gateway's
configuration holds every key an envelope carries to it when the file loads,
naming the key: `project_id`, `tenant_id`, `environment`, the
`listener.principal.*` and `listener.agent.*` keys, and an upstream's
`tenant_id` and `environment`. `Validate` holds each of those fields to the
identifier rule and its bound. The MCP and enforcement adapters do the same in
`New` for a Go caller, over the plane's keys and every string of the
listener's principal and agent.

## Security / compatibility impact

Additive in `pkg/contract`: a new exported function, pinned by
`TestExportedFunctionSetIsClosed` and documented on `docs/contracts.md`. It
authorizes nothing and changes no wire behaviour. None of the former copies
was looser, so nothing they refused changes. A configuration whose identifier
the contract refuses, which loaded and then had every call refused, now fails
to load.

## Alternatives considered

- `policy.ValidID` as the one copy: `internal/policy` imports
  `internal/policy/rules`, which would then import it back, and
  `internal/classify` imports only `pkg/contract`.
- Make `CheckIdentifier` refuse `""`: `Validate`'s walk applies it to every
  string of an envelope, optional ones included, and would refuse an envelope
  it accepts today.
- An internal package both import: a third party building envelopes against
  `pkg/contract` needs the same rule for an identifier it must send.

## Consequences

`pkg/contract` has one more function a caller may depend on; removing or
renaming it is a major change. A later change to the bound or to the rule
reaches every caller in the same build.

## Validation

`TestCheckIDHoldsPresenceTheBoundAndTheRule` holds the empty string, 1024 and
1025 bytes, a bound counted in bytes rather than runes, white space at either
end, U+00A0 and U+3000 included, a bidi control, a NUL and invalid UTF-8 to
literal sentinels, and `TestCheckIDIsValidateOnARequiredIdentifier` holds
`Validate` to the same verdict and sentinel on `request_id`;
`TestCheckIDRefusalCarriesNoCallerText` keeps the string out of the refusal. Each former site's own refusal test stays.
`TestAnIdentifierEveryEnvelopeCarriesIsRefusedAtLoad` and both adapters'
`TestNewRefusesAPlaneKeyNoEnvelopeCarries` hold the configuration to it.
