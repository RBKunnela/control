# ADR-0059: A tool's classification is one type, checked when it loads

Status: accepted
Date: 2026-10-23

Amends [ADR-0011](0011-contract-corrections-before-publication.md) on where
the identifier rule is applied to what an operator writes,
[ADR-0012](0012-policy-kernel-semantics.md) on which missing fields reach the
kernel, [ADR-0013](0013-mcp-interception-approvals-and-modes.md) on what an
override may hold, and
[ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)
on what a tool of the enforcement API may hold. Builds on
[ADR-0060](0060-pkg-contract-exports-what-each-effect-class-requires.md).

## Context

An operator classifies a tool twice over: an MCP override pins a definition
by its fingerprint, and a tool of the enforcement API is named in a table.
Both say the same six things: the effect class, the resource type, the pointer
the resource id is read through, where the tool sends data, and what its
results hold. Those six were declared as fields seven times: in the
configuration's override and tool entries, in the MCP adapter's override and
manifest entry, in the enforcement adapter's tool, and again by hand in the two
converters between them and in `coverage`. Four checks refused four different
sets of them. None applied the identifier rule, so a resource type with a
leading space or a zero-width character loaded and every call to its tool was
refused. The configuration held its own copy of the pointer check, kept equal
to the adapters' by a test, because the approver's binary links the
configuration and may not link the adapters' kit. The trust zone spellings were
a hand-written list beside the policy catalogue's, which reads the descriptor.

A classification can also be complete in its keys and still useless. An
envelope's `resource.id` comes only from the arguments at the classification's
pointer, and its destination only from its trust zone. A `WRITE` with no
pointer loads, and the contract refuses every call to it with
`REQUIRED_FIELD_ABSENT`; so does a `COMMUNICATE` with no zone.

## Decision

`internal/classify` holds the classification once:

- `Classification` is the six values as the contract types them, and
  `Spelling` the six as a configuration file writes them. The two adapters
  embed `Classification`; the configuration's override and tool entries embed
  `Spelling`, whose fields the field tables bind, and turn it into a
  `Classification` with `Parse`. The converters copy it whole.
- `Parse` reads each enum through the contract's descriptor, as the policy
  catalogue does; the empty string is the zero zone or sensitivity, and an
  explicit `UNSPECIFIED` is refused.
- `Check` is the one check, and every entry point calls it: the
  configuration loader for an override and for a tool, `mcp.New`, `enforce.New`
  and `coverage` through the loader. It refuses an effect class that is not
  declared or is the zero one; a resource type that is empty, longer than
  `contract.MaxStringBytes` or refused by `contract.CheckIdentifier`; a pointer
  that is not RFC 6901 or is past 8 tokens of 64 bytes; a trust zone or a
  sensitivity the contract does not declare; and, reading
  `contract.EffectRequires`, a class whose envelope needs `resource.id` with no
  pointer, or `destination.trust_zone` with the zero zone.
- Its rule is that a classification `Check` accepts never makes `Validate`
  refuse the envelope it supplies. For the fields that reach the envelope the
  converse holds too: given a non-empty resource type, which every entry point
  required before, each refusal is one `Validate` would make of every call.
  The returns zone and sensitivity never reach the envelope; an undeclared one
  is refused because the run's flow state reads it. Nothing else is refused: a
  pointer that names no member in a given call is that call's to answer.
- A refusal is an `*Error` naming the key as the file spells it,
  `resource_from` or `returns.trust`; the loader prefixes `overrides.N.` or
  `tools.N.`, the adapters `Overrides[N]` or `tools[N]` beside their sentinel.
  No refusal repeats the value, which may be anything an operator pasted.
- The enforcement API's tool name and provider are held to the same string
  rule, `CheckEnvelopeString`, and its refusal of a class that needs a
  delegation reads `RequiresDelegation`, which reads the contract's table too.
- The pointer check moved here from `internal/adapterkit`, which keeps reading
  the id; the configuration's copy and the test holding it equal are gone. The
  configuration's zone, sensitivity and effect spellings are the lists
  `EffectNames`, `ZoneNames` and `SensitivityNames` give.
- A test parses every non-test Go file of the module and fails on a struct
  field named `ResourceFrom`, `ReturnsTrust` or `ReturnsSensitivity` outside
  this package.

## Security / compatibility impact

A configuration that loaded before is refused when it holds an override or a
tool that no envelope could carry:

- a `WRITE`, `DELETE`, `CONFIGURE`, `TRANSACT` or `IDENTITY_OR_ACCESS` entry
  without `resource_from`, and a `COMMUNICATE` entry without `trust_zone`;
- a `resource_type`, a tool `name` or a `provider` the identifier rule refuses;
- an override's `resource_type` past 1024 bytes;
- an override's `resource_from` that is not RFC 6901 or is past its bounds,
  which `run` refused already when it built the adapter and `coverage` now
  refuses too;
- an upstream's `name` the identifier rule refuses or past 1024 bytes: it is
  the `action.provider` of every call to that upstream, so every one was
  refused. `mcp.New` refuses it too.

Through the Go API, an `mcp.Override` with an undeclared zone or sensitivity
number and an `enforce.Tool` with a provider or resource type past 1024 bytes
are refused by `New`. The refusals' wording changed: they name the key as the
file spells it.

None of the refusals of a field that reaches the envelope could let a call
run. Neither adapter sends a call whose envelope the contract refuses, in any
mode, `OBSERVE` included, so every call to such a tool was blocked before it
was sent, an `mcp.Override` with an undeclared `TrustZone` among them. The
refusal moves from each call to the file, and a plane that holds such an entry
stops starting until it is mended.

One refusal is a hardening of what ran. Through the Go API, an `mcp.Override`
with an undeclared `ReturnsTrust` or `ReturnsSensitivity` loaded and its calls
ran: those values feed the admission's result trust and sensitivity, not the
envelope, and `SensitivityAtLeast` of an undeclared number against a floor is
false, so the run's flow state under-reported what the call returned. `New`
now refuses it. The configuration file could not spell such a value, and
`enforce.New` refused it already.

The rule holds what the contract requires today. A class a later minor adds,
or a row the contract changes, changes what loads in the same build, because
the check reads the contract's own table.

## Alternatives considered

- One check per entry point, held equal by tests: that is what drifted, and
  the pointer copy existed only because of where the approver's binary may
  reach. One package below both removes the reason.
- Leave the effect requirements to the call: a plane that can only refuse its
  tool's calls starts, and `doctor` passes it.
- Refuse only outside `OBSERVE`: under `OBSERVE` too the adapters block every
  call whose envelope the contract refuses, so the entry does nothing there
  either.
- Build a sample envelope and ask `Validate`: the answer would depend on what
  the sample filled in, and the refusal would name a wire path, not the key.

## Consequences

An operator learns of an entry the contract would refuse when the file loads,
from the key, instead of from a blocked call. The adapters' Go types changed
shape, which no promise covers: `pkg/` is the public surface, and the adapters
are not in it. A new classification field is added once, here.

## Validation

- `internal/classify`: `TestCheckAcceptsExactlyWhatValidateAccepts`, a property
  over every declared class and one undeclared number, an empty or a valid
  pointer, every declared destination zone and one undeclared one, declared
  returns values only, and resource types valid and invalid, holds `Check` to
  `Validate` both ways over that domain; `TestCheckRefusesWhatNoEnvelopeCarries`
  covers an invalid pointer and undeclared returns values, which `Validate`
  never sees; `TestCheckRefusesAMissingFieldWhereValidateDoes` and
  `TestRequiresDelegationIsValidates` hold the requirements and the delegation
  rule to `Validate` per class; `FuzzParse` fuzzes the spelling;
  `TestTheClassificationIsDeclaredOnce` and its planted-file control hold the
  type to one declaration; `TestTheClassificationImportsOnlyTheContract` holds
  its imports.
- `cmd/guardana-gateway`: `TestAClassificationIsRefusedAlikeAtEveryEntryPoint`
  runs one table through the loader, `mcp.New` and `enforce.New` and requires
  the same key from each.
- `internal/gatewayconfig`: `TestAClassificationNoEnvelopeCarriesIsRefusedAtLoad`
  and `TestAToolNameOrProviderNoEnvelopeCarriesIsRefused`.
