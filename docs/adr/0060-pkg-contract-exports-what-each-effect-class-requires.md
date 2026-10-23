# ADR-0060: pkg/contract exports what each effect class requires

Status: accepted
Date: 2026-10-23

Adds one function to `pkg/contract`, whose surface
[ADR-0007](0007-repository-layout-and-dependency-rule.md) makes a
compatibility promise. Used by
[ADR-0059](0059-a-tools-classification-is-one-type-checked-when-it-loads.md).

## Context

`Validate` requires of an envelope what its effect class needs to be decided:
`action.provider` for every class but a read, and a row per class of the
contract's table, `resource.id` for a write, `destination.trust_zone` for a
message. The table was private to `pkg/contract`, and `docs/contracts.md`
renders it under a test. A configuration that classifies a tool has to know
the same table to refuse a classification no envelope could carry; a second
copy of it would drift from the one `Validate` reads, which is how the
configuration's checks drifted from the adapters'.

## Decision

`contract.EffectRequires(e)` returns the wire paths `Validate` requires of an
envelope of class `e` beyond those every envelope needs, in the order it
checks them: `action.provider` for a material class, then the class's row.
The zero class starts with `action.effect`, which `Validate` refuses it for
before it reads the list, so a reader that checks the list in order refuses
the field `Validate` names. A class this build does not declare gets the
material default alone, which is what `IsMaterial` already says of it. The list is a fresh copy on every call.
`Validate` reads its requirements through the same function, so the export is
the check, not a description of it.

## Security / compatibility impact

Additive: a new exported function, pinned by `TestExportedFunctionSetIsClosed`
and documented on `docs/contracts.md`. It authorizes nothing and changes no
wire behaviour. Whatever the contract requires of a class is what this
returns, so a later minor that changes a row changes what a caller refuses in
the same build; a caller reading it to refuse configuration refuses more as
the contract requires more.

## Alternatives considered

- Export the table as a map: a caller could change what `Validate` requires.
- Keep the table private and let a caller build an envelope and ask
  `Validate`: the answer depends on what the caller filled in, and a refusal
  names one field at a time.
- A copy of the table in the caller: two tables, one of them unchecked.
- The table in an internal package that both `pkg/contract` and
  `internal/classify` import, which the dependency rule allows and which would
  not grow `pkg/`: a third party that builds envelopes against `pkg/contract`
  needs the same requirements `Validate` applies, to refuse what it cannot
  send before it sends it, and only an export of `pkg/contract` gives it
  them.

## Consequences

`pkg/contract` has one more function a caller may depend on; removing or
renaming it is a major change.

## Validation

`TestEffectRequiresIsWhatValidateRequires` holds each class's list to a
literal copy of the table and to `Validate` both ways: an envelope carrying the
list is accepted, and one missing any entry is refused naming it.
`TestEffectRequiresOfTheZeroClassNamesTheEffect` holds the zero class's list
to the field `Validate` refuses it for. `TestEffectRequiresHandsOutACopy`
edits the answer for every declared class, the zero one included, and checks
the next one and `Validate`. `TestEffectTableIsDocumented` keeps the table on the page.
