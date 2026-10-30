# ADR-0070: A listing hides only what no call could be allowed

Status: accepted
Date: 2026-10-30

Amends [ADR-0013](0013-mcp-interception-approvals-and-modes.md) on what
`hide` subtracts and what `annotate` marks as decided per call.

## Context

A listing previews each tool with no arguments and no run. An `ALLOW` rule
that reads an input the preview lacks is unknown there, and the matcher
treated it as no match without a trace. A tool whose only `ALLOW` reads
`resource.id` therefore previewed as the `DENY` of no matching rule, and
`hide` left it out, though a call naming an allowed id ran. ADR-0013 already
said such a tool stays listed; the code did not do it.

Keeping every tool that has an unknown `ALLOW` goes too far the other way. An
input the listener fixes, such as the principal's authentication strength,
reads at the call exactly as at the preview, so a rule unknown on it is never
met and every call is denied.

## Decision

The matcher reports each `ALLOW` rule whose match is unknown with the inputs
it lacked, in wire spelling. The kernel reports whether its decision is
`DENY` for no matching rule alone, from each step's own flag rather than from
the codes. Neither changes a verdict, a code or a rule id.

The pipeline, not the adapter, says what a listing may do with a tool:
`Preview` returns the decision and a `Listing`, whose zero value keeps the
tool. A tool is decided per call only when the decision is the kernel's own,
it is `DENY` for no matching rule alone, and one unknown `ALLOW` lacked
nothing but inputs a call brings and a preview lacks: the resource id, when
the tool's classification points at one, and the run's flow. Every other
`DENY` is denied to the listing, a plane cause, a matched `DENY` rule and an
`ALLOW` unknown on any other input among them.

A preview that is not a verdict keeps the tool, as before. A tool whose effect
class needs a resource id has its preview refused, since a listing carries no
arguments; it is `INDETERMINATE` and listed even when a `DENY` rule names it.
An undetermined `DENY` or `REQUIRE_APPROVAL` rule keeps a tool listed too,
whatever input it lacked. Both show more than a call can do, never less, and
a call is still decided when it is made.

## Security / compatibility impact

A listing is never an authorization: every call is decided when it is made.
The change only moves a tool between listed and left out. `Preview`'s Go
signature changes inside the module; no wire contract or reason code moves.

## Alternatives considered

- Keep every tool beside an unknown `ALLOW`. Rejected: it lists tools no call
  can use, which `hide` exists to leave out.
- Compare the decision's codes with `NO_MATCHING_RULE`. Rejected: a later step
  that adds a code, or a plane decision that spells the same one, would be read
  as the kernel's verdict.
- Let each adapter decide what an unknown input means. Rejected: the rule is
  the same for every channel, and an adapter that forgot it would hide or show
  the wrong tools.

## Consequences

An input a future adapter's call brings and its preview lacks has to be named
in the gateway's `callSupplies`, or a tool it decides stays hidden. That is the
safe side: a hidden tool can still be called and is decided as any call.

## Validation

- `internal/policy/match`: `TestAddingAnUnknownAllowMovesNoVerdict`,
  `TestAnUnknownAllowNamesWhatItLacked`, `TestEveryTraceAgreesWithItsValue`.
- `internal/core`: `TestAnUnknownAllowReachesTheOutcome`,
  `TestOnlyANoMatchDenyIsMarked`.
- `internal/gateway`: `TestTheListingOfEachDecision`, `TestWhatACallSupplies`,
  `TestAToolOnlyItsCallCanDecideIsDecidedPerCall`,
  `TestAnAllowNoCallCanMeetIsDenied`, `TestADenyThatHoldsWithoutTheCallIsDenied`.
- `adapters/mcp`: `TestAListingKeepsOnlyWhatACallCouldBeAllowed`,
  `TestAToolOnlyItsCallCanDecideStaysListed`, `TestTheListingIsThePipelinesWord`.
