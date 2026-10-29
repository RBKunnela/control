# ADR-0067: The pipeline refuses what an adapter could not translate

Status: accepted
Date: 2026-10-28

Amends [ADR-0013](0013-mcp-interception-approvals-and-modes.md),
[ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)
and [ADR-0061](0061-an-obligations-parameters-are-the-catalogues.md).

## Context

An adapter translates a call into an envelope and hands it to the pipeline
with a refusal when the translation failed. Some rules about what may be
handed out were each adapter's to carry, so a third adapter could land on the
unsafe side by leaving one out:

- `OBSERVE` set the action to execute over the kernel's block of a refused
  translation. Each adapter then aborted the execution itself, and both
  repeated the same check.
- "Nothing classifies this call" was read as `errors.Is(refusal,
  ErrUnclassified)`. A refusal that joined that sentinel with another cause,
  such as arguments canon refused, read as unclassified alone, and `OBSERVE`'s
  exception for unclassified calls covered it.
- An adapter that built an envelope the contract refuses, and reported no
  refusal, was decided `INDETERMINATE` by the kernel and handed out by
  `OBSERVE` all the same.
- An adapter that reported nothing but "unclassified" was believed. The
  kernel stops at a refusal handed in, so it never ran `Validate` or the
  arguments hash check on that envelope, and `OBSERVE` handed out a missing
  principal, a string past its bound, an unanchored delegation chain or a
  hash naming other bytes. `Validate` itself could not be asked about such an
  envelope: it stops at the missing effect class before the values it checks
  after it.
- The action kinds and protocol names were string literals in each adapter
  and each reader. A pause scope compared the kind byte for byte, so `Tool`
  or `function` slipped past a tool-scoped pause.
- Coverage read a plane's strength from its listener kind as a boolean, and
  the run view read it from the protocol `enforce` by name. Any other
  protocol in an enforcing mode was drawn as enforced.
- Each adapter checked that rewritten bytes still name the resource the call
  was decided on, and aborted when they did not.

## Decision

**A refused translation is never handed out, in any mode.** `applyMode` lets
`OBSERVE` execute a call only when its translation is whole, or when nothing
but its classification is missing. In every other case the kernel's block
stands, `INDETERMINATE` with the refusal's code, and the trail is the one
`ENFORCE` writes: `ACTION_PROPOSED`, `POLICY_DECIDED`, `ACTION_BLOCKED`.

"Unclassified" is one cause alone. `ErrUnclassified` counts only when it is
the end of a chain of single wraps. A node that wraps several errors joins
another cause, and the call is refused for that cause. A node's `Is` method
is not consulted. `translationOf` is the one place this is read: the mode,
the pause and the run's flow all take it from there.

**The pipeline checks every unclassified claim itself.** Before anything reads
the call, in `Admit`, in `Preview` and on a retry alike, a claim that nothing
but the classification is missing stands only when the envelope's effect class
is unspecified, `contract.ValidateUnclassified` passes, the arguments are ones
canon reads, and a `canonical_hash`, when present, is `canon.ArgumentsHashV1`
of them, as the kernel's step 2 holds a classified call. Arguments past
canon's size or depth are `LIMIT_EXCEEDED`, as the kernel's digest codes them.
The envelope is held to `ValidateUnclassified` again once the plane has added
its flow tags, since the kernel validates a classified envelope after them and
an unclassified one never. Otherwise the claim is replaced by the refusal it
earns, which the kernel codes by its sentinel as it codes any refusal handed
in (`UNSUPPORTED_SCHEMA`, `REQUIRED_FIELD_ABSENT`, `LIMIT_EXCEEDED`,
`INVALID_FIELD_VALUE`), and `OBSERVE` blocks the call as any other refused
translation. A set effect class under the claim is `INVALID_FIELD_VALUE` on
`action.effect`. No adapter has to opt into this.

`adapterkit.Unclassified` builds an adapter's refusal from its own validation
of the envelope and never joins the two. A cause it is handed that does not
carry `ErrUnclassified` comes back as it is, so the call is refused for it.

**`pkg/contract` gains `ValidateUnclassified`.** It applies every rule of
`Validate` in the same order, from one implementation, except the effect
class's presence and `EffectRequires`: the size, the schema version, unknown
fields and enum numbers, the fields every envelope needs, and the values
(the delegation chain, the host, the labels, the hash's form and a preview
with no profile). It is an addition to the public surface because the rule
belongs to the contract: a second copy of `Validate`'s checks in the gateway
would drift from the first. `Validate`'s result for every envelope is
unchanged, so the goldens and the conformance vectors do not move.

The kernel's outcome carries `RefusedInput`, which is set where the decision
stops on the request itself: the refusal handed in, `Validate`'s refusal of
the envelope, arguments that cannot be digested, or a hash naming other
bytes. A call the adapter reported as whole is still not handed out by
`OBSERVE` when `RefusedInput` is set. Input causes found later, such as an
undetermined rule or a tenant named on one side, leave it unset, and
`OBSERVE` runs those calls as before.

**One vocabulary, in a leaf package.** `internal/channel` holds the action
kinds (`tool`, `prompt`, `resource`), the protocol names (`mcp`, `enforce`),
`KnownKind`, `KnownProtocol` and `Strength`. The pipeline refuses an envelope
whose kind is outside that list, or whose protocol is not its adapter's
`Name()`, as `INVALID_FIELD_VALUE` on `action.kind` or `action.protocol`. In
`Admit` and `Preview` that refusal replaces an unclassified-only one, so
`OBSERVE` cannot run a kind that no pause scope names, and it leaves any other
refusal alone. A pause entry treats a kind outside the vocabulary as it treats
an absent one: it matches. `contract.Validate` does not change, so a v1
producer and `policy test` are unaffected.

**Strength is an enum whose zero is None.** `channel.Strength` is `None`,
`Cooperative` or `Inline`, and `StrengthOf` gives the strength of a protocol.
The empty name and any protocol this build does not know are `None`. The
gateway's `Enforcement` is an alias of it, and each adapter declares
`StrengthOf(Name())`. Coverage reads a plane's strength from its listener's
protocol through `gatewayconfig.ProtocolOf`, and the run view reads it from
the protocol recorded on the call. Only `Inline` can be enforced.
`gateway.New` asks the adapter its name once and refuses an adapter whose
`Name()` is not one of `internal/channel`'s protocols (`ErrProtocol`), and one
whose declared `Enforcement` is not `StrengthOf(Name())` (`ErrStrength`), so
the mode gate and the cooperative close read the strength coverage and the run
view read. A new adapter adds its protocol and strength to `internal/channel`.
No protocol of this build is `None`, so no adapter of that strength starts.

**The moved-resource check is the pipeline's.** `Admission.Classification`
is the classification the adapter translated the call under, and its
`ResourceFrom` the pointer it read the resource id at. Bytes whose
member there no longer names the resource the call was decided on are a DENY
of the plane's own, `OBLIGATION_NOT_UNDERSTOOD`, before anything is handed
out, for every adapter. The adapters' own aborts are gone. A pointer that is
not RFC 6901, checked by `classify.CheckPointer`, would read another member
or none, so the call is refused as `INVALID_FIELD_VALUE` in every mode. The
pipeline cannot tell where an id came from: an adapter that reads the
resource id from the arguments and leaves `ResourceFrom` empty holds no
rewrite to the resource.

## Security / compatibility impact

No wire field and no evidence field changes. Only `OBSERVE` changes for a
refused translation, an unclassified claim the envelope does not bear out
included. `pkg/contract` gains one function and `Validate` does not change.
`gateway.New` refuses an adapter named after no protocol of this build, or
declaring another strength than its protocol's; both built-in adapters
declare their protocol's. Over MCP, the block now carries the kernel's code
instead of `MALFORMED_INPUT` with the refusal's text. Over the enforcement
API, `BLOCK` no longer appends `INVALID_FIELD_VALUE`. Such calls now count as
blocked, not executed.

A rewrite that moves the resource is now a plane DENY with no
`ACTION_STARTED`, in place of an abort that ended `ACTION_FAILED`.

A trail that names no protocol, or one this build does not know, in an
enforcing mode moves from enforced to decided in coverage and in the run
view. Any MCP or enforcement API trail reads as before.

## Alternatives considered

- **A send gate in `adapterkit` that each adapter calls, plus a conformance
  table.** It changes no behaviour, but an adapter opts into it, so one that
  forgets still runs.
- **Keep the copies and fix the worked example.** It is the cheapest, but the
  defect class stays.
- **Match the kernel's reason codes, or run `Validate` again in the
  pipeline, to tell a refused input.** A verdict never derives from a code,
  and a second copy of the check can drift from the first. The kernel states
  the fact where it takes it.
- **Have the kernel validate an envelope under a handed-in unclassified
  refusal.** The kernel would have to read the gateway's sentinel, which it
  does not import. The contract states the rule once, and the pipeline, which
  reads the claim, applies it.
- **Leave the claim to `adapterkit.Unclassified`.** An adapter opts into it,
  so one that does not still runs.
- **Record a strength on each event.** That is a new field on a v1 event,
  frozen at 1.0. The protocol a call recorded is vouched for by the
  vocabulary refusal, so the table is read instead.
- **Make `Validate` refuse an unknown kind.** That is a change of v1
  meaning. Only the plane's own adapters are held to the vocabulary.

## Consequences

An adapter needs no refusal check of its own. Its worked example in
`docs/extending/adapters.md` names its protocol and strength from
`internal/channel`. `internal/channel` is a tree
the guarded trees reach, so it is held to the dependency rule.

A run is still minted, before the kernel decides, for a call the adapter
reported as whole whose input the kernel then refuses. The call is blocked,
and the run holds nothing it took in.

## Validation

- `internal/gateway/translation_test.go`: a property test over every mode
  `New` starts and twenty-seven refusal shapes, among them
  `errors.Join(contract.ErrTooLarge, ErrUnclassified)`,
  `fmt.Errorf("%w: %w", ErrUnclassified, ErrInvalidValue)`, envelopes
  `Validate` refuses with no refusal reported, and an unclassified claim over
  schema version `9.0`, an empty `principal.id`, an `action.name` past its
  bound, a hop that does not start at the principal, a hash of other bytes, a
  hash beside arguments canon refuses, arguments canon refuses or finds too
  deep with no hash, tags the plane's own take past their bound, a preview
  with no profile and a set effect class. No refused shape is handed
  out or recorded as started; a tenant named on one side, and a hash of the
  arguments, still run under `OBSERVE`.
  `TestAnUnclassifiedClaimIsHeldToTheContract` checks each refused claim's
  code in `Admit` and `Preview` and that no raw content reaches the trail. The
  same file checks that `OBSERVE` writes the trail `ENFORCE` writes, and that
  a refused translation mints no run.
- `pkg/contract/unclassified_test.go`: over generated envelopes with an
  effect class and what it requires, `ValidateUnclassified` and `Validate`
  agree; every rule `Validate` checks after the effect refuses an envelope
  with no effect that breaks it alone.
- `internal/gateway/pipeline_test.go` and `mode_test.go`: `New` refuses an
  unknown, an empty and a differently spelled name, and each protocol at
  another strength.
- `internal/adapterkit/unclassified_test.go`: a cause without the sentinel
  comes back as it is.
- `internal/gateway/translation_internal_test.go`: the `unclassifiedOnly`
  and `translationOf` tables, and `FuzzUnclassifiedOnly`, with its seeds in
  `testdata/fuzz/`.
- `internal/core/refused_input_test.go`: `RefusedInput` is set on every
  refusal of steps 1 and 2 and on no other `INDETERMINATE`.
- `internal/gateway/vocabulary_test.go`: an unknown kind, a foreign
  protocol and a resource pointer that is not RFC 6901 are refused under
  `OBSERVE` and `ENFORCE`, in `Admit` and `Preview`, and a rewrite that moves
  the resource is a plane DENY.
- `internal/gateway/resource_internal_test.go`: the moved-resource table and
  `FuzzSameResource`.
- Per adapter: `TestRefusedTranslationIsNeverSent`,
  `TestAnOverlongClientNameIsNotSent` and
  `TestARewriteThatMovesTheResourceIsNotSent` in `adapters/mcp`, and
  `TestAnUntranslatedCallIsHandedOutInNoMode` and
  `TestARewriteThatMovesTheResourceIsBlocked` in `adapters/enforce`.
- `internal/channel`, `internal/gatewayconfig`, `internal/pause`,
  `internal/coverage` and `internal/runview` each hold their part of the
  vocabulary and the strength table. `make check-imports` and the layering
  tests in `internal/core` hold `internal/channel` to the dependency rule.
