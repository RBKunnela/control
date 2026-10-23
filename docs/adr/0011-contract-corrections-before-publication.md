# ADR-0011: Corrections to the v1 contract before it is first published

Status: accepted
Date: 2026-09-10

Amends [ADR-0002](0002-wire-contracts-and-versioning.md),
[ADR-0003](0003-policy-model-and-external-pdp.md),
[ADR-0004](0004-evidence-and-privacy-defaults.md),
[ADR-0005](0005-canonical-action-digest.md) and
[ADR-0010](0010-digest-domain-separation.md).

Amended by [ADR-0059](0059-a-tools-classification-is-one-type-checked-when-it-loads.md): the identifier rule is applied to an
operator's resource type, tool name and provider when the configuration
loads, not first at the call.

## Context

The v1 contract was frozen by ADR-0002, which made every breaking change after
it a failure. A review of the whole repository before the policy kernel was
built found places where the frozen text contradicts itself,
where absence is more permissive than presence, and one where an approval
covers two actions an operator would call different.

None of it has been published. The public history of this repository starts
from a single commit taken after this record, so no v1 message, digest or
approval exists anywhere a correction could break. A correction now costs this
record. After publication the same correction is a new major version.

## Decision

The corrections below are made once, together. The commit that lands them is
the baseline `buf breaking` compares against, and from it on a breaking finding
is a failure again, as ADR-0002 says. Two of them hold only because the history
is squashed, and say so.

**The name.** The proto package is `guardana.control.v1` (ADR-0006). No message
changes on the wire, because v1 has no service and no `Any`; either, added
later, would put the package name on the wire.

**The action digest covers where the action happens.** The canonical action has
ten members: the seven of ADR-0005, and `projectId`, `tenantId` and
`environment`, the envelope's own values as top-level strings, `""` when absent.
They were left out as fields that two attempts at one action differ in, which is
false for all three. Without them an approval granted in one project, tenant or
environment matches the identical action in another, and an approved staging
deletion matches a production one whenever the resource's own environment is
empty.

The tag stays `agent-action-digest/v1`. That overrides, once, ADR-0005's "a
field added to the digest input needs its own record and a new package version"
and ADR-0010's "the `v1` in the tag separates versions of the canonical form".
It is honest only because no digest under the seven-member form will ever be
published: the goldens that used it exist only in the local history, which is
squashed away. Publishing that history would first require a `v2` tag.

**Keys that fold together are refused.** Two member names in one object equal
under simple case folding (CaseFolding.txt, statuses C and S, Unicode 17.0.0,
compared code point by code point) are refused like a duplicate, in every object
of the canonical action. A consumer that folds case, as Go's `encoding/json`
does for U+017F and U+212A as well as for ASCII, would otherwise read one value
where the digest covers another. It does not defend a consumer that compares
through case mapping, where U+0131 and `I` are equal.

**The arguments hash has a formula.** `arguments.canonical_hash` is `"sha256:"`
and the lowercase hex of sha256 over `agent-arguments-hash/v1\n` followed by the
canonical form of the authorized arguments, `{}` when there are none. The
receiver, which holds the arguments, compares it and refuses a mismatch;
`Validate`, which does not, checks its shape. Every producer of `EXECUTE` and
`TRANSACT` therefore implements the canonical form, and until a second
implementation is proved against the goldens only a Go producer can.

**The policy bundle names its inputs.** The signature is Ed25519 over DSSE's
pre-authentication encoding of `application/vnd.agent-policy+json` and the
decoded bytes of `canonical`. `signature_alg` is the fixed string
`ed25519-dsse`; it selects nothing, and any other value is refused. `key_id` is
an unauthenticated hint that selects a key the operator pinned; an unknown one
is refused. The bundle digest is `"sha256:"` and the lowercase hex of sha256 over
those bytes, which must equal their own canonical form, so that one policy has
one digest. Every field outside `canonical` must equal what the signed document
says. The document's format is recorded with the policy kernel.

**An unknown sensitivity is unknown.** A check that denies at or above a floor
answers yes when a known part of what the call carries is at or above it: what
the run read, a declared label, or `contains_secrets`. Otherwise it refuses to
answer when any part is unknown, and the kernel records that as
`INDETERMINATE`. Otherwise it answers no. A check that allows at or below a
ceiling never passes an unknown.

**Obligations bind whenever the call proceeds**: under
`ALLOW_WITH_OBLIGATIONS`, and under `REQUIRE_APPROVAL` once approved.
`ALLOW_WITH_OBLIGATIONS` with no obligation is never produced. A receiver that
cannot apply a non-advisory obligation denies with `OBLIGATION_NOT_UNDERSTOOD`,
and no fail-open setting relieves that denial.

**Approvals follow one model, the held call.** An approval is honoured only in
the trail of the request it was requested for: `request_id` must equal the
envelope's, and the binding must match. A call submitted again as a new request
needs a new approval, which is why data labels and the run context can stay out
of the digest. An approval with no `expires_at` is expired. Expiry of an approval
or a delegation hop is measured against the receiver's clock when deciding, and
again before execution (`planned`), never against the producer's `occurred_at`.
`APPROVAL_STATE_UNSPECIFIED` is not approved, and `APPROVED` with no
`approver_id` is refused.

**An external decision point** returns `ALLOW`, `DENY` or `INDETERMINATE` and
nothing else in v1. An AuthZEN 1.0 decision is a boolean: it carries no
obligations, and there is no policy digest an approval could bind to.

**A fail-open read keeps its verdict.** The verdict of a read nothing evaluated
stays `INDETERMINATE`, and only what is enforced changes; its reason code is
documented with `INDETERMINATE`, not `ALLOW`, the collapse invariant 4 forbids.
When a read may fail open is recorded with the kernel's fail-closed table.

**Three fields are declared now**, so that filling them later is not a field
every 1.0 reader refuses:

- `Event.prev_event_digest`, number 31, where the reservation stood. Empty, and
  read by nothing, until the hash chain lands (`planned`); an empty link claims
  nothing.
- `ActionResult.redaction_profile`, number 14, with the meaning
  `Arguments.redaction_profile` has. Empty means no redaction ran, which is right
  only when there is no preview; the check that pairs them is `planned` for the
  result path.
- `Decision.decided_at`, number 18, by the receiver's clock.

**The contract states what the zero values mean**, on the contracts page and in
one line per enforcement mode: `ENFORCEMENT_MODE_UNSPECIFIED` is refused as
configuration and, in evidence, means that nothing is known to have been
enforced.

**Validation refuses more**, in `pkg/contract`:

- in every string of the envelope and every map key and value: White_Space at
  either end, a space separator other than U+0020 anywhere, a code point in Cc,
  Cf, Zl or Zp, a Default_Ignorable_Code_Point, and invalid UTF-8, per Unicode
  17.0.0. A reader cannot tell U+00A0 or U+3000 from a space, so two identifiers
  that look alike would be two. The two free-text fields,
  `arguments.redacted_preview` and `delegation[].reason`, are held only to valid
  UTF-8 and to the control-character rule, with tab, line feed and carriage
  return allowed;
- in every map, a key whose first nine code points fold to `reserved.`, so
  `Reserved.x` is refused as `reserved.x` is, and so is a key spelled with
  U+017F; and two keys that fold together;
- `TRANSACT` and `IDENTITY_OR_ACCESS` without both `principal.tenant_id` and
  `resource.tenant_id`; `WRITE`, `DELETE` and `CONFIGURE` without
  `resource.environment`, besides the envelope's `environment`, which stays
  required;
- a delegation chain that does not start at `principal.id` and end at
  `agent.id`, a hop with no `expires_at`, and a hop that expires before it was
  issued;
- a redacted preview that names no redaction profile;
- a `destination.host` that holds a byte outside `[a-z0-9.:-]`, starts or ends
  with a dot, or has an empty label. A host that holds a colon must be an IPv6
  literal: at least two colons, and nothing but `[0-9a-f:.]`. Letter case, a
  trailing dot, a port and a Unicode name are then not second spellings of one
  host, and an internationalized name arrives as A-labels. IP-literal
  spellings are not normalized, so a DENY keyed on one is only as strong as
  the producer's spelling;
- `SENSITIVITY_UNSPECIFIED` as an element of `data.sensitivities`;
- on the binary path, a second occurrence of a field that is not repeated; two
  entries of one map whose keys the runtime reads as one key, where an entry
  with no key, or with its key on the wrong wire type, reads as the empty key;
  and an enum number outside int32 when its varint is read as a
  two's-complement int64. The JSON path refuses all three already;
- inside a map entry, any field other than the key and the value, and either
  of those on a wire type other than its own. The runtime would discard it
  before any walk could see it. A map entry has two fields by definition, so
  this closes the one exception ADR-0002 recorded to "unknown fields are
  refused".

## Security / compatibility impact

Every correction narrows what is accepted or makes a stated guarantee true,
with two exceptions that widen and are stated here. The three new fields are
accepted where the frozen 1.0 refused them; no reader exists. Expiry moves from a
producer-set anchor to the receiver's clock, so a slow receiver clock lengthens
an approval's life; `occurred_at` could be back-dated, which is worse.

The cost is that the frozen contract moved once more than ADR-0002 said it
would. This record is where that is written down, and the gate restarts behind
it.

## Alternatives considered

- **Fix only the semantics, in the kernel.** Most of the validation items could
  live there. The digest scope, the folded keys, the three fields and the frozen
  comments cannot: each is fixed by the contract, and every later implementation
  would have to rediscover the kernel's exceptions.
- **A `v2` package now.** A second package before the first has one user is
  version churn with nothing on the other side of it.
- **`agent-action-digest/v2`.** Just as safe, and it implies a v1 that someone
  could hold.
- **Folding ASCII only.** Simpler to specify, and Go's own decoder folds beyond
  ASCII.

## Consequences

The four digest goldens change once; a fifth pins the escaping rules and a sixth
the arguments hash, each computed by two implementations. `docs/contracts.md`
states every rule above. ADR-0002, ADR-0003, ADR-0004, ADR-0005 and ADR-0010
carry a line pointing here.

## Validation

`buf breaking` from the commit that lands this record against the commit
before it reports the removed reservation of `Event` field 31 and its name,
and nothing else.

Planned with the policy kernel, each a test that fails when its correction is
undone: the digest over envelopes that differ only in project, tenant or
environment; the folded-key refusal, in the canonical form and in `Validate`;
the unknown sensitivity, including an unknown run state beside a declared
`PUBLIC`; the arguments hash, computed twice; each validation refusal above,
with a boundary case.
