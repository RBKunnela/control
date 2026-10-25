---
title: Policy document format
summary: Every member of an agent-policy/v1alpha1 document, the values each admits, the bounds, and the members of a policy test case.
type: reference
covers: [internal/policy/rules/**, cmd/guardana-control/testcase.go, internal/gateway/admit.go, internal/core/clock.go]
---

# Policy document format

What `internal/policy/rules` reads, member by member. The meaning of a rule
and the order of the decision are
[ADR-0012](../adr/0012-policy-kernel-semantics.md)'s; how to write and test a
document is [guides/write-and-test-a-policy.md](../guides/write-and-test-a-policy.md).
The parser is `implemented`.

## The document

A document is JSON, and strict JSON: a duplicate key, two keys that fold
together, a float, an integer outside the JSON-safe range, invalid UTF-8 and
nesting past 32 containers are refused before any member is read. Keys match
exactly, case included. Every object below is closed: a key it does not list
is refused, and the refusal names the object, never the key.

| Member | Required | Holds |
| --- | --- | --- |
| `apiVersion` | yes | `agent-policy/v1alpha1`, exactly. A later version is refused, never read as this one. |
| `bundle` | yes | The document's identity, below. |
| `rules` | yes | 1 to 4096 rules, evaluated in document order. |

### `bundle`

| Member | Required | Holds |
| --- | --- | --- |
| `id` | yes | An identifier. A plane pinned to one bundle id refuses every other. |
| `version` | yes | An identifier the author chooses. |
| `serial` | yes | An integer from 1 up. |
| `maxStaleSeconds` | yes | An integer from 1 up: how long a plane may decide on this document after a freshness statement confirmed it, at most `policy.max_stale`. |

There is no creation time: none is signed, so a key for one is an unknown key.

### A rule

| Member | Required | Holds |
| --- | --- | --- |
| `id` | yes | An identifier, unique in the document. A duplicate names the earlier rule by position. |
| `effect` | yes | `ALLOW`, `DENY`, `REQUIRE_APPROVAL` or `ALLOW_WITH_OBLIGATIONS`. |
| `reason` | no | A reason code the effect may name, from the table below; the effect's default may be written or left off. |
| `obligations` | see below | 1 to 8 obligations. Refused on `ALLOW` and `DENY`, which carry none into a decision; required on `ALLOW_WITH_OBLIGATIONS`; optional on `REQUIRE_APPROVAL`. |
| `when` | yes | The constraint groups, at least one: a rule that constrains nothing would match every call. |

| Effect | Reason codes it may name, default first |
| --- | --- |
| `ALLOW` | `RULE_ALLOW` |
| `DENY` | `RULE_DENY`, `ENVIRONMENT_BOUNDARY`, `OUT_OF_SCOPE_ACTION`, `TOXIC_FLOW_SENSITIVE_TO_EXTERNAL` |
| `REQUIRE_APPROVAL` | `APPROVAL_REQUIRED` |
| `ALLOW_WITH_OBLIGATIONS` | `OBLIGATIONS_ATTACHED` |

A code the kernel emits about its own checks, such as `TENANT_MISMATCH` or
`POLICY_STALE`, is on no list: a policy that could name one could dress its
own denial as the kernel's. Every code is in
[reason-codes.md](reason-codes.md).

### An obligation

| Member | Required | Holds |
| --- | --- | --- |
| `type` | yes | A type in [obligations.md](obligations.md), spelled exactly. |
| `params` | no | 1 to 32 string entries, checked against [obligations.md](obligations.md) by `policy lint` and when signing, not when loading. |
| `advisory` | no | `true` or `false`. A receiver that cannot apply a non-advisory obligation denies. |

### `when`

Each group is optional and constrains nothing when absent; a present group
holds at least one member. A list means any of its values, 1 to 64 of them,
and a value matches by exact equality: no regular expressions, no prefixes,
no scripts. A map constraint names entries the envelope's map must hold, each
with the values it may hold there. Every constraint of a rule has to hold.

| Group | Member | Holds |
| --- | --- | --- |
| `principal` | `id`, `type`, `authnStrength`, `tenantId` | Lists of identifiers. |
| `principal` | `attributes` | A map constraint over `principal.attributes`. |
| `agent` | `id`, `framework` | Lists of identifiers. |
| `action` | `name`, `provider`, `protocol`, `kind` | Lists of identifiers. |
| `action` | `effect` | A list of effect classes: `READ`, `WRITE`, `DELETE`, `EXECUTE`, `COMMUNICATE`, `TRANSACT`, `IDENTITY_OR_ACCESS`, `CONFIGURE`, `SPAWN_OR_DELEGATE`. |
| `resource` | `type`, `id`, `tenantId`, `environment` | Lists of identifiers. |
| `resource` | `labels` | A map constraint over `resource.labels`. |
| `destination` | `trustZone` | A list of `TRUSTED_INTERNAL`, `PARTNER`, `UNTRUSTED_EXTERNAL`, `USER_CONTROLLED`, `MODEL_GENERATED`. |
| `destination` | `host` | A list of hosts, each in the one spelling the contract admits: lower case, no trailing dot, no Unicode. |
| `data` | `sensitivityAtLeast` | Required in the group. A floor, `PUBLIC` to `SECRET`, compared with the envelope's own labels; `containsSecrets` meets every floor. |
| `flow` | `toxicAtLeast` | Required in the group. The same floor, compared with the run's flow. |
| `delegation` | `scopes` | Required in the group. A list of identifiers a delegated call's effective scopes must include. Unknown for a call with no chain. |
| `external` | `denies` | Required in the group, and only `true`. Holds when the external decision point denies the call. Legal on a `DENY` rule only. |

Enum values are spelled without the wire prefix: `TRANSACT`, not
`EFFECT_CLASS_TRANSACT`. `UNSPECIFIED` is refused everywhere.

### The external decision point

`external` lets a configured decision point veto what the bundle allows
([ADR-0017](../adr/0017-an-external-decision-point-can-veto.md)). It never
grants, so it is legal on `DENY` alone, and letting it decide a scope takes
two rules:

```json
[
  {"id": "refunds", "effect": "ALLOW", "when": {"action": {"name": ["refund"]}}},
  {"id": "refunds-vetoed", "effect": "DENY", "when": {"action": {"name": ["refund"]}, "external": {"denies": true}}}
]
```

The gateway asks the decision point its `pdp.` keys name only when a rule
reading `external` has no other constraint that is false and the decision
without the answer is not `DENY`;
[guides/let-a-decision-point-veto.md](../guides/let-a-decision-point-veto.md)
sets one up. The answer sets the constraint:

| Answer | `external` | Code on the decision |
| --- | --- | --- |
| denies the call | true | `PDP_DENY` |
| allows it with an obligation this plane cannot fulfil | true | `OBLIGATION_NOT_UNDERSTOOD` |
| does not deny it | false | `PDP_ALLOW` |
| no answer within the deadline | unknown | `PDP_TIMEOUT` |
| no decision came back | unknown | `PDP_UNAVAILABLE` |
| a reply this plane will not read | unknown | `PDP_ANSWER_REFUSED` |

An unknown `external` leaves its rule undetermined, which blocks every
effect class, a read under `fail_open_read` too. A decision that consulted an
answer names the decision point in `pdp_instance`.

## Strings and bounds

| What | Bound |
| --- | --- |
| The document | 1 MiB; `policy lint` refuses a file over 2 MiB before parsing it |
| Rules | 4096 |
| Values in one list | 64 |
| Entries in one map | 32 |
| Obligations on one rule | 8 |
| One string | 1024 bytes |
| Nesting | 32 containers |
| `serial` | 1 to 2^53 - 1 |
| `maxStaleSeconds` | 1 to the largest whole-second duration Go holds |

An identifier is a non-empty string the envelope could carry: valid UTF-8,
no white space at either end, and no code point of the classes the
identifier rule of [ADR-0011](../adr/0011-contract-corrections-before-publication.md)
refuses. The empty string is refused wherever an identifier is read, because
an envelope field holding `""` is an absent input that no constraint
compares. A map key is held to the same rule and may not sit in the reserved
namespace, `reserved.`.

## Refusals

`Parse` returns the first refusal in a fixed order: the document, its bundle,
then each rule in document order, each member in the order of the tables
above. A refusal names the rule, once its id has been read, and the refused
member as a path such as `rules[2].when.action.name[0]`; an entry of a map is
named by its position in sorted key order, never by its key. The refused
value is never repeated, because a refusal is written to logs.

| Sentinel | Means |
| --- | --- |
| `rules: over a bound` | A bound of the table above. |
| `rules: not strict JSON` | What the canonical form refuses. |
| `rules: wrong JSON type` | A string where an object was wanted, and so on. |
| `rules: a key this document format does not have` | An unknown key in a closed object. |
| `rules: a required key is missing` | A required member absent. |
| `rules: empty` | An empty string, list or group. |
| `rules: breaks the identifier rule` | A string no envelope could carry. |
| `rules: a key in the reserved namespace` | A map key the contract reserves. |
| `rules: an apiVersion this build does not read` | Any `apiVersion` but this one. |
| `rules: not above zero` | A `serial` or `maxStaleSeconds` at zero or below. |
| `rules: not a name this document spells a value with` | An effect, effect class, trust zone or sensitivity outside the lists. |
| `rules: a floor nothing can be compared against` | `UNSPECIFIED` as a floor. |
| `rules: a rule id used twice` | A duplicate `id`. |
| `rules: obligations on a rule whose effect carries none` | `obligations` on `ALLOW` or `DENY`. |
| `rules: an obligation type outside the catalogue` | A `type` not in the catalogue. |
| `rules: a reason this rule's effect may not name` | A `reason` outside the effect's list. |
| `rules: external holds only when the decision point denies` | `denies` given as `false`. |
| `rules: external on a rule whose effect is not DENY` | `external` on `ALLOW`, `REQUIRE_APPROVAL` or `ALLOW_WITH_OBLIGATIONS`. |

## A test case

A case for `policy test` is one JSON object holding each member below once,
all required but `external`. An unknown, missing or repeated member, and
anything after the object, are refused.

| Member | Holds |
| --- | --- |
| `document` | The policy document, inline, as `policy lint` reads it from a file. |
| `envelope` | The `ActionEnvelope`, in Protobuf JSON. What the decoder refuses is handed to the kernel as its refusal, so a case can expect `INDETERMINATE` for a malformed envelope. |
| `authorized_args` | The authorized arguments document as one string, `""` for none. When the envelope carries `arguments.canonicalHash`, the kernel compares it with the hash of this string. |
| `flow` | `untrusted` (`true` or `false`) and `floor`, a `Sensitivity` name without its prefix: the state of the run the call belongs to. |
| `options` | The kernel's configuration: `fail_open_read` (`true` or `false`), `max_stale_seconds` (an integer, above zero) and `applicable` (the catalogue's obligation types the enforcement point can apply). |
| `loaded_at` | When the bundle was loaded, RFC 3339 with a zero offset, `Z` or `+00:00`. |
| `decided_at` | When the kernel decides, in the same form; one before 1970 or before `loaded_at` decides `INDETERMINATE` `POLICY_STALE` and blocks. |
| `external` | Optional. The decision point's answer handed to the kernel: `allowed`, `denied`, `denied_with_obligations`, `timeout`, `unavailable` or `answer_refused`. Without it nothing was asked: a rule reading `external` is undetermined unless another constraint is false. |
| `expect` | `verdict` (a `Verdict` name without its prefix, never `UNSPECIFIED`), `action` (`Block`, `Execute`, `ExecuteWithObligations` or `AwaitApproval`) and `reason_codes`, compared exactly and in order. |
