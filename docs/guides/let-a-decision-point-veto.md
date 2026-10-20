---
title: Let a decision point veto calls
summary: Point the gateway at an AuthZEN decision point, write the two rules that let it veto a scope, test what each answer does, and check the plane before it serves.
type: how-to
covers: [cmd/guardana-gateway/pdp.go, cmd/guardana-gateway/health.go, adapters/authzen/**, internal/gatewayconfig/**, internal/gateway/decisionpoint.go, internal/gateway/admit.go]
---

# Let a decision point veto calls

## When to use this

Connect your organization's existing authorization service to the agent's
decision path without replacing the signed local policy. Some of the calls
an agent makes should pass that service too. The gateway can
ask a decision point that speaks the OpenID AuthZEN Authorization API 1.0
about those calls. Its answer can only veto: every grant still comes from a
rule in your signed bundle, and while the decision point is silent, the calls
it governs are blocked in every mode that enforces; `OBSERVE` records the
silence and runs them
([ADR-0017](../adr/0017-an-external-decision-point-can-veto.md)). This is
`experimental`; [status.md](../status.md) is the inventory.

This is the external-veto API. The separate
[Enforcement API](../adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)
is `experimental`: custom tools ask Control before they act
([guide](decide-a-tool-of-your-own.md)). An operator
management API is another role. Their scopes are described in
[control and supervision](../concepts/control-and-supervision.md#three-api-roles).

## Prerequisites

- A gateway you can run ([run-the-gateway.md](run-the-gateway.md)) and a
  policy you can test ([write-and-test-a-policy.md](write-and-test-a-policy.md)).
- A decision point that answers `POST` at its access evaluation endpoint, by
  default `/access/v1/evaluation` under its identifier, and returns the
  `X-Request-ID` header it was sent. An answer without that echo is refused,
  so every call it governs is blocked.
- Its identifier, the `policy_decision_point` its metadata names: an `https`
  URL with no user, query or fragment. Never put a credential in it, since
  every decision that consulted the answer records it. A credential goes in a
  header, in step 3.
- Tools whose calls name a resource id. A call with no resource id is never
  sent to the decision point, so one a veto rule covers is blocked.

## Steps

### 1. Write the two rules

The decision point decides a scope only where the bundle allows it and lets
the decision point veto it. Write both rules over the same scope:

```json
{"id": "refunds", "effect": "ALLOW", "when": {"action": {"name": ["refund"]}}},
{"id": "refunds-vetoed", "effect": "DENY", "when": {"action": {"name": ["refund"]}, "external": {"denies": true}}}
```

`external` is legal on a `DENY` rule only, and `policy lint` refuses it
anywhere else. A call no rule reading `external` covers is never sent
anywhere.

### 2. Test what each answer does

A `policy test` case names the answer the kernel is handed in `external`:
`allowed`, `denied`, `denied_with_obligations`, `timeout`, `unavailable` or
`answer_refused`. Write one case for an allowing answer and one for silence
at least. For a read under the two rules of step 1, with `fail_open_read`
on, a timeout still blocks:

```json
"external": "timeout",
"expect": {"verdict": "INDETERMINATE", "action": "Block", "reason_codes": ["RULE_ALLOW", "RULE_UNDETERMINED", "PDP_TIMEOUT"]}
```

`fail_open_read` covers the bundle's availability, never the decision
point's. An allowing answer decides as if the veto rule were not there,
`ALLOW` with `RULE_ALLOW` and `PDP_ALLOW`. What each answer sets is in
[policy-format.md](../reference/policy-format.md).

### 3. Configure the decision point

```yaml
pdp:
  identifier: https://pdp.example.com
  timeout: 100ms         # silence past it blocks the call
  max_in_flight: 16      # an ask past it is silence at once
```

Set the credential from the environment, never in the file:
`GUARDANA_CONTROL_PDP_HEADERS_AUTHORIZATION` sends an `Authorization` header
on every question, and `doctor` never prints its value. The other keys:

- `evaluation_endpoint`, when it is not the default path. It must share the
  identifier's scheme, host and port.
- `allow_plaintext`, for a decision point over `http` on a loopback address,
  and nowhere else.
- `proxy`, to send the questions through a proxy. Without it none is used,
  whatever the environment says.
- `informational_context`, the context members an allowing answer may carry.
  None by default: any member but those and `obligations` makes an allow
  unreadable, and the call is blocked. A non-empty `obligations` is a veto.

`timeout` covers connecting too: the first ask on a new connection pays for
the handshake, so a decision point on another host may need more than the
default. Every key and its variable are on
[configuration.md](../reference/configuration.md). The plane refuses to start
with a bundle that reads `external` and no `pdp.identifier`, and with a
`pdp.identifier` no rule reads; the message says which to change. Starting
never contacts the decision point. Its certificate is verified against the
system's roots; there is no setting for a private certificate authority.

### 4. Check it with doctor

```
guardana-gateway doctor --config gateway.yaml
```

With every earlier check `ok`, the last line is `pdp`. `doctor` reads the decision point's published
metadata, `/.well-known/authzen-configuration` followed by the identifier's
path, and compares it with your
identifier and evaluation endpoint: `ok` when it agrees, `fail` when it does
not or leaves one out, `unknown` when it cannot be read or either is not a
string. Only `doctor` reads it, and the plane
starts whatever it says. `doctor` sends no question and no credential, so `ok`
does not mean the decision point accepts your credential. A setting the client
refuses, such as an `http` identifier without `allow_plaintext`, fails the
`seams` line before it.

### 5. Watch the asks

`/healthz` carries `pipeline.asks`: `made`, then how each ask came back
(`allowed`, `denied`, `denied_obligations`, `timed_out`, `unavailable`,
`answer_refused`), and `wait_us`, the time spent waiting on them. A rise in
`timed_out` or `unavailable` is asks left unanswered, and outside `OBSERVE`
each one blocked its call. A decision that consulted the answer names the
decision point in `pdp_instance` and carries one of the codes on
[reason-codes.md](../reference/reason-codes.md).

## Verify

- `policy test` passes one case per answer you rely on, silence among them.
- `doctor` ends with `ok` on its `pdp` line.
- A call the veto covers, and that no pause, stop, halt or `DENY` of the
  kernel's blocks first, raises `pipeline.asks.made` and one outcome;
  `allowed`, `denied` or `denied_obligations` shows the decision point
  answered. A call it does not cover leaves the counters where they were.

## What the decision point sees

The question carries the principal, the agent, the action, the resource, the
destination, the data labels and the request's ids, as mapping version 1 in
ADR-0017 lists them. It never carries
the call's arguments, their hash, the run context or the delegation chain.

## Roll back

Remove the `external` rules from the bundle and the `pdp.` keys from the
configuration together, since the plane refuses either without the other.
Without the rules, the bundle decides as it did before.
