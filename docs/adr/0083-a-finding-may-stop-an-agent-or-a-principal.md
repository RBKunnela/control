# ADR-0083: A finding may stop an agent or a principal

Status: accepted
Date: 2026-11-15

Amends [ADR-0046](0046-a-finding-stops-one-run-through-a-signed-route.md),
which stops one run, and
[ADR-0019](0019-an-operator-can-pause-calls.md) on the order of the plane's
causes, under the signed formats of
[ADR-0077](0077-a-signed-plane-takes-a-stop-list-only-from-operators-signatures.md)
and [ADR-0082](0082-a-signed-document-names-its-plane-and-a-signed-plane-serves-one-tenant.md).

## Context

A confirmed finding stops the run it is about. Some findings describe the
actor, not the task: an agent that retries denied calls does so in its next
run as well, and a stop of one run lets it open another. Only an operator's
signed pause could stop an agent, by hand.

ADR-0082 gave the signed stop line and lift a scope and a subject, and the
route a scope per rule, but served only `run`.

## Decision

- A `reaction-route/v1alpha3` rule may carry scope `agent` or `principal`
  for `REPEATED_DENIAL` version `2`, `DENIED_ACTION_RETRIED_ARGUMENTS`
  version `1` and `DENIED_ACTION_RETRIED_RESOURCE` version `1`, the rules
  about the actor's behaviour, and only with `expires_seconds`. Any other
  rule with either scope, and either scope without a lifetime, is refused
  when the route is read. The bar for a finding is unchanged: deterministic,
  confirmed, its run open and unexpired.
- `react` takes the stop's subject from the judged run's record, its agent
  or principal, and refuses a record that names none. `run_id` stays the
  finding's run. An agent or principal stop ends at its creation plus the
  rule's lifetime, never at the run's end.
- A plane matches such a stop against the agent and principal its listener's
  configuration names, within its tenant, never against the envelope or a
  run record. Every opened run of a plane carries the listener's identity,
  so on one plane a stop of its agent or principal stops the plane: every
  run, runs opened after the stop, and calls with no run. The tool listing
  is unchanged, as under a run stop. An active stop whose subject the call
  does not name reads as unknown, never as clear. A principal stop matches
  the principal's id alone, never its type, so it can only block more.
- One reason code, `AGENT_OR_PRINCIPAL_STOPPED` (48, DENY), for both scopes,
  right after `RUN_STOPPED` in the plane's causes; a call under both lists
  both. `supervise` counts it as a plane block and never as a denial, so a
  stopped agent's blocked calls raise no new finding.
- A lift names a scope and a subject and ends only stops of that scope and
  subject: a lift of a run leaves a stop of its agent standing.
  `stops lift` takes exactly one of `--run`, `--agent` and `--principal`;
  the last two only under `signed`. A finding is covered only by an active
  stop of the same scope and subject that lasts as long.
- The health answer is schema `3`: a stop entry names its scope and subject,
  and `unheld_entries` and `unread_entries` name entry ids in place of runs.

## Security / compatibility impact

An admin who signs such a rule lets one confirmed finding of one run stop
every call the plane serves for the rule's lifetime. The route is signed by
an admin and the lifetime is required, so the widening is deliberate and
bounded. A reader of `/healthz` or `health.socket` that reads
`unheld_runs` or `unread_runs` reads `unheld_entries` and `unread_entries`.
No contract under `api/proto` changes; reason code numbers below 48 are
unchanged. The MCP adapter can bind a principal through a listener
authenticator, which no configuration of the gateway binary wires; a plane
that wired one would still match a principal stop against the configured
principal, not the authenticated user, so such a stop would match none of
its calls.

## Alternatives considered

- A threshold of several confirmed findings from distinct runs before an
  agent stop: it resists one induced run but needs `react` to keep state
  across passes. Left for later.
- Naming the agent and principal on a run stop for display only, with the
  signed pause as the only way to stop an agent: no change to matching,
  but the stop stays manual.
- One code per scope: two codes where the operator's remedy, a lift of the
  named subject, is the same.
- Matching the agent of the call's run record: a client that opens a run
  under another identity would choose which stop applies.

## Consequences

`doctor` names each rule that stops an agent or a principal, and each stop
whose subject the plane does not serve. A stop of another tenant's agent or
principal matches nothing on the plane and is listed as unheld.

## Validation

`internal/reaction` tests the rule table, the refusals at parse, the
matcher (an agent stop matching every run and a runless call, another
tenant's stop matching none, an empty field read as unknown), lifts keyed by
scope and subject, and the lifetime; `internal/reaction/stopwrite` tests
coverage by scope and subject; `internal/gateway` tests two operators'
runs on one plane under agent, principal and run stops and their lifts, the
listing under a stop, and the subject taken from the listener alone;
`internal/supervise` tests that code 48 is no denial; `cmd/guardana-control`
tests `react` and `stops lift`.

## Amendment: only repeated denials stop an agent or a principal

Amended by [ADR-0088](0088-a-verdict-that-compares-two-events-times-is-at-most-suspected.md). `DENIED_ACTION_RETRIED_ARGUMENTS` and
`DENIED_ACTION_RETRIED_RESOURCE` version `1` may no longer stop anything:
their verdict ordered two events' times that may come from two clocks.
`REPEATED_DENIAL` version `2` is the one rule a route may give scope
`agent` or `principal`. An agent or principal stop already written under
a retry rule's version `1` is kept by a carry, within the stop lifetime
bound, and lifted by its operator.
