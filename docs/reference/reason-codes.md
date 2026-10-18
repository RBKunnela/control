---
title: Reason codes
summary: Every reason code a decision may carry, with its number and the verdict it usually accompanies.
type: reference
covers: [internal/policy/reasons/**]
generated: scripts/gen-reason-codes.go
---

# Reason codes

A reason code is the machine-readable answer to why a call received the
verdict it did, and it travels in `Decision.reason_codes` and in the
evidence record. The verdict column records the verdict a code normally
accompanies, and it is documentation: a verdict comes from the matcher and
from deny-overrides precedence
([ADR-0003](../adr/0003-policy-model-and-external-pdp.md)), never from the
code attached to it afterwards.

A decision may carry several codes, and the column does not compose: where
there is more than one, the verdict is the one deny-overrides precedence
reaches and not anything read off a single row. What is built and what is
not is in [status.md](../status.md).

Rendered from the table in `internal/policy/reasons/codes.go`. Rebuild it
with `make docs-gen`; an edit made here does not survive the next run.

| Code | Number | Usual verdict | Summary |
| --- | --- | --- | --- |
| `NO_MATCHING_RULE` | 1 | `DENY` | No rule in the policy bundle matches this call, and the matcher has no implicit allow. |
| `RULE_ALLOW` | 2 | `ALLOW` | A rule in the policy bundle matches this call and allows it. |
| `RULE_DENY` | 3 | `DENY` | A rule in the policy bundle matches this call and denies it. |
| `APPROVAL_REQUIRED` | 4 | `REQUIRE_APPROVAL` | A rule matches this call and requires an approval bound to its action digest before it runs. |
| `OBLIGATIONS_ATTACHED` | 5 | `ALLOW_WITH_OBLIGATIONS` | A rule allows this call only if the obligations carried on the decision are applied to it. |
| `TENANT_MISMATCH` | 6 | `DENY` | The principal's tenant is not the tenant that owns the resource the call names. |
| `ENVIRONMENT_BOUNDARY` | 7 | `DENY` | The resource named is in an environment the policy does not let this principal reach. |
| `OUT_OF_SCOPE_ACTION` | 8 | `DENY` | The action falls outside the set of actions this principal is authorized to propose. |
| `DELEGATION_EXCEEDS_PARENT` | 9 | `DENY` | The delegation claims more authority than the delegation it was derived from. |
| `DELEGATION_CYCLE` | 10 | `DENY` | The delegation chain returns to a party it already passed through, which would launder back authority an earlier hop narrowed. |
| `DELEGATION_EXPIRED` | 11 | `DENY` | The delegation this call relies on had expired, by this receiver's clock, when it was checked. |
| `APPROVAL_DIGEST_MISMATCH` | 12 | `DENY` | The approval presented names a different canonical action digest than the call it accompanies. |
| `APPROVAL_EXPIRED` | 13 | `DENY` | The approval presented had expired, by this receiver's clock, when it was checked. |
| `APPROVAL_PENDING` | 14 | `REQUIRE_APPROVAL` | An approval for this exact action digest is open and no approver has answered it yet. |
| `POLICY_STALE` | 15 | `INDETERMINATE` | The policy bundle is not known to be current: it is past the staleness budget in force for this call, no freshness statement confirms it, another bundle replaced it before the call was handed out, or this receiver's clock reads before 1970, after 9999, or earlier than a time it verified for the bundle or already relied on for the call. |
| `POLICY_UNAVAILABLE` | 16 | `INDETERMINATE` | No policy bundle is available for this call, so nothing evaluated it. |
| `PDP_TIMEOUT` | 17 | `INDETERMINATE` | The external policy decision point does not answer within the deadline set for this call. |
| `MALFORMED_INPUT` | 18 | `INDETERMINATE` | The request could not be read as this contract at all, which is answered with a decision rather than a transport error. |
| `UNSUPPORTED_SCHEMA` | 19 | `INDETERMINATE` | The request names a schema version, a field or an enum number this receiver does not have, which is answered with a decision rather than a transport error. |
| `EXECUTED_ARGS_MISMATCH` | 20 | `DENY` | The arguments about to be sent upstream differ from the arguments the decision was made about. |
| `TOXIC_FLOW_SENSITIVE_TO_EXTERNAL` | 21 | `DENY` | The call moves data the producer did not establish as public into a destination it did not establish as trusted. |
| `IDEMPOTENCY_REQUIRED` | 22 | `DENY` | The call has an effect that cannot be safely repeated and nothing in the request distinguishes it from a repeat. |
| `SELF_ADMINISTRATION` | 23 | `DENY` | The call targets the enforcement plane's own policy, approvals or evidence. |
| `PAUSED` | 24 | `DENY` | An operator paused calls in a scope this call falls in, so the enforcement point blocked it whatever the policy decided. |
| `FAIL_OPEN_READ_CONFIGURED` | 25 | `INDETERMINATE` | This read was not evaluated and keeps its verdict, and it runs only because an operator turned on fail-open for read-only calls, which changes the enforcement and never the verdict. |
| `REQUIRED_FIELD_ABSENT` | 26 | `INDETERMINATE` | A field this contract requires is absent, and an absent field is never read as the permissive answer. |
| `LIMIT_EXCEEDED` | 27 | `INDETERMINATE` | A field on the request is larger than the limit this contract sets for it. |
| `INVALID_FIELD_VALUE` | 28 | `INDETERMINATE` | A field on the request is present and within its limit, and its value breaks a rule the contract states. |
| `OBLIGATION_NOT_UNDERSTOOD` | 29 | `DENY` | The call comes with an obligation this enforcement point cannot apply, attached by a policy rule that did not mark it advisory or by an external decision point's answer. |
| `APPROVAL_REJECTED` | 30 | `DENY` | An approver answered the request for this action digest and refused it. |
| `APPROVAL_ALREADY_USED` | 31 | `DENY` | The approval presented was already spent on an earlier call of this request and was not issued as multi-use, and a spent approval does not by itself say that the earlier call ran. |
| `APPROVAL_BUNDLE_MISMATCH` | 32 | `DENY` | The approval presented was issued under a different policy bundle than the one deciding this call. |
| `RULE_UNDETERMINED` | 33 | `INDETERMINATE` | A rule that would restrict this call cannot be evaluated against it, because a field or a fact it constrains is absent or unknown. |
| `TENANT_UNDETERMINED` | 34 | `INDETERMINATE` | The request names a tenant on only one side of the cross-tenant comparison, so whether this call crosses tenants cannot be established. |
| `LOCKDOWN` | 35 | `DENY` | The enforcement point is in LOCKDOWN, which blocks every call with a material effect whatever the policy decided. |
| `EVIDENCE_UNAVAILABLE` | 36 | `INDETERMINATE` | The enforcement point could not write, keep or read back a record the decision depends on, so the call was not allowed to proceed. |
| `ACTION_UNCLASSIFIED` | 37 | `INDETERMINATE` | The enforcement point's manifest holds no entry for the operation this call names, so no effect class can be given to it. |
| `APPROVAL_NOT_RESUMED` | 38 | `DENY` | An approver granted this action and the request it was granted for no longer exists, so the call was never run and the enforcement point closed its record instead. |
| `PDP_UNAVAILABLE` | 39 | `INDETERMINATE` | No decision came back from the external decision point for this call, because it could not be asked or reached or replied with something other than a decision. |
| `PDP_ANSWER_REFUSED` | 40 | `INDETERMINATE` | The external decision point replied about this call, and this enforcement point refused to read the reply as a decision. |
| `PDP_DENY` | 41 | `DENY` | The decision consulted the external decision point and it denied this call; the verdict is still INDETERMINATE when a rule stays undetermined. |
| `PDP_ALLOW` | 42 | `ALLOW` | The decision consulted the external decision point and it did not deny this call; the verdict is still INDETERMINATE when a rule stays undetermined. |
| `PAUSE_STATE_UNAVAILABLE` | 43 | `INDETERMINATE` | The enforcement point could not read the operator's pause state, so it blocked the call rather than assume that nothing is paused. |
| `APPROVAL_STATE_UNKNOWN` | 44 | `INDETERMINATE` | The enforcement point could not read or trust the approver's answer for a lost hold, so the call was never run. |
| `RUN_STOPPED` | 45 | `DENY` | A stop the operator's route allows names the opened run this call belongs to, so the enforcement point blocked it whatever the policy decided. |
| `STOP_STATE_UNAVAILABLE` | 46 | `INDETERMINATE` | The enforcement point could not read or trust the stop list, so it blocked the call rather than assume that no run is stopped. |
| `EXECUTION_ABANDONED` | 47 | `INDETERMINATE` | An execution the enforcement point handed out was neither completed nor aborted before it expired, so it was closed without knowing whether the call ran. |
