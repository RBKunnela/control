package reasons

import controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"

// Code is one entry in the registry.
type Code struct {
	// ID is what appears on the wire, in Decision.reason_codes and in
	// evidence. A code is retired, never renamed: an old record has to keep
	// meaning what it meant when it was written.
	ID string

	// Num is the stable numeric identifier, never reused. A retired code
	// leaves a gap rather than letting a new code inherit its number.
	Num uint32

	// Verdict is the verdict this code normally accompanies. It exists for the
	// reference page, and it is never an input to a decision; see the package
	// comment. Each pairing is pinned as a literal in registry_test.go, so
	// changing one here is a change to that table too.
	Verdict controlv1.Verdict

	// Summary is one sentence stating what happened, in the words someone
	// reading a decision needs, not what to do about it.
	Summary string
}

// codes is the whole registry, in Num order. Nothing writes to it after
// initialization and All copies it before handing it out.
//
// Duplicate identifiers, duplicate numbers, a zero Num and any drift between
// an identifier, its number and its documented verdict are caught by
// registry_test.go, not by a check that panics at init: this package sits on
// the decision path, and a panic there takes the enforcement plane down at
// startup, while the test fails the build before anything ships.
var codes = [...]Code{
	{
		ID:      "NO_MATCHING_RULE",
		Num:     1,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "No rule in the policy bundle matches this call, and the matcher has no implicit allow.",
	},
	{
		ID:      "RULE_ALLOW",
		Num:     2,
		Verdict: controlv1.Verdict_VERDICT_ALLOW,
		Summary: "A rule in the policy bundle matches this call and allows it.",
	},
	{
		ID:      "RULE_DENY",
		Num:     3,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "A rule in the policy bundle matches this call and denies it.",
	},
	{
		ID:      "APPROVAL_REQUIRED",
		Num:     4,
		Verdict: controlv1.Verdict_VERDICT_REQUIRE_APPROVAL,
		Summary: "A rule matches this call and requires an approval bound to its action digest before it runs.",
	},
	{
		ID:      "OBLIGATIONS_ATTACHED",
		Num:     5,
		Verdict: controlv1.Verdict_VERDICT_ALLOW_WITH_OBLIGATIONS,
		Summary: "A rule allows this call only if the obligations carried on the decision are applied to it.",
	},
	{
		ID:      "TENANT_MISMATCH",
		Num:     6,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The principal's tenant is not the tenant that owns the resource the call names.",
	},
	{
		ID:      "ENVIRONMENT_BOUNDARY",
		Num:     7,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The resource named is in an environment the policy does not let this principal reach.",
	},
	{
		ID:      "OUT_OF_SCOPE_ACTION",
		Num:     8,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The action falls outside the set of actions this principal is authorized to propose.",
	},
	{
		ID:      "DELEGATION_EXCEEDS_PARENT",
		Num:     9,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The delegation claims more authority than the delegation it was derived from.",
	},
	{
		ID:      "DELEGATION_CYCLE",
		Num:     10,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The delegation chain returns to a party it already passed through, which would launder back authority an earlier hop narrowed.",
	},
	{
		ID:      "DELEGATION_EXPIRED",
		Num:     11,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The delegation this call relies on had expired, by this receiver's clock, when it was checked.",
	},
	{
		ID:      "APPROVAL_DIGEST_MISMATCH",
		Num:     12,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The approval presented names a different canonical action digest than the call it accompanies.",
	},
	{
		ID:      "APPROVAL_EXPIRED",
		Num:     13,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The approval presented had expired, by this receiver's clock, when it was checked.",
	},
	{
		ID:      "APPROVAL_PENDING",
		Num:     14,
		Verdict: controlv1.Verdict_VERDICT_REQUIRE_APPROVAL,
		Summary: "An approval for this exact action digest is open and no approver has answered it yet.",
	},
	{
		ID:      "POLICY_STALE",
		Num:     15,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The policy bundle is not known to be current: it is past the staleness budget in force for this call, no freshness statement confirms it, another bundle replaced it before the call was handed out, or this receiver's clock reads before 1970, after 9999, or earlier than a time it verified for the bundle or already relied on for the call.",
	},
	{
		ID:      "POLICY_UNAVAILABLE",
		Num:     16,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "No policy bundle is available for this call, so nothing evaluated it.",
	},
	{
		ID:      "PDP_TIMEOUT",
		Num:     17,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The external policy decision point does not answer within the deadline set for this call.",
	},
	{
		ID:      "MALFORMED_INPUT",
		Num:     18,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The request could not be read as this contract at all, which is answered with a decision rather than a transport error.",
	},
	{
		ID:      "UNSUPPORTED_SCHEMA",
		Num:     19,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The request names a schema version, a field or an enum number this receiver does not have, which is answered with a decision rather than a transport error.",
	},
	{
		ID:      "EXECUTED_ARGS_MISMATCH",
		Num:     20,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The arguments about to be sent upstream differ from the arguments the decision was made about.",
	},
	{
		ID:      "TOXIC_FLOW_SENSITIVE_TO_EXTERNAL",
		Num:     21,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The call moves data the producer did not establish as public into a destination it did not establish as trusted.",
	},
	{
		ID:      "IDEMPOTENCY_REQUIRED",
		Num:     22,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The call has an effect that cannot be safely repeated and nothing in the request distinguishes it from a repeat.",
	},
	{
		ID:      "SELF_ADMINISTRATION",
		Num:     23,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The call targets the enforcement plane's own policy, approvals or evidence.",
	},
	{
		ID:      "PAUSED",
		Num:     24,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "An operator paused calls in a scope this call falls in, so the enforcement point blocked it whatever the policy decided.",
	},
	{
		ID:      "FAIL_OPEN_READ_CONFIGURED",
		Num:     25,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "This read was not evaluated and keeps its verdict, and it runs only because an operator turned on fail-open for read-only calls, which changes the enforcement and never the verdict.",
	},
	{
		ID:      "REQUIRED_FIELD_ABSENT",
		Num:     26,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "A field this contract requires is absent, and an absent field is never read as the permissive answer.",
	},
	{
		ID:      "LIMIT_EXCEEDED",
		Num:     27,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "A field on the request is larger than the limit this contract sets for it.",
	},
	{
		ID:      "INVALID_FIELD_VALUE",
		Num:     28,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "A field on the request is present and within its limit, and its value breaks a rule the contract states.",
	},
	{
		ID:      "OBLIGATION_NOT_UNDERSTOOD",
		Num:     29,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The call comes with an obligation this enforcement point cannot apply, attached by a policy rule that did not mark it advisory or by an external decision point's answer.",
	},
	{
		ID:      "APPROVAL_REJECTED",
		Num:     30,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "An approver answered the request for this action digest and refused it.",
	},
	{
		ID:      "APPROVAL_ALREADY_USED",
		Num:     31,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The approval presented was already spent on an earlier call of this request and was not issued as multi-use, and a spent approval does not by itself say that the earlier call ran.",
	},
	{
		ID:      "APPROVAL_BUNDLE_MISMATCH",
		Num:     32,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The approval presented was issued under a different policy bundle than the one deciding this call.",
	},
	{
		ID:      "RULE_UNDETERMINED",
		Num:     33,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "A rule that would restrict this call cannot be evaluated against it, because a field or a fact it constrains is absent or unknown.",
	},
	{
		ID:      "TENANT_UNDETERMINED",
		Num:     34,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The request names a tenant on only one side of the cross-tenant comparison, so whether this call crosses tenants cannot be established.",
	},
	{
		ID:      "LOCKDOWN",
		Num:     35,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The enforcement point is in LOCKDOWN, which blocks every call with a material effect whatever the policy decided.",
	},
	{
		ID:      "EVIDENCE_UNAVAILABLE",
		Num:     36,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The enforcement point could not write, keep or read back a record the decision depends on, so the call was not allowed to proceed.",
	},
	{
		ID:      "ACTION_UNCLASSIFIED",
		Num:     37,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The enforcement point's manifest holds no entry for the operation this call names, so no effect class can be given to it.",
	},
	{
		ID:      "APPROVAL_NOT_RESUMED",
		Num:     38,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "An approver granted this action and the request it was granted for no longer exists, so the call was never run and the enforcement point closed its record instead.",
	},
	{
		ID:      "PDP_UNAVAILABLE",
		Num:     39,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "No decision came back from the external decision point for this call, because it could not be asked or reached or replied with something other than a decision.",
	},
	{
		ID:      "PDP_ANSWER_REFUSED",
		Num:     40,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The external decision point replied about this call, and this enforcement point refused to read the reply as a decision.",
	},
	{
		ID:      "PDP_DENY",
		Num:     41,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "The decision consulted the external decision point and it denied this call; the verdict is still INDETERMINATE when a rule stays undetermined.",
	},
	{
		ID:      "PDP_ALLOW",
		Num:     42,
		Verdict: controlv1.Verdict_VERDICT_ALLOW,
		Summary: "The decision consulted the external decision point and it did not deny this call; the verdict is still INDETERMINATE when a rule stays undetermined.",
	},
	{
		ID:      "PAUSE_STATE_UNAVAILABLE",
		Num:     43,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The enforcement point could not read the operator's pause state, so it blocked the call rather than assume that nothing is paused.",
	},
	{
		ID:      "APPROVAL_STATE_UNKNOWN",
		Num:     44,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The enforcement point could not read or trust the approver's answer for a lost hold, so the call was never run.",
	},
	{
		ID:      "RUN_STOPPED",
		Num:     45,
		Verdict: controlv1.Verdict_VERDICT_DENY,
		Summary: "A stop the operator's route allows names the opened run this call belongs to, so the enforcement point blocked it whatever the policy decided.",
	},
	{
		ID:      "STOP_STATE_UNAVAILABLE",
		Num:     46,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "The enforcement point could not read or trust the stop list, so it blocked the call rather than assume that no run is stopped.",
	},
	{
		ID:      "EXECUTION_ABANDONED",
		Num:     47,
		Verdict: controlv1.Verdict_VERDICT_INDETERMINATE,
		Summary: "An execution the enforcement point handed out was neither completed nor aborted before it expired, so it was closed without knowing whether the call ran.",
	},
}
