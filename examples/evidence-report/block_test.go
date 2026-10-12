package main

import "testing"

const oneBlocked = "totals: requests 1, completed 0, failed 0, uncertain 0, aborted 0, blocked 1, open 0, unknown 0; " +
	"gaps 0, duplicates 0, conflicting 0, refused 0" + endReached

// TestBlockColumn holds the block column to the decision ACTION_BLOCKED
// carries: = when it is the kernel's by decision_id, the block's own
// verdict and codes otherwise, and never in place of the kernel's verdict and codes.
func TestBlockColumn(t *testing.T) {
	proposal := step{"ACTION_PROPOSED", proposed("refund")}
	blocked := func(kernel, block string) string {
		return whole("r1", proposal, step{"POLICY_DECIDED", kernel}, step{"ACTION_BLOCKED", block})
	}
	afterApproval := whole("r3", step{"ACTION_PROPOSED", proposed("update_order")},
		step{"POLICY_DECIDED", decidedAs("k1", "REQUIRE_APPROVAL", "APPROVAL_REQUIRED")},
		step{"APPROVAL_REQUESTED", approval("PENDING")}, step{"APPROVAL_DECIDED", approval("APPROVED")},
		step{"ACTION_BLOCKED", decidedAs("e1", "DENY", "APPROVAL_EXPIRED")})
	cases := []reportCase{
		{name: "a call paused after the kernel allowed it",
			in:   blocked(decidedAs("k1", "ALLOW", "RULE_ALLOW"), decidedAs("e1", "DENY", "PAUSED")),
			rows: []string{"t\tp\tr1\trun-r1\trefund\tALLOW\tRULE_ALLOW\tDENY PAUSED\tno\t-\tblocked\t-"}, totals: oneBlocked},
		{name: "a tool the plane cannot classify",
			in:   blocked(decidedAs("k1", "INDETERMINATE", "MALFORMED_INPUT"), decidedAs("e1", "INDETERMINATE", "ACTION_UNCLASSIFIED")),
			rows: []string{"t\tp\tr1\trun-r1\trefund\tINDETERMINATE\tMALFORMED_INPUT\tINDETERMINATE ACTION_UNCLASSIFIED\tno\t-\tblocked\t-"}, totals: oneBlocked},
		{name: "the kernel's own deny", in: blocked(decidedAs("k1", "DENY", "RULE_DENY"), decidedAs("k1", "DENY", "RULE_DENY")),
			rows: []string{"t\tp\tr1\trun-r1\trefund\tDENY\tRULE_DENY\t=\tno\t-\tblocked\t-"}, totals: oneBlocked},
		{name: "the plane's decision repeating the kernel's codes", in: blocked(decidedAs("k1", "DENY", "RULE_DENY"), decidedAs("e1", "DENY", "RULE_DENY")),
			rows: []string{"t\tp\tr1\trun-r1\trefund\tDENY\tRULE_DENY\tDENY RULE_DENY\tno\t-\tblocked\t-"}, totals: oneBlocked},
		{name: "two decisions that name no decision_id", in: blocked(decided("DENY", "RULE_DENY"), decided("DENY", "RULE_DENY")),
			rows: []string{"t\tp\tr1\trun-r1\trefund\tDENY\tRULE_DENY\tDENY RULE_DENY\tno\t-\tblocked\t-"}, totals: oneBlocked},
		{name: "a block after the approval was answered yes", in: afterApproval,
			rows: []string{"t\tp\tr3\trun-r3\tupdate_order\tREQUIRE_APPROVAL\tAPPROVAL_REQUIRED\tDENY APPROVAL_EXPIRED\tyes\tapproved\tblocked\t-"}, totals: oneBlocked},
		{name: "a call that was never blocked", in: whole("r1", allowed...), rows: []string{rowAllowed},
			totals: oneCompleted + "gaps 0, duplicates 0, conflicting 0, refused 0" + endReached},
		unknownOne("a second POLICY_DECIDED, which keeps the first",
			whole("r1", proposal, step{"POLICY_DECIDED", decidedAs("k1", "ALLOW", "RULE_ALLOW")},
				step{"POLICY_DECIDED", decidedAs("k2", "DENY", "RULE_DENY")}, step{"ACTION_BLOCKED", decidedAs("k2", "DENY", "RULE_DENY")}),
			"t\tp\tr1\trun-r1\trefund\tALLOW\tRULE_ALLOW\tDENY RULE_DENY\tno\t-\tunknown\tPOLICY_DECIDED cannot follow POLICY_DECIDED"),
		unknownOne("a block without its decision", blocked(decidedAs("k1", "ALLOW", "RULE_ALLOW"), ""),
			"t\tp\tr1\trun-r1\trefund\tALLOW\tRULE_ALLOW\t-\tno\t-\tunknown\tevent r1-3 is ACTION_BLOCKED and carries no decision"),
		unknownOne("a block that decides no verdict", blocked(decidedAs("k1", "ALLOW", "RULE_ALLOW"), `,"decision":{"decisionId":"e1"}`),
			"t\tp\tr1\trun-r1\trefund\tALLOW\tRULE_ALLOW\tUNSPECIFIED -\tno\t-\tunknown\tevent r1-3 is ACTION_BLOCKED and decides no verdict"),
		unknownOne("a block with a verdict the contract does not declare",
			blocked(decidedAs("k1", "ALLOW", "RULE_ALLOW"), `,"decision":{"decisionId":"e1","verdict":99,"reasonCodes":["PAUSED"]}`),
			"t\tp\tr1\trun-r1\trefund\tALLOW\tRULE_ALLOW\t99 PAUSED\tno\t-\tunknown\tevent r1-3 decides verdict 99, which this reader does not declare"),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc) })
	}
}
