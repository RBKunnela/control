package approvals_test

import (
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// TestTheOwnRecordRefusedForItsApproverIsReadAsUnknown: the plane's own
// answered record is rewritten to an approver id the claim rule refuses. Find
// then hands it back as unknown, never as an approval or as pending, which
// would tell the agent its request still waits rather than block it. The same
// record under a plain approver reads as its answer says.
func TestTheOwnRecordRefusedForItsApproverIsReadAsUnknown(t *testing.T) {
	for _, c := range []struct {
		name, approver string
		want           controlv1.ApprovalState
	}{
		{"a plain approver", "approver-2", controlv1.ApprovalState_APPROVAL_STATE_APPROVED},
		{"a reserved approver", reservedApprover, controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, dir, h := heldOne(t)
			answerAt(t, dir, minted.Add(time.Minute))
			writeFile(t, dir, answeredName, withApprovalField(t, readFile(t, dir, answeredName), "approverId", `"`+c.approver+`"`))

			found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
			if err != nil || len(found) != 1 {
				t.Fatalf("Find = %d record(s), %v; want the one record", len(found), err)
			}
			if got := found[0].Approval.GetState(); got != c.want {
				t.Errorf("the record reads %s, want %s", got, c.want)
			}
			if c.want == controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED {
				expectUnknownOf(t, found[0], firstApproval, "req-1")
			}
		})
	}
}
