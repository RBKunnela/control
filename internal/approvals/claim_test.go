package approvals_test

import (
	"errors"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// TestAClaimIsTheRecordFiledUnderItsApproval: a held record comes back
// pending, the same record once an approver answered it comes back with the
// claim, and an approval id nothing is filed under is ErrNoApproval.
func TestAClaimIsTheRecordFiledUnderItsApproval(t *testing.T) {
	p, dir := openPlane(t)
	if err := p.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatal(err)
	}
	rec, err := p.Claim(t.Context(), firstApproval)
	if err != nil || rec.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_PENDING || rec.RequestID != "req-1" {
		t.Fatalf("the held claim is %+v, %v", rec, err)
	}
	if _, err := openApprover(t, dir).Answer(t.Context(), firstApproval, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", minted.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rec, err = p.Claim(t.Context(), firstApproval)
	if err != nil || rec.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED || rec.Approval.GetApproverId() != "approver-1" {
		t.Fatalf("the answered claim is %+v, %v", rec, err)
	}
	if _, err := p.Claim(t.Context(), "APPROVAL2"); !errors.Is(err, approvals.ErrNoApproval) {
		t.Errorf("an approval nothing is filed under: %v", err)
	}
	if _, err := p.Claim(t.Context(), "../x"); !errors.Is(err, approvals.ErrRecordName) {
		t.Errorf("an approval id no file takes: %v", err)
	}
}
