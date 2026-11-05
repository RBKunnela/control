package approvals_test

import (
	"errors"
	"maps"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// sibling is the approval id a writer of the directory files a second record
// under.
const sibling = "APPROVAL2"

// reservedApprover is an approver id the claim rule refuses.
const reservedApprover = "authn:okta:alice"

// forgeSibling files a copy of the answered record under another approval id,
// for requestID, naming approverID, as a writer of the directory would.
func forgeSibling(t *testing.T, dir, requestID, approverID string) {
	t.Helper()
	b := withField(t, readFile(t, dir, answeredName), "approval_id", `"`+sibling+`"`)
	b = withApprovalField(t, b, "approvalId", `"`+sibling+`"`)
	b = withField(t, b, "request_id", `"`+requestID+`"`)
	b = withApprovalField(t, b, "requestId", `"`+requestID+`"`)
	b = withApprovalField(t, b, "approverId", `"`+approverID+`"`)
	writeFile(t, dir, sibling+".1-answered.rec", b)
}

// recordOf is the one record of approvalID among found.
func recordOf(t *testing.T, found []approvals.Record, approvalID string) approvals.Record {
	t.Helper()
	for _, rec := range found {
		if rec.ApprovalID == approvalID {
			return rec
		}
	}
	t.Fatalf("no record of %s among %d", approvalID, len(found))
	return approvals.Record{}
}

// expectUnknown holds a refused record to what Find may say of it: what
// identifies it and its window, and nothing about its answer.
func expectUnknown(t *testing.T, rec approvals.Record, requestID string) {
	t.Helper()
	expectUnknownOf(t, rec, sibling, requestID)
}

// expectUnknownOf is expectUnknown for the record of approvalID.
func expectUnknownOf(t *testing.T, rec approvals.Record, approvalID, requestID string) {
	t.Helper()
	a := rec.Approval
	switch {
	case a.GetState() != controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED || a.GetApproverId() != "" || a.GetDecidedAt() != nil:
		t.Errorf("the refused record carries its answer: %s by %q at %v", a.GetState(), a.GetApproverId(), a.GetDecidedAt())
	case a.GetApprovalId() != approvalID || a.GetRequestId() != requestID || rec.RequestID != requestID:
		t.Errorf("the refused record names %s for %s, want %s for %s", a.GetApprovalId(), a.GetRequestId(), approvalID, requestID)
	case !a.GetRequestedAt().AsTime().Equal(minted) || !a.GetExpiresAt().AsTime().Equal(expires):
		t.Errorf("the refused record's window is %v to %v, want %v to %v", a.GetRequestedAt(), a.GetExpiresAt(), minted, expires)
	case a.GetActionDigest() == "" || a.GetPolicyBundleDigest() != string(bundle):
		t.Errorf("the refused record's digests are %q and %q", a.GetActionDigest(), a.GetPolicyBundleDigest())
	}
}

// TestARefusedRecordOfAnotherRequestBlocksNothing: a writer files a record
// for another request of the same action, or a second file for the plane's
// own request, under an approver id the claim rule refuses. Find answers about
// every record of the binding, the refused one as unknown and the plane's own
// as it stands, and writes nothing.
func TestARefusedRecordOfAnotherRequestBlocksNothing(t *testing.T) {
	for name, requestID := range map[string]string{"another request": "req-2", "the same request": "req-1"} {
		t.Run(name, func(t *testing.T) {
			p, dir, h := heldOne(t)
			answerAt(t, dir, minted.Add(time.Minute))
			forgeSibling(t, dir, requestID, reservedApprover)
			now := minted.Add(2 * time.Minute)

			found, err := p.Find(t.Context(), h.Binding, now)
			if err != nil || len(found) != 2 {
				t.Fatalf("Find = %d record(s), %v; want the plane's own and the refused one", len(found), err)
			}
			expectUnknown(t, recordOf(t, found, sibling), requestID)
			own := recordOf(t, found, firstApproval)
			if own.Approval.GetApproverId() != "approver-1" || own.Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
				t.Errorf("the plane's own record reads %s by %q", own.Approval.GetState(), own.Approval.GetApproverId())
			}
			assertNames(t, dir, answeredName, sibling+".1-answered.rec")
		})
	}
}

// TestARefusedRecordPastItsExpiryIsHidden: Find hides a refused record that
// has expired, as it hides any other, so it says nothing past its window.
func TestARefusedRecordPastItsExpiryIsHidden(t *testing.T) {
	p, dir, h := heldOne(t)
	answerAt(t, dir, minted.Add(time.Minute))
	forgeSibling(t, dir, "req-2", reservedApprover)
	early := expires.Add(-5 * time.Minute)
	writeFile(t, dir, sibling+".1-answered.rec", withApprovalField(t, readFile(t, dir, sibling+".1-answered.rec"),
		"expiresAt", mustJSON(t, early.Format(time.RFC3339Nano))))

	found, err := p.Find(t.Context(), h.Binding, early.Add(-time.Second))
	if err != nil || len(found) != 2 {
		t.Fatalf("Find before the refused record's expiry = %d record(s), %v; want both", len(found), err)
	}
	found, err = p.Find(t.Context(), h.Binding, early)
	if err != nil || len(found) != 1 || found[0].ApprovalID != firstApproval {
		t.Errorf("Find at the refused record's expiry = %v, %v; want the plane's own record alone", found, err)
	}
	if found, err := p.Find(t.Context(), h.Binding, expires.Add(time.Hour)); !errors.Is(err, approvals.ErrNoApproval) {
		t.Errorf("Find past every expiry = %v, %v; want ErrNoApproval", found, err)
	}
}

// TestARefusedOwnRecordIsReadAsUnknownBesideAnAcceptedSibling: the plane's
// own record is refused for its approver id and a writer files an accepted
// record of the same request under another approval id. Find hands back the
// sibling as it stands and the plane's own record as unknown, so nothing it
// says about its answer reaches the plane, and the directory is left byte for
// byte as it was.
func TestARefusedOwnRecordIsReadAsUnknownBesideAnAcceptedSibling(t *testing.T) {
	p, dir, h := heldOne(t)
	answerAt(t, dir, minted.Add(time.Minute))
	forgeSibling(t, dir, "req-1", "approver-2")
	writeFile(t, dir, answeredName, withApprovalField(t, readFile(t, dir, answeredName), "approverId", `"`+reservedApprover+`"`))
	before := dirContents(t, dir)

	found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
	if err != nil || len(found) != 2 {
		t.Fatalf("Find = %d record(s), %v; want both", len(found), err)
	}
	expectUnknownOf(t, recordOf(t, found, firstApproval), firstApproval, "req-1")
	if sib := recordOf(t, found, sibling); sib.Approval.GetApproverId() != "approver-2" {
		t.Errorf("the accepted sibling reads approver %q", sib.Approval.GetApproverId())
	}
	if after := dirContents(t, dir); !maps.Equal(before, after) {
		t.Fatalf("Find changed the directory: %v, was %v", keysOf(after), keysOf(before))
	}
}

// TestFindTellsARefusedRecordFromAnUnreadableOne: a record that will not
// decode still refuses the whole Find, which is what the claim rule's
// exception is an exception to.
func TestFindTellsARefusedRecordFromAnUnreadableOne(t *testing.T) {
	p, dir, h := heldOne(t)
	answerAt(t, dir, minted.Add(time.Minute))
	forgeSibling(t, dir, "req-2", "approver-2")
	writeFile(t, dir, sibling+".1-answered.rec", withApprovalField(t, readFile(t, dir, sibling+".1-answered.rec"),
		"decidedAt", mustJSON(t, minted.Add(-time.Hour).Format(time.RFC3339Nano))))
	if found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute)); !errors.Is(err, approvals.ErrDecidedAt) {
		t.Errorf("Find beside a record decided before its request = %d record(s), %v; want ErrDecidedAt", len(found), err)
	}
}
