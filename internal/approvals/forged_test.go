package approvals_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
)

// The approval id a writer of the directory files under, which is every id the
// plane did not mint.
const forgedApproval = "MALLORY1"

// forgeUnder writes a record of forgedApproval by taking the plane's own
// answered record and renaming it inside and out. Everything else — the
// binding, the request id, the answer — is what the plane wrote, so the only
// thing that tells the two apart is the approval id.
func forgeUnder(t *testing.T, dir string, st string) {
	t.Helper()
	framed := readFile(t, dir, firstApproval+st)
	body := replaceInBody(t, framed, `"approval_id":"`+firstApproval+`"`, `"approval_id":"`+forgedApproval+`"`)
	body = bytes.Replace(body, []byte(`"approvalId":"`+firstApproval+`"`), []byte(`"approvalId":"`+forgedApproval+`"`), 1)
	writeFile(t, dir, forgedApproval+st, reframe(t, body))
}

// answeredAndForged leaves the plane's own answered record for req-1 beside a
// forged one under the same binding and the same request id.
func answeredAndForged(t *testing.T) (*approvals.Plane, string, approvals.Hold) {
	t.Helper()
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))
	forgeUnder(t, dir, ".1-answered.rec")
	return p, dir, h
}

// approvalIDs is the approval ids among found, in the order Find gave them.
func approvalIDs(found []approvals.Record) []string {
	var ids []string
	for _, rec := range found {
		ids = append(ids, rec.ApprovalID)
	}
	return ids
}

// TestAForgedRecordComesBackUnderItsOwnApprovalID: a record filed under the
// binding and the request id of a held call, with any other approval id, is
// handed back under that id and no other, so the plane, which judges only the
// record of the approval id it minted, never reads it as its own. The plane's
// own record is unlinked here because a writer of the directory may unlink as
// well as write.
func TestAForgedRecordComesBackUnderItsOwnApprovalID(t *testing.T) {
	p, dir, h := answeredAndForged(t)
	if err := os.Remove(filepath.Join(dir, firstApproval+".1-answered.rec")); err != nil {
		t.Fatalf("unlinking the plane's own record: %v", err)
	}
	found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
	if err != nil || !slices.Equal(approvalIDs(found), []string{forgedApproval}) ||
		found[0].Approval.GetApprovalId() != forgedApproval || found[0].Approval.GetRequestId() != "req-1" {
		t.Fatalf("Find = %v, %v; want the forged record under its own id alone", approvalIDs(found), err)
	}
	assertNames(t, dir, forgedApproval+".1-answered.rec")
}

// TestThePlanesOwnRecordComesBackBesideAForgedOne: the same directory with
// the plane's own record still there. Both come back, each under its own id,
// and Find writes nothing.
func TestThePlanesOwnRecordComesBackBesideAForgedOne(t *testing.T) {
	p, dir, h := answeredAndForged(t)
	found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
	if err != nil || !slices.Equal(approvalIDs(found), []string{firstApproval, forgedApproval}) {
		t.Fatalf("Find = %v, %v; want the plane's own record and the forged one", approvalIDs(found), err)
	}
	assertNames(t, dir, firstApproval+".1-answered.rec", forgedApproval+".1-answered.rec")
}

// TestAnApprovalNobodyClaimedIsNotUsable: an APPROVED record with no
// approver, written straight into the directory past Answer's own check, is a
// grant nobody made. Find hands it back as it stands and what the plane judges
// it by says it is no approval.
func TestAnApprovalNobodyClaimedIsNotUsable(t *testing.T) {
	p, dir, h := heldOne(t)
	answerAt(t, dir, minted.Add(time.Minute))
	writeFile(t, dir, answeredName, withApprovalField(t, readFile(t, dir, answeredName), "approverId", `""`))
	now := minted.Add(2 * time.Minute)
	found, err := p.Find(t.Context(), h.Binding, now)
	if err != nil || len(found) != 1 {
		t.Fatalf("Find = %v, %v", found, err)
	}
	if got := approval.Consumable(found[0].Approval, now); got != approval.StandingUnusable {
		t.Errorf("an approval nobody claimed stands %v, want unusable", got)
	}
	assertNames(t, dir, answeredName)
}

// TestAnAnswerIsStillReadBackFromTheRecordThePlaneMinted holds the ordinary
// path against the checks above: the plane mints, an approver answers, and
// the plane reads the answer from its own record.
func TestAnAnswerIsStillReadBackFromTheRecordThePlaneMinted(t *testing.T) {
	p, dir := openPlane(t)
	h := held(t, firstApproval, "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatalf("holding: %v", err)
	}
	answerAt(t, dir, minted.Add(time.Minute))
	found, err := p.Find(t.Context(), h.Binding, minted.Add(2*time.Minute))
	if err != nil || len(found) != 1 || found[0].Approval.GetState() != controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Fatalf("Find = %v, %v; want the approved record", found, err)
	}
}
